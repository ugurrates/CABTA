"""
Playbook Engine - Execute predefined investigation workflows.

Supports:
  - Sequential and conditional step execution
  - ``for_each`` iteration over dynamic result sets
  - Human-in-the-loop approval checkpoints
  - YAML-based playbook definitions (loaded from ``data/playbooks/``)
  - Runtime variable interpolation in tool parameters

A playbook is a list of steps.  Each step invokes a tool and can branch
based on the outcome (``on_success`` / ``on_failure`` / ``condition``).
"""

import json
import logging
import operator
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Try to import yaml; fall back gracefully if not installed
try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PlaybookStep:
    """One step in a playbook."""
    name: str
    tool: str
    params: Dict[str, Any] = field(default_factory=dict)
    condition: Optional[str] = None  # e.g. "verdict == 'MALICIOUS'"
    on_success: Optional[str] = None  # Name of the next step on success
    on_failure: Optional[str] = None  # Name of the next step on failure
    requires_approval: bool = False  # Pause for human approval
    for_each: Optional[str] = None  # Iterate over a context variable
    timeout: int = 120  # Per-step timeout in seconds
    description: str = ""
    action: Optional[str] = None  # e.g. "final_answer", "trigger_playbook", "input"

    def to_dict(self) -> Dict:
        d = {
            "name": self.name,
            "tool": self.tool,
            "params": self.params,
            "condition": self.condition,
            "on_success": self.on_success,
            "on_failure": self.on_failure,
            "requires_approval": self.requires_approval,
            "for_each": self.for_each,
            "timeout": self.timeout,
            "description": self.description,
        }
        if self.action:
            d["action"] = self.action
        return d

    @classmethod
    def from_dict(cls, d: Dict) -> "PlaybookStep":
        # Handle condition: can be a string or a dict with if/then/else
        raw_cond = d.get("condition")
        condition_str = None
        on_success = d.get("on_success")
        on_failure = d.get("on_failure")

        if isinstance(raw_cond, dict):
            # Playbook YAML format: condition: {if: "...", then: "step", else: "step"}
            condition_str = raw_cond.get("if")
            if isinstance(condition_str, str):
                condition_str = condition_str.strip()
            cond_then = raw_cond.get("then")
            cond_else = raw_cond.get("else")
            if cond_then and not on_success:
                on_success = cond_then
            if cond_else and not on_failure:
                on_failure = cond_else
        elif isinstance(raw_cond, str):
            condition_str = raw_cond

        return cls(
            name=d["name"],
            tool=d.get("tool", ""),
            params=d.get("params") or {},
            condition=condition_str,
            on_success=on_success,
            on_failure=on_failure,
            requires_approval=d.get("requires_approval", False),
            for_each=d.get("for_each"),
            timeout=d.get("timeout", 120),
            description=d.get("description", ""),
            action=d.get("action"),
        )


# ---------------------------------------------------------------------------
# Safe condition evaluator (no eval)
# ---------------------------------------------------------------------------

# Supported operators for condition parsing
_OPERATORS = {
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
}

# Regex to parse simple conditions like: variable op value
_SIMPLE_COND = re.compile(
    r"^\s*(\w[\w.]*)\s*(==|!=|>=?|<=?)\s*(.+?)\s*$"
)
# Regex to parse 'value in variable' conditions
_IN_COND = re.compile(
    r"""^\s*['"](.+?)['"]\s+in\s+(\w[\w.]*)\s*$"""
)
# Regex to parse 'variable in (val1, val2)' conditions
_VAR_IN_TUPLE = re.compile(
    r"""^\s*(\w[\w.]*)\s+in\s+\((.+?)\)\s*$"""
)


def _parse_literal(text: str) -> Any:
    """Parse a string literal into a Python value."""
    text = text.strip()
    if (text.startswith("'") and text.endswith("'")) or \
       (text.startswith('"') and text.endswith('"')):
        return text[1:-1]
    if text.lower() == "true":
        return True
    if text.lower() == "false":
        return False
    if text.lower() == "none":
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def _resolve_var(var_path: str, context: Dict) -> Any:
    """Resolve a dotted variable path in the context dict."""
    parts = var_path.split(".")
    obj = context
    for part in parts:
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        else:
            return None
    return obj


def safe_evaluate_condition(condition: str, context: Dict) -> bool:
    """
    Evaluate a step condition safely WITHOUT using eval().

    Supported syntax:
    - ``verdict == 'MALICIOUS'``
    - ``score > 70``
    - ``score >= 50``
    - ``'ransomware' in tags``
    - ``file_type in ('PE', 'ELF')``
    - ``cond1 and cond2``   (split on ' and ')
    - ``cond1 or cond2``    (split on ' or ')

    Returns False on any parse error (safe default).
    """
    if not condition or not condition.strip():
        return True

    condition = condition.strip()

    try:
        # Handle 'and' by splitting
        if " and " in condition:
            parts = condition.split(" and ")
            return all(safe_evaluate_condition(p.strip(), context) for p in parts)

        # Handle 'or' by splitting
        if " or " in condition:
            parts = condition.split(" or ")
            return any(safe_evaluate_condition(p.strip(), context) for p in parts)

        # Flatten context: include last_result fields at top level
        flat_ctx = dict(context)
        lr = context.get("last_result", {})
        if isinstance(lr, dict):
            for k, v in lr.items():
                if k not in flat_ctx:
                    flat_ctx[k] = v
        # Also flatten one level of nested dicts
        for key, val in list(context.items()):
            if isinstance(val, dict):
                for k2, v2 in val.items():
                    fk = f"{key}_{k2}"
                    if fk not in flat_ctx:
                        flat_ctx[fk] = v2

        # Pattern: 'value' in variable
        m = _IN_COND.match(condition)
        if m:
            needle = m.group(1)
            haystack = _resolve_var(m.group(2), flat_ctx)
            if isinstance(haystack, (list, tuple, set)):
                return needle in haystack
            if isinstance(haystack, str):
                return needle in haystack
            return False

        # Pattern: variable in (val1, val2, ...)
        m = _VAR_IN_TUPLE.match(condition)
        if m:
            var_val = _resolve_var(m.group(1), flat_ctx)
            tuple_items = [_parse_literal(v.strip()) for v in m.group(2).split(",")]
            return var_val in tuple_items

        # Pattern: variable op value
        m = _SIMPLE_COND.match(condition)
        if m:
            left_val = _resolve_var(m.group(1), flat_ctx)
            op_str = m.group(2)
            right_val = _parse_literal(m.group(3))

            op_func = _OPERATORS.get(op_str)
            if op_func is None:
                return False

            # Type coercion for numeric comparisons
            if isinstance(right_val, (int, float)) and left_val is not None:
                try:
                    left_val = type(right_val)(left_val)
                except (ValueError, TypeError):
                    pass

            try:
                return op_func(left_val, right_val)
            except TypeError:
                return False

        # Unrecognised pattern
        logger.debug("[PLAYBOOK] Could not parse condition: %s", condition)
        return False

    except Exception as exc:
        logger.debug("[PLAYBOOK] Condition '%s' failed: %s", condition, exc)
        return False


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class PlaybookEngine:
    """
    Loads and executes investigation playbooks.

    A playbook is identified by its ``playbook_id`` (which is either its
    file-stem for built-in YAML playbooks or the DB ``id`` for user-created
    ones).

    The engine delegates actual tool calls to the ``agent_loop``, which
    handles MCP tool routing, local tools, and result recording.
    """

    def __init__(self, agent_loop, agent_store):
        """
        Parameters
        ----------
        agent_loop
            An object with an async ``run_tool(tool_name, params) -> dict``
            method.
        agent_store
            An ``AgentStore`` instance for persistence.
        """
        self.agent_loop = agent_loop
        self.store = agent_store

        # Built-in playbooks directory
        self._playbooks_dir = Path(__file__).parent.parent.parent / "data" / "playbooks"

        # In-memory cache: playbook_id -> definition dict
        self._cache: Dict[str, Dict] = {}

        # Load built-in playbooks at start
        self.load_builtin_playbooks()

    # ------------------------------------------------------------------ #
    #  Loading
    # ------------------------------------------------------------------ #

    def load_builtin_playbooks(self) -> int:
        """
        Load YAML playbook definitions from ``data/playbooks/``.

        Returns the number of playbooks loaded.
        """
        if not self._playbooks_dir.is_dir():
            logger.debug("[PLAYBOOK] No playbooks directory at %s", self._playbooks_dir)
            return 0

        if not _HAS_YAML:
            logger.warning(
                "[PLAYBOOK] PyYAML is not installed -- cannot load YAML playbooks. "
                "Install with: pip install pyyaml"
            )
            return 0

        count = 0
        for path in sorted(self._playbooks_dir.glob("*.yaml")) + sorted(self._playbooks_dir.glob("*.yml")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    definition = yaml.safe_load(f)

                if not isinstance(definition, dict):
                    logger.warning("[PLAYBOOK] Skipping %s (not a dict)", path.name)
                    continue

                pid = definition.get("id", path.stem)
                definition["id"] = pid
                definition["source"] = "builtin"
                definition["file"] = str(path)

                # Validate steps
                steps = definition.get("steps", [])
                if not steps:
                    logger.warning("[PLAYBOOK] Skipping %s (no steps)", path.name)
                    continue

                # Parse steps into PlaybookStep objects (validation)
                parsed = [PlaybookStep.from_dict(s) for s in steps]
                definition["_parsed_steps"] = parsed

                self._cache[pid] = definition
                count += 1
                logger.debug("[PLAYBOOK] Loaded: %s (%d steps)", pid, len(parsed))

            except Exception as exc:
                logger.warning("[PLAYBOOK] Failed to load %s: %s", path.name, exc)

        # Also load from DB
        try:
            for pb in self.store.list_playbooks():
                pid = pb.get("id", pb.get("name", ""))
                if pid and pid not in self._cache:
                    steps_data = pb.get("steps_json", [])
                    if isinstance(steps_data, str):
                        steps_data = json.loads(steps_data)
                    self._cache[pid] = {
                        "id": pid,
                        "name": pb.get("name", pid),
                        "description": pb.get("description", ""),
                        "steps": steps_data,
                        "_parsed_steps": [PlaybookStep.from_dict(s) for s in steps_data],
                        "source": "database",
                    }
                    count += 1
        except Exception as exc:
            logger.debug("[PLAYBOOK] DB load error: %s", exc)

        logger.info("[PLAYBOOK] %d playbooks available", len(self._cache))
        return count

    # ------------------------------------------------------------------ #
    #  Accessors
    # ------------------------------------------------------------------ #

    def get_playbook(self, playbook_id: str) -> Optional[Dict]:
        """Get a playbook definition by ID."""
        pb = self._cache.get(playbook_id)
        if pb:
            return {
                "id": pb.get("id", playbook_id),
                "name": pb.get("name", playbook_id),
                "description": pb.get("description", ""),
                "steps": [
                    s.to_dict() if hasattr(s, "to_dict") else s
                    for s in pb.get("_parsed_steps", pb.get("steps", []))
                ],
                "source": pb.get("source", "unknown"),
                "trigger_type": pb.get("trigger_type", "manual"),
            }
        return None

    def list_playbooks(self) -> List[Dict]:
        """List all available playbooks (built-in + database)."""
        results = []
        for pid, pb in self._cache.items():
            results.append({
                "id": pid,
                "name": pb.get("name", pid),
                "description": pb.get("description", ""),
                "step_count": len(pb.get("_parsed_steps", pb.get("steps", []))),
                "source": pb.get("source", "unknown"),
                "trigger_type": pb.get("trigger_type", "manual"),
            })
        return results

    def list_available(self) -> List[Dict]:
        """Alias for ``list_playbooks`` -- lists all available playbooks."""
        return self.list_playbooks()

    def load_playbook(self, yaml_path: str) -> Dict:
        """Load a single YAML playbook from a file path and register it.

        Args:
            yaml_path: Absolute or relative path to the YAML playbook file.

        Returns:
            Dict with playbook metadata (id, name, step_count) on success,
            or a dict with an ``error`` key on failure.
        """
        if not _HAS_YAML:
            return {"error": "PyYAML is not installed. Install with: pip install pyyaml"}

        path = Path(yaml_path)
        if not path.is_file():
            return {"error": f"Playbook file not found: {yaml_path}"}

        try:
            with open(path, "r", encoding="utf-8") as f:
                definition = yaml.safe_load(f)

            if not isinstance(definition, dict):
                return {"error": f"Invalid playbook format in {path.name} (expected a dict)"}

            pid = definition.get("id", path.stem)
            definition["id"] = pid
            definition["source"] = "file"
            definition["file"] = str(path.resolve())

            steps = definition.get("steps", [])
            if not steps:
                return {"error": f"Playbook {path.name} has no steps"}

            parsed = [PlaybookStep.from_dict(s) for s in steps]
            definition["_parsed_steps"] = parsed

            self._cache[pid] = definition

            logger.info("[PLAYBOOK] Loaded from file: %s (%d steps)", pid, len(parsed))

            return {
                "id": pid,
                "name": definition.get("name", pid),
                "description": definition.get("description", ""),
                "step_count": len(parsed),
                "source": "file",
                "file": str(path.resolve()),
            }

        except Exception as exc:
            logger.error("[PLAYBOOK] Failed to load %s: %s", yaml_path, exc)
            return {"error": f"Failed to load playbook: {exc}"}

    # ------------------------------------------------------------------ #
    #  Execution
    # ------------------------------------------------------------------ #

    async def execute(
        self,
        playbook_id: str,
        input_data: Dict,
        case_id: Optional[str] = None,
    ) -> str:
        """
        Execute a playbook.

        Parameters
        ----------
        playbook_id : str
            ID of the playbook to run.
        input_data : dict
            Initial context variables (e.g. ``{"file_path": "/tmp/mal.exe"}``).
        case_id : str, optional
            Associated case ID for tracking.

        Returns
        -------
        str
            Session ID of the execution.
        """
        pb = self._cache.get(playbook_id)
        if pb is None:
            raise ValueError(f"Playbook '{playbook_id}' not found")

        steps: List[PlaybookStep] = pb.get("_parsed_steps", [])
        if not steps:
            raise ValueError(f"Playbook '{playbook_id}' has no steps")

        # Create a session
        goal = f"Playbook: {pb.get('name', playbook_id)}"
        session_id = self.store.create_session(
            goal=goal, case_id=case_id, playbook_id=playbook_id,
        )

        # Execution context (variables available to steps)
        context: Dict[str, Any] = {
            "session_id": session_id,
            "playbook_id": playbook_id,
            "input": input_data,
            **input_data,
        }

        # Build step lookup by name
        step_map: Dict[str, PlaybookStep] = {s.name: s for s in steps}

        logger.info(
            "[PLAYBOOK] Starting %s (session %s, %d steps)",
            playbook_id, session_id, len(steps),
        )

        current_step: Optional[PlaybookStep] = steps[0]
        step_number = 0

        try:
            while current_step is not None:
                step_number += 1

                # Safety: prevent infinite loops
                if step_number > 200:
                    logger.error("[PLAYBOOK] Step limit (200) reached -- aborting")
                    self.store.update_session_status(
                        session_id, "failed",
                        summary="Aborted: exceeded maximum step count (200)",
                    )
                    return session_id

                # Evaluate condition
                if current_step.condition:
                    if not self.evaluate_condition(current_step.condition, context):
                        logger.debug(
                            "[PLAYBOOK] Skipping step '%s' (condition false)",
                            current_step.name,
                        )
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, step_number,
                        )
                        continue

                # Human approval checkpoint
                if current_step.requires_approval:
                    logger.info(
                        "[PLAYBOOK] Step '%s' requires human approval -- pausing",
                        current_step.name,
                    )
                    self.store.add_step(
                        session_id=session_id,
                        step_number=step_number,
                        step_type="approval_required",
                        content=f"Waiting for approval: {current_step.description or current_step.name}",
                        tool_name=current_step.tool,
                        tool_params=json.dumps(
                            self._interpolate_params(current_step.params, context),
                            default=str,
                        ),
                    )
                    self.store.update_session_status(session_id, "waiting_approval")

                    # In a real system this would block until approval arrives.
                    # For now we log and return -- the UI / API layer handles
                    # the approval flow and re-calls execute_from_step.
                    return session_id

                # Handle action-only steps (no tool call needed)
                if current_step.action and not current_step.tool:
                    action = current_step.action
                    params = self._interpolate_params(current_step.params, context)

                    if action == "final_answer":
                        # Terminal step: record description as final report
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="final_answer",
                            content=current_step.description or current_step.name,
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result=json.dumps(
                                {"action": "final_answer", "report": current_step.description},
                                default=str,
                            ),
                            duration_ms=0,
                        )
                        context[current_step.name] = {
                            "action": "final_answer",
                            "report": current_step.description,
                        }
                        context["last_result"] = context[current_step.name]
                        # final_answer is terminal — go to next sequential or end
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, step_number,
                        )
                        continue

                    elif action == "trigger_playbook":
                        # Trigger another playbook
                        target_pb = params.get("playbook", "")
                        trigger_input = {k: v for k, v in params.items() if k != "playbook"}
                        trigger_input.update({k: v for k, v in context.items()
                                              if k not in ("session_id", "playbook_id", "input")})

                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="trigger_playbook",
                            content=f"Triggering playbook: {target_pb}",
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result="",
                            duration_ms=0,
                        )

                        try:
                            sub_session = await self.execute(
                                target_pb, trigger_input, case_id=case_id,
                            )
                            context[current_step.name] = {
                                "action": "trigger_playbook",
                                "playbook": target_pb,
                                "sub_session_id": sub_session,
                            }
                        except Exception as exc:
                            logger.warning(
                                "[PLAYBOOK] trigger_playbook '%s' failed: %s",
                                target_pb, exc,
                            )
                            context[current_step.name] = {
                                "action": "trigger_playbook",
                                "playbook": target_pb,
                                "error": str(exc),
                            }
                        context["last_result"] = context[current_step.name]
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, step_number,
                        )
                        continue

                    elif action == "input":
                        # Input step: use existing context data or record prompt
                        prompt = params.get("prompt", current_step.description)
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="input",
                            content=f"Input: {prompt}",
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result=json.dumps(
                                {"action": "input", "prompt": prompt, "value": prompt},
                                default=str,
                            ),
                            duration_ms=0,
                        )
                        context[current_step.name] = {
                            "action": "input",
                            "value": prompt,
                        }
                        context["last_result"] = context[current_step.name]
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, step_number,
                        )
                        continue

                    else:
                        # Unknown action — log and skip
                        logger.warning(
                            "[PLAYBOOK] Unknown action '%s' in step '%s'",
                            action, current_step.name,
                        )
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="action",
                            content=f"Action: {action} - {current_step.description}",
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result="",
                            duration_ms=0,
                        )
                        context[current_step.name] = {"action": action}
                        context["last_result"] = context[current_step.name]
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, step_number,
                        )
                        continue

                # Handle for_each iteration
                if current_step.for_each:
                    items = _resolve_var(current_step.for_each, context)
                    if not isinstance(items, list):
                        items = [items] if items else []

                    logger.debug(
                        "[PLAYBOOK] for_each '%s': %d items",
                        current_step.for_each, len(items),
                    )

                    iteration_results = []
                    for i, item in enumerate(items[:50]):  # Cap iterations
                        iter_context = {**context, "item": item, "item_index": i}
                        params = self._interpolate_params(current_step.params, iter_context)

                        start = time.time()
                        result = await self._run_tool(
                            current_step.tool, params, current_step.timeout,
                        )
                        duration_ms = int((time.time() - start) * 1000)

                        iteration_results.append(result)

                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="for_each_iteration",
                            content=f"{current_step.name} (item {i})",
                            tool_name=current_step.tool,
                            tool_params=json.dumps(params, default=str),
                            tool_result=json.dumps(result, default=str)[:10000],
                            duration_ms=duration_ms,
                        )

                    context[f"{current_step.name}_results"] = iteration_results
                    context["last_result"] = iteration_results

                    # Determine success
                    has_error = any("error" in r for r in iteration_results if isinstance(r, dict))
                    next_step_name = current_step.on_failure if has_error else current_step.on_success

                else:
                    # Single execution
                    params = self._interpolate_params(current_step.params, context)

                    start = time.time()
                    result = await self._run_tool(
                        current_step.tool, params, current_step.timeout,
                    )
                    duration_ms = int((time.time() - start) * 1000)

                    # Record step
                    self.store.add_step(
                        session_id=session_id,
                        step_number=step_number,
                        step_type="tool_call",
                        content=current_step.description or current_step.name,
                        tool_name=current_step.tool,
                        tool_params=json.dumps(params, default=str),
                        tool_result=json.dumps(result, default=str)[:10000],
                        duration_ms=duration_ms,
                    )

                    # Store result in context
                    context[current_step.name] = result
                    context["last_result"] = result

                    # Also expose nested result fields
                    if isinstance(result, dict):
                        for key, val in result.items():
                            context[f"{current_step.name}_{key}"] = val

                    # Determine next step
                    success = not (isinstance(result, dict) and "error" in result)
                    next_step_name = (
                        current_step.on_success if success else current_step.on_failure
                    )

                # Resolve the next step
                current_step = self._resolve_next(
                    next_step_name, step_map, steps, step_number,
                )

            # All steps completed
            self.store.update_session_status(
                session_id, "completed",
                summary=f"Playbook '{pb.get('name', playbook_id)}' completed "
                        f"({step_number} steps executed)",
            )
            logger.info(
                "[PLAYBOOK] Completed %s (session %s, %d steps)",
                playbook_id, session_id, step_number,
            )

        except Exception as exc:
            logger.error(
                "[PLAYBOOK] Execution error in %s step %d: %s",
                playbook_id, step_number, exc,
            )
            self.store.add_step(
                session_id=session_id,
                step_number=step_number,
                step_type="error",
                content=f"Playbook error: {exc}",
            )
            self.store.update_session_status(
                session_id, "failed", summary=f"Error: {str(exc)[:200]}",
            )

        return session_id

    # ------------------------------------------------------------------ #
    #  Condition evaluation
    # ------------------------------------------------------------------ #

    def evaluate_condition(self, condition: str, context: Dict) -> bool:
        """
        Evaluate a step condition against the current context.

        Delegates to ``safe_evaluate_condition`` which uses pattern matching
        instead of eval() for safety.

        Supported syntax:
        - ``verdict == 'MALICIOUS'``
        - ``score > 70``
        - ``score >= 50 and verdict != 'CLEAN'``
        - ``'ransomware' in tags``
        - ``file_type in ('PE', 'ELF')``
        """
        return safe_evaluate_condition(condition, context)

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    async def _run_tool(self, tool_name: str, params: Dict, timeout: int) -> Dict:
        """
        Run a tool via the agent loop with a timeout.

        Returns the tool result dict, or an ``error`` dict on failure/timeout.
        """
        try:
            if hasattr(self.agent_loop, "run_tool"):
                import asyncio
                result = await asyncio.wait_for(
                    self.agent_loop.run_tool(tool_name, params),
                    timeout=timeout,
                )
                return result if isinstance(result, dict) else {"result": result}
            else:
                return {"error": "agent_loop has no run_tool method"}
        except TimeoutError:
            return {"error": f"Tool '{tool_name}' timed out after {timeout}s"}
        except Exception as exc:
            return {"error": f"Tool '{tool_name}' failed: {exc}"}

    def _interpolate_params(self, params: Dict, context: Dict) -> Dict:
        """
        Replace ``{{variable}}`` placeholders in parameter values with
        values from the context.

        Supports:
        - ``{{file_path}}`` -- simple variable
        - ``{{step_name.field}}`` -- nested access
        - ``{{item}}`` -- current for_each item
        """
        result = {}
        for key, value in params.items():
            if isinstance(value, str):
                result[key] = self._interpolate_string(value, context)
            elif isinstance(value, dict):
                result[key] = self._interpolate_params(value, context)
            elif isinstance(value, list):
                result[key] = [
                    self._interpolate_string(v, context) if isinstance(v, str) else v
                    for v in value
                ]
            else:
                result[key] = value
        return result

    @staticmethod
    def _interpolate_string(template: str, context: Dict) -> str:
        """Replace ``{{var}}`` tokens in a string."""

        def _replacer(match):
            var_path = match.group(1).strip()
            resolved = _resolve_var(var_path, context)
            if resolved is not None:
                return str(resolved)
            return match.group(0)  # Leave placeholder as-is

        return re.sub(r"\{\{(.+?)\}\}", _replacer, template)

    @staticmethod
    def _resolve_next(
        next_name: Optional[str],
        step_map: Dict[str, PlaybookStep],
        steps: List[PlaybookStep],
        current_index: int,
    ) -> Optional[PlaybookStep]:
        """
        Resolve the next step to execute.

        If ``next_name`` is given, look it up in ``step_map``.
        Otherwise fall through to the next sequential step.
        ``None`` means the playbook is done.
        """
        if next_name == "__end__" or next_name == "end":
            return None

        if next_name:
            return step_map.get(next_name)

        # Default: next sequential step
        if current_index < len(steps):
            return steps[current_index]

        return None

    # ------------------------------------------------------------------ #
    #  Playbook creation
    # ------------------------------------------------------------------ #

    def register_playbook(
        self,
        name: str,
        description: str,
        steps: List[Dict],
        trigger_type: str = "manual",
    ) -> str:
        """
        Register a new playbook (saved to DB and cache).

        Returns the playbook ID.
        """
        # Validate steps
        parsed = [PlaybookStep.from_dict(s) for s in steps]

        pid = self.store.save_playbook(
            name=name,
            description=description,
            steps=steps,
            trigger_type=trigger_type,
        )

        self._cache[pid] = {
            "id": pid,
            "name": name,
            "description": description,
            "steps": steps,
            "_parsed_steps": parsed,
            "source": "database",
            "trigger_type": trigger_type,
        }

        logger.info("[PLAYBOOK] Registered: %s (%d steps)", name, len(parsed))
        return pid
