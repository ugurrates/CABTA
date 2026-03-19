"""
Agent Loop - ReAct reasoning engine for autonomous security investigations.

The loop cycles through THINK -> ACT -> OBSERVE until the LLM decides to emit
a final answer or the step budget is exhausted.  Dangerous actions pause for
analyst approval (WAITING_HUMAN).
"""

import asyncio
import json
import logging
import re
import time
import threading
from typing import Any, Dict, List, Optional

import aiohttp

from .agent_state import AgentPhase, AgentState
from .agent_store import AgentStore
from .tool_registry import ToolRegistry

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------- #
#  System prompt template
# -------------------------------------------------------------------- #

_SYSTEM_PROMPT = """\
You are a Blue Team Security Agent. You investigate security threats autonomously.

Investigation goal: {goal}

Previous findings:
{findings_block}

{playbooks_block}

INSTRUCTIONS:
1. You MUST use tools to gather evidence before drawing conclusions. Never answer from memory alone.
2. For IOC investigations: call investigate_ioc first, then use MCP tools like osint-tools.whois_lookup, network-analysis.geoip_lookup, threat-intel-free.threatfox_ioc_lookup for deeper analysis.
3. For file analysis: call analyze_malware first, then use MCP tools like remnux.pe_analyze, flare.strings_analysis, remnux.yara_scan, forensics-tools.file_metadata for deeper analysis.
4. For email analysis: call analyze_email first, then use MCP tools like osint-tools.email_security_check, arguswatch.openphish_lookup for deeper analysis.
5. After gathering evidence, call correlate_findings to produce the final verdict.
6. Only write a final text answer (no tool call) AFTER you have gathered real evidence from at least 2 tools.
7. When calling a tool, ONLY pass the tool's own parameters (e.g. {{"ioc": "8.8.8.8"}}). Do NOT include extra keys like "action", "reasoning", or "tool" in the arguments.
8. Use DIFFERENT tools each step. Never call the same tool with the same parameters twice.

If previous findings are "(none yet)", you MUST call a tool now. Do NOT skip to a conclusion.

RULES:
- Never execute malware on the host system. Use sandbox tools for dynamic analysis.
- Be methodical: gather evidence first, then correlate, then conclude.
- Only use the tools provided. Do NOT invent tool names.
"""

# Fallback prompt for when no native tool calling is available
_SYSTEM_PROMPT_NO_TOOLS = """\
You are a Blue Team Security Agent. You investigate security threats autonomously.

Available tools:
{tools_block}

{playbooks_block}

Investigation goal: {goal}

Previous findings:
{findings_block}

Decide your next action. Respond in JSON (no markdown, no extra text):
{{"action": "use_tool", "tool": "tool_name", "params": {{...}}, "reasoning": "why"}}
OR
{{"action": "run_playbook", "playbook_id": "playbook_name", "params": {{...}}, "reasoning": "why"}}
OR
{{"action": "final_answer", "answer": "investigation summary", "verdict": "MALICIOUS/SUSPICIOUS/CLEAN", "reasoning": "why"}}

IMPORTANT:
- Never execute malware on the host system. Use sandbox tools for dynamic analysis.
- Actions marked as requiring approval will pause for analyst review.
- Be methodical: gather evidence first, then correlate, then conclude.
- Only use tools that are listed above. Do NOT invent tool names.
- If a playbook matches the investigation goal, prefer running the playbook for structured analysis.
- Always include the "action" key in your JSON response.
"""

_SUMMARY_PROMPT = """\
You are a Blue Team Security Agent. Summarise the following investigation
in 3-5 sentences suitable for a SOC ticket.  Include the verdict
(MALICIOUS / SUSPICIOUS / CLEAN), key evidence, and recommended next steps.

Goal: {goal}

Steps taken: {step_count}

Findings:
{findings_json}

Respond in plain text (no JSON).
"""


class AgentLoop:
    """Orchestrates the ReAct loop, delegates to LLM + tools."""

    def __init__(
        self,
        config: Dict[str, Any],
        tool_registry: ToolRegistry,
        agent_store: AgentStore,
        llm_analyzer=None,
        mcp_client=None,
        playbook_engine=None,
    ):
        self.config = config
        self.tools = tool_registry
        self.store = agent_store
        self.llm = llm_analyzer
        self.mcp_client = mcp_client
        self._playbook_engine = playbook_engine

        agent_cfg = config.get('agent', {})
        self.max_steps = agent_cfg.get('max_steps', 50)

        # LLM connection settings (mirrors LLMAnalyzer)
        llm_cfg = config.get('llm', {})
        self.provider = llm_cfg.get('provider', 'ollama')
        self.ollama_endpoint = llm_cfg.get('ollama_endpoint', 'http://localhost:11434')
        self.ollama_model = llm_cfg.get('ollama_model', 'llama3.1:8b')
        self.anthropic_key = config.get('api_keys', {}).get('anthropic', '')
        self.anthropic_model = llm_cfg.get('anthropic_model', 'claude-sonnet-4-20250514')
        self.timeout = aiohttp.ClientTimeout(total=120)

        # Active sessions & pub-sub
        self._active_sessions: Dict[str, AgentState] = {}
        self._approval_events: Dict[str, asyncio.Event] = {}
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}
        self._main_loop: Optional[asyncio.AbstractEventLoop] = None  # set on first investigate()

    # ================================================================== #
    #  Public API
    # ================================================================== #

    async def investigate(
        self,
        goal: str,
        case_id: Optional[str] = None,
        playbook_id: Optional[str] = None,
        max_steps: Optional[int] = None,
    ) -> str:
        """Start an autonomous investigation. Returns *session_id* immediately."""

        session_id = self.store.create_session(
            goal=goal, case_id=case_id, playbook_id=playbook_id,
        )

        effective_max_steps = max_steps if max_steps is not None else self.max_steps
        state = AgentState(
            session_id=session_id,
            goal=goal,
            max_steps=effective_max_steps,
        )
        self._active_sessions[session_id] = state
        self._approval_events[session_id] = asyncio.Event()

        # Capture the main event loop so _notify() can safely push
        # messages to subscriber queues from background threads.
        try:
            self._main_loop = asyncio.get_running_loop()
        except RuntimeError:
            self._main_loop = None

        # Fire-and-forget the loop in a background thread so the caller
        # gets the session_id without blocking.
        def _run():
            asyncio.run(self._run_loop(session_id))

        t = threading.Thread(target=_run, daemon=True, name=f"agent-{session_id}")
        t.start()

        logger.info(f"[AGENT] Investigation started: {session_id} - {goal[:80]}")
        return session_id

    async def approve_action(self, session_id: str) -> bool:
        """Approve the pending action so the loop can resume."""
        state = self._active_sessions.get(session_id)
        if state is None or state.pending_approval is None:
            return False
        # Signal the event so _wait_for_approval unblocks
        evt = self._approval_events.get(session_id)
        if evt:
            state.pending_approval["approved"] = True
            evt.set()
        return True

    async def reject_action(self, session_id: str) -> bool:
        """Reject the pending action; the loop will skip it and re-think."""
        state = self._active_sessions.get(session_id)
        if state is None or state.pending_approval is None:
            return False
        evt = self._approval_events.get(session_id)
        if evt:
            state.pending_approval["approved"] = False
            evt.set()
        return True

    async def cancel_session(self, session_id: str) -> None:
        """Cancel a running investigation."""
        state = self._active_sessions.get(session_id)
        if state and not state.is_terminal():
            state.errors.append("Cancelled by analyst")
            state.phase = AgentPhase.FAILED  # direct set to avoid transition check
            self.store.update_session_status(session_id, 'failed', 'Cancelled by analyst')
            self._notify(session_id, {"type": "cancelled"})
            # Unblock any waiting approval
            evt = self._approval_events.get(session_id)
            if evt:
                evt.set()
        logger.info(f"[AGENT] Session cancelled: {session_id}")

    def get_state(self, session_id: str) -> Optional[Dict]:
        """Return live state dict (or None)."""
        state = self._active_sessions.get(session_id)
        return state.to_dict() if state else None

    async def run_tool(self, tool_name: str, params: Dict) -> Dict:
        """Execute a single tool by name (used by PlaybookEngine).

        Supports multiple tool name formats:
        - ``mcp:server-name/tool_name`` (playbook YAML format)
        - ``server-name.tool_name`` (internal registry format)
        - ``tool_name`` (local tool)

        Returns the tool result dict.
        """
        # ---- Normalise playbook-style "mcp:server/tool" references ----
        original_name = tool_name
        mcp_server = None
        mcp_tool = None

        if tool_name.startswith("mcp:"):
            # Format: mcp:server-name/tool_name
            rest = tool_name[4:]  # strip "mcp:"
            if "/" in rest:
                mcp_server, mcp_tool = rest.split("/", 1)
                # Convert to registry format: server-name.tool_name
                tool_name = f"{mcp_server}.{mcp_tool}"
            else:
                # mcp:tool_name (no server specified)
                tool_name = rest

        tool_def = self.tools.get_tool(tool_name)

        if tool_def is None and mcp_server and mcp_tool:
            # Tool not registered yet -- try calling MCP directly
            if self.mcp_client is not None:
                try:
                    result = await self.mcp_client.call_tool(
                        mcp_server, mcp_tool, params,
                    )
                    return result if isinstance(result, dict) else {"result": result}
                except Exception as exc:
                    return {"error": f"MCP tool '{original_name}' call failed: {exc}"}
            return {"error": f"MCP client not available for tool: {original_name}"}

        if tool_def is None:
            return {"error": f"Tool not found: {original_name}"}

        if tool_def.source == 'local':
            return await self.tools.execute_local_tool(tool_name, **params)
        elif self.mcp_client is not None:
            return await self.mcp_client.call_tool(
                tool_def.source, tool_name.split(".", 1)[-1], params,
            )
        else:
            return {"error": f"MCP client not available for tool: {original_name}"}

    # ------------------------------------------------------------------ #
    #  Pub / Sub
    # ------------------------------------------------------------------ #

    def subscribe(self, session_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(session_id, []).append(q)
        return q

    def unsubscribe(self, session_id: str, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(session_id, [])
        if queue in subs:
            subs.remove(queue)

    def _notify(self, session_id: str, message: Dict) -> None:
        """Push a message to all WebSocket subscribers for *session_id*.

        Thread-safe: if called from a background thread (agent loop),
        schedules the put on the main event loop so asyncio.Queue
        operations happen in the correct loop context.
        """
        subs = self._subscribers.get(session_id, [])
        if not subs:
            return

        main_loop = self._main_loop

        def _put_all():
            for q in subs:
                try:
                    q.put_nowait(message)
                except asyncio.QueueFull:
                    pass

        # If we have a reference to the main loop AND we're in a different
        # thread, use call_soon_threadsafe to schedule the put.
        if main_loop is not None and main_loop.is_running():
            try:
                main_loop.call_soon_threadsafe(_put_all)
                return
            except RuntimeError:
                pass  # loop closed, fall through

        # Fallback: direct put (works when called from the main loop)
        _put_all()

    # ================================================================== #
    #  Main ReAct Loop
    # ================================================================== #

    async def _run_loop(self, session_id: str) -> None:
        state = self._active_sessions.get(session_id)
        if state is None:
            return

        # Track previously called tools to prevent infinite loops
        _prev_tool_calls: list = []

        try:
            state.transition(AgentPhase.THINKING)

            while not state.is_terminal() and state.step_count < state.max_steps:
                # ---- THINK ----
                state.phase = AgentPhase.THINKING
                state.current_tool = None
                self._notify(session_id, {
                    "type": "phase", "phase": "thinking",
                    "step": state.step_count,
                    "max_steps": state.max_steps,
                })

                decision = await self._think(state)

                if decision is None:
                    # Retry once: LLM may have returned an unparseable
                    # response or had a transient connection issue.
                    logger.warning("[AGENT] First LLM call returned None, retrying...")
                    await asyncio.sleep(1)
                    decision = await self._think(state)

                if decision is None:
                    state.errors.append(
                        "LLM returned no decision. Verify Ollama is running "
                        f"({self.ollama_endpoint}) and model '{self.ollama_model}' "
                        "is pulled. Run: ollama pull " + self.ollama_model
                    )
                    state.transition(AgentPhase.FAILED)
                    break

                # Record the thinking step
                self.store.add_step(
                    session_id, state.step_count, 'thinking',
                    json.dumps(decision, default=str),
                )

                # ---- Check for final answer ----
                if decision.get('action') == 'final_answer':
                    summary = decision.get('answer', '')
                    verdict = decision.get('verdict', 'UNKNOWN')
                    state.add_finding({
                        "type": "final_answer",
                        "answer": summary,
                        "verdict": verdict,
                        "reasoning": decision.get('reasoning', ''),
                    })
                    self.store.add_step(
                        session_id, state.step_count, 'final_answer',
                        json.dumps(decision, default=str),
                    )
                    break

                # ---- Check for run_playbook action ----
                if decision.get('action') == 'run_playbook':
                    pb_id = decision.get('playbook_id', '')
                    pb_params = decision.get('params', {})
                    reasoning = decision.get('reasoning', '')

                    if hasattr(self, '_playbook_engine') and self._playbook_engine:
                        self.store.add_step(
                            session_id, state.step_count, 'run_playbook',
                            json.dumps({
                                "playbook_id": pb_id,
                                "params": pb_params,
                                "reasoning": reasoning,
                            }, default=str),
                        )
                        self._notify(session_id, {
                            "type": "phase", "phase": "running_playbook",
                            "step": state.step_count, "playbook_id": pb_id,
                        })
                        try:
                            pb_session = await self._playbook_engine.execute(
                                pb_id, pb_params, case_id=state.goal,
                            )
                            state.add_finding({
                                "type": "playbook_completed",
                                "playbook_id": pb_id,
                                "session_id": pb_session,
                                "reasoning": reasoning,
                            })
                            self.store.add_step(
                                session_id, state.step_count, 'playbook_result',
                                json.dumps({
                                    "playbook_id": pb_id,
                                    "sub_session_id": pb_session,
                                    "status": "completed",
                                }, default=str),
                            )
                        except Exception as exc:
                            state.add_finding({
                                "type": "playbook_error",
                                "playbook_id": pb_id,
                                "error": str(exc),
                            })
                            self.store.add_step(
                                session_id, state.step_count, 'playbook_error',
                                json.dumps({
                                    "playbook_id": pb_id,
                                    "error": str(exc),
                                }, default=str),
                            )
                        state.step_count += 1
                        continue
                    else:
                        state.errors.append(f"Playbook engine not available for: {pb_id}")
                        state.step_count += 1
                        continue

                # ---- Validate action field ----
                action = decision.get('action', '')
                if action not in ('use_tool', 'final_answer', 'run_playbook'):
                    # LLM returned a JSON without a valid action - treat as
                    # a thinking step and continue so it can try again.
                    state.errors.append(
                        f"LLM returned invalid action '{action}'. "
                        "Expected: use_tool, final_answer, or run_playbook."
                    )
                    state.step_count += 1
                    continue

                # ---- Resolve tool ----
                tool_name = decision.get('tool', '')
                tool_def = self.tools.get_tool(tool_name)

                if tool_def is None:
                    # Unknown tool - record error and let agent re-think
                    state.errors.append(f"Unknown tool: {tool_name}")
                    state.add_finding({
                        "type": "error",
                        "message": f"Tool '{tool_name}' not found in registry.",
                    })
                    state.step_count += 1
                    continue

                # ---- Approval gate ----
                if tool_def.requires_approval:
                    state.request_approval(
                        decision,
                        f"Tool '{tool_name}' requires analyst approval before execution.",
                    )
                    state.phase = AgentPhase.WAITING_HUMAN
                    self._notify(session_id, {
                        "type": "approval_required",
                        "tool": tool_name,
                        "params": decision.get('params', {}),
                        "reason": state.pending_approval["reason"],
                    })

                    # Wait until approve/reject/cancel
                    approved = await self._wait_for_approval(session_id, state)
                    if state.is_terminal():
                        break
                    if not approved:
                        # Rejected - skip tool and re-think
                        state.add_finding({
                            "type": "approval_rejected",
                            "tool": tool_name,
                        })
                        state.step_count += 1
                        state.transition(AgentPhase.THINKING)
                        continue
                    # Approved - fall through to ACT
                    state.transition(AgentPhase.ACTING)
                else:
                    state.transition(AgentPhase.ACTING)

                # ---- Duplicate call guard ----
                call_sig = (tool_name, json.dumps(decision.get('params', {}), sort_keys=True, default=str))
                if call_sig in _prev_tool_calls:
                    logger.warning(
                        "[AGENT] Duplicate tool call detected: %s. "
                        "Forcing final_answer.", tool_name,
                    )
                    # Force conclusion instead of repeating
                    if state.findings:
                        break  # exit loop → generate summary
                    # No findings at all → escalate to correlate_findings
                    decision = {
                        "action": "use_tool",
                        "tool": "correlate_findings",
                        "params": {"findings": state.findings},
                        "reasoning": "Breaking duplicate loop",
                    }
                    call_sig = ("correlate_findings", "break")
                _prev_tool_calls.append(call_sig)

                # ---- ACT ----
                state.current_tool = tool_name
                is_mcp = '.' in tool_name
                self._notify(session_id, {
                    "type": "phase", "phase": "acting",
                    "step": state.step_count, "max_steps": state.max_steps,
                    "tool": tool_name,
                    "tool_source": "mcp" if is_mcp else "local",
                    "tool_server": tool_name.split('.')[0] if is_mcp else None,
                    "params": decision.get('params', {}),
                })

                import time as _time
                _act_start = _time.time()
                result = await self._act(state, decision)
                _act_dur = int((_time.time() - _act_start) * 1000)

                # ---- OBSERVE ----
                state.transition(AgentPhase.OBSERVING)
                state.current_tool = None
                state.add_finding({
                    "type": "tool_result",
                    "tool": tool_name,
                    "params": decision.get('params', {}),
                    "result": result,
                })
                state.step_count += 1

                # Persist findings snapshot
                self.store.update_session_findings(session_id, state.findings)

                # Notify WS with tool result for live display
                self._notify(session_id, {
                    "type": "tool_result",
                    "step": state.step_count - 1,
                    "max_steps": state.max_steps,
                    "tool": tool_name,
                    "tool_source": "mcp" if is_mcp else "local",
                    "tool_server": tool_name.split('.')[0] if is_mcp else None,
                    "duration_ms": _act_dur,
                    "params": decision.get('params', {}),
                    "result": result,
                })

                # ---- AUTO-ENRICH with MCP tools ----
                # After first local tool, automatically run relevant MCP tools
                if (tool_name in ('investigate_ioc', 'analyze_malware', 'analyze_email')
                        and state.step_count <= 3
                        and state.step_count < state.max_steps - 1):
                    mcp_calls = self._get_enrichment_mcp_tools(
                        tool_name, decision.get('params', {}), state.goal,
                    )
                    logger.warning(
                        "[AGENT] Auto-enrich: %d MCP tools queued for %s",
                        len(mcp_calls), tool_name,
                    )
                    for mcp_tool, mcp_params in mcp_calls:
                        if state.step_count >= state.max_steps - 1:
                            break
                        try:
                            logger.warning(
                                "[AGENT] Auto-enrich: calling %s",
                                mcp_tool,
                            )
                            state.current_tool = mcp_tool
                            state.phase = AgentPhase.ACTING
                            mcp_server = mcp_tool.split('.')[0] if '.' in mcp_tool else None
                            self._notify(session_id, {
                                "type": "phase", "phase": "acting",
                                "step": state.step_count, "max_steps": state.max_steps,
                                "tool": mcp_tool,
                                "tool_source": "mcp",
                                "tool_server": mcp_server,
                                "params": mcp_params,
                            })
                            mcp_decision = {
                                "action": "use_tool",
                                "tool": mcp_tool,
                                "params": mcp_params,
                                "reasoning": "Auto-enrichment with MCP tool",
                            }
                            _mcp_start = _time.time()
                            mcp_result = await self._act(state, mcp_decision)
                            _mcp_dur = int((_time.time() - _mcp_start) * 1000)
                            state.phase = AgentPhase.OBSERVING
                            state.current_tool = None
                            state.add_finding({
                                "type": "tool_result",
                                "tool": mcp_tool,
                                "params": mcp_params,
                                "result": mcp_result,
                            })
                            state.step_count += 1
                            self.store.update_session_findings(
                                session_id, state.findings,
                            )
                            # Notify WS with MCP tool result
                            self._notify(session_id, {
                                "type": "tool_result",
                                "step": state.step_count - 1,
                                "max_steps": state.max_steps,
                                "tool": mcp_tool,
                                "tool_source": "mcp",
                                "tool_server": mcp_server,
                                "duration_ms": _mcp_dur,
                                "params": mcp_params,
                                "result": mcp_result,
                            })
                            logger.warning(
                                "[AGENT] Auto-enrich: %s done (%dms)", mcp_tool, _mcp_dur,
                            )
                        except Exception as enrich_exc:
                            logger.warning(
                                "[AGENT] Auto-enrich %s failed: %s",
                                mcp_tool, enrich_exc,
                            )
                            state.step_count += 1

                self._notify(session_id, {
                    "type": "observation",
                    "step": state.step_count,
                    "tool": tool_name,
                    "result_preview": _truncate(json.dumps(result, default=str), 500),
                })

                # Transition back to THINKING for next iteration
                state.transition(AgentPhase.THINKING)

            # ---- Loop finished ----
            if not state.is_terminal():
                if state.step_count >= state.max_steps:
                    state.errors.append(f"Step limit ({state.max_steps}) reached")
                state.phase = AgentPhase.COMPLETED

            summary = await self._generate_summary(state)
            final_status = 'completed' if state.phase == AgentPhase.COMPLETED else 'failed'
            self.store.update_session_status(session_id, final_status, summary)
            self.store.update_session_findings(session_id, state.findings)

            self._notify(session_id, {
                "type": "completed",
                "status": final_status,
                "summary": summary,
                "steps": state.step_count,
            })

        except Exception as exc:
            logger.error(f"[AGENT] Loop error for {session_id}: {exc}", exc_info=True)
            state.errors.append(str(exc))
            state.phase = AgentPhase.FAILED
            self.store.update_session_status(session_id, 'failed', str(exc))
            self._notify(session_id, {"type": "failed", "error": str(exc)})

        finally:
            # Clean up
            self._approval_events.pop(session_id, None)

    # ================================================================== #
    #  THINK - ask LLM for next action
    # ================================================================== #

    async def _think(self, state: AgentState) -> Optional[Dict]:
        """Build context and call the LLM to decide the next action."""
        tools_block = self._build_tools_block()
        findings_block = self._build_findings_block(state)
        playbooks_block = self._build_playbooks_block()
        all_tools = self.tools.get_tools_for_llm()
        # Filter tools to a manageable set for the LLM
        tools_json = self._filter_tools_for_goal(all_tools, state.goal, state)
        has_native_tools = len(tools_json) > 0

        if has_native_tools:
            # Use the clean prompt that doesn't instruct JSON response format
            # (avoids LLM stuffing decision JSON into tool_call arguments)
            system_prompt = _SYSTEM_PROMPT.format(
                goal=state.goal,
                findings_block=findings_block,
                playbooks_block=playbooks_block,
            )
        else:
            system_prompt = _SYSTEM_PROMPT_NO_TOOLS.format(
                tools_block=tools_block,
                goal=state.goal,
                findings_block=findings_block,
                playbooks_block=playbooks_block,
            )

        messages = [
            {"role": "user", "content": system_prompt},
        ]

        # Attempt tool-calling API first, fall back to plain chat
        raw = await self._chat_with_tools(messages)
        logger.info(f"[AGENT] LLM raw response type={type(raw).__name__}, "
                     f"preview={str(raw)[:500] if raw else 'None'}")
        if raw is None:
            return None

        # If the LLM used native tool_call, convert to our decision dict
        if isinstance(raw, dict) and 'tool_calls' in raw:
            return self._parse_tool_call_response(raw)

        # Otherwise parse the text as JSON
        if isinstance(raw, str):
            parsed = self._extract_json(raw)
            if parsed is not None:
                # Normalise non-standard JSON formats into our decision dict
                parsed = self._normalise_decision(parsed, state)
                return parsed
            # If we can't parse JSON and native tools were available,
            # the LLM gave a plain text answer.
            if has_native_tools and raw.strip():
                # If we already have findings → real conclusion
                if state.findings:
                    return {
                        "action": "final_answer",
                        "answer": raw.strip(),
                        "verdict": self._extract_verdict(raw),
                        "reasoning": "LLM provided text response after tool use",
                    }
                # No findings yet → auto-dispatch
                logger.warning(
                    "[AGENT] LLM gave text instead of tool call. "
                    "Auto-dispatching tool based on goal."
                )
                return {
                    "action": "use_tool",
                    "tool": self._guess_first_tool(state.goal),
                    "params": self._guess_tool_params(state.goal),
                    "reasoning": "Auto-dispatched: LLM did not call a tool",
                }
            return None

        # Already a dict (from JSON-mode response)
        if isinstance(raw, dict):
            return raw

        return None

    @staticmethod
    def _extract_verdict(text: str) -> str:
        """Extract verdict keyword from text."""
        text_upper = text.upper()
        if 'MALICIOUS' in text_upper:
            return 'MALICIOUS'
        if 'SUSPICIOUS' in text_upper:
            return 'SUSPICIOUS'
        if 'CLEAN' in text_upper:
            return 'CLEAN'
        return 'UNKNOWN'

    def _normalise_decision(self, parsed: Dict, state) -> Dict:
        """Normalise various JSON formats the LLM might return into our
        standard decision dict ``{action, tool, params, reasoning}``.

        Handles:
        - Ollama text tool-call: ``{"name": "...", "parameters": {...}}``
        - Ollama text tool-call: ``{"name": "...", "arguments": {...}}``
        - Decision with nested params: ``{"action": "use_tool", "tool": "...",
          "params": {"action": "...", ...}}``
        - Standard format (pass through)
        - ``final_answer`` with no findings → auto-dispatch to tool
        """
        # --- Ollama text tool-call format ---
        # LLM writes JSON like {"name": "investigate_ioc", "parameters": {"ioc": "..."}}
        if 'name' in parsed and 'action' not in parsed:
            tool_name = parsed['name']
            params = parsed.get('parameters', parsed.get('arguments', {}))
            if isinstance(params, str):
                try:
                    params = json.loads(params)
                except json.JSONDecodeError:
                    params = {}
            logger.info(
                f"[AGENT] Normalised Ollama text tool-call: "
                f"tool={tool_name}, params={params}"
            )
            return {
                "action": "use_tool",
                "tool": tool_name,
                "params": params if isinstance(params, dict) else {},
                "reasoning": parsed.get("reasoning", "LLM text tool-call"),
            }

        # --- final_answer with no findings → force tool use ---
        if parsed.get('action') == 'final_answer' and not state.findings:
            logger.warning(
                "[AGENT] LLM tried final_answer with no findings. "
                "Auto-dispatching tool."
            )
            return {
                "action": "use_tool",
                "tool": self._guess_first_tool(state.goal),
                "params": self._guess_tool_params(state.goal),
                "reasoning": "Auto-dispatched: LLM skipped tool use",
            }

        # --- Bare params dict (no action/name/tool key) → auto-dispatch ---
        # LLM returned just the params like {"ioc": "..."} without wrapping
        if 'action' not in parsed and 'name' not in parsed and 'tool' not in parsed:
            logger.warning(
                "[AGENT] LLM returned bare params without action/name. "
                "Auto-dispatching tool. parsed=%s", parsed,
            )
            guessed_tool = self._guess_first_tool(state.goal)
            guessed_params = self._guess_tool_params(state.goal)
            # Merge LLM's parsed output with guessed params (LLM's take priority)
            final_params = {**guessed_params, **parsed}
            return {
                "action": "use_tool",
                "tool": guessed_tool,
                "params": final_params,
                "reasoning": "Auto-dispatched: LLM returned bare params",
            }

        # --- Standard format: pass through ---
        return parsed

    def _filter_tools_for_goal(
        self, all_tools: List[Dict], goal: str, state,
    ) -> List[Dict]:
        """Return a filtered subset of tools relevant to the investigation goal.

        Small LLMs (8B-14B) can't handle 90+ tool definitions effectively.
        We keep all 10 local tools + the most relevant MCP tools, capped
        at ~30 total to stay within the model's effective context.
        """
        MAX_TOOLS = 30
        goal_lower = goal.lower()

        # Always include all local tools (10)
        local_tools = [
            t for t in all_tools
            if not t.get('function', {}).get('name', '').count('.')
        ]

        # Categorize MCP tools by relevance to the goal
        mcp_tools = [
            t for t in all_tools
            if t.get('function', {}).get('name', '').count('.')
        ]

        if len(local_tools) + len(mcp_tools) <= MAX_TOOLS:
            return all_tools  # Small enough, send all

        # Score MCP tools by relevance
        is_ip = any(kw in goal_lower for kw in ('ip', 'address', '185.', '10.', '192.'))
        is_domain = any(kw in goal_lower for kw in ('domain', 'dns', '.com', '.org', '.net'))
        is_file = any(kw in goal_lower for kw in ('file', 'malware', 'exe', 'dll', 'binary', 'sample', 'pe '))
        is_email = any(kw in goal_lower for kw in ('email', 'eml', 'phish'))
        is_url = any(kw in goal_lower for kw in ('url', 'http', 'link'))
        is_hash = any(kw in goal_lower for kw in ('hash', 'sha256', 'md5', 'sha1'))
        is_vuln = any(kw in goal_lower for kw in ('cve', 'vuln', 'exploit'))

        # Define relevant server prefixes per category
        ioc_servers = {
            'threat-intel-free', 'malwoverview', 'arguswatch',
            'network-analysis', 'osint-tools',
        }
        file_servers = {
            'remnux', 'flare', 'ghidra', 'forensics-tools',
            'malwoverview',
        }
        email_servers = {
            'osint-tools', 'threat-intel-free', 'arguswatch',
        }
        vuln_servers = {'vulnerability-tools'}

        # Build set of wanted server prefixes
        wanted = set()
        if is_ip or is_domain or is_url:
            wanted |= ioc_servers
        if is_file or is_hash:
            wanted |= file_servers
        if is_email:
            wanted |= email_servers
        if is_vuln:
            wanted |= vuln_servers
        # If nothing specific, include the most useful general ones
        if not wanted:
            wanted = ioc_servers | {'forensics-tools'}

        # Filter MCP tools
        relevant_mcp = []
        other_mcp = []
        for t in mcp_tools:
            name = t.get('function', {}).get('name', '')
            server = name.split('.')[0] if '.' in name else ''
            if server in wanted:
                relevant_mcp.append(t)
            else:
                other_mcp.append(t)

        # Fill remaining slots with other MCP tools
        remaining = MAX_TOOLS - len(local_tools) - len(relevant_mcp)
        selected = local_tools + relevant_mcp
        if remaining > 0:
            selected += other_mcp[:remaining]

        logger.info(
            "[AGENT] Filtered tools: %d local + %d relevant MCP + %d other = %d total "
            "(from %d available)",
            len(local_tools), len(relevant_mcp),
            min(remaining, len(other_mcp)) if remaining > 0 else 0,
            len(selected), len(all_tools),
        )
        return selected

    def _get_enrichment_mcp_tools(
        self, primary_tool: str, params: dict, goal: str,
    ) -> List[tuple]:
        """Return a list of (mcp_tool_name, params) for auto-enrichment.

        After the primary local tool runs, these MCP tools provide
        additional context without relying on the LLM to pick them.
        """
        import re
        result = []

        if primary_tool == 'investigate_ioc':
            ioc_val = params.get('ioc', '')
            # Check if it's an IP
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc_val):
                result.extend([
                    ('network-analysis.whois_lookup', {'target': ioc_val}),
                    ('network-analysis.geoip_lookup', {'ip': ioc_val}),
                    ('arguswatch.shodan_internetdb_lookup', {'ip': ioc_val}),
                ])
            elif re.match(r'[a-zA-Z0-9]', ioc_val) and '.' in ioc_val:
                # Domain
                result.extend([
                    ('osint-tools.whois_lookup', {'domain': ioc_val}),
                    ('osint-tools.dns_resolve', {'domain': ioc_val}),
                    ('arguswatch.crtsh_subdomain_search', {'domain': ioc_val}),
                ])
            elif re.match(r'^[a-fA-F0-9]{32,64}$', ioc_val):
                # Hash
                result.extend([
                    ('malwoverview.malwoverview_hash_lookup', {'hash_value': ioc_val}),
                    ('threat-intel-free.malwarebazaar_hash_lookup', {'hash_value': ioc_val}),
                ])

        elif primary_tool == 'analyze_malware':
            file_path = params.get('file_path', params.get('ioc', ''))
            if file_path:
                result.extend([
                    ('remnux.hash_file', {'file_path': file_path}),
                    ('remnux.file_entropy', {'file_path': file_path}),
                    ('flare.strings_analysis', {'file_path': file_path}),
                    ('forensics-tools.file_metadata', {'file_path': file_path}),
                ])

        elif primary_tool == 'analyze_email':
            file_path = params.get('file_path', params.get('eml_path', ''))
            # Extract IOCs from goal for enrichment
            ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', goal)
            domain_match = re.search(
                r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})',
                goal,
            )
            if file_path:
                result.append(
                    ('forensics-tools.string_analysis', {'file_path': file_path}),
                )
            if ip_match:
                result.append(
                    ('network-analysis.geoip_lookup', {'ip': ip_match.group(1)}),
                )
            if domain_match:
                result.append(
                    ('osint-tools.email_security_check', {'domain': domain_match.group(1)}),
                )

        # Only include MCP tools that are actually registered
        available = []
        for tool_name, tool_params in result:
            if self.tools.get_tool(tool_name) is not None:
                available.append((tool_name, tool_params))
        return available[:4]  # Max 4 enrichment calls

    def _guess_first_tool(self, goal: str) -> str:
        """Pick the most appropriate tool name based on the investigation goal."""
        goal_lower = goal.lower()

        # File / malware analysis keywords
        if any(kw in goal_lower for kw in ('file', 'malware', 'sample', 'binary',
                                            'exe', 'dll', 'pdf', 'macro', '.eml')):
            if any(kw in goal_lower for kw in ('.eml', 'email', 'phish')):
                return 'analyze_email'
            return 'analyze_malware'

        # Default: treat as IOC investigation
        return 'investigate_ioc'

    def _guess_tool_params(self, goal: str) -> dict:
        """Extract the most likely tool parameter from the goal text."""
        import re

        tool = self._guess_first_tool(goal)

        # Try to extract a file path first (for file/email analysis)
        path_match = re.search(r'([A-Z]:[/\\][\w/\\.\- ]+|/[\w/.\- ]+)', goal)
        if path_match:
            path_val = path_match.group(1)
            if tool in ('analyze_malware', 'analyze_email'):
                return {"file_path": path_val}
            return {"ioc": path_val}

        # Try to extract an IP address
        ip_match = re.search(
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', goal,
        )
        if ip_match:
            return {"ioc": ip_match.group(1)}

        # Try to extract a domain
        domain_match = re.search(
            r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b',
            goal,
        )
        if domain_match:
            candidate = domain_match.group(1)
            # Filter out common non-domain words
            if '.' in candidate and candidate.lower() not in ('e.g', 'i.e', 'vs.'):
                return {"ioc": candidate}

        # Try to extract a hash (MD5/SHA1/SHA256)
        hash_match = re.search(r'\b([a-fA-F0-9]{32,64})\b', goal)
        if hash_match:
            return {"ioc": hash_match.group(1)}

        # Try to extract a URL
        url_match = re.search(r'(https?://\S+)', goal)
        if url_match:
            return {"ioc": url_match.group(1)}

        # Fallback: use the full goal text as input
        return {"ioc": goal}

    def _build_tools_block(self) -> str:
        """Format registered tools into a readable list for the prompt."""
        lines = []
        for td in self.tools.list_tools():
            approval_tag = " [REQUIRES APPROVAL]" if td.requires_approval else ""
            params_desc = ", ".join(
                f"{k}: {v.get('type', 'any')}"
                for k, v in td.parameters.get("properties", {}).items()
            )
            lines.append(
                f"- {td.name}({params_desc}){approval_tag}: {td.description}"
            )
        return "\n".join(lines) if lines else "(no tools registered)"

    def _build_playbooks_block(self) -> str:
        """Format available playbooks into a readable list for the prompt."""
        if not hasattr(self, '_playbook_engine') or self._playbook_engine is None:
            return ""
        try:
            playbooks = self._playbook_engine.list_playbooks()
            if not playbooks:
                return ""
            lines = ["Available playbooks (use run_playbook action to execute):"]
            for pb in playbooks:
                step_count = pb.get('step_count', 0)
                desc = pb.get('description', '')
                if len(desc) > 120:
                    desc = desc[:120] + "..."
                lines.append(f"- {pb['id']} ({step_count} steps): {desc}")
            return "\n".join(lines)
        except Exception:
            return ""

    @staticmethod
    def _build_findings_block(state: AgentState) -> str:
        """Summarise findings so far (capped to keep context manageable)."""
        if not state.findings:
            return "(none yet)"
        # Show last 10 findings to avoid blowing up context window
        recent = state.findings[-10:]
        parts = []
        for i, f in enumerate(recent):
            preview = json.dumps(f, default=str)
            if len(preview) > 600:
                preview = preview[:600] + "..."
            parts.append(f"[{f.get('step', i)}] {preview}")
        return "\n".join(parts)

    # ================================================================== #
    #  ACT - execute a tool
    # ================================================================== #

    async def _act(self, state: AgentState, decision: Dict) -> Dict:
        """Execute the tool specified in *decision*."""
        tool_name = decision.get('tool', '')
        params = decision.get('params', {})
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except json.JSONDecodeError:
                params = {}

        logger.info(f"[AGENT] _act: tool={tool_name}, params={params}")

        start = time.time()
        try:
            tool_def = self.tools.get_tool(tool_name)
            if tool_def is None:
                result = {"error": f"Tool not found: {tool_name}"}
            elif tool_def.source == 'local':
                result = await self.tools.execute_local_tool(tool_name, **params)
            elif self.mcp_client is not None:
                # MCP remote tool call
                result = await self.mcp_client.call_tool(
                    tool_def.source, tool_name.split(".", 1)[-1], params,
                )
                if not isinstance(result, dict):
                    result = {"result": result}
            else:
                result = {"error": f"MCP client not available for tool: {tool_name}"}
        except Exception as exc:
            logger.error(f"[AGENT] Tool {tool_name} failed: {exc}", exc_info=True)
            result = {"error": str(exc)}

        duration_ms = int((time.time() - start) * 1000)

        # Persist step
        self.store.add_step(
            state.session_id,
            state.step_count,
            'tool_call',
            json.dumps(decision, default=str),
            tool_name,
            json.dumps(params, default=str),
            json.dumps(result, default=str),
            duration_ms,
        )

        return result

    # ================================================================== #
    #  Approval wait
    # ================================================================== #

    async def _wait_for_approval(
        self, session_id: str, state: AgentState,
    ) -> bool:
        """Block until the analyst approves/rejects or the session is cancelled.

        Returns True if approved, False if rejected or cancelled.
        """
        evt = self._approval_events.get(session_id)
        if evt is None:
            return False

        evt.clear()
        # Wait up to 30 minutes for human response
        try:
            await asyncio.wait_for(evt.wait(), timeout=1800)
        except asyncio.TimeoutError:
            state.errors.append("Approval timed out (30 min)")
            state.phase = AgentPhase.FAILED
            return False

        approval = state.clear_approval()
        if approval is None:
            return False
        return approval.get("approved", False)

    # ================================================================== #
    #  Summary generation
    # ================================================================== #

    async def _generate_summary(self, state: AgentState) -> str:
        """Ask the LLM to produce a concise investigation summary."""
        # If there is a final_answer finding, use it directly
        for f in reversed(state.findings):
            if f.get("type") == "final_answer":
                answer = f.get("answer", "")
                verdict = f.get("verdict", "")
                if answer:
                    return f"[{verdict}] {answer}"

        # Otherwise ask LLM to summarise
        findings_json = json.dumps(state.findings[-15:], default=str, indent=1)
        prompt = _SUMMARY_PROMPT.format(
            goal=state.goal,
            step_count=state.step_count,
            findings_json=findings_json[:4000],
        )

        try:
            raw = await self._call_llm_text(prompt)
            if raw:
                return raw[:2000]
        except Exception as exc:
            logger.warning(f"[AGENT] Summary generation failed: {exc}")

        # Fallback
        return (
            f"Investigation completed in {state.step_count} steps. "
            f"{len(state.findings)} findings collected. "
            f"Errors: {len(state.errors)}."
        )

    # ================================================================== #
    #  LLM communication
    # ================================================================== #

    async def _chat_with_tools(
        self, messages: List[Dict],
    ) -> Optional[Any]:
        """Call the LLM with a messages list and available tools.

        Supports both Ollama /api/chat and Anthropic /v1/messages.
        Returns raw response text/dict or None on failure.
        """
        tools_json = self.tools.get_tools_for_llm()

        if self.provider == 'ollama':
            return await self._ollama_chat(messages, tools_json)
        else:
            return await self._anthropic_chat(messages, tools_json)

    async def _call_llm_text(self, prompt: str) -> Optional[str]:
        """Simple single-prompt call returning plain text (for summaries)."""
        if self.provider == 'ollama':
            return await self._ollama_generate(prompt)
        else:
            return await self._anthropic_generate(prompt)

    # ---- Ollama ---- #

    async def _ollama_chat(
        self, messages: List[Dict], tools: List[Dict],
    ) -> Optional[Any]:
        """Ollama /api/chat with optional tool definitions.

        IMPORTANT: ``format: "json"`` is intentionally NOT used when tools
        are provided because it prevents Ollama from generating native
        ``tool_calls`` in its response.  JSON-mode is only enabled for
        tool-less requests where we need structured text output.
        """
        try:
            # Convert tools to Ollama format
            ollama_tools = []
            for t in tools:
                func = t.get("function", t)
                ollama_tools.append({
                    "type": "function",
                    "function": {
                        "name": func.get("name", ""),
                        "description": func.get("description", ""),
                        "parameters": func.get("parameters", {}),
                    },
                })

            payload: Dict[str, Any] = {
                "model": self.ollama_model,
                "messages": messages,
                "stream": False,
            }

            if ollama_tools:
                # When tools are available, let the model decide to use
                # tool_calls OR respond with JSON text.  Do NOT force
                # format: json – it suppresses native tool calling.
                payload["tools"] = ollama_tools
            else:
                # No tools → force JSON for structured answers
                payload["format"] = "json"

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.ollama_endpoint}/api/chat", json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.error(f"[AGENT] Ollama chat error {resp.status}: {body[:300]}")
                        return None

                    data = await resp.json()

                    # Check for tool_calls in response
                    msg = data.get("message", {})
                    if msg.get("tool_calls"):
                        return {"tool_calls": msg["tool_calls"]}

                    # Plain content
                    content = msg.get("content", "")
                    return content

        except aiohttp.ClientConnectorError:
            logger.error(
                f"[AGENT] Cannot connect to Ollama at {self.ollama_endpoint}. "
                "Is Ollama running? Start it with: ollama serve"
            )
            return None
        except Exception as exc:
            logger.error(f"[AGENT] Ollama chat failed: {exc}", exc_info=True)
            return None

    async def _ollama_generate(self, prompt: str) -> Optional[str]:
        """Ollama /api/generate for plain text responses."""
        try:
            payload = {
                "model": self.ollama_model,
                "prompt": prompt,
                "stream": False,
            }
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.ollama_endpoint}/api/generate", json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.error(f"[AGENT] Ollama generate error {resp.status}: {body[:200]}")
                        return None
                    data = await resp.json()
                    return data.get("response", "")
        except aiohttp.ClientConnectorError:
            logger.error(
                f"[AGENT] Cannot connect to Ollama at {self.ollama_endpoint}. "
                "Is Ollama running? Start it with: ollama serve"
            )
            return None
        except Exception as exc:
            logger.error(f"[AGENT] Ollama generate failed: {exc}")
            return None

    # ---- Anthropic ---- #

    async def _anthropic_chat(
        self, messages: List[Dict], tools: List[Dict],
    ) -> Optional[Any]:
        """Anthropic /v1/messages with tool_use support."""
        if not self.anthropic_key:
            logger.warning("[AGENT] No Anthropic API key configured")
            return None

        try:
            # Convert tools to Anthropic format
            anthropic_tools = []
            for t in tools:
                func = t.get("function", t)
                anthropic_tools.append({
                    "name": func.get("name", ""),
                    "description": func.get("description", ""),
                    "input_schema": func.get("parameters", {}),
                })

            # Extract system message and user messages
            system_text = ""
            api_messages = []
            for m in messages:
                role = m.get("role", "user")
                content = m.get("content", "")
                if role == "system":
                    system_text = content
                else:
                    api_messages.append({"role": role, "content": content})

            if not api_messages:
                # If everything was in "user" role, use as-is
                api_messages = [{"role": "user", "content": messages[0].get("content", "")}]

            headers = {
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
                "x-api-key": self.anthropic_key,
            }

            payload: Dict[str, Any] = {
                "model": self.anthropic_model,
                "max_tokens": 4096,
                "messages": api_messages,
            }
            if system_text:
                payload["system"] = system_text
            if anthropic_tools:
                payload["tools"] = anthropic_tools

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.error(f"[AGENT] Anthropic chat error {resp.status}: {body[:300]}")
                        return None

                    data = await resp.json()
                    content_blocks = data.get("content", [])

                    # Check for tool_use blocks
                    tool_calls = []
                    text_parts = []
                    for block in content_blocks:
                        if block.get("type") == "tool_use":
                            tool_calls.append({
                                "function": {
                                    "name": block.get("name", ""),
                                    "arguments": block.get("input", {}),
                                },
                            })
                        elif block.get("type") == "text":
                            text_parts.append(block.get("text", ""))

                    if tool_calls:
                        return {"tool_calls": tool_calls}

                    return "\n".join(text_parts)

        except Exception as exc:
            logger.error(f"[AGENT] Anthropic chat failed: {exc}", exc_info=True)
            return None

    async def _anthropic_generate(self, prompt: str) -> Optional[str]:
        """Anthropic /v1/messages for plain text responses."""
        if not self.anthropic_key:
            return None

        try:
            headers = {
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
                "x-api-key": self.anthropic_key,
            }
            payload = {
                "model": self.anthropic_model,
                "max_tokens": 2000,
                "messages": [{"role": "user", "content": prompt}],
            }
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    content = data.get("content", [])
                    if content and content[0].get("type") == "text":
                        return content[0].get("text", "")
                    return None
        except Exception as exc:
            logger.error(f"[AGENT] Anthropic generate failed: {exc}")
            return None

    # ================================================================== #
    #  Response parsing helpers
    # ================================================================== #

    def _parse_tool_call_response(self, raw: Dict) -> Optional[Dict]:
        """Convert native tool_call response into our standard decision dict.

        Handles the common case where the LLM merges the system prompt's
        JSON format into the tool_call arguments, producing::

            arguments: {
                "params": {"ioc": "8.8.8.8"},
                "action": "use_tool",
                "tool": "investigate_ioc",
                "reasoning": "..."
            }

        instead of the expected ``{"ioc": "8.8.8.8"}``.
        """
        calls = raw.get("tool_calls", [])
        if not calls:
            return None
        first = calls[0]
        func = first.get("function", first)
        name = func.get("name", "")
        args = func.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        if not isinstance(args, dict):
            args = {}

        # ---- Unwrap nested params ----
        # If the LLM stuffed the full decision JSON into tool_call arguments,
        # the REAL tool parameters live under args["params"].
        if "params" in args and isinstance(args["params"], dict):
            nested = args["params"]
            # Verify this looks like the system-prompt JSON leak
            # (has 'action' or 'tool' or 'reasoning' alongside 'params')
            has_decision_keys = any(
                k in args for k in ("action", "tool", "reasoning")
            )
            if has_decision_keys or len(nested) > 0:
                reasoning = args.get("reasoning", "Selected by LLM tool_call")
                # Use the tool name from the native call (more reliable)
                # but fall back to args["tool"] if the native name is empty
                if not name and args.get("tool"):
                    name = args["tool"]
                args = nested
                logger.info(
                    f"[AGENT] Unwrapped nested params for {name}: {args}"
                )

        logger.info(
            f"[AGENT] Parsed tool_call: tool={name}, args={args}, "
            f"raw_first={json.dumps(first, default=str)[:300]}"
        )
        return {
            "action": "use_tool",
            "tool": name,
            "params": args,
            "reasoning": args.pop("reasoning", "Selected by LLM tool_call")
                         if "reasoning" in args else "Selected by LLM tool_call",
        }

    @staticmethod
    def _extract_json(text: str) -> Optional[Dict]:
        """Best-effort extraction of a JSON object from LLM text output."""
        if not text:
            return None

        # 1. Try parsing entire text as JSON
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 2. Try extracting from code blocks
        m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass

        # 3. Find first { ... } block
        start = text.find('{')
        if start >= 0:
            depth = 0
            for i in range(start, len(text)):
                if text[i] == '{':
                    depth += 1
                elif text[i] == '}':
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start:i + 1])
                        except json.JSONDecodeError:
                            break

        return None


# -------------------------------------------------------------------- #
#  Utility
# -------------------------------------------------------------------- #

def _truncate(s: str, max_len: int) -> str:
    return s if len(s) <= max_len else s[:max_len] + "..."
