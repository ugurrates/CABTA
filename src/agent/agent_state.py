"""
Agent State Machine - Tracks the phase and context of an autonomous investigation.

Phases: IDLE -> THINKING -> ACTING -> OBSERVING -> REFLECTING -> COMPLETED/FAILED
        At any point the loop may enter WAITING_HUMAN when analyst approval is needed.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class AgentPhase(str, Enum):
    """Phases of the ReAct reasoning loop."""
    IDLE = "idle"
    THINKING = "thinking"
    ACTING = "acting"
    OBSERVING = "observing"
    REFLECTING = "reflecting"
    WAITING_HUMAN = "waiting_human"
    COMPLETED = "completed"
    FAILED = "failed"


# Allowed phase transitions (source -> set of valid targets)
_TRANSITIONS = {
    AgentPhase.IDLE:          {AgentPhase.THINKING, AgentPhase.FAILED},
    AgentPhase.THINKING:      {AgentPhase.ACTING, AgentPhase.COMPLETED, AgentPhase.FAILED, AgentPhase.WAITING_HUMAN},
    AgentPhase.ACTING:        {AgentPhase.OBSERVING, AgentPhase.FAILED, AgentPhase.WAITING_HUMAN},
    AgentPhase.OBSERVING:     {AgentPhase.REFLECTING, AgentPhase.THINKING, AgentPhase.COMPLETED, AgentPhase.FAILED},
    AgentPhase.REFLECTING:    {AgentPhase.THINKING, AgentPhase.COMPLETED, AgentPhase.FAILED},
    AgentPhase.WAITING_HUMAN: {AgentPhase.ACTING, AgentPhase.THINKING, AgentPhase.FAILED, AgentPhase.COMPLETED},
    AgentPhase.COMPLETED:     set(),
    AgentPhase.FAILED:        set(),
}


@dataclass
class AgentState:
    """Mutable state for a single investigation session."""

    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    phase: AgentPhase = AgentPhase.IDLE
    goal: str = ""
    current_tool: Optional[str] = None
    step_count: int = 0
    max_steps: int = 50
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    pending_approval: Optional[Dict[str, Any]] = field(default=None)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # ------------------------------------------------------------------ #
    # Phase transitions
    # ------------------------------------------------------------------ #

    def transition(self, new_phase: AgentPhase) -> None:
        """Transition to *new_phase*, raising ValueError on illegal moves."""
        allowed = _TRANSITIONS.get(self.phase, set())
        if new_phase not in allowed:
            raise ValueError(
                f"Invalid transition: {self.phase.value} -> {new_phase.value}. "
                f"Allowed targets: {[p.value for p in allowed]}"
            )
        self.phase = new_phase

    # ------------------------------------------------------------------ #
    # Findings & approval helpers
    # ------------------------------------------------------------------ #

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Append a tool result / observation to the findings list."""
        stamped = {
            "step": self.step_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **finding,
        }
        self.findings.append(stamped)

    def request_approval(self, action: Dict[str, Any], reason: str) -> None:
        """Park the loop until an analyst approves or rejects *action*."""
        self.pending_approval = {
            "action": action,
            "reason": reason,
            "requested_at": datetime.now(timezone.utc).isoformat(),
        }

    def clear_approval(self) -> Optional[Dict[str, Any]]:
        """Pop and return the pending approval (if any)."""
        approval = self.pending_approval
        self.pending_approval = None
        return approval

    # ------------------------------------------------------------------ #
    # Status helpers
    # ------------------------------------------------------------------ #

    def is_terminal(self) -> bool:
        """Return True when the session cannot make further progress."""
        return self.phase in (AgentPhase.COMPLETED, AgentPhase.FAILED)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the entire state to a plain dict."""
        return {
            "session_id": self.session_id,
            "phase": self.phase.value,
            "goal": self.goal,
            "current_tool": self.current_tool,
            "step_count": self.step_count,
            "max_steps": self.max_steps,
            "findings": self.findings,
            "errors": self.errors,
            "pending_approval": self.pending_approval,
            "created_at": self.created_at,
            "is_terminal": self.is_terminal(),
        }
