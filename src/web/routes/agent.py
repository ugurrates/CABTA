"""
Author: Ugur Ates
Agent API routes - Investigation management.
"""

import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
router = APIRouter()


class InvestigateRequest(BaseModel):
    goal: str = Field(..., min_length=1, description="Investigation goal in natural language")
    case_id: Optional[str] = None
    playbook_id: Optional[str] = None
    max_steps: Optional[int] = Field(None, ge=1, le=500, description="Maximum investigation steps")


class ApprovalRequest(BaseModel):
    approved: bool
    comment: str = ""


def _require_agent_loop(request: Request):
    loop = request.app.state.agent_loop
    if loop is None:
        raise HTTPException(503, "Agent loop not initialized")
    return loop


def _require_agent_store(request: Request):
    store = request.app.state.agent_store
    if store is None:
        raise HTTPException(503, "Agent store not initialized")
    return store


@router.post('/investigate')
async def start_investigation(request: Request, body: InvestigateRequest):
    """Start a new agent investigation."""
    agent_loop = _require_agent_loop(request)
    session_id = await agent_loop.investigate(
        body.goal, body.case_id, body.playbook_id, max_steps=body.max_steps
    )
    return {"session_id": session_id, "status": "active", "goal": body.goal}


@router.get('/stats')
async def agent_stats(request: Request):
    """Get agent statistics."""
    store = _require_agent_store(request)
    stats = store.get_agent_stats()
    # Add tool count
    tool_registry = request.app.state.tool_registry
    if tool_registry:
        stats['registered_tools'] = len(tool_registry.list_tools())
    # Add MCP connection count
    mcp_client = request.app.state.mcp_client
    if mcp_client:
        status = mcp_client.get_connection_status()
        stats['mcp_servers'] = len(status)
        stats['mcp_connected'] = sum(1 for s in status.values() if s.get('connected'))
    return stats


@router.get('/tools')
async def list_tools(request: Request, category: Optional[str] = None):
    """List all registered tools."""
    tool_registry = request.app.state.tool_registry
    if tool_registry is None:
        raise HTTPException(503, "Tool registry not initialized")
    tools = tool_registry.list_tools(category=category)
    return {"tools": [t.to_dict() for t in tools]}


@router.get('/memory/ioc/{ioc}')
async def recall_ioc(request: Request, ioc: str):
    """Check investigation memory for a previously analyzed IOC."""
    memory = request.app.state.investigation_memory
    if memory is None:
        raise HTTPException(503, "Investigation memory not initialized")

    cached = memory.recall_ioc(ioc)
    if cached:
        return {"cached": True, "ioc": ioc, "result": cached}
    return {"cached": False, "ioc": ioc, "message": f"No prior investigation found for {ioc}"}


@router.get('/memory/stats')
async def memory_stats(request: Request):
    """Get investigation memory statistics."""
    memory = request.app.state.investigation_memory
    if memory is None:
        raise HTTPException(503, "Investigation memory not initialized")

    summary = memory.get_pattern_summary()
    return summary


@router.get('/sandbox/status')
async def sandbox_status(request: Request):
    """Get sandbox environment status."""
    sandbox = request.app.state.sandbox_orchestrator
    if sandbox is None:
        raise HTTPException(503, "Sandbox orchestrator not initialized")

    status = sandbox.get_sandbox_status()
    return {"sandboxes": status}


@router.get('/correlation/{session_id}')
async def get_session_correlation(request: Request, session_id: str):
    """Get correlation analysis for a session's findings."""
    store = _require_agent_store(request)
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")

    correlation_engine = request.app.state.correlation_engine
    if correlation_engine is None:
        raise HTTPException(503, "Correlation engine not initialized")

    # Get session findings and correlate
    findings = session.get('findings', [])
    if isinstance(findings, str):
        import json
        try:
            findings = json.loads(findings)
        except (json.JSONDecodeError, TypeError):
            findings = []

    result = correlation_engine.correlate(findings)
    return {"session_id": session_id, "correlation": result}


@router.get('/sessions')
async def list_sessions(request: Request, limit: int = 50, status: Optional[str] = None):
    """List agent investigation sessions."""
    store = _require_agent_store(request)
    sessions = store.list_sessions(limit=limit, status=status)
    return {"sessions": sessions}


@router.get('/sessions/{session_id}')
async def get_session(request: Request, session_id: str):
    """Get session details with all steps."""
    store = _require_agent_store(request)
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    steps = store.get_steps(session_id)
    session['steps'] = steps
    # Include live state if available
    agent_loop = request.app.state.agent_loop
    if agent_loop:
        live_state = agent_loop.get_state(session_id)
        if live_state:
            session['live_state'] = live_state
    return session


@router.post('/sessions/{session_id}/approve')
async def approve_action(request: Request, session_id: str, body: ApprovalRequest):
    """Approve or reject a pending action."""
    agent_loop = _require_agent_loop(request)
    if body.approved:
        success = await agent_loop.approve_action(session_id)
    else:
        success = await agent_loop.reject_action(session_id)
    return {"success": success}


@router.post('/sessions/{session_id}/cancel')
async def cancel_session(request: Request, session_id: str):
    """Cancel an active investigation."""
    agent_loop = _require_agent_loop(request)
    await agent_loop.cancel_session(session_id)
    return {"status": "cancelled"}
