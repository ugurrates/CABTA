"""
Author: Ugur Ates
Playbook API routes.
"""

import logging
from typing import Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter()


class PlaybookRunRequest(BaseModel):
    params: Dict = {}
    case_id: Optional[str] = None


@router.get('')
async def list_playbooks(request: Request):
    """List all available playbooks."""
    engine = request.app.state.playbook_engine
    if engine:
        return {"playbooks": engine.list_playbooks()}
    store = request.app.state.agent_store
    if store:
        return {"playbooks": store.list_playbooks()}
    return {"playbooks": []}


@router.get('/{playbook_id}')
async def get_playbook(request: Request, playbook_id: str):
    """Get playbook details."""
    engine = request.app.state.playbook_engine
    if engine:
        pb = engine.get_playbook(playbook_id)
        if pb:
            return pb
    store = request.app.state.agent_store
    if store:
        pb = store.get_playbook(playbook_id)
        if pb:
            return pb
    raise HTTPException(404, "Playbook not found")


@router.post('/{playbook_id}/run')
async def run_playbook(request: Request, playbook_id: str, body: PlaybookRunRequest = PlaybookRunRequest()):
    """Execute a playbook."""
    engine = request.app.state.playbook_engine
    if engine is None:
        raise HTTPException(503, "Playbook engine not initialized")
    try:
        session_id = await engine.execute(playbook_id, body.params, body.case_id)
        return {"session_id": session_id, "status": "running"}
    except ValueError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        raise HTTPException(500, f"Playbook execution failed: {str(e)}")
