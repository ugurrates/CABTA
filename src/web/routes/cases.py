"""
Author: Ugur Ates
Case Management API endpoints.
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request

from ..models import CaseCreate, CaseNote, CaseStatusUpdate

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post('')
async def create_case(request: Request, payload: CaseCreate):
    """Create a new case."""
    store = request.app.state.case_store
    case_id = store.create_case(
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
    )
    return {'id': case_id, 'message': f'Case created: {payload.title}'}


@router.get('')
async def list_cases(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
):
    """List all cases."""
    store = request.app.state.case_store
    cases = store.list_cases(limit=limit, offset=offset, status=status)
    return {'items': cases}


@router.get('/{case_id}')
async def get_case(request: Request, case_id: str):
    """Get case details with linked analyses and notes."""
    store = request.app.state.case_store
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(404, 'Case not found')
    return case


@router.patch('/{case_id}/status')
async def update_case_status(request: Request, case_id: str, payload: CaseStatusUpdate):
    """Update case status."""
    store = request.app.state.case_store
    ok = store.update_case_status(case_id, payload.status.value)
    if not ok:
        raise HTTPException(404, 'Case not found')
    return {'message': f'Status updated to {payload.status.value}'}


@router.post('/{case_id}/analyses')
async def link_analysis(request: Request, case_id: str, analysis_id: str):
    """Link an analysis to a case."""
    store = request.app.state.case_store
    ok = store.link_analysis(case_id, analysis_id)
    if not ok:
        raise HTTPException(400, 'Failed to link analysis')
    return {'message': 'Analysis linked to case'}


@router.post('/{case_id}/notes')
async def add_note(request: Request, case_id: str, payload: CaseNote):
    """Add a note to a case."""
    store = request.app.state.case_store
    note_id = store.add_note(case_id, payload.content, payload.author)
    return {'id': note_id, 'message': 'Note added'}
