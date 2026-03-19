"""
Author: Ugur Ates
Dashboard API endpoints.
"""

import logging
from fastapi import APIRouter, Request

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get('/stats')
async def get_stats(request: Request):
    """Get dashboard statistics."""
    mgr = request.app.state.analysis_manager
    return mgr.get_stats()


@router.get('/recent')
async def get_recent(request: Request, limit: int = 10):
    """Get recent analyses."""
    mgr = request.app.state.analysis_manager
    jobs = mgr.list_jobs(limit=limit)
    return {'items': jobs}


@router.get('/sources')
async def get_sources(request: Request):
    """Get TI source health status."""
    # Placeholder - would integrate with RateLimitManager in production
    sources = [
        {'name': 'VirusTotal', 'status': 'healthy', 'avg_response_ms': 450},
        {'name': 'AbuseIPDB', 'status': 'healthy', 'avg_response_ms': 320},
        {'name': 'Shodan', 'status': 'healthy', 'avg_response_ms': 580},
        {'name': 'GreyNoise', 'status': 'healthy', 'avg_response_ms': 290},
        {'name': 'AlienVault OTX', 'status': 'healthy', 'avg_response_ms': 410},
    ]
    return {'sources': sources}
