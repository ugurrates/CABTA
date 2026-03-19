"""
Author: Ugur Ates
Analysis API endpoints.
"""

import asyncio
import hashlib
import logging
import tempfile
import threading
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse

from ..models import (
    AnalysisState,
    AnalysisStatus,
    FileUploadResponse,
    IOCRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter()


def _load_config():
    """Load application config for analyzer initialization."""
    try:
        from src.utils.config import load_config
        return load_config()
    except Exception:
        return {}


# ------------------------------------------------------------------
# Background analysis helpers
# ------------------------------------------------------------------

def _run_email_analysis_bg(mgr, job_id: str, eml_path: str) -> None:
    """Run email analysis in a background thread."""
    try:
        mgr.update_progress(job_id, 5, 'Loading email analyzer...')
        from src.tools.email_analyzer import EmailAnalyzer
        config = _load_config()
        analyzer = EmailAnalyzer(config)

        mgr.update_progress(job_id, 10, 'Parsing email headers...')
        mgr.update_progress(job_id, 20, 'Analyzing authentication (SPF/DKIM/DMARC)...')
        mgr.update_progress(job_id, 35, 'Running forensics analysis...')
        mgr.update_progress(job_id, 45, 'Checking link mismatches...')
        mgr.update_progress(job_id, 55, 'Detecting lookalike domains...')
        mgr.update_progress(job_id, 65, 'Analyzing HTML obfuscation...')

        result = asyncio.run(analyzer.analyze(eml_path))

        mgr.update_progress(job_id, 80, 'Generating detection rules...')
        mgr.update_progress(job_id, 85, 'Running AI analysis...')

        verdict = result.get('verdict', 'UNKNOWN')
        score = result.get('composite_score', result.get('base_phishing_score', 0))

        mgr.update_progress(job_id, 95, 'Saving results...')
        mgr.complete_job(job_id, result, verdict=verdict, score=score)

    except Exception as e:
        logger.error(f"[EMAIL-BG] Analysis failed for {job_id}: {e}")
        mgr.fail_job(job_id, str(e))


def _run_file_analysis_bg(mgr, job_id: str, file_path: str) -> None:
    """Run file/malware analysis in a background thread."""
    try:
        mgr.update_progress(job_id, 5, 'Loading malware analyzer...')
        from src.tools.malware_analyzer import MalwareAnalyzer
        config = _load_config()
        analyzer = MalwareAnalyzer(config)

        mgr.update_progress(job_id, 10, 'Computing file hashes...')
        mgr.update_progress(job_id, 15, 'Running PE analysis...')
        mgr.update_progress(job_id, 25, 'Analyzing strings (FLOSS)...')
        mgr.update_progress(job_id, 35, 'Running YARA rules...')
        mgr.update_progress(job_id, 45, 'Computing entropy...')
        mgr.update_progress(job_id, 55, 'Querying sandbox APIs...')

        result = asyncio.run(analyzer.analyze(file_path))

        verdict = result.get('verdict', 'UNKNOWN')
        score = result.get('composite_score', result.get('threat_score', 0))

        mgr.update_progress(job_id, 85, 'Generating MITRE ATT&CK mapping...')
        mgr.update_progress(job_id, 90, 'Generating detection rules...')
        mgr.update_progress(job_id, 95, 'Saving results...')
        mgr.complete_job(job_id, result, verdict=verdict, score=score)

    except Exception as e:
        logger.error(f"[FILE-BG] Analysis failed for {job_id}: {e}")
        mgr.fail_job(job_id, str(e))


def _run_ioc_analysis_bg(mgr, job_id: str, value: str, ioc_type: str) -> None:
    """Run IOC investigation in a background thread."""
    try:
        mgr.update_progress(job_id, 5, 'Loading IOC investigator...')
        from src.tools.ioc_investigator import IOCInvestigator
        config = _load_config()
        investigator = IOCInvestigator(config)

        mgr.update_progress(job_id, 10, f'Investigating {value}...')

        # Register a progress callback so each source query is reported
        _source_count = [0]

        def _on_source_progress(source_name, status):
            _source_count[0] += 1
            pct = min(10 + int((_source_count[0] / 25) * 75), 85)
            mgr.update_progress(job_id, pct, f'Querying {source_name}...')

        # Set callback if investigator supports it
        if hasattr(investigator, 'set_progress_callback'):
            investigator.set_progress_callback(_on_source_progress)

        result = asyncio.run(investigator.investigate(value))

        verdict = result.get('verdict', 'UNKNOWN')
        score = result.get('threat_score', 0)

        mgr.update_progress(job_id, 90, 'Generating detection rules...')
        mgr.update_progress(job_id, 95, 'Saving results...')
        mgr.complete_job(job_id, result, verdict=verdict, score=score)

    except Exception as e:
        logger.error(f"[IOC-BG] Analysis failed for {job_id}: {e}")
        mgr.fail_job(job_id, str(e))


@router.post('/ioc')
async def analyze_ioc(request: Request, payload: IOCRequest):
    """Start IOC investigation."""
    mgr = request.app.state.analysis_manager
    ioc_type = payload.ioc_type.value if payload.ioc_type else 'auto'
    job_id = mgr.create_job('ioc', {
        'value': payload.value,
        'ioc_type': ioc_type,
    })

    # Launch background analysis
    t = threading.Thread(
        target=_run_ioc_analysis_bg,
        args=(mgr, job_id, payload.value, ioc_type),
        daemon=True,
    )
    t.start()

    return {
        'analysis_id': job_id,
        'status': 'queued',
        'message': f'IOC analysis queued for {payload.value}',
    }


@router.post('/file')
async def analyze_file(request: Request, file: UploadFile = File(...)):
    """Upload and analyze a file."""
    mgr = request.app.state.analysis_manager

    # Read file content
    content = await file.read()
    sha256 = hashlib.sha256(content).hexdigest()

    # Save to temp
    suffix = Path(file.filename or 'unknown').suffix
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    job_id = mgr.create_job('file', {
        'filename': file.filename,
        'sha256': sha256,
        'size': len(content),
        'temp_path': tmp_path,
    })

    # Launch background analysis
    t = threading.Thread(
        target=_run_file_analysis_bg,
        args=(mgr, job_id, tmp_path),
        daemon=True,
    )
    t.start()

    return FileUploadResponse(
        analysis_id=job_id,
        filename=file.filename or 'unknown',
        sha256=sha256,
    )


@router.post('/email')
async def analyze_email(request: Request, file: UploadFile = File(...)):
    """Upload and analyze an email (.eml)."""
    mgr = request.app.state.analysis_manager

    content = await file.read()
    sha256 = hashlib.sha256(content).hexdigest()

    with tempfile.NamedTemporaryFile(delete=False, suffix='.eml') as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    job_id = mgr.create_job('email', {
        'filename': file.filename,
        'sha256': sha256,
        'temp_path': tmp_path,
    })

    # Launch background email analysis
    t = threading.Thread(
        target=_run_email_analysis_bg,
        args=(mgr, job_id, tmp_path),
        daemon=True,
    )
    t.start()

    return {
        'analysis_id': job_id,
        'status': 'queued',
        'message': f'Email analysis queued: {file.filename}',
    }


@router.get('/{analysis_id}')
async def get_analysis(request: Request, analysis_id: str):
    """Get analysis result."""
    mgr = request.app.state.analysis_manager
    job = mgr.get_job(analysis_id)
    if job is None:
        raise HTTPException(status_code=404, detail='Analysis not found')
    return job


@router.get('/{analysis_id}/status')
async def get_analysis_status(request: Request, analysis_id: str):
    """Get analysis progress."""
    mgr = request.app.state.analysis_manager
    job = mgr.get_job(analysis_id)
    if job is None:
        raise HTTPException(status_code=404, detail='Analysis not found')
    return {
        'analysis_id': analysis_id,
        'status': job.get('status'),
        'progress': job.get('progress', 0),
        'current_step': job.get('current_step', ''),
        'verdict': job.get('verdict'),
        'score': job.get('score'),
    }


@router.get('/history/')
async def get_history(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
):
    """Get analysis history."""
    mgr = request.app.state.analysis_manager
    jobs = mgr.list_jobs(limit=limit, offset=offset, status=status)
    return {'items': jobs, 'limit': limit, 'offset': offset}
