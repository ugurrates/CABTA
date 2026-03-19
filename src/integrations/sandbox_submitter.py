"""
Author: Ugur Ates
Sandbox Submitter - Auto-Submit to Online Sandboxes.

v1.0.0 Features:
- Any.Run submission (public/private)
- Hybrid Analysis submission
- Joe Sandbox submission
- VirusTotal submission
- Submission status tracking
- Report retrieval
- Batch submission support

Best Practice: Only submit suspicious/unknown files to save quota
"""

import asyncio
import aiohttp
import logging
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)
class SandboxProvider(Enum):
    ANYRUN = "any.run"
    HYBRID_ANALYSIS = "hybrid-analysis"
    JOE_SANDBOX = "joe-sandbox"
    VIRUSTOTAL = "virustotal"
    TRIAGE = "tria.ge"
class SubmissionStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    QUOTA_EXCEEDED = "quota_exceeded"
@dataclass
class SubmissionResult:
    """Sandbox submission result."""
    provider: str
    success: bool
    task_id: str = ""
    report_url: str = ""
    status: SubmissionStatus = SubmissionStatus.PENDING
    error_message: str = ""
    submitted_at: str = ""
    completed_at: str = ""
    verdict: str = ""
    threat_score: int = 0
class SandboxSubmitter:
    """
    Auto-submit suspicious files to multiple sandbox providers.
    
    Supported Sandboxes:
    - Any.Run (Free tier: 5 public/day, Pro: unlimited)
    - Hybrid Analysis (Free tier: 10/day)
    - Joe Sandbox (Free tier: limited)
    - VirusTotal (Free tier: 4/min)
    - Tria.ge (Free tier available)
    
    Best Practice:
    - Only submit files with score 30-70 (unknown/suspicious)
    - Don't submit known clean or known malicious
    - Use private mode for sensitive files
    - Respect rate limits
    """
    
    # API endpoints
    ENDPOINTS = {
        'anyrun': {
            'submit': 'https://api.any.run/v1/analysis',
            'status': 'https://api.any.run/v1/analysis/{task_id}',
            'report': 'https://app.any.run/tasks/{task_id}',
        },
        'hybrid': {
            'submit': 'https://www.hybrid-analysis.com/api/v2/submit/file',
            'status': 'https://www.hybrid-analysis.com/api/v2/report/{id}/summary',
            'report': 'https://www.hybrid-analysis.com/sample/{sha256}',
        },
        'joe': {
            'submit': 'https://jbxcloud.joesecurity.org/api/v2/analysis/submit',
            'status': 'https://jbxcloud.joesecurity.org/api/v2/analysis/info',
            'report': 'https://www.joesandbox.com/analysis/{id}',
        },
        'virustotal': {
            'submit': 'https://www.virustotal.com/api/v3/files',
            'status': 'https://www.virustotal.com/api/v3/analyses/{id}',
            'report': 'https://www.virustotal.com/gui/file/{sha256}',
        },
        'triage': {
            'submit': 'https://api.tria.ge/v0/samples',
            'status': 'https://api.tria.ge/v0/samples/{id}',
            'report': 'https://tria.ge/{id}',
        }
    }
    
    # File size limits (bytes)
    SIZE_LIMITS = {
        'anyrun': 100 * 1024 * 1024,      # 100MB
        'hybrid': 100 * 1024 * 1024,      # 100MB
        'joe': 250 * 1024 * 1024,         # 250MB
        'virustotal': 650 * 1024 * 1024,  # 650MB
        'triage': 200 * 1024 * 1024,      # 200MB
    }
    
    def __init__(self, config: Dict):
        """
        Initialize submitter with API keys.
        
        Config should contain:
        {
            'anyrun_api_key': '...',
            'hybrid_api_key': '...',
            'joe_api_key': '...',
            'virustotal_api_key': '...',
            'triage_api_key': '...',
        }
        """
        self.config = config
        self.api_keys = {
            'anyrun': config.get('anyrun_api_key', os.environ.get('ANYRUN_API_KEY', '')),
            'hybrid': config.get('hybrid_api_key', os.environ.get('HYBRID_ANALYSIS_API_KEY', '')),
            'joe': config.get('joe_api_key', os.environ.get('JOE_SANDBOX_API_KEY', '')),
            'virustotal': config.get('virustotal_api_key', os.environ.get('VT_API_KEY', '')),
            'triage': config.get('triage_api_key', os.environ.get('TRIAGE_API_KEY', '')),
        }
        
        # Track submissions
        self.submissions: Dict[str, SubmissionResult] = {}
        
        # Available providers (with API keys)
        self.available_providers = [
            p for p, k in self.api_keys.items() if k
        ]
        
        logger.info(f"[SANDBOX] Available providers: {self.available_providers}")
    
    async def submit_file(self, file_path: str, 
                          providers: List[str] = None,
                          private: bool = False,
                          wait_for_result: bool = False,
                          timeout: int = 300) -> Dict[str, SubmissionResult]:
        """
        Submit file to sandbox providers.
        
        Args:
            file_path: Path to file
            providers: List of providers (None = all available)
            private: Use private analysis mode
            wait_for_result: Wait for analysis to complete
            timeout: Max wait time in seconds
        
        Returns:
            Dict mapping provider to SubmissionResult
        """
        results = {}
        
        # Validate file
        path = Path(file_path)
        if not path.exists():
            return {'error': SubmissionResult(
                provider='system',
                success=False,
                error_message=f"File not found: {file_path}"
            )}
        
        file_size = path.stat().st_size
        
        # Calculate hash
        with open(file_path, 'rb') as f:
            file_data = f.read()
            sha256 = hashlib.sha256(file_data).hexdigest()
        
        # Determine providers
        providers = providers or self.available_providers
        providers = [p for p in providers if p in self.available_providers]
        
        if not providers:
            return {'error': SubmissionResult(
                provider='system',
                success=False,
                error_message="No sandbox providers configured"
            )}
        
        logger.info(f"[SANDBOX] Submitting {path.name} to {providers}")
        
        # Submit to each provider
        tasks = []
        for provider in providers:
            # Check size limit
            if file_size > self.SIZE_LIMITS.get(provider, 100*1024*1024):
                results[provider] = SubmissionResult(
                    provider=provider,
                    success=False,
                    error_message=f"File too large for {provider}"
                )
                continue
            
            tasks.append(self._submit_to_provider(
                provider, file_path, file_data, sha256, private
            ))
        
        # Execute submissions
        if tasks:
            submission_results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(submission_results):
                provider = providers[i]
                if isinstance(result, Exception):
                    results[provider] = SubmissionResult(
                        provider=provider,
                        success=False,
                        error_message=str(result)
                    )
                else:
                    results[provider] = result
        
        # Wait for results if requested
        if wait_for_result:
            for provider, result in results.items():
                if result.success and result.task_id:
                    final_result = await self._wait_for_result(
                        provider, result.task_id, timeout
                    )
                    results[provider] = final_result
        
        # Track submissions
        for provider, result in results.items():
            key = f"{sha256}_{provider}"
            self.submissions[key] = result
        
        return results
    
    async def _submit_to_provider(self, provider: str, file_path: str,
                                   file_data: bytes, sha256: str,
                                   private: bool) -> SubmissionResult:
        """Submit to specific provider."""
        api_key = self.api_keys.get(provider)
        if not api_key:
            return SubmissionResult(
                provider=provider,
                success=False,
                error_message="No API key configured"
            )
        
        try:
            if provider == 'anyrun':
                return await self._submit_anyrun(file_path, file_data, api_key, private)
            elif provider == 'hybrid':
                return await self._submit_hybrid(file_path, file_data, api_key, private)
            elif provider == 'joe':
                return await self._submit_joe(file_path, file_data, api_key, private)
            elif provider == 'virustotal':
                return await self._submit_virustotal(file_path, file_data, sha256, api_key)
            elif provider == 'triage':
                return await self._submit_triage(file_path, file_data, api_key, private)
            else:
                return SubmissionResult(
                    provider=provider,
                    success=False,
                    error_message=f"Unknown provider: {provider}"
                )
        except Exception as e:
            logger.error(f"[SANDBOX] {provider} submission failed: {e}")
            return SubmissionResult(
                provider=provider,
                success=False,
                error_message=str(e)
            )
    
    async def _submit_anyrun(self, file_path: str, file_data: bytes,
                              api_key: str, private: bool) -> SubmissionResult:
        """Submit to Any.Run."""
        url = self.ENDPOINTS['anyrun']['submit']
        
        form_data = aiohttp.FormData()
        form_data.add_field('file', file_data, 
                            filename=Path(file_path).name,
                            content_type='application/octet-stream')
        form_data.add_field('env_os', 'windows')
        form_data.add_field('env_version', '10')
        form_data.add_field('env_bitness', '64')
        form_data.add_field('env_type', 'complete')
        form_data.add_field('opt_privacy_type', 'bylink' if private else 'public')
        form_data.add_field('opt_timeout', '60')
        
        headers = {'Authorization': f'API-Key {api_key}'}
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=form_data, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    task_id = data.get('data', {}).get('taskid', '')
                    return SubmissionResult(
                        provider='anyrun',
                        success=True,
                        task_id=task_id,
                        report_url=f"https://app.any.run/tasks/{task_id}",
                        status=SubmissionStatus.PENDING,
                        submitted_at=datetime.now().isoformat()
                    )
                elif resp.status == 429:
                    return SubmissionResult(
                        provider='anyrun',
                        success=False,
                        status=SubmissionStatus.QUOTA_EXCEEDED,
                        error_message="Rate limit exceeded"
                    )
                else:
                    text = await resp.text()
                    return SubmissionResult(
                        provider='anyrun',
                        success=False,
                        error_message=f"HTTP {resp.status}: {text[:200]}"
                    )
    
    async def _submit_hybrid(self, file_path: str, file_data: bytes,
                              api_key: str, private: bool) -> SubmissionResult:
        """Submit to Hybrid Analysis."""
        url = self.ENDPOINTS['hybrid']['submit']
        
        form_data = aiohttp.FormData()
        form_data.add_field('file', file_data,
                            filename=Path(file_path).name,
                            content_type='application/octet-stream')
        form_data.add_field('environment_id', '160')  # Windows 10 64-bit
        form_data.add_field('no_share_third_party', 'true' if private else 'false')
        
        headers = {
            'api-key': api_key,
            'User-Agent': 'Blue Team Assistant/6.2'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=form_data, headers=headers) as resp:
                if resp.status == 201:
                    data = await resp.json()
                    job_id = data.get('job_id', '')
                    sha256 = data.get('sha256', '')
                    return SubmissionResult(
                        provider='hybrid',
                        success=True,
                        task_id=job_id,
                        report_url=f"https://www.hybrid-analysis.com/sample/{sha256}",
                        status=SubmissionStatus.PENDING,
                        submitted_at=datetime.now().isoformat()
                    )
                elif resp.status == 429:
                    return SubmissionResult(
                        provider='hybrid',
                        success=False,
                        status=SubmissionStatus.QUOTA_EXCEEDED,
                        error_message="Rate limit exceeded"
                    )
                else:
                    text = await resp.text()
                    return SubmissionResult(
                        provider='hybrid',
                        success=False,
                        error_message=f"HTTP {resp.status}: {text[:200]}"
                    )
    
    async def _submit_joe(self, file_path: str, file_data: bytes,
                           api_key: str, private: bool) -> SubmissionResult:
        """Submit to Joe Sandbox."""
        url = self.ENDPOINTS['joe']['submit']
        
        form_data = aiohttp.FormData()
        form_data.add_field('sample', file_data,
                            filename=Path(file_path).name,
                            content_type='application/octet-stream')
        form_data.add_field('apikey', api_key)
        form_data.add_field('systems[]', 'w10x64')
        form_data.add_field('inet', 'true')
        form_data.add_field('privacy', 'true' if private else 'false')
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=form_data) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get('errors'):
                        return SubmissionResult(
                            provider='joe',
                            success=False,
                            error_message=str(data['errors'])
                        )
                    webids = data.get('data', {}).get('webids', [])
                    webid = webids[0] if webids else ''
                    return SubmissionResult(
                        provider='joe',
                        success=True,
                        task_id=webid,
                        report_url=f"https://www.joesandbox.com/analysis/{webid}",
                        status=SubmissionStatus.PENDING,
                        submitted_at=datetime.now().isoformat()
                    )
                else:
                    text = await resp.text()
                    return SubmissionResult(
                        provider='joe',
                        success=False,
                        error_message=f"HTTP {resp.status}: {text[:200]}"
                    )
    
    async def _submit_virustotal(self, file_path: str, file_data: bytes,
                                  sha256: str, api_key: str) -> SubmissionResult:
        """Submit to VirusTotal."""
        url = self.ENDPOINTS['virustotal']['submit']
        
        headers = {'x-apikey': api_key}
        
        async with aiohttp.ClientSession() as session:
            # Check if already analyzed
            check_url = f"https://www.virustotal.com/api/v3/files/{sha256}"
            async with session.get(check_url, headers=headers) as resp:
                if resp.status == 200:
                    # Already exists, return existing report
                    return SubmissionResult(
                        provider='virustotal',
                        success=True,
                        task_id=sha256,
                        report_url=f"https://www.virustotal.com/gui/file/{sha256}",
                        status=SubmissionStatus.COMPLETED,
                        submitted_at=datetime.now().isoformat()
                    )
            
            # Submit new file
            form_data = aiohttp.FormData()
            form_data.add_field('file', file_data,
                               filename=Path(file_path).name,
                               content_type='application/octet-stream')
            
            async with session.post(url, data=form_data, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    analysis_id = data.get('data', {}).get('id', '')
                    return SubmissionResult(
                        provider='virustotal',
                        success=True,
                        task_id=analysis_id,
                        report_url=f"https://www.virustotal.com/gui/file/{sha256}",
                        status=SubmissionStatus.PENDING,
                        submitted_at=datetime.now().isoformat()
                    )
                elif resp.status == 429:
                    return SubmissionResult(
                        provider='virustotal',
                        success=False,
                        status=SubmissionStatus.QUOTA_EXCEEDED,
                        error_message="Rate limit exceeded"
                    )
                else:
                    text = await resp.text()
                    return SubmissionResult(
                        provider='virustotal',
                        success=False,
                        error_message=f"HTTP {resp.status}: {text[:200]}"
                    )
    
    async def _submit_triage(self, file_path: str, file_data: bytes,
                              api_key: str, private: bool) -> SubmissionResult:
        """Submit to Tria.ge."""
        url = self.ENDPOINTS['triage']['submit']
        
        form_data = aiohttp.FormData()
        form_data.add_field('file', file_data,
                            filename=Path(file_path).name,
                            content_type='application/octet-stream')
        form_data.add_field('kind', 'file')
        
        if private:
            form_data.add_field('_selector', 'private')
        
        headers = {'Authorization': f'Bearer {api_key}'}
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=form_data, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    sample_id = data.get('id', '')
                    return SubmissionResult(
                        provider='triage',
                        success=True,
                        task_id=sample_id,
                        report_url=f"https://tria.ge/{sample_id}",
                        status=SubmissionStatus.PENDING,
                        submitted_at=datetime.now().isoformat()
                    )
                else:
                    text = await resp.text()
                    return SubmissionResult(
                        provider='triage',
                        success=False,
                        error_message=f"HTTP {resp.status}: {text[:200]}"
                    )
    
    async def _wait_for_result(self, provider: str, task_id: str,
                                timeout: int) -> SubmissionResult:
        """Wait for analysis to complete."""
        start_time = datetime.now()
        
        while (datetime.now() - start_time).seconds < timeout:
            result = await self.check_status(provider, task_id)
            
            if result.status in [SubmissionStatus.COMPLETED, SubmissionStatus.FAILED]:
                return result
            
            await asyncio.sleep(30)  # Check every 30 seconds
        
        return SubmissionResult(
            provider=provider,
            success=False,
            task_id=task_id,
            status=SubmissionStatus.PENDING,
            error_message=f"Timeout after {timeout}s"
        )
    
    async def check_status(self, provider: str, task_id: str) -> SubmissionResult:
        """Check analysis status."""
        api_key = self.api_keys.get(provider)
        if not api_key:
            return SubmissionResult(
                provider=provider,
                success=False,
                error_message="No API key"
            )
        
        try:
            if provider == 'anyrun':
                return await self._check_anyrun(task_id, api_key)
            elif provider == 'hybrid':
                return await self._check_hybrid(task_id, api_key)
            elif provider == 'virustotal':
                return await self._check_virustotal(task_id, api_key)
            else:
                return SubmissionResult(
                    provider=provider,
                    success=False,
                    error_message=f"Status check not implemented for {provider}"
                )
        except Exception as e:
            return SubmissionResult(
                provider=provider,
                success=False,
                error_message=str(e)
            )
    
    async def _check_anyrun(self, task_id: str, api_key: str) -> SubmissionResult:
        """Check Any.Run task status."""
        url = f"https://api.any.run/v1/analysis/{task_id}"
        headers = {'Authorization': f'API-Key {api_key}'}
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    status = data.get('data', {}).get('status', '')
                    verdict = data.get('data', {}).get('verdict', '')
                    score = data.get('data', {}).get('scores', {}).get('verdict', {}).get('score', 0)
                    
                    return SubmissionResult(
                        provider='anyrun',
                        success=True,
                        task_id=task_id,
                        report_url=f"https://app.any.run/tasks/{task_id}",
                        status=SubmissionStatus.COMPLETED if status == 'done' else SubmissionStatus.RUNNING,
                        verdict=verdict,
                        threat_score=score,
                        completed_at=datetime.now().isoformat() if status == 'done' else ''
                    )
                else:
                    return SubmissionResult(
                        provider='anyrun',
                        success=False,
                        task_id=task_id,
                        error_message=f"HTTP {resp.status}"
                    )
    
    async def _check_hybrid(self, job_id: str, api_key: str) -> SubmissionResult:
        """Check Hybrid Analysis status."""
        url = f"https://www.hybrid-analysis.com/api/v2/report/{job_id}/summary"
        headers = {
            'api-key': api_key,
            'User-Agent': 'Blue Team Assistant/6.2'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    verdict = data.get('verdict', '')
                    score = data.get('threat_score', 0)
                    
                    return SubmissionResult(
                        provider='hybrid',
                        success=True,
                        task_id=job_id,
                        report_url=data.get('report_url', ''),
                        status=SubmissionStatus.COMPLETED,
                        verdict=verdict,
                        threat_score=score,
                        completed_at=datetime.now().isoformat()
                    )
                elif resp.status == 404:
                    return SubmissionResult(
                        provider='hybrid',
                        success=True,
                        task_id=job_id,
                        status=SubmissionStatus.RUNNING
                    )
                else:
                    return SubmissionResult(
                        provider='hybrid',
                        success=False,
                        task_id=job_id,
                        error_message=f"HTTP {resp.status}"
                    )
    
    async def _check_virustotal(self, analysis_id: str, api_key: str) -> SubmissionResult:
        """Check VirusTotal analysis status."""
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        headers = {'x-apikey': api_key}
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    attrs = data.get('data', {}).get('attributes', {})
                    status = attrs.get('status', '')
                    stats = attrs.get('stats', {})
                    
                    malicious = stats.get('malicious', 0)
                    total = sum(stats.values()) if stats else 0
                    score = int((malicious / max(total, 1)) * 100)
                    
                    return SubmissionResult(
                        provider='virustotal',
                        success=True,
                        task_id=analysis_id,
                        status=SubmissionStatus.COMPLETED if status == 'completed' else SubmissionStatus.RUNNING,
                        verdict=f"{malicious}/{total} engines",
                        threat_score=score,
                        completed_at=datetime.now().isoformat() if status == 'completed' else ''
                    )
                else:
                    return SubmissionResult(
                        provider='virustotal',
                        success=False,
                        task_id=analysis_id,
                        error_message=f"HTTP {resp.status}"
                    )
    
    def get_submission_history(self) -> List[Dict]:
        """Get all submission history."""
        return [
            {
                'key': key,
                'provider': result.provider,
                'task_id': result.task_id,
                'status': result.status.value,
                'report_url': result.report_url,
                'verdict': result.verdict,
                'threat_score': result.threat_score,
                'submitted_at': result.submitted_at,
            }
            for key, result in self.submissions.items()
        ]
# ==================== HELPER FUNCTIONS ====================

def should_submit_to_sandbox(threat_score: int, verdict: str) -> bool:
    """
    Determine if file should be submitted to sandbox.
    
    Best Practice:
    - Submit files with score 30-70 (unknown/suspicious)
    - Don't submit known clean (<30) or known malicious (>70)
    """
    if verdict == 'CLEAN' and threat_score < 30:
        return False  # Probably safe
    if verdict == 'MALICIOUS' and threat_score > 70:
        return False  # Already known malicious
    return True
async def auto_submit_suspicious(file_path: str, threat_score: int,
                                  config: Dict) -> Optional[Dict]:
    """
    Auto-submit suspicious files to sandboxes.
    
    Args:
        file_path: Path to file
        threat_score: Current threat score
        config: API configuration
    
    Returns:
        Submission results or None if not submitted
    """
    if not should_submit_to_sandbox(threat_score, 
                                     'SUSPICIOUS' if 30 <= threat_score <= 70 else 'CLEAN'):
        logger.info(f"[SANDBOX] Skipping submission for score {threat_score}")
        return None
    
    submitter = SandboxSubmitter(config)
    results = await submitter.submit_file(file_path, private=True)
    
    return {
        'submitted': True,
        'results': {
            provider: {
                'success': result.success,
                'task_id': result.task_id,
                'report_url': result.report_url,
                'status': result.status.value,
                'error': result.error_message
            }
            for provider, result in results.items()
        }
    }
