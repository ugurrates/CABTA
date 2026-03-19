"""
Sandbox Adapters - Bridge non-MCP sandboxes to the agent.

Provides a unified interface for submitting files and retrieving results
from sandboxes that do not expose a native MCP server (CAPEv2, Hybrid
Analysis, ANY.RUN).

CRITICAL: Files are NEVER executed on the host system.  Every adapter
sends the file over a network API to an isolated analysis environment.
"""

import asyncio
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# Try to import aiohttp; it is an optional dependency for environments
# that only use MCP-native sandboxes.
try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class SandboxAdapter:
    """
    Abstract base class for sandbox adapters.

    Every subclass must implement at least ``submit_file`` and
    ``get_report``.  ``submit_url`` is optional (not all sandboxes
    support URL analysis).
    """

    name: str = "base"

    async def submit_file(self, file_path: str, **kwargs) -> Dict:
        """
        Submit a file for analysis.

        Returns a dict with at least ``submission_id`` on success, or an
        ``error`` key on failure.
        """
        raise NotImplementedError

    async def submit_url(self, url: str, **kwargs) -> Dict:
        """
        Submit a URL for analysis.

        Returns a dict with at least ``submission_id`` on success, or an
        ``error`` key on failure.
        """
        raise NotImplementedError

    async def get_report(self, submission_id: str) -> Dict:
        """
        Retrieve the analysis report for a completed submission.

        Returns a dict with the report data, or ``error`` on failure.
        """
        raise NotImplementedError

    async def get_status(self, submission_id: str) -> str:
        """
        Check the analysis status.

        Returns one of: ``pending``, ``running``, ``completed``, ``failed``,
        ``unknown``.
        """
        return "unknown"

    async def wait_for_result(
        self,
        submission_id: str,
        timeout: int = 300,
        poll_interval: int = 10,
    ) -> Dict:
        """
        Poll until the analysis completes or *timeout* seconds elapse.

        Returns the report on success or an ``error`` dict on timeout /
        failure.
        """
        elapsed = 0
        while elapsed < timeout:
            status = await self.get_status(submission_id)
            if status == "completed":
                return await self.get_report(submission_id)
            if status == "failed":
                return {
                    "error": "Analysis failed",
                    "submission_id": submission_id,
                    "status": status,
                }
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        return {
            "error": f"Timed out after {timeout}s waiting for analysis",
            "submission_id": submission_id,
            "last_status": status,
        }

    # ------------------------------------------------------------------ #
    #  Shared helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _read_file(file_path: str) -> tuple:
        """
        Read a file from disk and return ``(data, file_name, sha256)``.

        Raises ``FileNotFoundError`` if the path does not exist.
        """
        p = Path(file_path)
        if not p.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
        data = p.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        return data, p.name, sha256

    @staticmethod
    def _ensure_aiohttp() -> None:
        """Raise a clear error when aiohttp is missing."""
        if not _HAS_AIOHTTP:
            raise ImportError(
                "aiohttp is required for sandbox adapters.  "
                "Install it with: pip install aiohttp"
            )


# ---------------------------------------------------------------------------
# CAPEv2 adapter
# ---------------------------------------------------------------------------

class CAPEv2Adapter(SandboxAdapter):
    """
    CAPEv2 sandbox adapter via its REST API.

    CAPEv2 is self-hosted, so *api_url* must point to the running instance
    (e.g. ``http://cape.local:8000``).
    """

    name = "capev2"

    def __init__(self, api_url: str, api_key: str = ""):
        self._ensure_aiohttp()
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = aiohttp.ClientTimeout(total=60)

    def _headers(self) -> Dict[str, str]:
        headers = {"User-Agent": "Blue-Team-Agent/1.0"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def submit_file(self, file_path: str, **kwargs) -> Dict:
        """
        Submit a file to CAPEv2 for detonation.

        POST /api/tasks/create/file/
        """
        try:
            data, file_name, sha256 = self._read_file(file_path)
        except FileNotFoundError as exc:
            return {"error": str(exc)}

        url = f"{self.api_url}/api/tasks/create/file/"

        try:
            form = aiohttp.FormData()
            form.add_field(
                "file", data,
                filename=file_name,
                content_type="application/octet-stream",
            )
            # Optional CAPE-specific params
            if kwargs.get("package"):
                form.add_field("package", kwargs["package"])
            if kwargs.get("timeout"):
                form.add_field("timeout", str(kwargs["timeout"]))
            if kwargs.get("options"):
                form.add_field("options", kwargs["options"])

            async with aiohttp.ClientSession(
                timeout=self.timeout, headers=self._headers()
            ) as session:
                async with session.post(url, data=form) as resp:
                    if resp.status in (200, 201):
                        body = await resp.json()
                        task_id = str(body.get("task_id") or body.get("data", {}).get("task_ids", [None])[0] or "")
                        if not task_id:
                            return {"error": "No task_id in response", "raw": body}
                        logger.info("[CAPE] Submitted %s -> task %s", file_name, task_id)
                        return {
                            "submission_id": task_id,
                            "sha256": sha256,
                            "file_name": file_name,
                            "sandbox": self.name,
                        }
                    else:
                        text = await resp.text()
                        return {"error": f"HTTP {resp.status}: {text[:300]}"}

        except Exception as exc:
            logger.error("[CAPE] submit_file failed: %s", exc)
            return {"error": str(exc)}

    async def submit_url(self, url_to_analyze: str, **kwargs) -> Dict:
        """POST /api/tasks/create/url/"""
        url = f"{self.api_url}/api/tasks/create/url/"
        try:
            form = aiohttp.FormData()
            form.add_field("url", url_to_analyze)

            async with aiohttp.ClientSession(
                timeout=self.timeout, headers=self._headers()
            ) as session:
                async with session.post(url, data=form) as resp:
                    if resp.status in (200, 201):
                        body = await resp.json()
                        task_id = str(body.get("task_id", ""))
                        return {
                            "submission_id": task_id,
                            "url": url_to_analyze,
                            "sandbox": self.name,
                        }
                    else:
                        text = await resp.text()
                        return {"error": f"HTTP {resp.status}: {text[:300]}"}
        except Exception as exc:
            logger.error("[CAPE] submit_url failed: %s", exc)
            return {"error": str(exc)}

    async def get_report(self, task_id: str) -> Dict:
        """GET /api/tasks/report/{task_id}/"""
        url = f"{self.api_url}/api/tasks/report/{task_id}/"
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=120), headers=self._headers()
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        # Normalise the most useful fields
                        info = body.get("info", {})
                        target = body.get("target", {})
                        signatures = body.get("signatures", [])
                        network = body.get("network", {})
                        behavior = body.get("behavior", {})

                        return {
                            "task_id": task_id,
                            "sandbox": self.name,
                            "score": info.get("score", 0),
                            "duration": info.get("duration", 0),
                            "machine": info.get("machine", {}).get("name", ""),
                            "target": {
                                "file_name": target.get("file", {}).get("name", ""),
                                "sha256": target.get("file", {}).get("sha256", ""),
                                "file_type": target.get("file", {}).get("type", ""),
                            },
                            "signatures": [
                                {
                                    "name": s.get("name", ""),
                                    "severity": s.get("severity", 0),
                                    "description": s.get("description", ""),
                                    "categories": s.get("categories", []),
                                    "ttp": s.get("ttp", {}),
                                }
                                for s in signatures[:50]  # Cap to avoid huge payloads
                            ],
                            "network_summary": {
                                "dns": [
                                    {"request": d.get("request", ""), "answers": d.get("answers", [])}
                                    for d in network.get("dns", [])[:30]
                                ],
                                "http": [
                                    {"uri": h.get("uri", ""), "method": h.get("method", "")}
                                    for h in network.get("http", [])[:30]
                                ],
                                "hosts": network.get("hosts", [])[:30],
                                "domains": network.get("domains", [])[:30],
                            },
                            "process_count": len(behavior.get("processes", [])),
                            "report_url": f"{self.api_url}/analysis/{task_id}/",
                        }
                    elif resp.status == 404:
                        return {"error": "Report not found", "task_id": task_id}
                    else:
                        text = await resp.text()
                        return {"error": f"HTTP {resp.status}: {text[:300]}"}
        except Exception as exc:
            logger.error("[CAPE] get_report failed: %s", exc)
            return {"error": str(exc)}

    async def get_status(self, task_id: str) -> str:
        """GET /api/tasks/status/{task_id}/"""
        url = f"{self.api_url}/api/tasks/status/{task_id}/"
        try:
            async with aiohttp.ClientSession(
                timeout=self.timeout, headers=self._headers()
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        raw = str(body.get("status", body.get("data", "unknown"))).lower()
                        # Normalise CAPE status strings
                        if raw in ("reported", "completed", "success"):
                            return "completed"
                        if raw in ("running", "processing", "pending"):
                            return "running"
                        if raw in ("failed_analysis", "failed_processing", "failed"):
                            return "failed"
                        return raw
                    return "unknown"
        except Exception as exc:
            logger.debug("[CAPE] get_status error: %s", exc)
            return "unknown"


# ---------------------------------------------------------------------------
# Hybrid Analysis adapter
# ---------------------------------------------------------------------------

class HybridAnalysisAdapter(SandboxAdapter):
    """
    Hybrid Analysis adapter via its public REST API (v2).

    Requires an API key from https://www.hybrid-analysis.com.
    """

    name = "hybrid_analysis"

    def __init__(self, api_key: str):
        self._ensure_aiohttp()
        self.api_url = "https://www.hybrid-analysis.com/api/v2"
        self.api_key = api_key
        self.timeout = aiohttp.ClientTimeout(total=60)

    def _headers(self) -> Dict[str, str]:
        return {
            "api-key": self.api_key,
            "User-Agent": "Blue-Team-Agent/1.0",
            "accept": "application/json",
        }

    async def submit_file(self, file_path: str, **kwargs) -> Dict:
        """
        Submit a file to Hybrid Analysis.

        POST /submit/file  (multipart form data)
        """
        try:
            data, file_name, sha256 = self._read_file(file_path)
        except FileNotFoundError as exc:
            return {"error": str(exc)}

        url = f"{self.api_url}/submit/file"
        environment_id = kwargs.get("environment_id", "160")  # Win10 64-bit

        try:
            form = aiohttp.FormData()
            form.add_field(
                "file", data,
                filename=file_name,
                content_type="application/octet-stream",
            )
            form.add_field("environment_id", str(environment_id))

            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=120), headers=self._headers()
            ) as session:
                async with session.post(url, data=form) as resp:
                    if resp.status in (200, 201):
                        body = await resp.json()
                        job_id = body.get("job_id", "")
                        submission_id = body.get("submission_id", job_id)
                        logger.info(
                            "[HA] Submitted %s -> job %s", file_name, submission_id,
                        )
                        return {
                            "submission_id": str(submission_id),
                            "job_id": str(job_id),
                            "sha256": body.get("sha256", sha256),
                            "file_name": file_name,
                            "sandbox": self.name,
                            "report_url": f"https://www.hybrid-analysis.com/sample/{sha256}",
                        }
                    else:
                        text = await resp.text()
                        return {"error": f"HTTP {resp.status}: {text[:300]}"}

        except Exception as exc:
            logger.error("[HA] submit_file failed: %s", exc)
            return {"error": str(exc)}

    async def submit_url(self, url_to_analyze: str, **kwargs) -> Dict:
        """POST /submit/url-for-analysis"""
        url = f"{self.api_url}/submit/url-for-analysis"
        environment_id = kwargs.get("environment_id", "160")

        try:
            form = aiohttp.FormData()
            form.add_field("url", url_to_analyze)
            form.add_field("environment_id", str(environment_id))

            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=120), headers=self._headers()
            ) as session:
                async with session.post(url, data=form) as resp:
                    if resp.status in (200, 201):
                        body = await resp.json()
                        return {
                            "submission_id": str(body.get("job_id", "")),
                            "url": url_to_analyze,
                            "sandbox": self.name,
                        }
                    else:
                        text = await resp.text()
                        return {"error": f"HTTP {resp.status}: {text[:300]}"}
        except Exception as exc:
            logger.error("[HA] submit_url failed: %s", exc)
            return {"error": str(exc)}

    async def get_report(self, submission_id: str) -> Dict:
        """GET /report/{id}/summary"""
        url = f"{self.api_url}/report/{submission_id}/summary"
        try:
            async with aiohttp.ClientSession(
                timeout=self.timeout, headers=self._headers()
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        return {
                            "submission_id": submission_id,
                            "sandbox": self.name,
                            "verdict": body.get("verdict", "unknown"),
                            "threat_score": body.get("threat_score", 0),
                            "threat_level": body.get("threat_level", 0),
                            "malware_family": body.get("vx_family", ""),
                            "tags": body.get("tags", []),
                            "mitre_attck": body.get("mitre_attcks", []),
                            "network": {
                                "domains": body.get("domains", []),
                                "hosts": body.get("hosts", []),
                            },
                            "file_type": body.get("type", ""),
                            "report_url": f"https://www.hybrid-analysis.com/sample/{body.get('sha256', '')}",
                        }
                    elif resp.status == 404:
                        return {"error": "Report not found", "submission_id": submission_id}
                    else:
                        text = await resp.text()
                        return {"error": f"HTTP {resp.status}: {text[:300]}"}
        except Exception as exc:
            logger.error("[HA] get_report failed: %s", exc)
            return {"error": str(exc)}

    async def get_status(self, submission_id: str) -> str:
        """Check Hybrid Analysis job status via report endpoint."""
        url = f"{self.api_url}/report/{submission_id}/state"
        try:
            async with aiohttp.ClientSession(
                timeout=self.timeout, headers=self._headers()
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        state = str(body.get("state", "unknown")).upper()
                        if state == "SUCCESS":
                            return "completed"
                        if state in ("IN_QUEUE", "IN_PROGRESS"):
                            return "running"
                        if state == "ERROR":
                            return "failed"
                        return "pending"
                    return "unknown"
        except Exception as exc:
            logger.debug("[HA] get_status error: %s", exc)
            return "unknown"

    async def search_hash(self, file_hash: str) -> Dict:
        """
        Search Hybrid Analysis by hash before deciding to submit.

        POST /search/hash
        """
        url = f"{self.api_url}/search/hash"
        try:
            async with aiohttp.ClientSession(
                timeout=self.timeout, headers=self._headers()
            ) as session:
                async with session.post(url, data={"hash": file_hash}) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        if body and len(body) > 0:
                            first = body[0]
                            return {
                                "found": True,
                                "verdict": first.get("verdict", "unknown"),
                                "threat_score": first.get("threat_score", 0),
                                "malware_family": first.get("vx_family", ""),
                                "analysis_date": first.get("analysis_start_time", ""),
                                "report_url": f"https://www.hybrid-analysis.com/sample/{file_hash}",
                                "total_reports": len(body),
                            }
                        return {"found": False, "hash": file_hash}
                    else:
                        text = await resp.text()
                        return {"error": f"HTTP {resp.status}: {text[:200]}"}
        except Exception as exc:
            logger.error("[HA] search_hash failed: %s", exc)
            return {"error": str(exc)}


# ---------------------------------------------------------------------------
# ANY.RUN adapter
# ---------------------------------------------------------------------------

class ANYRUNAdapter(SandboxAdapter):
    """
    ANY.RUN adapter via its REST API (v1).

    Requires an API key from https://any.run.
    """

    name = "anyrun"

    def __init__(self, api_key: str):
        self._ensure_aiohttp()
        self.api_url = "https://api.any.run/v1"
        self.api_key = api_key
        self.timeout = aiohttp.ClientTimeout(total=60)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"API-Key {self.api_key}",
            "User-Agent": "Blue-Team-Agent/1.0",
        }

    async def submit_file(self, file_path: str, **kwargs) -> Dict:
        """
        Submit a file to ANY.RUN for analysis.

        POST /analysis
        """
        try:
            data, file_name, sha256 = self._read_file(file_path)
        except FileNotFoundError as exc:
            return {"error": str(exc)}

        url = f"{self.api_url}/analysis"

        try:
            form = aiohttp.FormData()
            form.add_field(
                "file", data,
                filename=file_name,
                content_type="application/octet-stream",
            )
            # ANY.RUN optional parameters
            env_os = kwargs.get("os", "windows")
            env_ver = kwargs.get("os_version", "10")
            env_bitness = kwargs.get("bitness", 64)

            form.add_field("obj_type", "file")
            form.add_field("obj_os", env_os)
            form.add_field("obj_os_ver", str(env_ver))
            form.add_field("obj_os_bitness", str(env_bitness))

            if kwargs.get("opt_privacy_type"):
                form.add_field("opt_privacy_type", kwargs["opt_privacy_type"])

            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=120), headers=self._headers()
            ) as session:
                async with session.post(url, data=form) as resp:
                    if resp.status in (200, 201):
                        body = await resp.json()
                        task_data = body.get("data", {})
                        task_id = task_data.get("taskid", "")
                        logger.info("[ANYRUN] Submitted %s -> task %s", file_name, task_id)
                        return {
                            "submission_id": str(task_id),
                            "sha256": sha256,
                            "file_name": file_name,
                            "sandbox": self.name,
                            "report_url": f"https://app.any.run/tasks/{task_id}",
                        }
                    else:
                        text = await resp.text()
                        return {"error": f"HTTP {resp.status}: {text[:300]}"}

        except Exception as exc:
            logger.error("[ANYRUN] submit_file failed: %s", exc)
            return {"error": str(exc)}

    async def submit_url(self, url_to_analyze: str, **kwargs) -> Dict:
        """POST /analysis (URL mode)"""
        url = f"{self.api_url}/analysis"
        try:
            payload = {
                "obj_type": "url",
                "obj_url": url_to_analyze,
                "obj_os": kwargs.get("os", "windows"),
                "obj_os_ver": kwargs.get("os_version", "10"),
                "obj_os_bitness": kwargs.get("bitness", 64),
            }
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=120), headers=self._headers()
            ) as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status in (200, 201):
                        body = await resp.json()
                        task_id = body.get("data", {}).get("taskid", "")
                        return {
                            "submission_id": str(task_id),
                            "url": url_to_analyze,
                            "sandbox": self.name,
                            "report_url": f"https://app.any.run/tasks/{task_id}",
                        }
                    else:
                        text = await resp.text()
                        return {"error": f"HTTP {resp.status}: {text[:300]}"}
        except Exception as exc:
            logger.error("[ANYRUN] submit_url failed: %s", exc)
            return {"error": str(exc)}

    async def get_report(self, task_id: str) -> Dict:
        """GET /analysis/{task_id}"""
        url = f"{self.api_url}/analysis/{task_id}"
        try:
            async with aiohttp.ClientSession(
                timeout=self.timeout, headers=self._headers()
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        data = body.get("data", {})
                        analysis = data.get("analysis", {})

                        # Extract IOCs
                        iocs = data.get("iocs", {})
                        network = data.get("network", {})

                        return {
                            "task_id": task_id,
                            "sandbox": self.name,
                            "verdict": analysis.get("scores", {}).get("verdict", {}).get("text", "unknown"),
                            "threat_level": analysis.get("scores", {}).get("specs", {}).get("overall", 0),
                            "tags": analysis.get("tags", []),
                            "process_count": len(data.get("processes", [])),
                            "network_summary": {
                                "dns": [
                                    d.get("request", "") for d in network.get("dns", [])[:20]
                                ],
                                "connections": [
                                    {"ip": c.get("ip", ""), "port": c.get("port", 0)}
                                    for c in network.get("connections", [])[:20]
                                ],
                                "http": [
                                    h.get("url", "") for h in network.get("http", [])[:20]
                                ],
                            },
                            "iocs": {
                                "ips": iocs.get("ips", [])[:30],
                                "domains": iocs.get("domains", [])[:30],
                                "urls": iocs.get("urls", [])[:30],
                                "hashes": iocs.get("hashes", [])[:30],
                            },
                            "report_url": f"https://app.any.run/tasks/{task_id}",
                        }
                    elif resp.status == 404:
                        return {"error": "Report not found", "task_id": task_id}
                    else:
                        text = await resp.text()
                        return {"error": f"HTTP {resp.status}: {text[:300]}"}
        except Exception as exc:
            logger.error("[ANYRUN] get_report failed: %s", exc)
            return {"error": str(exc)}

    async def get_status(self, task_id: str) -> str:
        """Check ANY.RUN task status."""
        url = f"{self.api_url}/analysis/{task_id}"
        try:
            async with aiohttp.ClientSession(
                timeout=self.timeout, headers=self._headers()
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        status = body.get("data", {}).get("status", "unknown")
                        if status in ("done",):
                            return "completed"
                        if status in ("running", "processing", "pending"):
                            return "running"
                        if status in ("failed",):
                            return "failed"
                        return "pending"
                    if resp.status == 404:
                        return "pending"  # May still be queued
                    return "unknown"
        except Exception as exc:
            logger.debug("[ANYRUN] get_status error: %s", exc)
            return "unknown"
