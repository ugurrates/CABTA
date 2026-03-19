"""
Sandbox Orchestrator - Routes malware analysis to appropriate sandbox environments.

CRITICAL SAFETY INVARIANT: Malware must NEVER execute on the host system.
All dynamic analysis is delegated to isolated environments (Docker containers
with ``--network none``, virtual machines, or cloud sandbox APIs).

File-type routing:
  PE (.exe/.dll/.sys) -> LitterBox / FLARE Docker container
  ELF (.elf/.so)      -> REMnux Docker container
  APK (.apk)          -> MobSF Docker container
  Office / PDF        -> local_static (oletools / pdf-parser, no execution)
  Scripts             -> Docker with network:none
  Unknown             -> cloud API fallback, then local_static
"""

import asyncio
import hashlib
import logging
import os
import uuid
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ====================================================================== #
#  Sandbox type enum
# ====================================================================== #

class SandboxType(str, Enum):
    """Available sandbox execution environments."""
    DOCKER = "docker"
    VM = "vm"
    CLOUD_API = "cloud_api"
    LOCAL_STATIC = "local_static"


# ====================================================================== #
#  File-type routing table
# ====================================================================== #

# Maps lowercase extensions to (SandboxType, docker_image_or_None, profile_tag)
_ROUTING_TABLE: Dict[str, Dict[str, Any]] = {
    # ---- PE executables -> LitterBox / FLARE Docker ----
    ".exe":  {"sandbox": SandboxType.DOCKER, "image": "remnux/flare",       "profile": "windows_pe"},
    ".dll":  {"sandbox": SandboxType.DOCKER, "image": "remnux/flare",       "profile": "windows_pe"},
    ".sys":  {"sandbox": SandboxType.DOCKER, "image": "remnux/flare",       "profile": "windows_pe"},
    ".scr":  {"sandbox": SandboxType.DOCKER, "image": "remnux/flare",       "profile": "windows_pe"},
    ".cpl":  {"sandbox": SandboxType.DOCKER, "image": "remnux/flare",       "profile": "windows_pe"},
    ".msi":  {"sandbox": SandboxType.DOCKER, "image": "remnux/flare",       "profile": "windows_pe"},
    ".ocx":  {"sandbox": SandboxType.DOCKER, "image": "remnux/flare",       "profile": "windows_pe"},
    # ---- ELF binaries -> REMnux Docker ----
    ".elf":  {"sandbox": SandboxType.DOCKER, "image": "remnux/remnux-distro", "profile": "linux_elf"},
    ".so":   {"sandbox": SandboxType.DOCKER, "image": "remnux/remnux-distro", "profile": "linux_elf"},
    ".bin":  {"sandbox": SandboxType.DOCKER, "image": "remnux/remnux-distro", "profile": "linux_elf"},
    # ---- Android APK -> MobSF Docker ----
    ".apk":  {"sandbox": SandboxType.DOCKER, "image": "opensecurity/mobile-security-framework-mobsf", "profile": "android_apk"},
    ".aab":  {"sandbox": SandboxType.DOCKER, "image": "opensecurity/mobile-security-framework-mobsf", "profile": "android_apk"},
    # ---- Office documents -> local static (oletools, NO execution) ----
    ".doc":  {"sandbox": SandboxType.LOCAL_STATIC, "image": None, "profile": "office_macro"},
    ".docx": {"sandbox": SandboxType.LOCAL_STATIC, "image": None, "profile": "office_macro"},
    ".docm": {"sandbox": SandboxType.LOCAL_STATIC, "image": None, "profile": "office_macro"},
    ".xls":  {"sandbox": SandboxType.LOCAL_STATIC, "image": None, "profile": "office_macro"},
    ".xlsx": {"sandbox": SandboxType.LOCAL_STATIC, "image": None, "profile": "office_macro"},
    ".xlsm": {"sandbox": SandboxType.LOCAL_STATIC, "image": None, "profile": "office_macro"},
    ".ppt":  {"sandbox": SandboxType.LOCAL_STATIC, "image": None, "profile": "office_macro"},
    ".pptx": {"sandbox": SandboxType.LOCAL_STATIC, "image": None, "profile": "office_macro"},
    ".pptm": {"sandbox": SandboxType.LOCAL_STATIC, "image": None, "profile": "office_macro"},
    ".rtf":  {"sandbox": SandboxType.LOCAL_STATIC, "image": None, "profile": "office_macro"},
    # ---- PDF -> local static (pdf-parser, NO execution) ----
    ".pdf":  {"sandbox": SandboxType.LOCAL_STATIC, "image": None, "profile": "pdf_analysis"},
    # ---- Scripts -> Docker with network:none ----
    ".js":   {"sandbox": SandboxType.DOCKER, "image": "remnux/remnux-distro", "profile": "script_analysis"},
    ".vbs":  {"sandbox": SandboxType.DOCKER, "image": "remnux/flare",         "profile": "script_analysis"},
    ".ps1":  {"sandbox": SandboxType.DOCKER, "image": "remnux/flare",         "profile": "script_analysis"},
    ".bat":  {"sandbox": SandboxType.DOCKER, "image": "remnux/flare",         "profile": "script_analysis"},
    ".cmd":  {"sandbox": SandboxType.DOCKER, "image": "remnux/flare",         "profile": "script_analysis"},
    ".hta":  {"sandbox": SandboxType.DOCKER, "image": "remnux/flare",         "profile": "script_analysis"},
    ".wsf":  {"sandbox": SandboxType.DOCKER, "image": "remnux/flare",         "profile": "script_analysis"},
    ".py":   {"sandbox": SandboxType.DOCKER, "image": "remnux/remnux-distro", "profile": "script_analysis"},
    ".sh":   {"sandbox": SandboxType.DOCKER, "image": "remnux/remnux-distro", "profile": "script_analysis"},
    # ---- Java -> Docker ----
    ".jar":   {"sandbox": SandboxType.DOCKER, "image": "remnux/remnux-distro", "profile": "java_analysis"},
    ".class": {"sandbox": SandboxType.DOCKER, "image": "remnux/remnux-distro", "profile": "java_analysis"},
    # ---- Archives -> Docker ----
    ".zip":  {"sandbox": SandboxType.DOCKER, "image": "remnux/remnux-distro", "profile": "archive_analysis"},
    ".rar":  {"sandbox": SandboxType.DOCKER, "image": "remnux/remnux-distro", "profile": "archive_analysis"},
    ".7z":   {"sandbox": SandboxType.DOCKER, "image": "remnux/remnux-distro", "profile": "archive_analysis"},
    ".iso":  {"sandbox": SandboxType.DOCKER, "image": "remnux/remnux-distro", "profile": "archive_analysis"},
}

# Maximum file size allowed for sandbox submission (100 MB)
_MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024


class SandboxOrchestrator:
    """Routes malware samples to the appropriate isolated sandbox for analysis.

    The orchestrator ensures that no malware is ever executed directly on the
    host system.  File-type detection drives sandbox selection: PE files go to
    FLARE/LitterBox Docker containers, ELF to REMnux, APK to MobSF, and
    Office/PDF documents are handled with local static-only tools (oletools,
    pdf-parser) that never execute embedded code.

    Docker containers are launched with ``--network none``, read-only bind
    mounts, memory/CPU limits, and ``--pids-limit`` to prevent lateral
    movement, resource exhaustion, and data exfiltration.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        mcp_client: Any = None,
        sandbox_adapters: Optional[Dict[str, Any]] = None,
    ):
        self._config = config or {}
        self.mcp_client = mcp_client
        self._cloud_adapters: Dict[str, Any] = sandbox_adapters or {}

        sandbox_cfg = self._config.get("sandbox", {})
        self._docker_timeout = sandbox_cfg.get("docker_timeout_seconds", 300)

        # task_id -> task metadata dict
        self._pending_tasks: Dict[str, Dict[str, Any]] = {}

        # Sandbox availability cache (name -> bool)
        self._available_cache: Dict[str, bool] = {}

    # ================================================================== #
    #  Adapter registration
    # ================================================================== #

    def register_cloud_adapter(self, name: str, adapter: Any) -> None:
        """Register an external sandbox adapter (CAPEv2, HybridAnalysis, etc.)."""
        self._cloud_adapters[name] = adapter
        logger.info("[SANDBOX] Registered cloud adapter: %s", name)

    # ================================================================== #
    #  select_sandbox  (file_path -> routing recommendation)
    # ================================================================== #

    def select_sandbox(self, file_path: str) -> Dict[str, Any]:
        """Determine the appropriate sandbox environment for a given file.

        Args:
            file_path: Absolute path to the file to be analysed.

        Returns:
            Dict with keys ``sandbox_type``, ``image``, ``profile``,
            ``file_ext``, ``file_name``, ``file_hash``, ``file_size``.
            On error returns a dict with an ``error`` key.
        """
        try:
            path = Path(file_path)
            if not path.is_file():
                return {"error": f"File not found: {file_path}"}

            file_size = path.stat().st_size
            if file_size > _MAX_FILE_SIZE_BYTES:
                return {"error": f"File too large ({file_size} bytes). Max: {_MAX_FILE_SIZE_BYTES}"}
            if file_size == 0:
                return {"error": "File is empty (0 bytes)"}

            ext = path.suffix.lower()
            file_hash = self._compute_sha256(file_path)

            route = _ROUTING_TABLE.get(ext)
            if route is not None:
                return {
                    "sandbox_type": route["sandbox"].value,
                    "image": route["image"],
                    "profile": route["profile"],
                    "file_ext": ext,
                    "file_name": path.name,
                    "file_hash": file_hash,
                    "file_size": file_size,
                }

            # Unknown extension -- prefer cloud API if an adapter is registered,
            # otherwise fall back to safe local_static.
            if self._cloud_adapters:
                adapter_name = next(iter(self._cloud_adapters))
                return {
                    "sandbox_type": SandboxType.CLOUD_API.value,
                    "image": None,
                    "profile": "cloud_generic",
                    "cloud_adapter": adapter_name,
                    "file_ext": ext,
                    "file_name": path.name,
                    "file_hash": file_hash,
                    "file_size": file_size,
                }

            return {
                "sandbox_type": SandboxType.LOCAL_STATIC.value,
                "image": None,
                "profile": "generic_static",
                "file_ext": ext,
                "file_name": path.name,
                "file_hash": file_hash,
                "file_size": file_size,
            }

        except Exception as exc:
            logger.error("[SANDBOX] select_sandbox failed: %s", exc, exc_info=True)
            return {"error": str(exc)}

    # ================================================================== #
    #  submit_to_sandbox  (file_path[, sandbox_type] -> task_id)
    # ================================================================== #

    async def submit_to_sandbox(
        self,
        file_path: str,
        sandbox_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Submit a file to the selected (or auto-detected) sandbox.

        Args:
            file_path:    Absolute path to the sample.
            sandbox_type: Override sandbox type string (``docker``, ``vm``,
                          ``cloud_api``, ``local_static``).  When *None*,
                          ``select_sandbox`` chooses automatically.

        Returns:
            Dict with ``task_id`` on success, or ``error`` on failure.
        """
        try:
            selection = self.select_sandbox(file_path)
            if "error" in selection:
                return selection

            if sandbox_type is not None:
                selection["sandbox_type"] = sandbox_type
            else:
                sandbox_type = selection["sandbox_type"]

            task_id = uuid.uuid4().hex[:12]

            if sandbox_type == SandboxType.DOCKER.value:
                result = await self._submit_docker(task_id, file_path, selection)
            elif sandbox_type == SandboxType.VM.value:
                result = await self._submit_vm(task_id, file_path, selection)
            elif sandbox_type == SandboxType.CLOUD_API.value:
                result = await self._submit_cloud(task_id, file_path, selection)
            elif sandbox_type == SandboxType.LOCAL_STATIC.value:
                result = await self._submit_local_static(task_id, file_path, selection)
            else:
                return {"error": f"Unknown sandbox type: {sandbox_type}"}

            # Track submitted tasks for later result retrieval
            if "error" not in result:
                self._pending_tasks[task_id] = {
                    "task_id": task_id,
                    "file_path": file_path,
                    "sandbox_type": sandbox_type,
                    "selection": selection,
                    "status": result.get("status", "submitted"),
                    "result": result,
                }

            return result

        except Exception as exc:
            logger.error("[SANDBOX] submit_to_sandbox failed: %s", exc, exc_info=True)
            return {"error": str(exc)}

    # ================================================================== #
    #  get_sandbox_result  (task_id -> analysis result)
    # ================================================================== #

    async def get_sandbox_result(self, task_id: str) -> Dict[str, Any]:
        """Retrieve the analysis result for a previously submitted task.

        Args:
            task_id: The identifier returned by ``submit_to_sandbox``.

        Returns:
            Dict with analysis results, or ``error`` key.
        """
        try:
            task = self._pending_tasks.get(task_id)
            if task is None:
                return {"error": f"Unknown task_id: {task_id}"}

            sandbox_type = task["sandbox_type"]

            # Cloud tasks may need a remote poll
            if sandbox_type == SandboxType.CLOUD_API.value:
                adapter_name = task["selection"].get("cloud_adapter")
                adapter = self._cloud_adapters.get(adapter_name) if adapter_name else None
                if adapter is not None:
                    cloud_id = (
                        task["result"].get("cloud_task_id")
                        or task["result"].get("submission_id", "")
                    )
                    if cloud_id:
                        result = await adapter.get_report(cloud_id)
                        task["result"] = result
                        task["status"] = result.get("status", "unknown")
                        return result
                return {"error": "Cloud adapter not available for result retrieval"}

            # Docker / VM / local_static results are available immediately
            return task.get("result", {"error": "No result available yet"})

        except Exception as exc:
            logger.error("[SANDBOX] get_sandbox_result failed: %s", exc, exc_info=True)
            return {"error": str(exc)}

    # ================================================================== #
    #  Docker sandbox  (network:none isolation)
    # ================================================================== #

    async def _submit_docker(
        self, task_id: str, file_path: str, selection: Dict,
    ) -> Dict[str, Any]:
        """Run analysis inside a Docker container with strict isolation.

        Container security flags:
          --network none       block all network access
          --read-only          immutable root filesystem
          --tmpfs /tmp         transient scratch space
          --memory 512m        memory ceiling
          --cpus 1.0           CPU ceiling
          --pids-limit 256     fork-bomb protection
          -v sample:ro         sample mounted read-only
        """
        image = selection.get("image", "remnux/remnux-distro")
        profile = selection.get("profile", "generic")
        file_name = Path(file_path).name
        container_name = f"bta-sandbox-{task_id}"
        mount_src = os.path.abspath(file_path)

        cmd = [
            "docker", "run",
            "--rm",
            "--name", container_name,
            "--network", "none",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
            "--memory", "512m",
            "--cpus", "1.0",
            "--pids-limit", "256",
            "-v", f"{mount_src}:/sample/{file_name}:ro",
            image,
        ]
        cmd.extend(self._docker_analysis_cmd(profile, file_name))

        logger.info(
            "[SANDBOX] Docker submit: task=%s image=%s profile=%s file=%s",
            task_id, image, profile, file_name,
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._docker_timeout,
            )
            return {
                "task_id": task_id,
                "sandbox_type": SandboxType.DOCKER.value,
                "image": image,
                "profile": profile,
                "status": "completed" if proc.returncode == 0 else "error",
                "return_code": proc.returncode,
                "stdout": stdout.decode(errors="replace")[:50_000],
                "stderr": stderr.decode(errors="replace")[:10_000],
            }

        except asyncio.TimeoutError:
            await self._kill_docker_container(container_name)
            return {
                "task_id": task_id,
                "sandbox_type": SandboxType.DOCKER.value,
                "status": "timeout",
                "error": f"Docker analysis timed out after {self._docker_timeout}s",
            }
        except FileNotFoundError:
            return {
                "task_id": task_id,
                "sandbox_type": SandboxType.DOCKER.value,
                "status": "error",
                "error": "Docker is not installed or not in PATH",
            }
        except Exception as exc:
            return {
                "task_id": task_id,
                "sandbox_type": SandboxType.DOCKER.value,
                "status": "error",
                "error": str(exc),
            }

    @staticmethod
    def _docker_analysis_cmd(profile: str, file_name: str) -> List[str]:
        """Return the in-container command for the given analysis profile."""
        sample = f"/sample/{file_name}"
        if profile == "windows_pe":
            return ["bash", "-c",
                    f"file {sample} && strings {sample} | head -500 && sha256sum {sample}"]
        if profile == "linux_elf":
            return ["bash", "-c",
                    f"file {sample} && readelf -h {sample} 2>/dev/null; "
                    f"strings {sample} | head -500 && sha256sum {sample}"]
        if profile == "android_apk":
            return ["bash", "-c",
                    f"unzip -l {sample} 2>/dev/null | head -100 && sha256sum {sample}"]
        if profile == "script_analysis":
            return ["bash", "-c",
                    f"file {sample} && cat {sample} | head -1000 && sha256sum {sample}"]
        if profile == "java_analysis":
            return ["bash", "-c",
                    f"file {sample} && jar tf {sample} 2>/dev/null | head -200 "
                    f"&& sha256sum {sample}"]
        if profile == "archive_analysis":
            return ["bash", "-c",
                    f"file {sample} && 7z l {sample} 2>/dev/null | head -200 "
                    f"&& sha256sum {sample}"]
        # generic fallback
        return ["bash", "-c",
                f"file {sample} && strings {sample} | head -200 && sha256sum {sample}"]

    @staticmethod
    async def _kill_docker_container(container_name: str) -> None:
        """Force-kill a running Docker container."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "kill", container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=10)
        except Exception as exc:
            logger.warning("[SANDBOX] Failed to kill container %s: %s", container_name, exc)

    # ================================================================== #
    #  VM sandbox
    # ================================================================== #

    async def _submit_vm(
        self, task_id: str, file_path: str, selection: Dict,
    ) -> Dict[str, Any]:
        """Submit a sample to a VM-based sandbox (e.g. CAPEv2 on local hypervisor).

        The file is copied to a staging directory; the VM-based sandbox picks
        it up asynchronously.
        """
        vm_cfg = self._config.get("sandbox", {}).get("vm", {})
        staging_dir = vm_cfg.get("staging_dir")
        if not staging_dir:
            return {
                "task_id": task_id,
                "sandbox_type": SandboxType.VM.value,
                "status": "error",
                "error": "VM sandbox staging_dir not configured",
            }
        try:
            import shutil
            staging_path = Path(staging_dir)
            staging_path.mkdir(parents=True, exist_ok=True)
            dest = staging_path / f"{task_id}_{Path(file_path).name}"
            shutil.copy2(file_path, str(dest))
            logger.info("[SANDBOX] VM submit: task=%s staged=%s", task_id, dest)
            return {
                "task_id": task_id,
                "sandbox_type": SandboxType.VM.value,
                "status": "submitted",
                "staged_path": str(dest),
            }
        except Exception as exc:
            return {"task_id": task_id, "sandbox_type": SandboxType.VM.value,
                    "status": "error", "error": str(exc)}

    # ================================================================== #
    #  Cloud API sandbox
    # ================================================================== #

    async def _submit_cloud(
        self, task_id: str, file_path: str, selection: Dict,
    ) -> Dict[str, Any]:
        """Submit a sample to a cloud sandbox adapter."""
        adapter_name = selection.get("cloud_adapter")
        if not adapter_name and self._cloud_adapters:
            adapter_name = next(iter(self._cloud_adapters))
        adapter = self._cloud_adapters.get(adapter_name) if adapter_name else None
        if adapter is None:
            return {"task_id": task_id, "sandbox_type": SandboxType.CLOUD_API.value,
                    "status": "error", "error": "No cloud sandbox adapters registered"}
        try:
            submit_result = await adapter.submit_file(file_path)
            if "error" in submit_result:
                return {**submit_result, "task_id": task_id,
                        "sandbox_type": SandboxType.CLOUD_API.value, "status": "error"}
            submission_id = submit_result.get("submission_id", "")
            logger.info("[SANDBOX] Cloud submit: task=%s adapter=%s submission=%s",
                        task_id, adapter_name, submission_id)
            return {
                "task_id": task_id,
                "submission_id": submission_id,
                "sandbox_type": SandboxType.CLOUD_API.value,
                "adapter": adapter_name,
                "status": "submitted",
            }
        except Exception as exc:
            return {"task_id": task_id, "sandbox_type": SandboxType.CLOUD_API.value,
                    "status": "error",
                    "error": f"Cloud submission failed ({adapter_name}): {exc}"}

    # ================================================================== #
    #  Local static analysis (no execution)
    # ================================================================== #

    async def _submit_local_static(
        self, task_id: str, file_path: str, selection: Dict,
    ) -> Dict[str, Any]:
        """Perform local static analysis without ever executing the sample."""
        profile = selection.get("profile", "generic_static")
        file_name = Path(file_path).name

        logger.info("[SANDBOX] Local static: task=%s profile=%s file=%s",
                    task_id, profile, file_name)

        results: Dict[str, Any] = {
            "task_id": task_id,
            "sandbox_type": SandboxType.LOCAL_STATIC.value,
            "profile": profile,
            "file_name": file_name,
            "file_hash": selection.get("file_hash", ""),
            "status": "completed",
            "indicators": [],
        }
        try:
            if profile == "office_macro":
                results["indicators"] = await self._static_office(file_path)
            elif profile == "pdf_analysis":
                results["indicators"] = await self._static_pdf(file_path)
            else:
                results["indicators"] = await self._static_generic(file_path)
        except Exception as exc:
            results["status"] = "error"
            results["error"] = str(exc)
            logger.error("[SANDBOX] Local static failed: %s", exc, exc_info=True)

        return results

    # ---- Office static ------------------------------------------------ #

    @staticmethod
    async def _static_office(file_path: str) -> List[Dict[str, Any]]:
        """Extract macro indicators from Office documents using oletools."""
        indicators: List[Dict[str, Any]] = []
        try:
            from oletools.olevba import VBA_Parser  # type: ignore[import-untyped]
            vba_parser = VBA_Parser(file_path)
            if vba_parser.detect_vba_macros():
                for vba_type, keyword, value, _ in vba_parser.analyze_macros():
                    indicators.append({"type": vba_type, "keyword": keyword,
                                       "value": str(value)[:500]})
            vba_parser.close()
        except ImportError:
            indicators.append({"type": "warning", "keyword": "oletools_missing",
                               "value": "pip install oletools"})
        except Exception as exc:
            indicators.append({"type": "error", "keyword": "analysis_error",
                               "value": str(exc)})
        return indicators

    # ---- PDF static --------------------------------------------------- #

    @staticmethod
    async def _static_pdf(file_path: str) -> List[Dict[str, Any]]:
        """Scan PDF for suspicious keywords without rendering."""
        indicators: List[Dict[str, Any]] = []
        suspicious = [
            b"/JavaScript", b"/JS", b"/AA", b"/OpenAction", b"/Launch",
            b"/EmbeddedFile", b"/RichMedia", b"/XFA", b"/AcroForm",
            b"/URI", b"/SubmitForm", b"/GoToR",
        ]
        try:
            with open(file_path, "rb") as fh:
                content = fh.read()
            for kw in suspicious:
                count = content.count(kw)
                if count > 0:
                    indicators.append({"type": "suspicious_keyword",
                                       "keyword": kw.decode(errors="replace"),
                                       "count": count})
            indicators.append({"type": "metadata", "keyword": "stream_count",
                               "count": content.count(b"stream")})
        except Exception as exc:
            indicators.append({"type": "error", "value": str(exc)})
        return indicators

    # ---- Generic static ----------------------------------------------- #

    @staticmethod
    async def _static_generic(file_path: str) -> List[Dict[str, Any]]:
        """Basic static analysis: magic bytes, size, entropy estimate."""
        indicators: List[Dict[str, Any]] = []
        try:
            path = Path(file_path)
            with open(file_path, "rb") as fh:
                header = fh.read(8192)

            magic_map = {
                b"MZ": "PE executable", b"\x7fELF": "ELF binary",
                b"PK": "ZIP/JAR/APK/Office archive", b"%PDF": "PDF document",
                b"\xd0\xcf\x11\xe0": "OLE Compound (old Office)",
            }
            detected = "unknown"
            for sig, desc in magic_map.items():
                if header.startswith(sig):
                    detected = desc
                    break
            indicators.append({"type": "file_type", "value": detected})
            indicators.append({"type": "file_size", "value": path.stat().st_size})

            if len(header) > 0:
                from collections import Counter
                import math
                freq = Counter(header)
                entropy = -sum(
                    (c / len(header)) * math.log2(c / len(header))
                    for c in freq.values() if c > 0
                )
                indicators.append({"type": "entropy", "value": round(entropy, 3)})
                if entropy > 7.5:
                    indicators.append({"type": "warning",
                                       "value": "High entropy -- possibly packed/encrypted"})
        except Exception as exc:
            indicators.append({"type": "error", "value": str(exc)})
        return indicators

    # ================================================================== #
    #  Utility helpers
    # ================================================================== #

    @staticmethod
    def _compute_sha256(file_path: str) -> str:
        """Compute SHA-256 hash of a file."""
        sha = hashlib.sha256()
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                sha.update(chunk)
        return sha.hexdigest()

    def invalidate_cache(self) -> None:
        """Clear the sandbox availability cache."""
        self._available_cache.clear()

    def get_sandbox_status(self) -> List[Dict]:
        """Return availability status of all known sandbox environments."""
        status_list: List[Dict] = []
        seen: set = set()

        if self.mcp_client is not None:
            for name, info in self.mcp_client.get_connection_status().items():
                seen.add(name)
                status_list.append({
                    "name": name, "type": "mcp",
                    "available": info.get("connected", False),
                    "tool_count": info.get("tool_count", 0),
                })

        for name, adapter in self._cloud_adapters.items():
            if name not in seen:
                seen.add(name)
                status_list.append({
                    "name": name, "type": "adapter",
                    "available": True,
                    "source": f"REST adapter ({getattr(adapter, 'name', name)})",
                })

        return status_list
