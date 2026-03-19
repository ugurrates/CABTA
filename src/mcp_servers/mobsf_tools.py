"""
MobSF (Mobile Security Framework) MCP Server - Mobile app analysis via MCP.

Connects to a running MobSF instance (Docker or local).
If MobSF is not running, provides helpful setup instructions.

Also includes standalone APK/IPA static analysis using Python:
  - APK manifest parsing (AndroidManifest.xml)
  - Permission analysis
  - Certificate extraction
  - DEX file analysis

Usage:
    python -m src.mcp_servers.mobsf_tools
"""

import hashlib
import json
import logging
import os
import struct
import urllib.request
import zipfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("mobsf")

MOBSF_URL = os.environ.get("MOBSF_URL", "http://localhost:8000")
MOBSF_API_KEY = os.environ.get("MOBSF_API_KEY", "")
TIMEOUT = 30


def _mobsf_api(endpoint: str, method: str = "GET", data: bytes = None, files: dict = None) -> dict:
    """Call MobSF REST API."""
    url = f"{MOBSF_URL}/api/v1/{endpoint}"
    headers = {"Authorization": MOBSF_API_KEY}

    if files:
        import io
        boundary = "----BlueTeamBoundary"
        body = b""
        for key, (filename, filedata) in files.items():
            body += f"--{boundary}\r\n".encode()
            body += f'Content-Disposition: form-data; name="{key}"; filename="{filename}"\r\n'.encode()
            body += b"Content-Type: application/octet-stream\r\n\r\n"
            body += filedata
            body += b"\r\n"
        body += f"--{boundary}--\r\n".encode()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        data = body
    elif data and isinstance(data, dict):
        data = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}


def _validate_file(file_path: str) -> str | None:
    p = Path(file_path).resolve()
    return str(p) if p.is_file() else None


@mcp.tool()
def mobsf_upload_and_scan(file_path: str) -> str:
    """Upload a mobile app (APK/IPA/APPX) to MobSF for analysis.
    Requires MobSF running (Docker: docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf).

    Args:
        file_path: Path to the APK, IPA, or APPX file
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": f"File not found: {file_path}"})

    # Check if MobSF is running
    try:
        req = urllib.request.Request(f"{MOBSF_URL}/api/v1/scans", headers={"Authorization": MOBSF_API_KEY})
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        return json.dumps({
            "error": "MobSF is not running",
            "setup": {
                "docker": "docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf",
                "env_vars": {
                    "MOBSF_URL": "http://localhost:8000",
                    "MOBSF_API_KEY": "Get from MobSF web UI at /api_docs",
                },
            },
        })

    with open(resolved, "rb") as f:
        file_data = f.read()

    filename = Path(resolved).name
    result = _mobsf_api("upload", method="POST", files={"file": (filename, file_data)})

    if "error" in result:
        return json.dumps(result)

    # Trigger scan
    scan_hash = result.get("hash", "")
    if scan_hash:
        import urllib.parse
        scan_data = urllib.parse.urlencode({"hash": scan_hash}).encode()
        scan_result = _mobsf_api("scan", method="POST", data=scan_data)
        return json.dumps({
            "status": "scan_started",
            "hash": scan_hash,
            "file_name": result.get("file_name"),
            "scan_type": result.get("scan_type"),
        }, indent=2)

    return json.dumps(result, indent=2)


@mcp.tool()
def apk_static_analysis(file_path: str) -> str:
    """Perform static analysis on an Android APK file without MobSF.
    Extracts permissions, activities, services, receivers, manifest data.

    Args:
        file_path: Path to the APK file
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": f"File not found: {file_path}"})

    if not resolved.lower().endswith(".apk"):
        return json.dumps({"error": "File must be an APK"})

    result = {"file": resolved, "type": "APK"}

    try:
        with zipfile.ZipFile(resolved, "r") as zf:
            # List all files
            file_list = zf.namelist()
            result["total_files"] = len(file_list)

            # Categorize files
            dex_files = [f for f in file_list if f.endswith(".dex")]
            so_files = [f for f in file_list if f.endswith(".so")]
            cert_files = [f for f in file_list if f.startswith("META-INF/") and (f.endswith(".RSA") or f.endswith(".DSA") or f.endswith(".EC"))]

            result["dex_files"] = dex_files
            result["native_libs"] = so_files
            result["certificate_files"] = cert_files

            # Analyze DEX files
            dex_info = []
            for dex_name in dex_files:
                dex_data = zf.read(dex_name)
                if dex_data[:4] == b"dex\n":
                    # Parse DEX header
                    dex_size = struct.unpack_from("<I", dex_data, 32)[0]
                    string_count = struct.unpack_from("<I", dex_data, 56)[0]
                    type_count = struct.unpack_from("<I", dex_data, 64)[0]
                    method_count = struct.unpack_from("<I", dex_data, 88)[0]
                    class_count = struct.unpack_from("<I", dex_data, 96)[0]
                    dex_info.append({
                        "name": dex_name,
                        "size": len(dex_data),
                        "strings": string_count,
                        "types": type_count,
                        "methods": method_count,
                        "classes": class_count,
                    })
            result["dex_analysis"] = dex_info

            # Try to parse binary AndroidManifest.xml
            if "AndroidManifest.xml" in file_list:
                manifest_data = zf.read("AndroidManifest.xml")
                result["manifest_size"] = len(manifest_data)
                # Binary XML - extract readable strings
                strings = []
                import re
                for match in re.finditer(rb"[\x20-\x7e]{4,}", manifest_data):
                    s = match.group().decode("ascii", errors="replace")
                    strings.append(s)
                # Extract permissions from strings
                permissions = [s for s in strings if "permission" in s.lower() or s.startswith("android.")]
                result["detected_permissions"] = list(set(permissions))[:100]

                # Detect suspicious indicators
                suspicious = []
                dangerous_perms = [
                    "SEND_SMS", "READ_SMS", "RECEIVE_SMS",
                    "READ_CONTACTS", "WRITE_CONTACTS",
                    "READ_CALL_LOG", "WRITE_CALL_LOG",
                    "CAMERA", "RECORD_AUDIO",
                    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
                    "READ_PHONE_STATE", "CALL_PHONE",
                    "INSTALL_PACKAGES", "DELETE_PACKAGES",
                    "SYSTEM_ALERT_WINDOW", "WRITE_SETTINGS",
                    "REQUEST_INSTALL_PACKAGES",
                    "BIND_ACCESSIBILITY_SERVICE",
                    "BIND_DEVICE_ADMIN",
                ]
                for perm in dangerous_perms:
                    if any(perm in p for p in permissions):
                        suspicious.append(f"Dangerous permission: {perm}")

                result["suspicious_indicators"] = suspicious

            # Hash the APK
            with open(resolved, "rb") as apk_f:
                apk_data = apk_f.read()
                result["hashes"] = {
                    "md5": hashlib.md5(apk_data).hexdigest(),
                    "sha256": hashlib.sha256(apk_data).hexdigest(),
                }

    except zipfile.BadZipFile:
        result["error"] = "Invalid ZIP/APK file"
    except Exception as e:
        result["error"] = str(e)

    return json.dumps(result, indent=2)


@mcp.tool()
def mobsf_get_report(scan_hash: str) -> str:
    """Get analysis report from MobSF for a previously scanned app.

    Args:
        scan_hash: The hash returned from upload/scan
    """
    import urllib.parse
    data = urllib.parse.urlencode({"hash": scan_hash}).encode()
    result = _mobsf_api("report_json", method="POST", data=data)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
def mobsf_status() -> str:
    """Check if MobSF is running and accessible.
    Returns server status and API information.
    """
    try:
        req = urllib.request.Request(
            f"{MOBSF_URL}/api/v1/scans",
            headers={"Authorization": MOBSF_API_KEY}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return json.dumps({
                "status": "online",
                "url": MOBSF_URL,
                "recent_scans": data.get("content", [])[:5] if isinstance(data, dict) else [],
            }, indent=2)
    except Exception as e:
        return json.dumps({
            "status": "offline",
            "url": MOBSF_URL,
            "error": str(e),
            "setup_instructions": {
                "docker_command": "docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf",
                "then_set": "MOBSF_API_KEY environment variable from MobSF web UI",
            },
        }, indent=2)


def main():
    """Run the MobSF MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
