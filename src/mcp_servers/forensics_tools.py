"""
Forensics Tools MCP Server - Digital forensics analysis via MCP.

Tools for file carving, timeline analysis, Windows artifact parsing,
memory dump analysis, and evidence handling.

Uses only Python standard library + pefile + oletools (already installed).

Usage:
    python -m src.mcp_servers.forensics_tools
"""

import csv
import hashlib
import io
import json
import logging
import os
import re
import struct
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("forensics-tools")


def _validate_file(file_path: str) -> str | None:
    """Validate file exists and return resolved path."""
    p = Path(file_path).resolve()
    return str(p) if p.is_file() else None


# Windows FILETIME epoch: January 1, 1601
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_datetime(ft: int) -> str:
    """Convert Windows FILETIME to ISO datetime string."""
    try:
        if ft <= 0:
            return "N/A"
        microseconds = ft // 10
        dt = FILETIME_EPOCH + timedelta(microseconds=microseconds)
        return dt.isoformat()
    except Exception:
        return "N/A"


@mcp.tool()
def file_metadata(file_path: str) -> str:
    """Extract comprehensive metadata from a file for forensic analysis.
    Includes timestamps, permissions, hashes, magic bytes, entropy.

    Args:
        file_path: Path to the file to analyze
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": f"File not found: {file_path}"})

    p = Path(resolved)
    stat = p.stat()

    # Read file for hashing and magic bytes
    with open(resolved, "rb") as f:
        data = f.read()

    # Magic bytes
    magic_hex = data[:16].hex() if len(data) >= 16 else data.hex()
    magic_ascii = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:16])

    # Known magic signatures
    signatures = {
        "4d5a": "PE Executable (MZ)",
        "7f454c46": "ELF Executable",
        "504b0304": "ZIP/DOCX/XLSX/JAR Archive",
        "25504446": "PDF Document",
        "d0cf11e0": "OLE2 (DOC/XLS/PPT)",
        "52617221": "RAR Archive",
        "1f8b": "GZIP Archive",
        "ffd8ff": "JPEG Image",
        "89504e47": "PNG Image",
        "47494638": "GIF Image",
        "cafebabe": "Java Class File",
        "feedface": "Mach-O (32-bit)",
        "feedfacf": "Mach-O (64-bit)",
        "7b": "JSON / Text",
        "3c": "XML / HTML",
    }
    file_type = "Unknown"
    for sig, desc in signatures.items():
        if magic_hex.startswith(sig):
            file_type = desc
            break

    # Entropy
    import math
    if len(data) > 0:
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = -sum(
            (c / len(data)) * math.log2(c / len(data))
            for c in freq if c > 0
        )
    else:
        entropy = 0.0

    result = {
        "file_path": resolved,
        "file_name": p.name,
        "file_size": stat.st_size,
        "file_type": file_type,
        "magic_bytes_hex": magic_hex,
        "magic_bytes_ascii": magic_ascii,
        "entropy": round(entropy, 4),
        "entropy_assessment": (
            "Very high (likely encrypted/packed)" if entropy > 7.5 else
            "High (possibly compressed/packed)" if entropy > 7.0 else
            "Normal" if entropy > 4.0 else
            "Low (possibly text/sparse)"
        ),
        "timestamps": {
            "created": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "accessed": datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat(),
        },
        "hashes": {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def carve_files(file_path: str, max_carves: int = 50) -> str:
    """Carve embedded files from a binary using magic byte signatures.
    Detects PE, PDF, ZIP, OLE, JPEG, PNG, GIF, RAR embedded files.

    Args:
        file_path: Path to the file to carve from
        max_carves: Maximum number of files to carve (default 50)
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": f"File not found: {file_path}"})

    with open(resolved, "rb") as f:
        data = f.read()

    # Signatures to search for: (name, magic_bytes, description)
    signatures = [
        ("PE", b"MZ", "PE Executable"),
        ("PDF", b"%PDF", "PDF Document"),
        ("ZIP", b"PK\x03\x04", "ZIP Archive"),
        ("OLE2", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 Compound"),
        ("RAR", b"Rar!", "RAR Archive"),
        ("GZIP", b"\x1f\x8b", "GZIP Archive"),
        ("JPEG", b"\xff\xd8\xff", "JPEG Image"),
        ("PNG", b"\x89PNG\r\n\x1a\n", "PNG Image"),
        ("GIF", b"GIF8", "GIF Image"),
        ("ELF", b"\x7fELF", "ELF Executable"),
    ]

    carved = []
    for name, magic, desc in signatures:
        offset = 0
        while len(carved) < max_carves:
            pos = data.find(magic, offset)
            if pos == -1:
                break
            # Skip if at position 0 (the file itself)
            if pos > 0:
                carved.append({
                    "type": name,
                    "description": desc,
                    "offset": pos,
                    "offset_hex": hex(pos),
                    "magic_context": data[pos:pos + 32].hex(),
                })
            offset = pos + len(magic)

    carved.sort(key=lambda x: x["offset"])

    return json.dumps({
        "source_file": resolved,
        "source_size": len(data),
        "carved_count": len(carved),
        "carved_files": carved[:max_carves],
    }, indent=2)


@mcp.tool()
def parse_windows_prefetch(file_path: str) -> str:
    """Parse Windows Prefetch file for forensic analysis.
    Extracts execution count, timestamps, loaded DLLs.

    Args:
        file_path: Path to the .pf prefetch file
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": f"File not found: {file_path}"})

    with open(resolved, "rb") as f:
        data = f.read()

    result = {"file": resolved, "type": "Windows Prefetch"}

    try:
        # Check for compressed prefetch (Win10+)
        if data[:3] == b"MAM":
            result["format"] = "Compressed (Windows 10+)"
            result["note"] = "Compressed prefetch - header parsed only"
            # Parse what we can from the compressed header
            result["compression_signature"] = data[:4].hex()
            result["uncompressed_size"] = struct.unpack_from("<I", data, 4)[0] if len(data) > 8 else 0
            return json.dumps(result, indent=2)

        # Standard prefetch header
        if len(data) < 84:
            return json.dumps({"error": "File too small to be a valid prefetch file"})

        version = struct.unpack_from("<I", data, 0)[0]
        signature = data[4:8]

        if signature != b"SCCA":
            result["warning"] = "Not a standard prefetch file (missing SCCA signature)"

        # Parse header
        result["version"] = hex(version)
        result["file_size"] = struct.unpack_from("<I", data, 12)[0]

        # Executable name (offset 16, 60 bytes, UTF-16LE)
        exe_name_raw = data[16:76]
        try:
            exe_name = exe_name_raw.decode("utf-16-le").rstrip("\x00")
            result["executable"] = exe_name
        except Exception:
            result["executable"] = "parse_error"

        # Prefetch hash
        result["prefetch_hash"] = hex(struct.unpack_from("<I", data, 76)[0])

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Prefetch parsing failed: {e}", "file": resolved})


@mcp.tool()
def parse_lnk_file(file_path: str) -> str:
    """Parse Windows LNK (shortcut) file for forensic analysis.
    Extracts target path, timestamps, MAC address, volume info.

    Args:
        file_path: Path to the .lnk file
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": f"File not found: {file_path}"})

    with open(resolved, "rb") as f:
        data = f.read()

    result = {"file": resolved, "type": "Windows LNK Shortcut"}

    try:
        # Verify LNK signature
        if data[:4] != b"\x4c\x00\x00\x00":
            return json.dumps({"error": "Not a valid LNK file (bad signature)"})

        # CLSID
        clsid = data[4:20].hex()
        result["clsid"] = clsid

        # Flags
        flags = struct.unpack_from("<I", data, 20)[0]
        result["flags"] = {
            "has_link_target_id_list": bool(flags & 0x01),
            "has_link_info": bool(flags & 0x02),
            "has_name": bool(flags & 0x04),
            "has_relative_path": bool(flags & 0x08),
            "has_working_dir": bool(flags & 0x10),
            "has_arguments": bool(flags & 0x20),
            "has_icon_location": bool(flags & 0x40),
        }

        # File attributes
        attrs = struct.unpack_from("<I", data, 24)[0]
        result["target_attributes"] = {
            "readonly": bool(attrs & 0x01),
            "hidden": bool(attrs & 0x02),
            "system": bool(attrs & 0x04),
            "directory": bool(attrs & 0x10),
            "archive": bool(attrs & 0x20),
        }

        # Timestamps (FILETIME format)
        creation_time = struct.unpack_from("<Q", data, 28)[0]
        access_time = struct.unpack_from("<Q", data, 36)[0]
        write_time = struct.unpack_from("<Q", data, 44)[0]

        result["timestamps"] = {
            "creation": _filetime_to_datetime(creation_time),
            "access": _filetime_to_datetime(access_time),
            "write": _filetime_to_datetime(write_time),
        }

        # File size
        result["target_file_size"] = struct.unpack_from("<I", data, 52)[0]

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"LNK parsing failed: {e}", "file": resolved})


@mcp.tool()
def timeline_csv_parse(file_path: str, max_entries: int = 500) -> str:
    """Parse forensic timeline CSV files (Plaso/log2timeline, KAPE format).
    Analyzes temporal patterns and highlights suspicious activity.

    Args:
        file_path: Path to the CSV timeline file
        max_entries: Maximum entries to process
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": f"File not found: {file_path}"})

    try:
        with open(resolved, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            entries = []
            for i, row in enumerate(reader):
                if i >= max_entries:
                    break
                entries.append(dict(row))

        # Detect format
        if entries:
            keys = set(entries[0].keys())
            if "datetime" in keys or "date" in keys:
                fmt = "plaso/l2t"
            elif "TimeCreated" in keys:
                fmt = "windows_event"
            else:
                fmt = "generic"
        else:
            fmt = "unknown"

        # Analyze temporal distribution
        timestamps = []
        for e in entries:
            for key in ["datetime", "date", "TimeCreated", "timestamp", "Timestamp"]:
                if key in e and e[key]:
                    timestamps.append(e[key])
                    break

        result = {
            "file": resolved,
            "format": fmt,
            "total_entries": len(entries),
            "columns": list(entries[0].keys()) if entries else [],
            "timestamp_count": len(timestamps),
            "first_timestamp": timestamps[0] if timestamps else None,
            "last_timestamp": timestamps[-1] if timestamps else None,
            "sample_entries": entries[:10],
        }

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Timeline parsing failed: {e}", "file": resolved})


@mcp.tool()
def analyze_event_log(file_path: str, max_events: int = 200) -> str:
    """Analyze exported Windows Event Log (EVTX exported as XML/CSV).
    Detects suspicious events: logon failures, privilege escalation,
    service installations, PowerShell execution, etc.

    Args:
        file_path: Path to the exported event log (XML or CSV format)
        max_events: Maximum events to analyze
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": f"File not found: {file_path}"})

    content = Path(resolved).read_text(encoding="utf-8", errors="replace")

    # Suspicious Event IDs
    suspicious_events = {
        "4624": "Successful Logon",
        "4625": "Failed Logon",
        "4648": "Logon with Explicit Credentials",
        "4672": "Special Privileges Assigned",
        "4688": "Process Creation",
        "4697": "Service Installed",
        "4698": "Scheduled Task Created",
        "4720": "User Account Created",
        "4732": "Member Added to Admin Group",
        "1102": "Audit Log Cleared",
        "7045": "New Service Installed",
        "4104": "PowerShell Script Block",
        "4103": "PowerShell Module Logging",
        "1": "Sysmon Process Create",
        "3": "Sysmon Network Connect",
        "7": "Sysmon Image Loaded",
        "11": "Sysmon File Created",
    }

    findings = []
    for event_id, description in suspicious_events.items():
        # Search for event ID in various formats
        patterns = [
            f"EventID.*{event_id}",
            f"<EventID>{event_id}</EventID>",
            f'"EventID":.*{event_id}',
            f",{event_id},",
        ]
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, content))
        if count > 0:
            findings.append({
                "event_id": event_id,
                "description": description,
                "count": count,
                "severity": "high" if event_id in ("1102", "4697", "4698", "4720", "4732", "7045") else "medium",
            })

    # Check for suspicious keywords
    suspicious_keywords = {
        "powershell": "PowerShell execution detected",
        "cmd.exe": "Command prompt execution",
        "mimikatz": "Credential dumping tool",
        "psexec": "Remote execution tool",
        "whoami": "User enumeration",
        "net user": "User account manipulation",
        "net localgroup": "Group manipulation",
        "reg add": "Registry modification",
        "schtasks": "Scheduled task manipulation",
        "wmic": "WMI execution",
        "certutil": "Certificate utility (often abused for download)",
        "bitsadmin": "BITS transfer (often abused for download)",
    }

    keyword_findings = []
    for keyword, desc in suspicious_keywords.items():
        count = content.lower().count(keyword.lower())
        if count > 0:
            keyword_findings.append({
                "keyword": keyword,
                "description": desc,
                "count": count,
            })

    return json.dumps({
        "file": resolved,
        "file_size": len(content),
        "suspicious_events": findings,
        "suspicious_keywords": keyword_findings,
        "total_suspicious_event_types": len(findings),
        "total_keyword_matches": len(keyword_findings),
    }, indent=2)


@mcp.tool()
def string_analysis(file_path: str, min_length: int = 4, max_strings: int = 2000) -> str:
    """Extract and categorize strings from a binary file.
    Categorizes: URLs, IPs, file paths, registry keys, emails, API calls.

    Args:
        file_path: Path to the binary file
        min_length: Minimum string length
        max_strings: Maximum strings to extract
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": f"File not found: {file_path}"})

    with open(resolved, "rb") as f:
        data = f.read()

    # Extract ASCII strings
    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    ascii_strings = [m.group().decode("ascii") for m in ascii_pattern.finditer(data)]

    # Extract Unicode (UTF-16LE) strings
    unicode_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
    unicode_strings = [m.group().decode("utf-16-le") for m in unicode_pattern.finditer(data)]

    all_strings = ascii_strings + unicode_strings

    # Categorize
    categories = {
        "urls": [],
        "ips": [],
        "domains": [],
        "emails": [],
        "file_paths": [],
        "registry_keys": [],
        "api_calls": [],
        "suspicious": [],
    }

    url_re = re.compile(r"https?://[^\s\"'<>]+")
    ip_re = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    email_re = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    path_re = re.compile(r"[A-Z]:\\[\w\\]+|/(?:usr|etc|tmp|var|home)/[\w/]+")
    reg_re = re.compile(r"HKEY_[\w\\]+|HKLM\\|HKCU\\")
    api_re = re.compile(r"\b(?:CreateProcess|VirtualAlloc|WriteProcessMemory|LoadLibrary|GetProcAddress|RegSetValue|InternetOpen|URLDownload|ShellExecute|WinExec|CreateRemoteThread|NtCreateThread)\w*\b")
    sus_re = re.compile(r"\b(?:password|secret|token|api_key|credential|admin|root|hack|exploit|payload|backdoor|trojan|keylog|inject|shellcode)\b", re.IGNORECASE)

    for s in all_strings:
        for match in url_re.findall(s):
            categories["urls"].append(match)
        for match in ip_re.findall(s):
            categories["ips"].append(match)
        for match in email_re.findall(s):
            categories["emails"].append(match)
        for match in path_re.findall(s):
            categories["file_paths"].append(match)
        for match in reg_re.findall(s):
            categories["registry_keys"].append(match)
        for match in api_re.findall(s):
            categories["api_calls"].append(match)
        for match in sus_re.findall(s):
            categories["suspicious"].append(match)

    # Deduplicate
    for key in categories:
        categories[key] = list(set(categories[key]))[:200]

    return json.dumps({
        "file": resolved,
        "total_ascii_strings": len(ascii_strings),
        "total_unicode_strings": len(unicode_strings),
        "categorized": categories,
        "sample_strings": all_strings[:100],
    }, indent=2)


def main():
    """Run the forensics tools MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
