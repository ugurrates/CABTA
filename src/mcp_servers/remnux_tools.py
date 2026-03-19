"""
REMnux Tools MCP Server - Python-based malware analysis tools via MCP.

Tools provided:
  - olevba_analyze: Extract and analyze VBA macros from Office documents
  - rtfobj_analyze: Analyze RTF files for embedded objects and exploits
  - pe_analyze: Static analysis of PE files (imports, sections, indicators)
  - yara_scan: Scan files with YARA rules for malware pattern matching
  - hash_file: Calculate multiple hashes (MD5, SHA1, SHA256, ssdeep-like)
  - file_entropy: Calculate Shannon entropy of file and PE sections
  - oleobj_extract: Extract embedded objects from OLE files

Usage:
    python -m src.mcp_servers.remnux_tools
"""

import json
import hashlib
import math
import os
import re
import struct
import logging
from pathlib import Path

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("remnux-tools")

MAX_OUTPUT_SIZE = 50000


def _validate_file(file_path: str) -> str | None:
    """Validate that a file exists and return its resolved path."""
    p = Path(file_path).resolve()
    if not p.is_file():
        return None
    return str(p)


def _safe_json(obj: dict, indent: int = 2) -> str:
    """Serialize to JSON, handling bytes and other non-serializable types."""
    def default_handler(o):
        if isinstance(o, bytes):
            try:
                return o.decode("utf-8", errors="replace")
            except Exception:
                return o.hex()
        if isinstance(o, set):
            return list(o)
        return str(o)
    return json.dumps(obj, indent=indent, default=default_handler)


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    length = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _simple_ssdeep(data: bytes) -> str:
    """Compute a simplified fuzzy hash inspired by ssdeep.

    This is NOT a real ssdeep hash; it provides a rough rolling-hash
    fingerprint useful for approximate comparison when ssdeep is unavailable.
    """
    if not data:
        return "3::"
    block_size = 3
    length = len(data)
    while block_size * 64 < length and block_size < 100000000:
        block_size *= 2

    base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    def _rolling_hash(chunk: bytes) -> int:
        h = 0
        for b in chunk:
            h = ((h * 31) + b) & 0xFFFFFFFF
        return h

    sig1 = []
    sig2 = []
    for i in range(0, length, block_size):
        chunk = data[i:i + block_size]
        h = _rolling_hash(chunk)
        sig1.append(base64_chars[h % 64])
    half_block = max(block_size // 2, 1)
    for i in range(0, length, half_block):
        chunk = data[i:i + half_block]
        h = _rolling_hash(chunk)
        sig2.append(base64_chars[h % 64])

    s1 = "".join(sig1)[:64]
    s2 = "".join(sig2)[:64]
    return "{}:{}:{}".format(block_size, s1, s2)


# ---------------------------------------------------------------------------
# Default YARA rules for common malware patterns
# ---------------------------------------------------------------------------
_YARA_RULE_SUSPICIOUS_STRINGS = r"""
rule suspicious_strings
{
    meta:
        description = "Detects common suspicious strings in malware"
    strings:
        $url1 = "http://" nocase
        $url2 = "https://" nocase
        $ip = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
        $reg1 = "CurrentVersion\\Run" nocase
        $reg2 = "CurrentVersion\\RunOnce" nocase
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell" nocase
        $cmd3 = "wscript" nocase
        $cmd4 = "cscript" nocase
        $b64 = "base64" nocase
        $shell = "WScript.Shell" nocase
        $download = "URLDownloadToFile" nocase
        $exec1 = "ShellExecute" nocase
        $exec2 = "CreateProcess" nocase
        $exec3 = "WinExec" nocase
    condition:
        3 of them
}
"""

_YARA_RULE_EMBEDDED_EXE = r"""
rule embedded_executable
{
    meta:
        description = "Detects embedded PE executable"
    strings:
        $mz = { 4D 5A }
        $pe = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 or ($mz and $pe)
}
"""

_YARA_RULE_OLE_MACROS = r"""
rule suspicious_ole_macros
{
    meta:
        description = "Detects suspicious OLE macro indicators"
    strings:
        $vba1 = "AutoOpen" nocase
        $vba2 = "Auto_Open" nocase
        $vba3 = "AutoExec" nocase
        $vba4 = "Document_Open" nocase
        $vba5 = "Workbook_Open" nocase
        $shell = "Shell" nocase
        $create = "CreateObject" nocase
        $environ = "Environ" nocase
    condition:
        any of ($vba*) and (any of ($shell, $create, $environ))
}
"""

_YARA_RULE_PACKED = r"""
rule packed_binary
{
    meta:
        description = "Indicators of packed or encrypted binary"
    strings:
        $upx = "UPX!" ascii
        $aspack = "aPLib" ascii
        $petite = ".petite" ascii
        $mpress = ".MPRESS" ascii
        $themida = ".themida" ascii
    condition:
        any of them
}
"""

DEFAULT_YARA_RULES = (
    _YARA_RULE_SUSPICIOUS_STRINGS
    + _YARA_RULE_EMBEDDED_EXE
    + _YARA_RULE_OLE_MACROS
    + _YARA_RULE_PACKED
)


@mcp.tool()
def olevba_analyze(file_path: str) -> str:
    """Analyze Office documents for VBA macros using oletools.

    Extracts macro source code, detects suspicious keywords (AutoOpen,
    Shell, CreateObject, etc.), and identifies potential IOCs (URLs, IPs,
    executable names) embedded in macro code.

    Args:
        file_path: Path to the Office document (.doc, .docm, .xls, .xlsm, etc.)
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": "File not found: {}".format(file_path)})

    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        return json.dumps({"error": "oletools is not installed. Install with: pip install oletools"})

    result = {
        "file": resolved,
        "has_macros": False,
        "macro_count": 0,
        "macros": [],
        "suspicious_keywords": [],
        "iocs": {
            "urls": [],
            "ips": [],
            "executables": [],
            "registry_keys": [],
        },
        "auto_exec_triggers": [],
    }

    try:
        vba_parser = VBA_Parser(resolved)
        result["has_macros"] = vba_parser.detect_vba_macros()

        if result["has_macros"]:
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                macro_entry = {
                    "filename": str(filename),
                    "stream_path": str(stream_path),
                    "vba_filename": str(vba_filename),
                    "code": str(vba_code)[:5000],
                    "code_length": len(str(vba_code)),
                }
                result["macros"].append(macro_entry)
                result["macro_count"] += 1

                code_str = str(vba_code)

                # Extract URLs
                urls = re.findall(r'https?://[^\s\"\'\)]+', code_str, re.IGNORECASE)
                result["iocs"]["urls"].extend(urls)

                # Extract IPs
                ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', code_str)
                result["iocs"]["ips"].extend(ips)

                # Extract executable references
                exes = re.findall(
                    r'[\w\-]+\.(?:exe|dll|bat|cmd|ps1|vbs|js|scr|pif)\b',
                    code_str, re.IGNORECASE,
                )
                result["iocs"]["executables"].extend(exes)

                # Extract registry key references
                reg_keys = re.findall(
                    r'(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\"\'\)]+',
                    code_str, re.IGNORECASE,
                )
                result["iocs"]["registry_keys"].extend(reg_keys)

            # Analyze for suspicious keywords and auto-exec triggers
            try:
                analysis_results = vba_parser.analyze_macros()
                for (kw_type, keyword, description) in analysis_results:
                    entry = {
                        "type": str(kw_type),
                        "keyword": str(keyword),
                        "description": str(description),
                    }
                    result["suspicious_keywords"].append(entry)
                    if str(kw_type).lower() == "autoexec":
                        result["auto_exec_triggers"].append(str(keyword))
            except Exception as e:
                result["analysis_warning"] = "Keyword analysis partial failure: {}".format(str(e))

        # Deduplicate IOCs
        for key in result["iocs"]:
            result["iocs"][key] = list(set(result["iocs"][key]))

        vba_parser.close()

    except Exception as e:
        result["error"] = "Analysis failed: {}".format(str(e))

    return _safe_json(result)


@mcp.tool()
def rtfobj_analyze(file_path: str) -> str:
    """Analyze RTF files for embedded objects and exploit indicators.

    Detects OLE objects, packages, equations (potential CVE-2017-11882),
    and other embedded content within RTF documents.

    Args:
        file_path: Path to the RTF file to analyze
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": "File not found: {}".format(file_path)})

    try:
        from oletools import rtfobj as rtfobj_module
    except ImportError:
        return json.dumps({"error": "oletools is not installed. Install with: pip install oletools"})

    result = {
        "file": resolved,
        "is_rtf": False,
        "object_count": 0,
        "objects": [],
        "exploit_indicators": [],
    }

    try:
        with open(resolved, "rb") as fh:
            raw_content = fh.read()
        rtf_parser = rtfobj_module.RtfObjParser(raw_content)
        rtf_parser.parse()
        result["is_rtf"] = True
        result["object_count"] = len(rtf_parser.objects)

        for idx, obj in enumerate(rtf_parser.objects):
            obj_info = {
                "index": idx,
                "format_id": getattr(obj, "format_id", None),
                "class_name": str(getattr(obj, "class_name", "unknown")),
                "is_ole": getattr(obj, "is_ole", False),
                "is_package": getattr(obj, "is_package", False),
                "is_equation": False,
                "oledata_size": len(obj.rawdata) if hasattr(obj, "rawdata") and obj.rawdata else 0,
                "start": getattr(obj, "start", None),
            }

            class_lower = obj_info["class_name"].lower()

            # Check for equation editor exploit (CVE-2017-11882)
            if "equation" in class_lower:
                obj_info["is_equation"] = True
                result["exploit_indicators"].append({
                    "type": "equation_editor",
                    "object_index": idx,
                    "description": "Equation Editor object detected - potential CVE-2017-11882 exploit",
                    "cve": "CVE-2017-11882",
                })

            # Check for OLE Package objects (can contain executables)
            if obj_info["is_package"] or "package" in class_lower:
                pkg_info = {
                    "type": "ole_package",
                    "object_index": idx,
                    "description": "OLE Package object - may contain embedded executable",
                }
                if hasattr(obj, "filename") and obj.filename:
                    pkg_info["filename"] = str(obj.filename)
                if hasattr(obj, "src_path") and obj.src_path:
                    pkg_info["source_path"] = str(obj.src_path)
                if hasattr(obj, "temp_path") and obj.temp_path:
                    pkg_info["temp_path"] = str(obj.temp_path)
                result["exploit_indicators"].append(pkg_info)

            # Check for shellcode-like content
            if hasattr(obj, "rawdata") and obj.rawdata:
                raw = obj.rawdata
                # NOP sled detection
                nop_count = raw.count(b"\x90")
                if nop_count > 20:
                    result["exploit_indicators"].append({
                        "type": "nop_sled",
                        "object_index": idx,
                        "nop_count": nop_count,
                        "description": "Potential NOP sled detected in embedded object",
                    })

                obj_info["entropy"] = _calculate_entropy(raw)

            result["objects"].append(obj_info)

    except Exception as e:
        result["error"] = "RTF analysis failed: {}".format(str(e))

    return _safe_json(result)


@mcp.tool()
def pe_analyze(file_path: str) -> str:
    """Analyze PE (Portable Executable) files for structure and suspicious indicators.

    Extracts imports, exports, sections, timestamps, and detects suspicious
    characteristics such as high entropy sections (packing), anti-debug API
    imports, and known packer signatures.

    Args:
        file_path: Path to the PE file (.exe, .dll, .sys, etc.)
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": "File not found: {}".format(file_path)})

    try:
        import pefile
    except ImportError:
        return json.dumps({"error": "pefile is not installed. Install with: pip install pefile"})

    result = {
        "file": resolved,
        "valid_pe": False,
        "headers": {},
        "sections": [],
        "imports": [],
        "exports": [],
        "suspicious_indicators": [],
        "resources": [],
    }

    ANTI_DEBUG_APIS = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA",
        "OutputDebugStringW", "GetTickCount",
        "QueryPerformanceCounter", "NtSetInformationThread",
    }

    SUSPICIOUS_APIS = {
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
        "WriteProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "QueueUserAPC",
        "SetWindowsHookEx", "CreateToolhelp32Snapshot",
        "Process32First", "Process32Next", "OpenProcess",
        "ReadProcessMemory", "URLDownloadToFile",
        "URLDownloadToCache", "InternetOpen",
        "InternetOpenUrl", "HttpOpenRequest", "HttpSendRequest",
        "WinExec", "ShellExecuteA", "ShellExecuteW",
        "ShellExecuteExA", "ShellExecuteExW",
        "CreateProcessA", "CreateProcessW",
        "RegSetValueExA", "RegSetValueExW",
        "RegCreateKeyExA", "RegCreateKeyExW",
        "CryptEncrypt", "CryptDecrypt", "CryptCreateHash",
    }

    try:
        pe = pefile.PE(resolved)
        result["valid_pe"] = True

        # File header info
        import time as _time
        timestamp = pe.FILE_HEADER.TimeDateStamp
        result["headers"] = {
            "machine": hex(pe.FILE_HEADER.Machine),
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "timestamp": timestamp,
            "timestamp_utc": _time.strftime("%Y-%m-%d %H:%M:%S", _time.gmtime(timestamp)),
            "characteristics": hex(pe.FILE_HEADER.Characteristics),
            "dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        }

        # Check for suspicious timestamp
        if timestamp == 0:
            result["suspicious_indicators"].append(
                "Zeroed timestamp (possible indicator of tampering)")
        elif timestamp > _time.time():
            result["suspicious_indicators"].append(
                "Future timestamp detected: {}".format(result["headers"]["timestamp_utc"]))

        # Section analysis
        for section in pe.sections:
            try:
                name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            except Exception:
                name = str(section.Name)

            section_data = section.get_data()
            entropy = _calculate_entropy(section_data)

            sec_info = {
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": entropy,
                "characteristics": hex(section.Characteristics),
                "readable": bool(section.Characteristics & 0x40000000),
                "writable": bool(section.Characteristics & 0x80000000),
                "executable": bool(section.Characteristics & 0x20000000),
            }
            result["sections"].append(sec_info)

            # High entropy = possibly packed/encrypted
            if entropy > 7.0:
                result["suspicious_indicators"].append(
                    "High entropy section '{}' ({}) - possible packing/encryption".format(
                        name, entropy))

            # Writable + Executable section
            if sec_info["writable"] and sec_info["executable"]:
                result["suspicious_indicators"].append(
                    "Section '{}' is both writable and executable".format(name))

            # Known packer section names
            packer_names = {
                ".upx", "upx0", "upx1", ".aspack", ".adata",
                ".nsp0", ".nsp1", ".mpress", ".themida", ".vmp0", ".vmp1",
            }
            if name.lower().strip() in packer_names:
                result["suspicious_indicators"].append(
                    "Packer section name detected: '{}'".format(name))

        # Import analysis
        found_anti_debug = []
        found_suspicious = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode("utf-8", errors="replace")
                except Exception:
                    dll_name = str(entry.dll)

                imports_list = []
                for imp in entry.imports:
                    if imp.name:
                        try:
                            func_name = imp.name.decode("utf-8", errors="replace")
                        except Exception:
                            func_name = str(imp.name)
                        imports_list.append(func_name)

                        if func_name in ANTI_DEBUG_APIS:
                            found_anti_debug.append(func_name)
                        if func_name in SUSPICIOUS_APIS:
                            found_suspicious.append(func_name)
                    else:
                        imports_list.append("ordinal_{}".format(imp.ordinal))

                result["imports"].append({
                    "dll": dll_name,
                    "functions": imports_list,
                })

        if found_anti_debug:
            result["suspicious_indicators"].append(
                "Anti-debug APIs imported: {}".format(
                    ", ".join(sorted(set(found_anti_debug)))))
        if found_suspicious:
            result["suspicious_indicators"].append(
                "Suspicious APIs imported: {}".format(
                    ", ".join(sorted(set(found_suspicious)))))

        # Export analysis
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    exp_name = (
                        exp.name.decode("utf-8", errors="replace")
                        if exp.name
                        else "ordinal_{}".format(exp.ordinal)
                    )
                except Exception:
                    exp_name = "ordinal_{}".format(exp.ordinal)
                result["exports"].append({
                    "name": exp_name,
                    "ordinal": exp.ordinal,
                    "address": hex(exp.address),
                })

        # Check for low import count (packing indicator)
        total_imports = sum(len(e["functions"]) for e in result["imports"])
        if 0 < total_imports < 5:
            result["suspicious_indicators"].append(
                "Very few imports ({}) - possible packing or dynamic resolution".format(
                    total_imports))

        # Check for TLS callbacks (anti-analysis technique)
        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            result["suspicious_indicators"].append(
                "TLS callbacks detected (possible anti-analysis)")

        pe.close()

    except pefile.PEFormatError as e:
        result["error"] = "Not a valid PE file: {}".format(str(e))
    except Exception as e:
        result["error"] = "PE analysis failed: {}".format(str(e))

    return _safe_json(result)


@mcp.tool()
def yara_scan(file_path: str, rules_path: str = "") -> str:
    """Scan a file with YARA rules for malware pattern matching.

    If no rules_path is given, looks for rules in the data/yara_rules/
    directory. If that directory is empty or missing, uses a built-in set
    of rules that detect common malware patterns.

    Args:
        file_path: Path to the file to scan
        rules_path: Optional path to a .yar/.yara rules file or directory of rules
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": "File not found: {}".format(file_path)})

    try:
        import yara
    except ImportError:
        return json.dumps({
            "error": "yara-python is not installed. Install with: pip install yara-python",
        })

    result = {
        "file": resolved,
        "rules_source": "",
        "matches": [],
        "match_count": 0,
    }

    try:
        rules = None

        if rules_path:
            rp = Path(rules_path).resolve()
            if rp.is_file():
                rules = yara.compile(filepath=str(rp))
                result["rules_source"] = str(rp)
            elif rp.is_dir():
                yara_files = {}
                for ext in ("*.yar", "*.yara", "*.rule", "*.rules"):
                    for f in rp.glob(ext):
                        yara_files[f.stem] = str(f)
                if yara_files:
                    rules = yara.compile(filepaths=yara_files)
                    result["rules_source"] = str(rp)
                else:
                    return json.dumps({
                        "error": "No YARA rule files found in: {}".format(rules_path),
                    })
            else:
                return json.dumps({
                    "error": "Rules path not found: {}".format(rules_path),
                })
        else:
            # Try data/yara_rules/ directory relative to project root
            project_root = Path(__file__).resolve().parent.parent.parent
            yara_dir = project_root / "data" / "yara_rules"
            yara_files = {}
            if yara_dir.is_dir():
                for ext in ("*.yar", "*.yara", "*.rule", "*.rules"):
                    for f in yara_dir.glob(ext):
                        yara_files[f.stem] = str(f)

            if yara_files:
                rules = yara.compile(filepaths=yara_files)
                result["rules_source"] = str(yara_dir)
            else:
                # Use built-in default rules
                rules = yara.compile(source=DEFAULT_YARA_RULES)
                result["rules_source"] = "built-in default rules"

        matches = rules.match(resolved)
        result["match_count"] = len(matches)

        for match in matches:
            match_info = {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags) if match.tags else [],
                "meta": dict(match.meta) if match.meta else {},
                "strings": [],
            }
            if hasattr(match, "strings"):
                for string_match in match.strings[:50]:
                    if hasattr(string_match, "instances"):
                        # Newer yara-python API (>= 4.x)
                        for instance in string_match.instances[:10]:
                            match_info["strings"].append({
                                "identifier": string_match.identifier,
                                "offset": (
                                    instance.offset
                                    if hasattr(instance, "offset")
                                    else 0
                                ),
                                "data": (
                                    instance.matched_data.hex()
                                    if hasattr(instance, "matched_data")
                                    else str(instance)[:200]
                                ),
                            })
                    elif isinstance(string_match, tuple):
                        # Older yara-python API (3.x)
                        offset = string_match[0] if len(string_match) > 0 else 0
                        identifier = string_match[1] if len(string_match) > 1 else ""
                        data = string_match[2] if len(string_match) > 2 else b""
                        match_info["strings"].append({
                            "offset": offset,
                            "identifier": str(identifier),
                            "data": (
                                data.hex() if isinstance(data, bytes) else str(data)[:200]
                            ),
                        })

            result["matches"].append(match_info)

    except yara.SyntaxError as e:
        result["error"] = "YARA rule syntax error: {}".format(str(e))
    except yara.Error as e:
        result["error"] = "YARA scan error: {}".format(str(e))
    except Exception as e:
        result["error"] = "YARA scan failed: {}".format(str(e))

    return _safe_json(result)


@mcp.tool()
def hash_file(file_path: str) -> str:
    """Calculate multiple cryptographic hashes of a file.

    Computes MD5, SHA1, SHA256, SHA512, and a simplified ssdeep-like
    fuzzy hash. For PE files also computes the import hash (imphash).
    Useful for malware identification and threat intelligence lookups.

    Args:
        file_path: Path to the file to hash
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": "File not found: {}".format(file_path)})

    result = {
        "file": resolved,
        "file_size": 0,
        "hashes": {},
    }

    try:
        data = Path(resolved).read_bytes()
        result["file_size"] = len(data)

        result["hashes"]["md5"] = hashlib.md5(data).hexdigest()
        result["hashes"]["sha1"] = hashlib.sha1(data).hexdigest()
        result["hashes"]["sha256"] = hashlib.sha256(data).hexdigest()
        result["hashes"]["sha512"] = hashlib.sha512(data).hexdigest()
        result["hashes"]["ssdeep_approx"] = _simple_ssdeep(data)

        # Also compute imphash for PE files
        try:
            import pefile
            pe = pefile.PE(resolved)
            imphash = pe.get_imphash()
            if imphash:
                result["hashes"]["imphash"] = imphash
            pe.close()
        except Exception:
            pass  # Not a PE file or pefile not available

    except Exception as e:
        result["error"] = "Hashing failed: {}".format(str(e))

    return _safe_json(result)


@mcp.tool()
def file_entropy(file_path: str) -> str:
    """Calculate Shannon entropy of a file and its PE sections if applicable.

    Shannon entropy measures randomness in data. Values close to 8.0
    indicate highly random data (encrypted/compressed/packed), while
    values near 0 indicate low randomness (sparse/repetitive data).

    Args:
        file_path: Path to the file to analyze
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": "File not found: {}".format(file_path)})

    result = {
        "file": resolved,
        "file_size": 0,
        "overall_entropy": 0.0,
        "entropy_assessment": "",
        "sections": [],
    }

    try:
        data = Path(resolved).read_bytes()
        result["file_size"] = len(data)
        overall = _calculate_entropy(data)
        result["overall_entropy"] = overall

        if overall > 7.5:
            result["entropy_assessment"] = (
                "Very high entropy - likely encrypted or compressed/packed"
            )
        elif overall > 7.0:
            result["entropy_assessment"] = (
                "High entropy - possibly packed or contains encrypted data"
            )
        elif overall > 6.0:
            result["entropy_assessment"] = (
                "Moderate-high entropy - may contain compressed resources"
            )
        elif overall > 4.0:
            result["entropy_assessment"] = (
                "Moderate entropy - typical for compiled code"
            )
        elif overall > 1.0:
            result["entropy_assessment"] = (
                "Low entropy - sparse data or text-heavy content"
            )
        else:
            result["entropy_assessment"] = (
                "Very low entropy - highly repetitive or nearly empty"
            )

        # If PE file, analyze per-section entropy
        try:
            import pefile
            pe = pefile.PE(resolved)
            for section in pe.sections:
                try:
                    name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
                except Exception:
                    name = str(section.Name)

                section_data = section.get_data()
                sec_entropy = _calculate_entropy(section_data)

                sec_info = {
                    "name": name,
                    "entropy": sec_entropy,
                    "raw_size": section.SizeOfRawData,
                    "virtual_size": section.Misc_VirtualSize,
                }

                if sec_entropy > 7.0:
                    sec_info["assessment"] = "HIGH - likely packed/encrypted"
                elif sec_entropy > 6.0:
                    sec_info["assessment"] = "Moderate-high"
                elif sec_entropy > 4.0:
                    sec_info["assessment"] = "Normal for code/data"
                else:
                    sec_info["assessment"] = "Low"

                result["sections"].append(sec_info)

            pe.close()
        except Exception:
            pass  # Not a PE file or pefile not available

        # Byte distribution: top 10 most frequent bytes
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        top_bytes = sorted(range(256), key=lambda i: byte_counts[i], reverse=True)[:10]
        result["top_bytes"] = [
            {
                "byte": "0x{:02x}".format(b),
                "count": byte_counts[b],
                "percentage": round(byte_counts[b] / len(data) * 100, 2),
            }
            for b in top_bytes
        ]

    except Exception as e:
        result["error"] = "Entropy calculation failed: {}".format(str(e))

    return _safe_json(result)


@mcp.tool()
def oleobj_extract(file_path: str) -> str:
    """Extract embedded objects from OLE files (Office documents).

    Detects and lists embedded OLE objects, their types, and sizes.
    Does NOT write extracted objects to disk - only reports what was found.

    Args:
        file_path: Path to the OLE file (.doc, .xls, .ppt, etc.)
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": "File not found: {}".format(file_path)})

    try:
        from oletools import oleobj as oleobj_module
    except ImportError:
        return json.dumps({
            "error": "oletools is not installed. Install with: pip install oletools",
        })

    result = {
        "file": resolved,
        "object_count": 0,
        "objects": [],
        "warnings": [],
    }

    try:
        ole_objects = list(oleobj_module.find_ole(resolved))

        for ole_index, (source_path, field_name, ole_data) in enumerate(ole_objects):
            obj_info = {
                "index": ole_index,
                "source_path": str(source_path) if source_path else "",
                "field_name": str(field_name) if field_name else "",
            }

            try:
                raw = None
                if hasattr(ole_data, "read"):
                    raw = ole_data.read()
                    ole_data.seek(0)
                elif hasattr(ole_data, "oledata"):
                    raw_attr = ole_data.oledata
                    if isinstance(raw_attr, bytes):
                        raw = raw_attr

                if raw is not None:
                    obj_info["size"] = len(raw)
                    obj_info["entropy"] = _calculate_entropy(raw)
                    obj_info["md5"] = hashlib.md5(raw).hexdigest()

                    # Check for PE header
                    if raw[:2] == b"MZ":
                        obj_info["contains_pe"] = True
                        result["warnings"].append(
                            "Object #{} contains embedded PE executable".format(ole_index))

                    # Check for common magic bytes
                    if raw[:4] == b"\xd0\xcf\x11\xe0":
                        obj_info["type"] = "OLE Compound File"
                    elif raw[:2] == b"PK":
                        obj_info["type"] = "ZIP/OOXML archive"
                    elif raw[:5] == b"{\\rtf":
                        obj_info["type"] = "RTF document"
                    else:
                        obj_info["type"] = "unknown"
                else:
                    obj_info["note"] = "Could not extract raw data"

            except Exception as e:
                obj_info["extraction_error"] = str(e)

            # Try to get filename/path from OLE Package
            for attr in ("filename", "src_path", "temp_path", "olepkgdata"):
                val = getattr(ole_data, attr, None)
                if val:
                    if isinstance(val, bytes):
                        obj_info[attr] = val.decode("utf-8", errors="replace")
                    else:
                        obj_info[attr] = str(val)

            result["objects"].append(obj_info)
            result["object_count"] += 1

    except Exception as e:
        result["error"] = "OLE object extraction failed: {}".format(str(e))

    return _safe_json(result)


def main():
    """Run the REMnux tools MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
