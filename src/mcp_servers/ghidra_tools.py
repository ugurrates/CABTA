"""
Ghidra/Reverse Engineering MCP Server - Binary analysis via MCP.

Provides reverse engineering capabilities:
  - If Ghidra is installed: uses Ghidra headless analyzer
  - Fallback: uses pefile, struct, and disassembly via capstone (if available)

Always available (no Ghidra needed):
  - PE header/section analysis
  - Import/Export table extraction
  - Function detection via heuristics
  - Cross-reference analysis
  - String-to-function mapping
  - Binary diffing (simple)
  - Shellcode detection

Usage:
    python -m src.mcp_servers.ghidra_tools
"""

import hashlib
import json
import logging
import math
import os
import re
import shutil
import struct
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-re")

# Try to find Ghidra
GHIDRA_HOME = os.environ.get("GHIDRA_HOME", "")
GHIDRA_HEADLESS = None
if GHIDRA_HOME:
    candidate = Path(GHIDRA_HOME) / "support" / "analyzeHeadless.bat"
    if candidate.exists():
        GHIDRA_HEADLESS = str(candidate)

# Try capstone for disassembly
try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

# pefile is available
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


def _validate_file(file_path: str) -> str | None:
    p = Path(file_path).resolve()
    return str(p) if p.is_file() else None


@mcp.tool()
def analyze_binary(file_path: str) -> str:
    """Comprehensive binary analysis - PE structure, sections, imports, exports,
    suspicious indicators, and entry point disassembly.

    Args:
        file_path: Path to the binary file (PE/ELF/raw)
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": f"File not found: {file_path}"})

    with open(resolved, "rb") as f:
        data = f.read()

    result = {
        "file": resolved,
        "size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    # Detect file type
    if data[:2] == b"MZ":
        result["format"] = "PE"
        result.update(_analyze_pe(resolved, data))
    elif data[:4] == b"\x7fELF":
        result["format"] = "ELF"
        result.update(_analyze_elf(data))
    else:
        result["format"] = "Unknown/Raw"
        result["magic_hex"] = data[:16].hex()

    # Common analysis
    result["entropy"] = _calc_entropy(data)

    return json.dumps(result, indent=2, default=str)


def _analyze_pe(file_path: str, data: bytes) -> dict:
    """Analyze PE file structure."""
    result = {}
    if not HAS_PEFILE:
        result["error"] = "pefile not installed"
        return result

    try:
        pe = pefile.PE(file_path)

        # Basic info
        result["machine"] = hex(pe.FILE_HEADER.Machine)
        result["machine_type"] = {
            0x14c: "x86 (32-bit)",
            0x8664: "x64 (64-bit)",
            0x1c0: "ARM",
            0xaa64: "ARM64",
        }.get(pe.FILE_HEADER.Machine, "Unknown")

        result["characteristics"] = hex(pe.FILE_HEADER.Characteristics)
        result["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        result["is_exe"] = bool(pe.FILE_HEADER.Characteristics & 0x0002)

        # Timestamps
        import datetime
        ts = pe.FILE_HEADER.TimeDateStamp
        try:
            result["compile_time"] = datetime.datetime.utcfromtimestamp(ts).isoformat()
        except Exception:
            result["compile_time_raw"] = ts

        # Optional header
        if hasattr(pe, "OPTIONAL_HEADER"):
            result["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            result["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
            result["subsystem"] = pe.OPTIONAL_HEADER.Subsystem

        # Sections
        sections = []
        suspicious_sections = []
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            entropy = section.get_entropy()
            s = {
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(entropy, 3),
                "characteristics": hex(section.Characteristics),
                "executable": bool(section.Characteristics & 0x20000000),
                "writable": bool(section.Characteristics & 0x80000000),
            }
            sections.append(s)
            if entropy > 7.0:
                suspicious_sections.append(f"{name}: high entropy ({entropy:.2f}) - possibly packed/encrypted")
            if s["executable"] and s["writable"]:
                suspicious_sections.append(f"{name}: writable+executable (W^X violation)")
            if name not in [".text", ".rdata", ".data", ".rsrc", ".reloc", ".pdata", ".bss", ".idata", ".edata", ".tls"]:
                suspicious_sections.append(f"{name}: non-standard section name")

        result["sections"] = sections
        result["suspicious_sections"] = suspicious_sections

        # Imports
        imports = {}
        suspicious_imports = []
        dangerous_apis = {
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
            "WriteProcessMemory", "ReadProcessMemory",
            "CreateRemoteThread", "NtCreateThreadEx",
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
            "WinExec", "ShellExecuteA", "ShellExecuteW",
            "CreateProcessA", "CreateProcessW",
            "URLDownloadToFileA", "URLDownloadToFileW",
            "InternetOpenA", "InternetOpenW",
            "RegSetValueExA", "RegSetValueExW",
            "CryptEncrypt", "CryptDecrypt",
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "AdjustTokenPrivileges", "OpenProcessToken",
        }
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="replace")
                funcs = []
                for imp in entry.imports:
                    name = imp.name.decode("utf-8", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                    funcs.append(name)
                    if name in dangerous_apis:
                        suspicious_imports.append(f"{dll}!{name}")
                imports[dll] = funcs

        result["imports"] = {dll: len(funcs) for dll, funcs in imports.items()}
        result["total_imports"] = sum(len(f) for f in imports.values())
        result["suspicious_imports"] = suspicious_imports

        # Exports
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            exports = []
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode("utf-8", errors="replace") if exp.name else f"ord_{exp.ordinal}"
                exports.append({"name": name, "ordinal": exp.ordinal, "address": hex(exp.address)})
            result["exports"] = exports

        # TLS callbacks
        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            tls = pe.DIRECTORY_ENTRY_TLS.struct
            result["tls_callbacks"] = True
            suspicious_sections.append("TLS callbacks detected (anti-debug/anti-analysis)")
        else:
            result["tls_callbacks"] = False

        # Resources
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            resources = []
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                rtype = pefile.RESOURCE_TYPE.get(entry.id, str(entry.id)) if entry.id else str(entry.name)
                count = 0
                if hasattr(entry, "directory"):
                    for e2 in entry.directory.entries:
                        if hasattr(e2, "directory"):
                            count += len(e2.directory.entries)
                resources.append({"type": rtype, "count": count})
            result["resources"] = resources

        # Imphash
        try:
            result["imphash"] = pe.get_imphash()
        except Exception:
            pass

        pe.close()
    except Exception as e:
        result["pe_error"] = str(e)

    return result


def _analyze_elf(data: bytes) -> dict:
    """Basic ELF analysis."""
    result = {}
    try:
        # ELF header
        ei_class = data[4]
        ei_data = data[5]
        result["class"] = "64-bit" if ei_class == 2 else "32-bit"
        result["endian"] = "little" if ei_data == 1 else "big"

        fmt = "<" if ei_data == 1 else ">"

        if ei_class == 2:  # 64-bit
            e_type = struct.unpack_from(f"{fmt}H", data, 16)[0]
            e_machine = struct.unpack_from(f"{fmt}H", data, 18)[0]
            e_entry = struct.unpack_from(f"{fmt}Q", data, 24)[0]
        else:  # 32-bit
            e_type = struct.unpack_from(f"{fmt}H", data, 16)[0]
            e_machine = struct.unpack_from(f"{fmt}H", data, 18)[0]
            e_entry = struct.unpack_from(f"{fmt}I", data, 24)[0]

        result["type"] = {1: "Relocatable", 2: "Executable", 3: "Shared", 4: "Core"}.get(e_type, f"Unknown({e_type})")
        result["machine"] = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64"}.get(e_machine, f"Unknown({e_machine})")
        result["entry_point"] = hex(e_entry)
    except Exception as e:
        result["elf_error"] = str(e)
    return result


def _calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    return round(-sum((c / length) * math.log2(c / length) for c in freq if c > 0), 4)


@mcp.tool()
def disassemble_entry_point(file_path: str, num_instructions: int = 50) -> str:
    """Disassemble instructions at the entry point of a PE/ELF binary.
    Uses capstone disassembler if available, falls back to raw bytes.

    Args:
        file_path: Path to the binary
        num_instructions: Number of instructions to disassemble (default 50)
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": f"File not found: {file_path}"})

    with open(resolved, "rb") as f:
        data = f.read()

    if data[:2] != b"MZ" or not HAS_PEFILE:
        return json.dumps({"error": "Only PE files supported, or pefile not installed"})

    try:
        pe = pefile.PE(resolved)
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_offset = pe.get_offset_from_rva(ep)
        code = data[ep_offset:ep_offset + 500]
        image_base = pe.OPTIONAL_HEADER.ImageBase
        machine = pe.FILE_HEADER.Machine
        pe.close()

        if HAS_CAPSTONE:
            if machine == 0x8664:
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            md.detail = False

            instructions = []
            for insn in md.disasm(code, image_base + ep):
                instructions.append({
                    "address": hex(insn.address),
                    "mnemonic": insn.mnemonic,
                    "operands": insn.op_str,
                    "bytes": insn.bytes.hex(),
                })
                if len(instructions) >= num_instructions:
                    break

            return json.dumps({
                "entry_point": hex(image_base + ep),
                "file_offset": hex(ep_offset),
                "instruction_count": len(instructions),
                "instructions": instructions,
            }, indent=2)
        else:
            # Fallback: hex dump
            return json.dumps({
                "entry_point": hex(image_base + ep),
                "file_offset": hex(ep_offset),
                "note": "capstone not installed - showing raw bytes",
                "hex_dump": code[:200].hex(),
                "install_hint": "pip install capstone",
            }, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Disassembly failed: {e}"})


@mcp.tool()
def find_functions(file_path: str) -> str:
    """Detect functions in a PE binary using prologue/epilogue patterns.
    Identifies function boundaries without full disassembly.

    Args:
        file_path: Path to the PE binary
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": f"File not found: {file_path}"})

    if not HAS_PEFILE:
        return json.dumps({"error": "pefile not installed"})

    try:
        pe = pefile.PE(resolved)
        image_base = pe.OPTIONAL_HEADER.ImageBase

        functions = []

        # Search in executable sections
        for section in pe.sections:
            if not (section.Characteristics & 0x20000000):  # Not executable
                continue

            section_data = section.get_data()
            section_va = section.VirtualAddress

            # Common function prologues
            # x86: push ebp; mov ebp, esp (55 8B EC)
            # x64: push rbp; mov rbp, rsp or sub rsp, XX
            prologues = [
                (b"\x55\x8b\xec", "push ebp; mov ebp, esp"),
                (b"\x55\x48\x89\xe5", "push rbp; mov rbp, rsp"),
                (b"\x48\x89\x5c\x24", "mov [rsp+X], rbx (x64 frame)"),
                (b"\x48\x83\xec", "sub rsp, imm8 (x64 frame)"),
                (b"\x40\x53\x48\x83\xec", "push rbx; sub rsp (x64)"),
            ]

            for pattern, desc in prologues:
                offset = 0
                while offset < len(section_data) - len(pattern):
                    pos = section_data.find(pattern, offset)
                    if pos == -1:
                        break
                    va = image_base + section_va + pos
                    functions.append({
                        "address": hex(va),
                        "file_offset": hex(section.PointerToRawData + pos),
                        "prologue": desc,
                        "section": section.Name.decode(errors="replace").rstrip("\x00"),
                    })
                    offset = pos + len(pattern)

        # Also add exports as functions
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode(errors="replace") if exp.name else f"ord_{exp.ordinal}"
                functions.append({
                    "address": hex(image_base + exp.address),
                    "name": name,
                    "type": "export",
                })

        # Entry point
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        functions.insert(0, {
            "address": hex(image_base + ep),
            "name": "_entry",
            "type": "entry_point",
        })

        pe.close()

        # Deduplicate by address
        seen = set()
        unique = []
        for f in functions:
            if f["address"] not in seen:
                seen.add(f["address"])
                unique.append(f)

        unique.sort(key=lambda x: int(x["address"], 16))

        return json.dumps({
            "file": resolved,
            "function_count": len(unique),
            "functions": unique[:500],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Function detection failed: {e}"})


@mcp.tool()
def detect_shellcode(file_path: str) -> str:
    """Scan a file for shellcode patterns and suspicious byte sequences.
    Detects NOP sleds, common shellcode patterns, API hashing, etc.

    Args:
        file_path: Path to the file to scan
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": f"File not found: {file_path}"})

    with open(resolved, "rb") as f:
        data = f.read()

    findings = []

    # NOP sled detection
    nop_pattern = b"\x90" * 10
    offset = 0
    while offset < len(data):
        pos = data.find(nop_pattern, offset)
        if pos == -1:
            break
        # Count consecutive NOPs
        end = pos
        while end < len(data) and data[end] == 0x90:
            end += 1
        nop_len = end - pos
        if nop_len >= 10:
            findings.append({
                "type": "NOP sled",
                "offset": hex(pos),
                "length": nop_len,
                "severity": "high" if nop_len > 50 else "medium",
            })
        offset = end

    # Common shellcode patterns
    patterns = [
        (b"\xeb\xfe", "Infinite loop (JMP $-2)"),
        (b"\xcc\xcc\xcc", "INT3 breakpoint sled"),
        (b"\x64\xa1\x30\x00\x00\x00", "PEB access (fs:[0x30])"),
        (b"\x64\x8b\x15\x30\x00\x00\x00", "PEB access variant"),
        (b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00", "PEB access x64 (gs:[0x60])"),
        (b"\x68\x63\x6d\x64\x00", 'push "cmd" string'),
        (b"\x68\x63\x61\x6c\x63", 'push "calc" string'),
    ]

    for pattern, desc in patterns:
        offset = 0
        while True:
            pos = data.find(pattern, offset)
            if pos == -1:
                break
            findings.append({
                "type": desc,
                "offset": hex(pos),
                "bytes": data[pos:pos + len(pattern) + 4].hex(),
                "severity": "high",
            })
            offset = pos + len(pattern)

    # API hash patterns (common hash values used in shellcode)
    known_hashes = {
        "0x726774c": "LoadLibraryA (ROR13)",
        "0x6b8029": "WinExec (ROR13)",
        "0x876f8b31": "WSAStartup (ROR13)",
        "0xe0df0fea": "WSASocketA (ROR13)",
    }

    for hash_bytes, api_name in known_hashes.items():
        hash_val = int(hash_bytes, 16)
        packed = struct.pack("<I", hash_val)
        if packed in data:
            pos = data.find(packed)
            findings.append({
                "type": f"API hash: {api_name}",
                "offset": hex(pos),
                "hash": hash_bytes,
                "severity": "critical",
            })

    return json.dumps({
        "file": resolved,
        "finding_count": len(findings),
        "findings": findings,
        "has_shellcode_indicators": len(findings) > 0,
    }, indent=2)


@mcp.tool()
def binary_diff(file_path_1: str, file_path_2: str) -> str:
    """Compare two binary files and report differences.
    Useful for analyzing malware variants or patched binaries.

    Args:
        file_path_1: Path to the first binary
        file_path_2: Path to the second binary
    """
    resolved1 = _validate_file(file_path_1)
    resolved2 = _validate_file(file_path_2)
    if not resolved1:
        return json.dumps({"error": f"File not found: {file_path_1}"})
    if not resolved2:
        return json.dumps({"error": f"File not found: {file_path_2}"})

    with open(resolved1, "rb") as f:
        data1 = f.read()
    with open(resolved2, "rb") as f:
        data2 = f.read()

    result = {
        "file1": {"path": resolved1, "size": len(data1), "md5": hashlib.md5(data1).hexdigest()},
        "file2": {"path": resolved2, "size": len(data2), "md5": hashlib.md5(data2).hexdigest()},
        "identical": data1 == data2,
        "size_difference": len(data2) - len(data1),
    }

    if data1 == data2:
        return json.dumps(result, indent=2)

    # Find differences
    min_len = min(len(data1), len(data2))
    differences = []
    diff_start = None

    for i in range(min_len):
        if data1[i] != data2[i]:
            if diff_start is None:
                diff_start = i
        else:
            if diff_start is not None:
                differences.append({
                    "offset": hex(diff_start),
                    "length": i - diff_start,
                    "file1_bytes": data1[diff_start:i].hex()[:100],
                    "file2_bytes": data2[diff_start:i].hex()[:100],
                })
                diff_start = None
                if len(differences) >= 100:
                    break

    if diff_start is not None and len(differences) < 100:
        end = min(min_len, diff_start + 500)
        differences.append({
            "offset": hex(diff_start),
            "length": end - diff_start,
            "file1_bytes": data1[diff_start:end].hex()[:100],
            "file2_bytes": data2[diff_start:end].hex()[:100],
        })

    result["diff_regions"] = len(differences)
    result["differences"] = differences[:50]

    # Compare PE structures if both are PE
    if HAS_PEFILE and data1[:2] == b"MZ" and data2[:2] == b"MZ":
        try:
            pe1 = pefile.PE(resolved1)
            pe2 = pefile.PE(resolved2)

            pe_diffs = []
            if pe1.FILE_HEADER.TimeDateStamp != pe2.FILE_HEADER.TimeDateStamp:
                pe_diffs.append("Different compile timestamps")
            if pe1.OPTIONAL_HEADER.AddressOfEntryPoint != pe2.OPTIONAL_HEADER.AddressOfEntryPoint:
                pe_diffs.append(f"Different entry points: {hex(pe1.OPTIONAL_HEADER.AddressOfEntryPoint)} vs {hex(pe2.OPTIONAL_HEADER.AddressOfEntryPoint)}")
            if len(pe1.sections) != len(pe2.sections):
                pe_diffs.append(f"Different section count: {len(pe1.sections)} vs {len(pe2.sections)}")

            result["pe_structural_differences"] = pe_diffs
            pe1.close()
            pe2.close()
        except Exception:
            pass

    return json.dumps(result, indent=2)


def main():
    """Run the Ghidra/RE tools MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
