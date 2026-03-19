"""
FLARE Tools MCP Server - Exposes local malware analysis tools via MCP.

Tools provided:
  - capa: Detect capabilities in executable files (MITRE ATT&CK mapping)
  - floss: Extract obfuscated strings from executables
  - diec: Detect It Easy - identify file type, packer, compiler
  - strings_analysis: Extract ASCII/Unicode strings from binary files

Usage:
    python -m src.mcp_servers.flare_tools
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("flare-tools")

# Tool paths (auto-detect from PATH or known locations)
CAPA_PATH = shutil.which("capa") or r"C:\Tools\capa\capa.exe"
FLOSS_PATH = shutil.which("floss") or r"C:\Tools\floss\floss.exe"
DIEC_PATH = shutil.which("diec") or r"C:\Tools\die\diec.exe"
STRINGS_PATH = shutil.which("strings") or r"C:\Tools\strings\strings.exe"

MAX_OUTPUT_SIZE = 50000  # Truncate output to avoid overwhelming the LLM


def _run_tool(cmd: list[str], timeout: int = 120) -> dict:
    """Run a tool and return stdout/stderr."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=tempfile.gettempdir(),
        )
        stdout = result.stdout[:MAX_OUTPUT_SIZE] if result.stdout else ""
        stderr = result.stderr[:5000] if result.stderr else ""
        return {
            "exit_code": result.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "truncated": len(result.stdout or "") > MAX_OUTPUT_SIZE,
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": "Timeout after {}s".format(timeout)}
    except FileNotFoundError as e:
        return {"exit_code": -1, "stdout": "", "stderr": "Tool not found: {}".format(e)}
    except Exception as e:
        return {"exit_code": -1, "stdout": "", "stderr": str(e)}


def _validate_file(file_path: str) -> str | None:
    """Validate that a file exists and return its resolved path."""
    p = Path(file_path).resolve()
    if not p.is_file():
        return None
    return str(p)


@mcp.tool()
def capa_analyze(file_path: str, verbose: bool = False) -> str:
    """Analyze an executable with capa to detect capabilities and MITRE ATT&CK techniques.

    Args:
        file_path: Path to the PE/ELF/shellcode file to analyze
        verbose: If True, include detailed rule matches
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": "File not found: {}".format(file_path)})

    cmd = [CAPA_PATH, resolved, "--json"]
    if verbose:
        cmd.append("-v")

    result = _run_tool(cmd, timeout=180)
    if result["exit_code"] != 0:
        return json.dumps({
            "error": "capa failed",
            "stderr": result["stderr"],
            "exit_code": result["exit_code"],
        })

    # Try to parse JSON output for structured data
    try:
        capa_data = json.loads(result["stdout"])
        # Extract key findings
        rules = capa_data.get("rules", {})
        summary = {
            "file": resolved,
            "matched_rules": len(rules),
            "capabilities": [],
            "mitre_attacks": [],
        }
        for rule_name, rule_data in rules.items():
            meta = rule_data.get("meta", {})
            summary["capabilities"].append({
                "name": rule_name,
                "namespace": meta.get("namespace", ""),
                "scope": meta.get("scope", ""),
            })
            for attack in meta.get("attack", []):
                summary["mitre_attacks"].append({
                    "technique": attack.get("technique", ""),
                    "id": attack.get("id", ""),
                    "tactic": attack.get("tactic", ""),
                })

        return json.dumps(summary, indent=2)
    except (json.JSONDecodeError, KeyError):
        return result["stdout"]


@mcp.tool()
def floss_extract(file_path: str, min_length: int = 4) -> str:
    """Extract obfuscated and encoded strings from an executable using FLOSS.

    FLOSS uses advanced static analysis to deobfuscate strings that
    regular 'strings' would miss (stack strings, decoded strings, etc.)

    Args:
        file_path: Path to the executable file
        min_length: Minimum string length to extract (default: 4)
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": "File not found: {}".format(file_path)})

    cmd = [FLOSS_PATH, resolved, "--json", "-n", str(min_length)]
    result = _run_tool(cmd, timeout=300)

    if result["exit_code"] != 0:
        return json.dumps({
            "error": "FLOSS failed",
            "stderr": result["stderr"],
            "exit_code": result["exit_code"],
        })

    try:
        floss_data = json.loads(result["stdout"])
        summary = {
            "file": resolved,
            "static_strings": len(floss_data.get("strings", {}).get("static_strings", [])),
            "stack_strings": len(floss_data.get("strings", {}).get("stack_strings", [])),
            "decoded_strings": len(floss_data.get("strings", {}).get("decoded_strings", [])),
            "tight_strings": len(floss_data.get("strings", {}).get("tight_strings", [])),
        }
        # Include interesting strings (URLs, IPs, paths, etc.)
        all_strings = []
        for category in ["static_strings", "stack_strings", "decoded_strings", "tight_strings"]:
            for s in floss_data.get("strings", {}).get(category, [])[:200]:
                val = s.get("string", s) if isinstance(s, dict) else str(s)
                all_strings.append(val)

        summary["sample_strings"] = all_strings[:500]
        return json.dumps(summary, indent=2)
    except (json.JSONDecodeError, KeyError):
        return result["stdout"]


@mcp.tool()
def diec_identify(file_path: str) -> str:
    """Identify file type, packer, compiler, and protector using Detect It Easy (DIE).

    Args:
        file_path: Path to the file to identify
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": "File not found: {}".format(file_path)})

    cmd = [DIEC_PATH, resolved, "--json"]
    result = _run_tool(cmd, timeout=60)

    if result["exit_code"] != 0:
        return json.dumps({
            "error": "DIE failed",
            "stderr": result["stderr"],
            "exit_code": result["exit_code"],
        })

    try:
        die_data = json.loads(result["stdout"])
        return json.dumps(die_data, indent=2)
    except json.JSONDecodeError:
        return result["stdout"] if result["stdout"] else result["stderr"]


@mcp.tool()
def strings_analysis(file_path: str, min_length: int = 4, encoding: str = "auto") -> str:
    """Extract printable strings from a binary file.

    Args:
        file_path: Path to the binary file
        min_length: Minimum string length (default: 4)
        encoding: String encoding - 'ascii', 'unicode', or 'auto' (both)
    """
    resolved = _validate_file(file_path)
    if not resolved:
        return json.dumps({"error": "File not found: {}".format(file_path)})

    results = {"file": resolved, "strings": []}

    if encoding in ("ascii", "auto"):
        cmd = [STRINGS_PATH, "-n", str(min_length), resolved]
        result = _run_tool(cmd, timeout=60)
        if result["exit_code"] == 0 and result["stdout"]:
            ascii_strings = result["stdout"].strip().split("\n")
            results["ascii_count"] = len(ascii_strings)
            results["strings"].extend(ascii_strings[:1000])

    if encoding in ("unicode", "auto"):
        cmd = [STRINGS_PATH, "-n", str(min_length), "-el", resolved]
        result = _run_tool(cmd, timeout=60)
        if result["exit_code"] == 0 and result["stdout"]:
            unicode_strings = result["stdout"].strip().split("\n")
            results["unicode_count"] = len(unicode_strings)
            results["strings"].extend(unicode_strings[:500])

    results["total_extracted"] = len(results["strings"])
    results["strings"] = results["strings"][:1500]  # Limit
    return json.dumps(results, indent=2)


def main():
    """Run the FLARE tools MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
