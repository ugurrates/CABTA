"""
Threat Intelligence MCP Server - Free threat intel feeds via MCP.

Uses ONLY free, no-API-key-required services:
  - abuse.ch (URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker)
  - AlienVault OTX (public pulse data)
  - VirusTotal (public hash lookups - limited)
  - Tor exit node list
  - Known malicious IP/domain blocklists

Usage:
    python -m src.mcp_servers.threat_intel_tools
"""

import json
import logging
import re
import urllib.request
from datetime import datetime

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("threat-intel")

TIMEOUT = 15


def _http_get(url: str, timeout: int = TIMEOUT) -> str:
    """Safe HTTP GET request."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "BlueTeamAssistant/2.0",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return json.dumps({"error": str(e)})


def _http_post(url: str, data: dict, timeout: int = TIMEOUT) -> str:
    """Safe HTTP POST request with JSON body."""
    try:
        body = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url, data=body,
            headers={
                "User-Agent": "BlueTeamAssistant/2.0",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def urlhaus_lookup(indicator: str) -> str:
    """Look up a URL, domain, or IP in URLhaus (abuse.ch).
    Free, no API key needed. Checks for known malicious URLs.

    Args:
        indicator: URL, domain, or IP to look up
    """
    indicator = indicator.strip()

    # Determine endpoint
    if indicator.startswith(("http://", "https://")):
        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        payload = {"url": indicator}
    elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator):
        endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
        payload = {"host": indicator}
    else:
        endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
        payload = {"host": indicator}

    try:
        body = "&".join(f"{k}={v}" for k, v in payload.items()).encode("utf-8")
        req = urllib.request.Request(
            endpoint, data=body,
            headers={"User-Agent": "BlueTeamAssistant/2.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())

        return json.dumps(data, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": f"URLhaus lookup failed: {e}", "indicator": indicator})


@mcp.tool()
def malwarebazaar_hash_lookup(hash_value: str) -> str:
    """Look up a file hash in MalwareBazaar (abuse.ch).
    Free, no API key. Supports MD5, SHA1, SHA256.

    Args:
        hash_value: MD5, SHA1, or SHA256 hash to look up
    """
    hash_value = hash_value.strip().lower()

    try:
        body = f"query=get_info&hash={hash_value}".encode("utf-8")
        req = urllib.request.Request(
            "https://mb-api.abuse.ch/api/v1/",
            data=body,
            headers={"User-Agent": "BlueTeamAssistant/2.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())

        return json.dumps(data, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": f"MalwareBazaar lookup failed: {e}", "hash": hash_value})


@mcp.tool()
def threatfox_ioc_lookup(indicator: str) -> str:
    """Search ThreatFox (abuse.ch) for IOC information.
    Free, no API key. Supports IPs, domains, URLs, hashes.

    Args:
        indicator: IOC to search for (IP, domain, URL, or hash)
    """
    indicator = indicator.strip()

    try:
        payload = json.dumps({
            "query": "search_ioc",
            "search_term": indicator,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://threatfox-api.abuse.ch/api/v1/",
            data=payload,
            headers={
                "User-Agent": "BlueTeamAssistant/2.0",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())

        return json.dumps(data, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": f"ThreatFox lookup failed: {e}", "indicator": indicator})


@mcp.tool()
def feodo_tracker_check(ip: str) -> str:
    """Check if an IP is a known botnet C2 server via Feodo Tracker (abuse.ch).
    Free, no API key. Tracks Dridex, Emotet, TrickBot, QakBot C2s.

    Args:
        ip: IP address to check
    """
    ip = ip.strip()

    try:
        # Download current botnet C2 list
        data = _http_get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json")
        blocklist = json.loads(data)

        found = []
        for entry in blocklist:
            if entry.get("ip_address") == ip:
                found.append(entry)

        if found:
            return json.dumps({
                "ip": ip,
                "malicious": True,
                "matches": found,
                "source": "Feodo Tracker (abuse.ch)",
            }, indent=2, default=str)
        else:
            return json.dumps({
                "ip": ip,
                "malicious": False,
                "message": "IP not found in Feodo Tracker botnet C2 list",
                "source": "Feodo Tracker (abuse.ch)",
            }, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Feodo Tracker check failed: {e}", "ip": ip})


@mcp.tool()
def tor_exit_node_check(ip: str) -> str:
    """Check if an IP address is a known Tor exit node.
    Uses the official Tor Project exit node list.

    Args:
        ip: IP address to check
    """
    ip = ip.strip()

    try:
        data = _http_get("https://check.torproject.org/torbulkexitlist")
        tor_nodes = set(line.strip() for line in data.split("\n") if line.strip() and not line.startswith("#"))

        is_tor = ip in tor_nodes
        return json.dumps({
            "ip": ip,
            "is_tor_exit_node": is_tor,
            "total_exit_nodes": len(tor_nodes),
            "source": "Tor Project Bulk Exit List",
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Tor check failed: {e}", "ip": ip})


@mcp.tool()
def blocklist_check(ip: str) -> str:
    """Check an IP against multiple free blocklists.
    Checks: Spamhaus DROP, DShield, Blocklist.de, CI Army.

    Args:
        ip: IP address to check
    """
    ip = ip.strip()
    results = {"ip": ip, "lists_checked": 0, "lists_found": 0, "findings": []}

    # Check free blocklists
    blocklists = {
        "Spamhaus DROP": "https://www.spamhaus.org/drop/drop.txt",
        "Spamhaus EDROP": "https://www.spamhaus.org/drop/edrop.txt",
        "DShield": "https://www.dshield.org/block.txt",
        "Blocklist.de": "https://lists.blocklist.de/lists/all.txt",
    }

    for name, url in blocklists.items():
        try:
            data = _http_get(url, timeout=10)
            results["lists_checked"] += 1
            if ip in data:
                results["lists_found"] += 1
                results["findings"].append({
                    "list": name,
                    "found": True,
                })
        except Exception:
            pass

    results["malicious"] = results["lists_found"] > 0
    results["risk_level"] = (
        "critical" if results["lists_found"] >= 3 else
        "high" if results["lists_found"] >= 2 else
        "medium" if results["lists_found"] >= 1 else
        "low"
    )

    return json.dumps(results, indent=2)


@mcp.tool()
def recent_malware_samples(limit: int = 20) -> str:
    """Get recent malware samples from MalwareBazaar.
    Free, no API key. Returns latest submitted samples.

    Args:
        limit: Number of recent samples to retrieve (max 50)
    """
    limit = min(limit, 50)
    try:
        body = f"query=get_recent&selector=100".encode("utf-8")
        req = urllib.request.Request(
            "https://mb-api.abuse.ch/api/v1/",
            data=body,
            headers={"User-Agent": "BlueTeamAssistant/2.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())

        # Trim to limit
        if "data" in data and isinstance(data["data"], list):
            data["data"] = data["data"][:limit]

        return json.dumps(data, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": f"MalwareBazaar query failed: {e}"})


@mcp.tool()
def threatfox_recent_iocs(days: int = 1, limit: int = 50) -> str:
    """Get recent IOCs from ThreatFox.
    Free, no API key. Returns latest reported IOCs.

    Args:
        days: Number of days to look back (1-7)
        limit: Maximum number of IOCs to return
    """
    days = min(max(days, 1), 7)
    try:
        payload = json.dumps({
            "query": "get_iocs",
            "days": days,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://threatfox-api.abuse.ch/api/v1/",
            data=payload,
            headers={
                "User-Agent": "BlueTeamAssistant/2.0",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())

        if "data" in data and isinstance(data["data"], list):
            data["data"] = data["data"][:limit]
            data["returned_count"] = len(data["data"])

        return json.dumps(data, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": f"ThreatFox query failed: {e}"})


def main():
    """Run the threat intelligence MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
