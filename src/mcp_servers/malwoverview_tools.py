"""
Malwoverview MCP Server - Malware threat intelligence lookups via MCP.

Wraps the malwoverview Python package and provides free, API-key-free
threat intelligence using abuse.ch services (MalwareBazaar, URLhaus,
ThreatFox, Feodo Tracker).

Usage:
    python -m src.mcp_servers.malwoverview_tools
"""

import hashlib
import json
import logging
import os
import re
import subprocess
import urllib.request
import urllib.parse
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("malwoverview")

TIMEOUT = 20
USER_AGENT = "BlueTeamAssistant-Malwoverview/1.0"

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _http_get(url: str, timeout: int = TIMEOUT) -> str:
    """Safe HTTP GET returning response body as string."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return json.dumps({"error": str(e)})


def _http_post_json(url: str, data: dict, timeout: int = TIMEOUT) -> str:
    """Safe HTTP POST with JSON body."""
    try:
        body = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url, data=body,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return json.dumps({"error": str(e)})


def _http_post_form(url: str, fields: dict, timeout: int = TIMEOUT) -> str:
    """Safe HTTP POST with application/x-www-form-urlencoded body."""
    try:
        body = urllib.parse.urlencode(fields).encode("utf-8")
        req = urllib.request.Request(
            url, data=body,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# malwoverview CLI helper
# ---------------------------------------------------------------------------

def _run_malwoverview(*args: str, timeout: int = 30) -> dict:
    """Run malwoverview CLI and return parsed result or error dict."""
    cmd = ["malwoverview"] + list(args)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "source": "malwoverview_cli",
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip() if proc.stdout else "",
            "stderr": proc.stderr.strip() if proc.stderr else "",
        }
    except FileNotFoundError:
        return {"source": "malwoverview_cli", "error": "malwoverview binary not found"}
    except subprocess.TimeoutExpired:
        return {"source": "malwoverview_cli", "error": "command timed out"}
    except Exception as e:
        return {"source": "malwoverview_cli", "error": str(e)}


# ---------------------------------------------------------------------------
# abuse.ch API helpers
# ---------------------------------------------------------------------------

MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
FEODO_TRACKER_API = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
FEODO_TRACKER_JSON = "https://feodotracker.abuse.ch/exports/json/recent/"


def _query_malwarebazaar_hash(hash_value: str) -> dict:
    """Query MalwareBazaar by hash."""
    raw = _http_post_form(MALWAREBAZAAR_API, {
        "query": "get_info",
        "hash": hash_value,
    })
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON from MalwareBazaar", "raw": raw[:500]}


def _query_urlhaus_url(url: str) -> dict:
    """Query URLhaus by URL."""
    raw = _http_post_form(f"{URLHAUS_API}/url/", {"url": url})
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON from URLhaus", "raw": raw[:500]}


def _query_urlhaus_host(host: str) -> dict:
    """Query URLhaus by host (domain or IP)."""
    raw = _http_post_form(f"{URLHAUS_API}/host/", {"host": host})
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON from URLhaus", "raw": raw[:500]}


def _query_threatfox_ioc(ioc: str) -> dict:
    """Query ThreatFox for an IOC."""
    raw = _http_post_json(THREATFOX_API, {
        "query": "search_ioc",
        "search_term": ioc,
    })
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON from ThreatFox", "raw": raw[:500]}


def _query_feodo_tracker_ip(ip: str) -> dict:
    """Check IP against Feodo Tracker blocklist."""
    try:
        raw = _http_get(FEODO_TRACKER_JSON)
        entries = json.loads(raw)
        matches = [e for e in entries if e.get("ip_address") == ip]
        if matches:
            return {
                "found": True,
                "source": "feodo_tracker",
                "matches": matches[:10],
            }
        return {"found": False, "source": "feodo_tracker"}
    except Exception as e:
        return {"error": str(e), "source": "feodo_tracker"}


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def malwoverview_hash_lookup(hash_value: str) -> str:
    """Look up a file hash (MD5, SHA1, or SHA256) for malware intelligence.

    Tries malwoverview CLI first, then falls back to the free MalwareBazaar
    (abuse.ch) API. No API key required.

    Args:
        hash_value: MD5, SHA1, or SHA256 hash of the file to look up.

    Returns:
        JSON string with lookup results from available sources.
    """
    try:
        hash_value = hash_value.strip().lower()
        results: dict = {
            "hash": hash_value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sources": {},
        }

        # Try malwoverview CLI
        cli_result = _run_malwoverview("-s", hash_value)
        if cli_result.get("stdout") and not cli_result.get("error"):
            results["sources"]["malwoverview_cli"] = cli_result

        # Query MalwareBazaar (free, no key)
        mb_result = _query_malwarebazaar_hash(hash_value)
        if mb_result.get("query_status") == "hash_not_found":
            results["sources"]["malwarebazaar"] = {
                "found": False,
                "message": "Hash not found in MalwareBazaar",
            }
        elif mb_result.get("query_status") == "ok" and mb_result.get("data"):
            entry = mb_result["data"][0] if isinstance(mb_result["data"], list) else mb_result["data"]
            results["sources"]["malwarebazaar"] = {
                "found": True,
                "sha256": entry.get("sha256_hash"),
                "sha1": entry.get("sha1_hash"),
                "md5": entry.get("md5_hash"),
                "file_type": entry.get("file_type"),
                "file_size": entry.get("file_size"),
                "signature": entry.get("signature"),
                "tags": entry.get("tags"),
                "first_seen": entry.get("first_seen"),
                "last_seen": entry.get("last_seen"),
                "reporter": entry.get("reporter"),
                "delivery_method": entry.get("delivery_method"),
                "intelligence": entry.get("intelligence"),
            }
        else:
            results["sources"]["malwarebazaar"] = mb_result

        # Query ThreatFox
        tf_result = _query_threatfox_ioc(hash_value)
        if tf_result.get("query_status") == "ok" and tf_result.get("data"):
            results["sources"]["threatfox"] = {
                "found": True,
                "entries": tf_result["data"][:5],
            }
        else:
            results["sources"]["threatfox"] = {"found": False}

        # Determine verdict
        found_anywhere = any(
            src.get("found") for src in results["sources"].values()
            if isinstance(src, dict)
        )
        results["verdict"] = "KNOWN MALWARE" if found_anywhere else "NOT FOUND in free databases"

        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e), "hash": hash_value})


@mcp.tool()
def malwoverview_domain_check(domain: str) -> str:
    """Check domain reputation using free threat intelligence sources.

    Queries URLhaus and ThreatFox (abuse.ch) for known malicious activity
    associated with the domain. No API key required.

    Args:
        domain: The domain name to check (e.g., 'example.com').

    Returns:
        JSON string with domain reputation results.
    """
    try:
        domain = domain.strip().lower()
        results: dict = {
            "domain": domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sources": {},
        }

        # URLhaus host lookup
        uh_result = _query_urlhaus_host(domain)
        if uh_result.get("query_status") == "no_results":
            results["sources"]["urlhaus"] = {
                "found": False,
                "message": "Domain not found in URLhaus",
            }
        elif uh_result.get("query_status") in ("is_host", "ok"):
            urls = uh_result.get("urls", [])
            results["sources"]["urlhaus"] = {
                "found": True,
                "urlhaus_reference": uh_result.get("urlhaus_reference"),
                "url_count": uh_result.get("url_count", len(urls)),
                "urls_online": uh_result.get("urls_online", 0),
                "blacklists": uh_result.get("blacklists"),
                "recent_urls": [
                    {
                        "url": u.get("url"),
                        "url_status": u.get("url_status"),
                        "threat": u.get("threat"),
                        "date_added": u.get("date_added"),
                        "tags": u.get("tags"),
                    }
                    for u in (urls[:10] if urls else [])
                ],
            }
        else:
            results["sources"]["urlhaus"] = uh_result

        # ThreatFox IOC search
        tf_result = _query_threatfox_ioc(domain)
        if tf_result.get("query_status") == "ok" and tf_result.get("data"):
            results["sources"]["threatfox"] = {
                "found": True,
                "ioc_count": len(tf_result["data"]),
                "entries": [
                    {
                        "ioc": e.get("ioc"),
                        "threat_type": e.get("threat_type"),
                        "malware": e.get("malware"),
                        "confidence_level": e.get("confidence_level"),
                        "first_seen": e.get("first_seen_utc"),
                        "last_seen": e.get("last_seen_utc"),
                        "tags": e.get("tags"),
                    }
                    for e in tf_result["data"][:10]
                ],
            }
        else:
            results["sources"]["threatfox"] = {"found": False}

        # Try malwoverview CLI
        cli_result = _run_malwoverview("-d", domain)
        if cli_result.get("stdout") and not cli_result.get("error"):
            results["sources"]["malwoverview_cli"] = cli_result

        # Verdict
        found_anywhere = any(
            src.get("found") for src in results["sources"].values()
            if isinstance(src, dict)
        )
        results["verdict"] = "SUSPICIOUS/MALICIOUS" if found_anywhere else "NOT FOUND in free databases"

        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e), "domain": domain})


@mcp.tool()
def malwoverview_ip_check(ip: str) -> str:
    """Check IP address reputation using free threat intelligence sources.

    Queries Feodo Tracker, URLhaus, and ThreatFox (abuse.ch) for known
    malicious activity associated with the IP. No API key required.

    Args:
        ip: The IPv4 address to check (e.g., '192.168.1.1').

    Returns:
        JSON string with IP reputation results.
    """
    try:
        ip = ip.strip()
        results: dict = {
            "ip": ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sources": {},
        }

        # Feodo Tracker
        feodo = _query_feodo_tracker_ip(ip)
        results["sources"]["feodo_tracker"] = feodo

        # URLhaus host lookup
        uh_result = _query_urlhaus_host(ip)
        if uh_result.get("query_status") == "no_results":
            results["sources"]["urlhaus"] = {
                "found": False,
                "message": "IP not found in URLhaus",
            }
        elif uh_result.get("query_status") in ("is_host", "ok"):
            urls = uh_result.get("urls", [])
            results["sources"]["urlhaus"] = {
                "found": True,
                "urlhaus_reference": uh_result.get("urlhaus_reference"),
                "url_count": uh_result.get("url_count", len(urls)),
                "urls_online": uh_result.get("urls_online", 0),
                "blacklists": uh_result.get("blacklists"),
                "recent_urls": [
                    {
                        "url": u.get("url"),
                        "url_status": u.get("url_status"),
                        "threat": u.get("threat"),
                        "date_added": u.get("date_added"),
                    }
                    for u in (urls[:10] if urls else [])
                ],
            }
        else:
            results["sources"]["urlhaus"] = uh_result

        # ThreatFox
        tf_result = _query_threatfox_ioc(ip)
        if tf_result.get("query_status") == "ok" and tf_result.get("data"):
            results["sources"]["threatfox"] = {
                "found": True,
                "entries": [
                    {
                        "ioc": e.get("ioc"),
                        "threat_type": e.get("threat_type"),
                        "malware": e.get("malware"),
                        "confidence_level": e.get("confidence_level"),
                        "tags": e.get("tags"),
                    }
                    for e in tf_result["data"][:10]
                ],
            }
        else:
            results["sources"]["threatfox"] = {"found": False}

        # Try malwoverview CLI
        cli_result = _run_malwoverview("-i", ip)
        if cli_result.get("stdout") and not cli_result.get("error"):
            results["sources"]["malwoverview_cli"] = cli_result

        # Verdict
        found_anywhere = any(
            src.get("found") for src in results["sources"].values()
            if isinstance(src, dict)
        )
        results["verdict"] = "SUSPICIOUS/MALICIOUS" if found_anywhere else "NOT FOUND in free databases"

        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e), "ip": ip})


@mcp.tool()
def malwoverview_url_check(url: str) -> str:
    """Check a URL against free threat intelligence sources.

    Queries URLhaus (abuse.ch) for known malicious URLs. No API key required.

    Args:
        url: The full URL to check (e.g., 'http://evil.com/malware.exe').

    Returns:
        JSON string with URL reputation results.
    """
    try:
        results: dict = {
            "url": url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sources": {},
        }

        # URLhaus URL lookup
        uh_result = _query_urlhaus_url(url)
        if uh_result.get("query_status") == "no_results":
            results["sources"]["urlhaus"] = {
                "found": False,
                "message": "URL not found in URLhaus",
            }
        elif uh_result.get("query_status") in ("ok", "url_found"):
            payloads = uh_result.get("payloads", [])
            results["sources"]["urlhaus"] = {
                "found": True,
                "urlhaus_reference": uh_result.get("urlhaus_reference"),
                "url_status": uh_result.get("url_status"),
                "threat": uh_result.get("threat"),
                "date_added": uh_result.get("date_added"),
                "host": uh_result.get("host"),
                "tags": uh_result.get("tags"),
                "blacklists": uh_result.get("blacklists"),
                "payloads": [
                    {
                        "filename": p.get("filename"),
                        "file_type": p.get("file_type"),
                        "sha256": p.get("response_sha256"),
                        "signature": p.get("signature"),
                        "virustotal_percent": p.get("virustotal", {}).get("percent") if isinstance(p.get("virustotal"), dict) else None,
                    }
                    for p in (payloads[:10] if payloads else [])
                ],
            }
        else:
            results["sources"]["urlhaus"] = uh_result

        # Extract host from URL and check ThreatFox
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or ""
        except Exception:
            host = ""

        if host:
            tf_result = _query_threatfox_ioc(host)
            if tf_result.get("query_status") == "ok" and tf_result.get("data"):
                results["sources"]["threatfox"] = {
                    "found": True,
                    "entries": tf_result["data"][:5],
                }
            else:
                results["sources"]["threatfox"] = {"found": False}

        # Try malwoverview CLI
        cli_result = _run_malwoverview("-u", url)
        if cli_result.get("stdout") and not cli_result.get("error"):
            results["sources"]["malwoverview_cli"] = cli_result

        # Verdict
        found_anywhere = any(
            src.get("found") for src in results["sources"].values()
            if isinstance(src, dict)
        )
        results["verdict"] = "MALICIOUS/SUSPICIOUS" if found_anywhere else "NOT FOUND in free databases"

        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e), "url": url})


@mcp.tool()
def malwoverview_sample_download_info(hash_value: str) -> str:
    """Get download information for a known malware sample from MalwareBazaar.

    Retrieves detailed sample metadata including download link, tags,
    signature, file type, and intelligence data. No API key required.

    Args:
        hash_value: MD5, SHA1, or SHA256 hash of the malware sample.

    Returns:
        JSON string with sample download info and metadata.
    """
    try:
        hash_value = hash_value.strip().lower()
        results: dict = {
            "hash": hash_value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        mb_result = _query_malwarebazaar_hash(hash_value)

        if mb_result.get("query_status") == "hash_not_found":
            results["found"] = False
            results["message"] = "Sample not found in MalwareBazaar"
            return json.dumps(results, indent=2)

        if mb_result.get("query_status") == "ok" and mb_result.get("data"):
            entry = mb_result["data"][0] if isinstance(mb_result["data"], list) else mb_result["data"]
            results["found"] = True
            results["sample"] = {
                "sha256": entry.get("sha256_hash"),
                "sha1": entry.get("sha1_hash"),
                "md5": entry.get("md5_hash"),
                "file_name": entry.get("file_name"),
                "file_type": entry.get("file_type"),
                "file_type_mime": entry.get("file_type_mime"),
                "file_size": entry.get("file_size"),
                "signature": entry.get("signature"),
                "tags": entry.get("tags"),
                "first_seen": entry.get("first_seen"),
                "last_seen": entry.get("last_seen"),
                "reporter": entry.get("reporter"),
                "origin_country": entry.get("origin_country"),
                "delivery_method": entry.get("delivery_method"),
                "comment": entry.get("comment"),
                "intelligence": entry.get("intelligence"),
            }
            # MalwareBazaar download link
            sha256 = entry.get("sha256_hash", hash_value)
            results["download"] = {
                "url": f"https://mb-api.abuse.ch/api/v1/?query=get_file&sha256_hash={sha256}",
                "method": "POST",
                "note": "POST with query=get_file&sha256_hash=<hash>. File is ZIP-encrypted with password 'infected'.",
                "password": "infected",
            }
        else:
            results["found"] = False
            results["raw_response"] = mb_result

        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e), "hash": hash_value})


@mcp.tool()
def malwoverview_triage(file_path: str) -> str:
    """Quick triage of a local file - compute hashes and check threat intel.

    Computes MD5, SHA1, SHA256 of the file, then checks MalwareBazaar and
    ThreatFox for matches. No API key required.

    Args:
        file_path: Absolute path to the local file to triage.

    Returns:
        JSON string with file hashes, threat intel matches, and verdict.
    """
    try:
        file_path = file_path.strip()
        results: dict = {
            "file_path": file_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Verify file exists
        if not os.path.isfile(file_path):
            results["error"] = "File not found"
            return json.dumps(results, indent=2)

        # Compute hashes
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        file_size = 0

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                file_size += len(chunk)
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        hashes = {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
        results["file_info"] = {
            "name": os.path.basename(file_path),
            "size_bytes": file_size,
            "hashes": hashes,
        }

        results["sources"] = {}

        # Check MalwareBazaar by SHA256
        mb_result = _query_malwarebazaar_hash(hashes["sha256"])
        if mb_result.get("query_status") == "ok" and mb_result.get("data"):
            entry = mb_result["data"][0] if isinstance(mb_result["data"], list) else mb_result["data"]
            results["sources"]["malwarebazaar"] = {
                "found": True,
                "signature": entry.get("signature"),
                "file_type": entry.get("file_type"),
                "tags": entry.get("tags"),
                "first_seen": entry.get("first_seen"),
                "intelligence": entry.get("intelligence"),
            }
        else:
            results["sources"]["malwarebazaar"] = {"found": False}

        # Check ThreatFox by SHA256
        tf_result = _query_threatfox_ioc(hashes["sha256"])
        if tf_result.get("query_status") == "ok" and tf_result.get("data"):
            results["sources"]["threatfox"] = {
                "found": True,
                "entries": tf_result["data"][:5],
            }
        else:
            results["sources"]["threatfox"] = {"found": False}

        # Also try MD5 on MalwareBazaar if SHA256 was not found
        if not results["sources"]["malwarebazaar"].get("found"):
            mb_md5 = _query_malwarebazaar_hash(hashes["md5"])
            if mb_md5.get("query_status") == "ok" and mb_md5.get("data"):
                entry = mb_md5["data"][0] if isinstance(mb_md5["data"], list) else mb_md5["data"]
                results["sources"]["malwarebazaar"] = {
                    "found": True,
                    "matched_on": "md5",
                    "signature": entry.get("signature"),
                    "file_type": entry.get("file_type"),
                    "tags": entry.get("tags"),
                    "first_seen": entry.get("first_seen"),
                    "intelligence": entry.get("intelligence"),
                }

        # Verdict
        found_anywhere = any(
            src.get("found") for src in results["sources"].values()
            if isinstance(src, dict)
        )
        if found_anywhere:
            results["verdict"] = "KNOWN MALWARE - matches found in threat intel databases"
        else:
            results["verdict"] = "UNKNOWN - no matches in free threat intel databases (not necessarily safe)"

        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e), "file_path": file_path})


@mcp.tool()
def malwoverview_yara_from_report(report_text: str) -> str:
    """Generate a basic YARA rule skeleton from analysis report text.

    Extracts strings, IOCs (hashes, IPs, domains, URLs), and creates a
    YARA rule template that can be refined by an analyst.

    Args:
        report_text: Analysis report text to extract IOCs and strings from.

    Returns:
        JSON string containing the generated YARA rule and extracted IOCs.
    """
    try:
        results: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "extracted_iocs": {},
        }

        # Extract IOCs using regex
        sha256_hashes = list(set(re.findall(r'\b[A-Fa-f0-9]{64}\b', report_text)))
        sha1_hashes = list(set(re.findall(r'\b[A-Fa-f0-9]{40}\b', report_text)))
        md5_hashes = list(set(re.findall(r'\b[A-Fa-f0-9]{32}\b', report_text)))

        # Remove SHA256 substrings from SHA1 matches and SHA1 from MD5
        sha1_hashes = [h for h in sha1_hashes if h not in ''.join(sha256_hashes)]
        md5_hashes = [h for h in md5_hashes if h not in ''.join(sha1_hashes) and h not in ''.join(sha256_hashes)]

        ipv4s = list(set(re.findall(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
            report_text
        )))

        domains = list(set(re.findall(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw|su|de|uk|fr|nl|br|in)\b',
            report_text
        )))

        urls = list(set(re.findall(
            r'https?://[^\s<>"\')\]]+',
            report_text
        )))

        # Extract interesting strings (quoted strings, file paths, registry keys)
        quoted_strings = list(set(re.findall(r'"([^"]{4,80})"', report_text)))
        file_paths = list(set(re.findall(
            r'(?:[A-Za-z]:\\[\w\\. -]+|/(?:tmp|var|etc|usr|home)/[\w/. -]+)',
            report_text
        )))
        registry_keys = list(set(re.findall(
            r'(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s"\']+',
            report_text
        )))

        # Extract malware family names (common pattern: capitalized names near "malware", "trojan", etc)
        malware_names = list(set(re.findall(
            r'\b(?:(?:Trojan|Backdoor|Ransomware|Worm|Dropper|Loader|Stealer|RAT|Miner)[.:/ ]+)?([A-Z][a-zA-Z0-9]{2,20}(?:\.[A-Z][a-zA-Z0-9]+)*)\b',
            report_text
        )))
        # Filter out common English words
        common_words = {
            "The", "This", "That", "These", "Those", "From", "With", "About",
            "After", "Before", "Where", "When", "Which", "While", "Because",
            "However", "File", "Hash", "Domain", "Address", "Report", "Analysis",
            "Sample", "Note", "Figure", "Table", "Section", "Source", "Type",
            "Data", "Info", "Date", "Time", "Name", "Value", "Result",
            "Windows", "Linux", "System", "Process", "Network", "String",
            "True", "False", "None", "Unknown", "Not", "Found",
        }
        malware_names = [n for n in malware_names if n not in common_words][:10]

        results["extracted_iocs"] = {
            "sha256_hashes": sha256_hashes[:20],
            "sha1_hashes": sha1_hashes[:20],
            "md5_hashes": md5_hashes[:20],
            "ipv4_addresses": ipv4s[:20],
            "domains": domains[:20],
            "urls": urls[:20],
            "file_paths": file_paths[:20],
            "registry_keys": registry_keys[:20],
            "quoted_strings": quoted_strings[:20],
            "possible_malware_names": malware_names[:10],
        }

        # Generate YARA rule
        rule_name = "generated_rule"
        if malware_names:
            safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', malware_names[0])
            rule_name = f"mal_{safe_name}"

        yara_lines = []
        yara_lines.append(f'rule {rule_name}')
        yara_lines.append('{')
        yara_lines.append('    meta:')
        yara_lines.append(f'        description = "Auto-generated YARA rule from report analysis"')
        yara_lines.append(f'        date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"')
        yara_lines.append(f'        author = "BlueTeamAssistant (auto-generated)"')
        if malware_names:
            yara_lines.append(f'        malware_family = "{malware_names[0]}"')
        yara_lines.append(f'        hash_count = "{len(sha256_hashes)}"')
        yara_lines.append('')
        yara_lines.append('    strings:')

        str_idx = 0

        # Add notable quoted strings
        for s in quoted_strings[:8]:
            safe_s = s.replace('\\', '\\\\').replace('"', '\\"')
            yara_lines.append(f'        $s{str_idx} = "{safe_s}" ascii wide nocase')
            str_idx += 1

        # Add file paths
        for fp in file_paths[:4]:
            safe_fp = fp.replace('\\', '\\\\').replace('"', '\\"')
            yara_lines.append(f'        $s{str_idx} = "{safe_fp}" ascii wide')
            str_idx += 1

        # Add registry keys
        for rk in registry_keys[:4]:
            safe_rk = rk.replace('\\', '\\\\').replace('"', '\\"')
            yara_lines.append(f'        $s{str_idx} = "{safe_rk}" ascii wide')
            str_idx += 1

        # Add domains as strings
        for d in domains[:4]:
            yara_lines.append(f'        $s{str_idx} = "{d}" ascii wide')
            str_idx += 1

        # Add IPs as strings
        for ip in ipv4s[:4]:
            yara_lines.append(f'        $s{str_idx} = "{ip}" ascii wide')
            str_idx += 1

        if str_idx == 0:
            yara_lines.append('        $placeholder = "REPLACE_WITH_ACTUAL_STRING" ascii wide')
            str_idx = 1

        yara_lines.append('')
        yara_lines.append('    condition:')
        if str_idx <= 3:
            yara_lines.append(f'        any of them')
        else:
            threshold = max(2, str_idx // 3)
            yara_lines.append(f'        {threshold} of them')
        yara_lines.append('}')

        yara_rule = '\n'.join(yara_lines)

        results["yara_rule"] = yara_rule
        results["note"] = (
            "This is an auto-generated YARA rule skeleton. "
            "Review and refine strings, adjust the condition threshold, "
            "and test against known samples before deploying."
        )

        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Run the malwoverview MCP server via stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
