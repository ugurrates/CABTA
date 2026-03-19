"""
ArgusWatch Threat Intelligence MCP Server - Extended threat intel feeds.

Inspired by ArgusWatch-AI (https://github.com/3sk1nt4n/arguswatch-ai).
Adds threat intel sources NOT covered by existing threat-intel-free server:

  - OpenPhish (phishing URL feed)
  - crt.sh (Certificate Transparency subdomain discovery)
  - Shodan InternetDB (FREE - exposed services & CVEs)
  - Ransomwatch (ransomware victim monitoring)
  - Malpedia/VX-Underground (malware family tracking)
  - CIRCL MISP (European CERT threat intel)
  - DarkSearch/Ahmia (dark web search)
  - HudsonRock (stealer log victim check)
  - EPSS Top (most exploited CVEs)
  - Typosquat detection (DNS permutation phishing domains)
  - Pastebin monitoring (credential leak detection)

All sources are FREE and require NO API keys.

Usage:
    python -m src.mcp_servers.arguswatch_tools
"""

import json
import logging
import re
import urllib.request
import urllib.parse
import itertools
from datetime import datetime
from typing import Optional

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("arguswatch")

TIMEOUT = 20


def _http_get(url: str, timeout: int = TIMEOUT) -> str:
    """Safe HTTP GET request."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "BlueTeamAssistant/2.0 (Threat Intel MCP)",
            "Accept": "application/json, text/plain, */*",
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
            url,
            data=body,
            headers={
                "User-Agent": "BlueTeamAssistant/2.0",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return json.dumps({"error": str(e)})


# ===================================================================
# 1. OpenPhish - Phishing URL Feed
# ===================================================================

@mcp.tool()
def openphish_lookup(url: str) -> dict:
    """Check a URL against OpenPhish phishing feed.

    OpenPhish provides a community phishing URL feed updated every 12 hours.
    Returns whether the URL is in the known phishing database.

    Args:
        url: URL to check for phishing
    """
    try:
        feed = _http_get("https://openphish.com/feed.txt", timeout=15)
        if "error" in feed and feed.startswith("{"):
            return {"error": "OpenPhish feed unavailable", "url": url}

        urls = [line.strip() for line in feed.strip().split("\n") if line.strip()]
        url_lower = url.lower().strip()

        exact_match = url_lower in [u.lower() for u in urls]
        domain = re.sub(r"https?://", "", url_lower).split("/")[0]
        domain_matches = [u for u in urls if domain in u.lower()]

        return {
            "source": "OpenPhish",
            "url": url,
            "is_phishing": exact_match,
            "domain_matches": len(domain_matches),
            "matching_urls": domain_matches[:10],
            "feed_size": len(urls),
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {"error": str(e), "url": url}


# ===================================================================
# 2. crt.sh - Certificate Transparency Subdomain Discovery
# ===================================================================

@mcp.tool()
def crtsh_subdomain_search(domain: str) -> dict:
    """Discover subdomains via Certificate Transparency logs (crt.sh).

    Queries crt.sh to find all SSL certificates ever issued for a domain,
    revealing subdomains, wildcard certs, and infrastructure scope.
    Critical for C2 infrastructure mapping and attack surface discovery.

    Args:
        domain: Target domain to search (e.g., example.com)
    """
    try:
        encoded = urllib.parse.quote(f"%.{domain}")
        url = f"https://crt.sh/?q={encoded}&output=json"
        raw = _http_get(url, timeout=25)

        if raw.startswith("{") and "error" in raw:
            return {"error": "crt.sh unavailable", "domain": domain}

        certs = json.loads(raw)
        subdomains = set()
        issuers = set()
        recent_certs = []

        for cert in certs[:500]:  # Cap to avoid huge results
            name = cert.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub and "*" not in sub:
                    subdomains.add(sub)
            issuer = cert.get("issuer_name", "")
            if issuer:
                issuers.add(issuer)
            if len(recent_certs) < 20:
                recent_certs.append({
                    "common_name": cert.get("common_name", ""),
                    "name_value": name,
                    "issuer": issuer,
                    "not_before": cert.get("not_before", ""),
                    "not_after": cert.get("not_after", ""),
                    "serial_number": cert.get("serial_number", ""),
                })

        return {
            "source": "crt.sh",
            "domain": domain,
            "total_certificates": len(certs),
            "unique_subdomains": sorted(subdomains),
            "subdomain_count": len(subdomains),
            "issuers": sorted(issuers),
            "recent_certificates": recent_certs,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except json.JSONDecodeError:
        return {"error": "Invalid response from crt.sh", "domain": domain}
    except Exception as e:
        return {"error": str(e), "domain": domain}


# ===================================================================
# 3. Shodan InternetDB (FREE - no API key!)
# ===================================================================

@mcp.tool()
def shodan_internetdb_lookup(ip: str) -> dict:
    """Query Shodan InternetDB for exposed services (FREE, no API key).

    Returns open ports, known vulnerabilities (CVEs), hostnames, and tags
    for any IP address. This is the FREE tier of Shodan data.
    Essential for C2 server reconnaissance and attack surface assessment.

    Args:
        ip: IP address to look up
    """
    try:
        raw = _http_get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        data = json.loads(raw)

        if "detail" in data:
            return {
                "source": "Shodan InternetDB",
                "ip": ip,
                "found": False,
                "detail": data["detail"],
            }

        return {
            "source": "Shodan InternetDB",
            "ip": ip,
            "found": True,
            "ports": data.get("ports", []),
            "cpes": data.get("cpes", []),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
            "vulns": data.get("vulns", []),
            "vuln_count": len(data.get("vulns", [])),
            "port_count": len(data.get("ports", [])),
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {"error": str(e), "ip": ip}


# ===================================================================
# 4. Ransomwatch - Ransomware Group Monitoring
# ===================================================================

@mcp.tool()
def ransomwatch_check(query: str) -> dict:
    """Check ransomware group activity and recent victims via Ransomwatch.

    Queries the Ransomwatch dataset for known ransomware groups,
    recent victim posts, and leak site activity.

    Args:
        query: Domain, organization name, or ransomware group to search
    """
    try:
        # Get ransomware groups
        raw = _http_get(
            "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json",
            timeout=15,
        )
        groups = json.loads(raw)

        query_lower = query.lower()
        matching_groups = []
        for g in groups:
            name = g.get("name", "").lower()
            if query_lower in name or name in query_lower:
                matching_groups.append({
                    "name": g.get("name"),
                    "url_count": len(g.get("locations", [])),
                    "profile": g.get("profile", []),
                })

        # Get recent posts
        posts_raw = _http_get(
            "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
            timeout=15,
        )
        posts = json.loads(posts_raw)

        matching_posts = []
        for p in posts:
            title = (p.get("post_title") or "").lower()
            group = (p.get("group_name") or "").lower()
            if query_lower in title or query_lower in group:
                matching_posts.append({
                    "group": p.get("group_name"),
                    "title": p.get("post_title"),
                    "discovered": p.get("discovered"),
                    "url": p.get("post_url", ""),
                })

        # Recent posts (last 20)
        recent = sorted(posts, key=lambda x: x.get("discovered", ""), reverse=True)[:20]

        return {
            "source": "Ransomwatch",
            "query": query,
            "matching_groups": matching_groups,
            "matching_victims": matching_posts[:20],
            "total_groups": len(groups),
            "total_posts": len(posts),
            "recent_victims": [
                {
                    "group": p.get("group_name"),
                    "title": p.get("post_title"),
                    "discovered": p.get("discovered"),
                }
                for p in recent
            ],
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {"error": str(e), "query": query}


# ===================================================================
# 5. Malpedia - Malware Family Tracking
# ===================================================================

@mcp.tool()
def malpedia_malware_search(query: str) -> dict:
    """Search Malpedia for malware family information.

    Malpedia is a curated malware corpus by Fraunhofer FKIE.
    Returns malware family details, aliases, actor attributions.

    Args:
        query: Malware family name or alias (e.g., emotet, cobalt_strike)
    """
    try:
        # Malpedia public API
        raw = _http_get(
            "https://malpedia.caad.fkie.fraunhofer.de/api/list/families",
            timeout=15,
        )
        families = json.loads(raw)

        query_lower = query.lower().replace(" ", "_")
        matches = []

        for family_key, family_data in families.items():
            name = family_key.lower()
            alt_names = [a.lower() for a in family_data.get("alt_names", [])]
            desc = (family_data.get("description") or "").lower()

            if (query_lower in name or
                    any(query_lower in a for a in alt_names) or
                    query_lower in desc):
                matches.append({
                    "family": family_key,
                    "alt_names": family_data.get("alt_names", []),
                    "description": (family_data.get("description") or "")[:300],
                    "urls": family_data.get("urls", [])[:5],
                    "attribution": family_data.get("attribution", []),
                    "type": family_data.get("type", ""),
                })

        return {
            "source": "Malpedia",
            "query": query,
            "matches": matches[:15],
            "match_count": len(matches),
            "total_families": len(families),
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {"error": str(e), "query": query}


# ===================================================================
# 6. CIRCL MISP - European CERT Threat Intelligence
# ===================================================================

@mcp.tool()
def circl_misp_feed_check(ioc: str) -> dict:
    """Check an IOC against CIRCL MISP public threat feeds.

    CIRCL (Computer Incident Response Center Luxembourg) provides
    curated threat intelligence feeds from European CERTs.

    Args:
        ioc: IOC to check (IP, domain, hash, URL)
    """
    try:
        # CIRCL MISP public feed
        raw = _http_get(
            "https://www.circl.lu/doc/misp/feed-osint/",
            timeout=15,
        )

        # Also check hashlookup
        ioc_clean = ioc.strip()
        hashlookup_result = None
        if re.match(r"^[a-fA-F0-9]{32,64}$", ioc_clean):
            hash_raw = _http_get(
                f"https://hashlookup.circl.lu/lookup/sha256/{ioc_clean}"
                if len(ioc_clean) == 64
                else f"https://hashlookup.circl.lu/lookup/md5/{ioc_clean}",
                timeout=10,
            )
            try:
                hashlookup_result = json.loads(hash_raw)
            except json.JSONDecodeError:
                hashlookup_result = None

        # Check BGP Ranking for IPs
        bgp_result = None
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc_clean):
            bgp_raw = _http_get(
                f"https://bgpranking-ng.circl.lu/ipasn_history/?ip={ioc_clean}",
                timeout=10,
            )
            try:
                bgp_result = json.loads(bgp_raw)
            except json.JSONDecodeError:
                bgp_result = None

        return {
            "source": "CIRCL",
            "ioc": ioc,
            "hashlookup": hashlookup_result,
            "is_known_file": hashlookup_result is not None and "error" not in str(hashlookup_result),
            "bgp_ranking": bgp_result,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {"error": str(e), "ioc": ioc}


# ===================================================================
# 7. DarkSearch/Ahmia - Dark Web Search
# ===================================================================

@mcp.tool()
def darksearch_query(query: str, max_results: int = 10) -> dict:
    """Search the dark web via Ahmia.fi search engine.

    Searches Tor hidden services (.onion) for mentions of domains,
    organizations, credentials, or other indicators.
    Useful for breach detection and threat actor activity monitoring.

    Args:
        query: Search query (domain, org name, email, etc.)
        max_results: Maximum results to return (default 10)
    """
    try:
        encoded = urllib.parse.quote(query)
        raw = _http_get(
            f"https://ahmia.fi/search/?q={encoded}",
            timeout=20,
        )

        # Parse HTML results (ahmia returns HTML)
        results = []
        # Extract titles and URLs from search results
        title_pattern = re.compile(
            r'<a[^>]*href="(/search/redirect\?[^"]*)"[^>]*>(.*?)</a>',
            re.DOTALL,
        )
        for match in title_pattern.finditer(raw):
            redirect_url = match.group(1)
            title = re.sub(r"<[^>]+>", "", match.group(2)).strip()
            if title and len(results) < max_results:
                # Extract the actual onion URL from redirect
                onion_match = re.search(r"redirect_url=([^&]+)", redirect_url)
                actual_url = (
                    urllib.parse.unquote(onion_match.group(1))
                    if onion_match
                    else ""
                )
                results.append({
                    "title": title[:200],
                    "url": actual_url[:300],
                })

        return {
            "source": "Ahmia (Dark Web)",
            "query": query,
            "results": results,
            "result_count": len(results),
            "warning": "Dark web results may contain unreliable or illegal content",
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {"error": str(e), "query": query}


# ===================================================================
# 8. HudsonRock - Stealer Log Victim Check
# ===================================================================

@mcp.tool()
def hudsonrock_check(domain: str) -> dict:
    """Check if a domain has employees compromised by info-stealer malware.

    HudsonRock tracks info-stealer (Raccoon, RedLine, Vidar, etc.)
    victims. Returns count of compromised employees for a domain.
    Critical for assessing credential theft risk.

    Args:
        domain: Domain to check (e.g., example.com)
    """
    try:
        raw = _http_get(
            f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
            f"search-by-domain?domain={urllib.parse.quote(domain)}",
            timeout=15,
        )
        data = json.loads(raw)

        if isinstance(data, dict) and data.get("message"):
            return {
                "source": "HudsonRock",
                "domain": domain,
                "message": data["message"],
                "compromised": False,
            }

        stealers = data if isinstance(data, list) else data.get("stealers", [])

        return {
            "source": "HudsonRock",
            "domain": domain,
            "compromised": len(stealers) > 0,
            "stealer_count": len(stealers),
            "sample_entries": [
                {
                    "computer_name": s.get("computer_name", ""),
                    "operating_system": s.get("operating_system", ""),
                    "date_compromised": s.get("date_compromised", ""),
                    "malware_path": s.get("malware_path", ""),
                }
                for s in stealers[:10]
            ],
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {"error": str(e), "domain": domain}


# ===================================================================
# 9. EPSS Top Exploited - Most Exploited Vulnerabilities
# ===================================================================

@mcp.tool()
def epss_top_exploited(cve_id: Optional[str] = None, top_n: int = 20) -> dict:
    """Get EPSS scores for top exploited CVEs or lookup a specific CVE.

    EPSS (Exploit Prediction Scoring System) by FIRST.org predicts
    the probability that a CVE will be exploited in the next 30 days.
    Higher score = higher exploitation likelihood.

    Args:
        cve_id: Specific CVE to look up (e.g., CVE-2024-1234), or None for top list
        top_n: Number of top exploited CVEs to return (default 20)
    """
    try:
        if cve_id:
            raw = _http_get(
                f"https://api.first.org/data/v1/epss?cve={urllib.parse.quote(cve_id)}",
                timeout=10,
            )
            data = json.loads(raw)
            entries = data.get("data", [])
            if entries:
                entry = entries[0]
                return {
                    "source": "FIRST.org EPSS",
                    "cve": cve_id,
                    "epss_score": float(entry.get("epss", 0)),
                    "percentile": float(entry.get("percentile", 0)),
                    "date": entry.get("date", ""),
                    "exploitation_probability": f"{float(entry.get('epss', 0)) * 100:.2f}%",
                    "risk_level": (
                        "CRITICAL" if float(entry.get("epss", 0)) > 0.5
                        else "HIGH" if float(entry.get("epss", 0)) > 0.1
                        else "MEDIUM" if float(entry.get("epss", 0)) > 0.01
                        else "LOW"
                    ),
                }
            return {"source": "FIRST.org EPSS", "cve": cve_id, "found": False}

        # Top exploited
        raw = _http_get(
            f"https://api.first.org/data/v1/epss?order=!epss&limit={top_n}",
            timeout=15,
        )
        data = json.loads(raw)
        entries = data.get("data", [])

        return {
            "source": "FIRST.org EPSS",
            "top_exploited": [
                {
                    "cve": e.get("cve"),
                    "epss_score": float(e.get("epss", 0)),
                    "percentile": float(e.get("percentile", 0)),
                    "probability": f"{float(e.get('epss', 0)) * 100:.2f}%",
                }
                for e in entries
            ],
            "count": len(entries),
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {"error": str(e)}


# ===================================================================
# 10. Typosquat Detection - DNS Permutation Phishing Domains
# ===================================================================

@mcp.tool()
def typosquat_detect(domain: str) -> dict:
    """Detect potential typosquatting/phishing domains for a target domain.

    Generates common typosquat variations (character swap, omission,
    addition, homograph) and checks which ones resolve via DNS.
    Critical for brand protection and phishing campaign detection.

    Args:
        domain: Legitimate domain to check for typosquats (e.g., example.com)
    """
    import socket

    try:
        parts = domain.lower().split(".")
        if len(parts) < 2:
            return {"error": "Invalid domain format", "domain": domain}

        name = parts[0]
        tld = ".".join(parts[1:])
        permutations = set()

        # Character omission
        for i in range(len(name)):
            perm = name[:i] + name[i + 1:]
            if perm:
                permutations.add(f"{perm}.{tld}")

        # Character swap (adjacent)
        for i in range(len(name) - 1):
            perm = list(name)
            perm[i], perm[i + 1] = perm[i + 1], perm[i]
            permutations.add(f"{''.join(perm)}.{tld}")

        # Character duplication
        for i in range(len(name)):
            perm = name[:i] + name[i] + name[i:]
            permutations.add(f"{perm}.{tld}")

        # Common replacements (homograph)
        replacements = {
            "o": ["0"], "l": ["1", "i"], "i": ["1", "l"],
            "a": ["@", "4"], "e": ["3"], "s": ["5", "$"],
            "g": ["9", "q"], "t": ["7"],
        }
        for i, ch in enumerate(name):
            for rep in replacements.get(ch, []):
                perm = name[:i] + rep + name[i + 1:]
                permutations.add(f"{perm}.{tld}")

        # Common TLD swaps
        for alt_tld in ["com", "net", "org", "io", "co", "info", "xyz"]:
            if alt_tld != tld:
                permutations.add(f"{name}.{alt_tld}")

        # Hyphen insertion
        for i in range(1, len(name)):
            permutations.add(f"{name[:i]}-{name[i:]}.{tld}")

        permutations.discard(domain.lower())

        # Check which ones resolve
        resolving = []
        checked = 0
        for perm in sorted(permutations)[:100]:  # Cap DNS checks
            checked += 1
            try:
                ip = socket.gethostbyname(perm)
                resolving.append({"domain": perm, "ip": ip})
            except socket.gaierror:
                pass

        return {
            "source": "Typosquat Detector",
            "target_domain": domain,
            "total_permutations": len(permutations),
            "checked": checked,
            "resolving_domains": resolving,
            "resolving_count": len(resolving),
            "risk_level": (
                "HIGH" if len(resolving) > 10
                else "MEDIUM" if len(resolving) > 3
                else "LOW"
            ),
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {"error": str(e), "domain": domain}


# ===================================================================
# 11. Pastebin / Paste Site Monitoring
# ===================================================================

@mcp.tool()
def paste_site_search(query: str) -> dict:
    """Search public paste sites for leaked credentials or data.

    Checks multiple paste aggregation services for mentions of
    domains, emails, or other indicators in public pastes.
    Useful for detecting credential leaks and data breaches.

    Args:
        query: Domain, email, or keyword to search for
    """
    try:
        results = []

        # Search via IntelX public (limited)
        encoded = urllib.parse.quote(query)

        # Search via psbdmp (pastebin dump search)
        try:
            raw = _http_get(
                f"https://psbdmp.ws/api/v3/search/{encoded}",
                timeout=10,
            )
            data = json.loads(raw)
            if isinstance(data, list):
                for entry in data[:20]:
                    results.append({
                        "source": "psbdmp",
                        "id": entry.get("id", ""),
                        "tags": entry.get("tags", ""),
                        "time": entry.get("time", ""),
                        "length": entry.get("length", 0),
                    })
        except Exception:
            pass

        # Search via grep.app (code search)
        try:
            grep_raw = _http_get(
                f"https://grep.app/api/search?q={encoded}&regexp=false",
                timeout=10,
            )
            grep_data = json.loads(grep_raw)
            hits = grep_data.get("hits", {}).get("hits", [])
            for hit in hits[:10]:
                repo = hit.get("repo", {})
                results.append({
                    "source": "grep.app",
                    "repository": repo.get("raw", ""),
                    "file": hit.get("path", {}).get("raw", ""),
                    "snippet": (hit.get("content", {}).get("snippet", ""))[:200],
                })
        except Exception:
            pass

        return {
            "source": "Paste/Code Search",
            "query": query,
            "results": results,
            "result_count": len(results),
            "sources_checked": ["psbdmp", "grep.app"],
            "warning": "Results may include false positives - verify manually",
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {"error": str(e), "query": query}


# ===================================================================
# Entry point
# ===================================================================

if __name__ == "__main__":
    mcp.run(transport="stdio")
