"""
OSINT Tools MCP Server - Open-source intelligence gathering via MCP.

Tools: WHOIS, DNS, GeoIP, reverse DNS, domain age, email validation,
       subdomain enumeration, HTTP header analysis, SSL certificate info.

No API keys required - uses free public services and Python stdlib.

Usage:
    python -m src.mcp_servers.osint_tools
"""

import json
import logging
import re
import socket
import ssl
import struct
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("osint-tools")


def _safe_request(url: str, timeout: int = 10) -> str:
    """Make a safe HTTP GET request."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "BlueTeamAssistant/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def whois_lookup(target: str) -> str:
    """Perform WHOIS lookup for a domain or IP address.

    Args:
        target: Domain name or IP address to look up
    """
    target = target.strip().lower()

    # Determine WHOIS server
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        whois_server = "whois.arin.net"
    else:
        # Try to get WHOIS server from IANA
        tld = target.rsplit(".", 1)[-1] if "." in target else target
        whois_server_map = {
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "info": "whois.afilias.net",
            "io": "whois.nic.io",
            "dev": "whois.nic.google",
            "app": "whois.nic.google",
            "xyz": "whois.nic.xyz",
            "me": "whois.nic.me",
            "co": "whois.nic.co",
            "uk": "whois.nic.uk",
            "de": "whois.denic.de",
            "ru": "whois.tcinet.ru",
            "cn": "whois.cnnic.cn",
            "tr": "whois.nic.tr",
        }
        whois_server = whois_server_map.get(tld, f"whois.nic.{tld}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((whois_server, 43))
        sock.sendall((target + "\r\n").encode())

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()

        text = response.decode("utf-8", errors="replace")

        # Parse key fields
        result = {
            "target": target,
            "whois_server": whois_server,
            "raw": text[:5000],
        }

        # Extract common fields
        for field_name, patterns in {
            "registrar": [r"Registrar:\s*(.+)", r"registrar:\s*(.+)"],
            "creation_date": [r"Creation Date:\s*(.+)", r"created:\s*(.+)", r"Registered on:\s*(.+)"],
            "expiry_date": [r"Registry Expiry Date:\s*(.+)", r"Expiry Date:\s*(.+)", r"expires:\s*(.+)"],
            "name_servers": [r"Name Server:\s*(.+)"],
            "status": [r"Status:\s*(.+)", r"Domain Status:\s*(.+)"],
            "registrant_org": [r"Registrant Organization:\s*(.+)"],
            "registrant_country": [r"Registrant Country:\s*(.+)"],
        }.items():
            values = []
            for pattern in patterns:
                values.extend(re.findall(pattern, text, re.IGNORECASE))
            if values:
                result[field_name] = values if len(values) > 1 else values[0]

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": f"WHOIS lookup failed: {e}", "target": target})


@mcp.tool()
def dns_resolve(domain: str, record_types: str = "A,AAAA,MX,NS,TXT,CNAME") -> str:
    """Resolve DNS records for a domain.

    Args:
        domain: Domain name to resolve
        record_types: Comma-separated DNS record types to query
    """
    domain = domain.strip().lower()
    results = {"domain": domain, "records": {}}

    # A record via socket
    try:
        ips = socket.getaddrinfo(domain, None)
        ipv4 = list(set(addr[4][0] for addr in ips if addr[0] == socket.AF_INET))
        ipv6 = list(set(addr[4][0] for addr in ips if addr[0] == socket.AF_INET6))
        if ipv4:
            results["records"]["A"] = ipv4
        if ipv6:
            results["records"]["AAAA"] = ipv6
    except socket.gaierror as e:
        results["records"]["A"] = {"error": str(e)}

    # MX, NS, TXT via nslookup subprocess
    import subprocess
    for rtype in record_types.split(","):
        rtype = rtype.strip().upper()
        if rtype in ("A", "AAAA"):
            continue  # Already done above
        try:
            result = subprocess.run(
                ["nslookup", "-type=" + rtype, domain],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout
            # Parse nslookup output
            records = []
            for line in output.split("\n"):
                line = line.strip()
                if rtype == "MX" and "mail exchanger" in line.lower():
                    records.append(line.split("=")[-1].strip() if "=" in line else line)
                elif rtype == "NS" and "nameserver" in line.lower():
                    records.append(line.split("=")[-1].strip() if "=" in line else line)
                elif rtype == "TXT" and ('"' in line or "text" in line.lower()):
                    records.append(line.strip('"').strip())
                elif rtype == "CNAME" and "canonical name" in line.lower():
                    records.append(line.split("=")[-1].strip() if "=" in line else line)
            if records:
                results["records"][rtype] = records
        except Exception as e:
            results["records"][rtype] = {"error": str(e)}

    return json.dumps(results, indent=2)


@mcp.tool()
def geoip_lookup(ip: str) -> str:
    """Look up geographic location and ASN information for an IP address.
    Uses free ip-api.com service (no API key needed, 45 req/min limit).

    Args:
        ip: IPv4 or IPv6 address to look up
    """
    ip = ip.strip()
    try:
        data = _safe_request(f"http://ip-api.com/json/{ip}?fields=66846719")
        result = json.loads(data)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"GeoIP lookup failed: {e}", "ip": ip})


@mcp.tool()
def reverse_dns(ip: str) -> str:
    """Perform reverse DNS lookup for an IP address.

    Args:
        ip: IP address to reverse-resolve
    """
    ip = ip.strip()
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)
        return json.dumps({
            "ip": ip,
            "hostname": hostname,
            "aliases": aliases,
            "addresses": addresses,
        }, indent=2)
    except socket.herror as e:
        return json.dumps({"ip": ip, "hostname": None, "error": str(e)})
    except Exception as e:
        return json.dumps({"ip": ip, "error": str(e)})


@mcp.tool()
def ssl_certificate_info(host: str, port: int = 443) -> str:
    """Retrieve and analyze SSL/TLS certificate for a host.

    Args:
        host: Hostname to check
        port: Port number (default 443)
    """
    host = host.strip().lower()
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        result = {
            "host": host,
            "port": port,
            "tls_version": version,
            "cipher_suite": cipher[0] if cipher else None,
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "serial_number": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [
                entry[1] for entry in cert.get("subjectAltName", [])
            ],
        }

        # Check expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                from email.utils import parsedate_to_datetime
                expiry = parsedate_to_datetime(not_after)
                now = datetime.now(timezone.utc)
                days_left = (expiry - now).days
                result["days_until_expiry"] = days_left
                result["expired"] = days_left < 0
            except Exception:
                pass

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": f"SSL check failed: {e}", "host": host})


@mcp.tool()
def http_headers(url: str) -> str:
    """Retrieve and analyze HTTP response headers for security assessment.

    Checks for: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
    CORS, server info disclosure, cookie security flags.

    Args:
        url: URL to check (http:// or https://)
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "BlueTeamAssistant/2.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = dict(resp.headers)
            status = resp.status

        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "X-XSS-Protection": headers.get("X-XSS-Protection"),
            "Referrer-Policy": headers.get("Referrer-Policy"),
            "Permissions-Policy": headers.get("Permissions-Policy"),
        }

        # Assess security posture
        issues = []
        if not security_headers["Strict-Transport-Security"]:
            issues.append("Missing HSTS header")
        if not security_headers["Content-Security-Policy"]:
            issues.append("Missing CSP header")
        if not security_headers["X-Frame-Options"]:
            issues.append("Missing X-Frame-Options (clickjacking risk)")
        if not security_headers["X-Content-Type-Options"]:
            issues.append("Missing X-Content-Type-Options")
        if headers.get("Server"):
            issues.append(f"Server header discloses: {headers['Server']}")

        return json.dumps({
            "url": url,
            "status": status,
            "all_headers": headers,
            "security_headers": {k: v for k, v in security_headers.items() if v},
            "missing_security_headers": [k for k, v in security_headers.items() if not v],
            "security_issues": issues,
            "score": f"{sum(1 for v in security_headers.values() if v)}/7",
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": f"HTTP header check failed: {e}", "url": url})


@mcp.tool()
def subdomain_enumerate(domain: str) -> str:
    """Enumerate subdomains using certificate transparency logs (crt.sh).
    Free service, no API key needed.

    Args:
        domain: Base domain to enumerate subdomains for
    """
    domain = domain.strip().lower()
    try:
        data = _safe_request(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
        entries = json.loads(data)

        subdomains = set()
        for entry in entries:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub and sub.endswith(domain) and "*" not in sub:
                    subdomains.add(sub)

        sorted_subs = sorted(subdomains)
        return json.dumps({
            "domain": domain,
            "subdomain_count": len(sorted_subs),
            "subdomains": sorted_subs[:500],
            "source": "crt.sh (Certificate Transparency)",
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Subdomain enumeration failed: {e}", "domain": domain})


@mcp.tool()
def email_security_check(domain: str) -> str:
    """Check email security configuration for a domain.
    Checks SPF, DKIM, DMARC records.

    Args:
        domain: Domain to check email security for
    """
    import subprocess
    domain = domain.strip().lower()
    result = {"domain": domain, "checks": {}}

    # SPF check
    try:
        r = subprocess.run(
            ["nslookup", "-type=TXT", domain],
            capture_output=True, text=True, timeout=10
        )
        spf_records = [
            line.strip().strip('"')
            for line in r.stdout.split("\n")
            if "v=spf1" in line.lower()
        ]
        result["checks"]["SPF"] = {
            "found": bool(spf_records),
            "records": spf_records,
        }
    except Exception as e:
        result["checks"]["SPF"] = {"error": str(e)}

    # DMARC check
    try:
        r = subprocess.run(
            ["nslookup", "-type=TXT", f"_dmarc.{domain}"],
            capture_output=True, text=True, timeout=10
        )
        dmarc_records = [
            line.strip().strip('"')
            for line in r.stdout.split("\n")
            if "v=dmarc1" in line.lower()
        ]
        result["checks"]["DMARC"] = {
            "found": bool(dmarc_records),
            "records": dmarc_records,
        }
    except Exception as e:
        result["checks"]["DMARC"] = {"error": str(e)}

    # DKIM (check common selectors)
    dkim_selectors = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]
    dkim_found = []
    for selector in dkim_selectors:
        try:
            r = subprocess.run(
                ["nslookup", "-type=TXT", f"{selector}._domainkey.{domain}"],
                capture_output=True, text=True, timeout=5
            )
            if "v=dkim1" in r.stdout.lower() or "p=" in r.stdout:
                dkim_found.append(selector)
        except Exception:
            pass
    result["checks"]["DKIM"] = {
        "found": bool(dkim_found),
        "selectors_found": dkim_found,
    }

    # Assessment
    issues = []
    if not result["checks"].get("SPF", {}).get("found"):
        issues.append("No SPF record found - email spoofing possible")
    if not result["checks"].get("DMARC", {}).get("found"):
        issues.append("No DMARC record found - no email authentication policy")
    if not result["checks"].get("DKIM", {}).get("found"):
        issues.append("No DKIM record found (checked common selectors)")

    result["security_issues"] = issues
    result["score"] = f"{sum(1 for c in result['checks'].values() if c.get('found'))}/3"

    return json.dumps(result, indent=2)


def main():
    """Run the OSINT tools MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
