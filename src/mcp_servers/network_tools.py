"""
Network Tools MCP Server - Network security analysis tools via MCP.

Tools provided:
  - parse_pcap: Lightweight PCAP/PCAPNG parser using struct
  - analyze_zeek_logs: Parse Zeek TSV log files and detect suspicious patterns
  - analyze_suricata_alerts: Parse Suricata EVE JSON alert logs
  - dns_lookup: Perform DNS lookups via socket/subprocess
  - whois_lookup: Raw WHOIS protocol lookup via socket
  - geoip_lookup: Free GeoIP via ip-api.com
  - port_check: Check if common ports are open on a host
  - analyze_network_iocs: Extract network IOCs from free-form text

Usage:
    python -m src.mcp_servers.network_tools
"""

import json
import logging
import os
import re
import socket
import struct
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("network-tools")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_OUTPUT_SIZE = 50000

# Ethernet/IP protocol numbers
PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

# Well-known ports for labeling
WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 135: "RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP-Sub",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Suspicious ports often seen in attacks
SUSPICIOUS_PORTS = {
    4444, 4445, 5555, 6666, 6667, 6668, 6669, 7777, 8888, 9999,
    1234, 31337, 12345, 54321, 65535, 1337,
}

# MITRE ATT&CK mapping for common Suricata signature categories
MITRE_CATEGORY_MAP = {
    "trojan": "TA0011 - Command and Control",
    "malware": "TA0011 - Command and Control",
    "exploit": "TA0001 - Initial Access",
    "scan": "TA0043 - Reconnaissance",
    "dos": "TA0040 - Impact",
    "shellcode": "TA0002 - Execution",
    "web-application-attack": "TA0001 - Initial Access",
    "attempted-admin": "TA0004 - Privilege Escalation",
    "attempted-user": "TA0006 - Credential Access",
    "policy-violation": "TA0010 - Exfiltration",
    "c2": "TA0011 - Command and Control",
    "command-and-control": "TA0011 - Command and Control",
    "lateral": "TA0008 - Lateral Movement",
    "exfiltration": "TA0010 - Exfiltration",
    "credential": "TA0006 - Credential Access",
    "phishing": "TA0001 - Initial Access",
    "dns": "TA0011 - Command and Control",
    "crypto": "TA0040 - Impact",
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _ip_from_bytes(raw: bytes) -> str:
    """Convert 4 raw bytes to dotted-quad IP string."""
    return ".".join(str(b) for b in raw)


def _classify_mitre(signature: str, category: str) -> str:
    """Attempt MITRE ATT&CK classification from signature/category text."""
    text = f"{signature} {category}".lower()
    for keyword, tactic in MITRE_CATEGORY_MAP.items():
        if keyword in text:
            return tactic
    return "Unknown"


def _safe_json(obj: object) -> str:
    """Serialize to JSON, truncating if needed."""
    result = json.dumps(obj, indent=2, default=str)
    if len(result) > MAX_OUTPUT_SIZE:
        result = result[:MAX_OUTPUT_SIZE] + "\n... (truncated)"
    return result


# ---------------------------------------------------------------------------
# Tool 1: parse_pcap
# ---------------------------------------------------------------------------

@mcp.tool()
def parse_pcap(file_path: str, max_packets: int = 100) -> str:
    """Parse PCAP/PCAPNG files using Python struct module.
    Extracts packet summaries including src/dst IP, port, protocol, and size.
    This is a lightweight parser for quick triage - not a full protocol decoder.
    """
    try:
        path = Path(file_path)
        if not path.exists():
            return _safe_json({"error": f"File not found: {file_path}"})
        if not path.is_file():
            return _safe_json({"error": f"Not a file: {file_path}"})

        file_size = path.stat().st_size
        if file_size < 24:
            return _safe_json({"error": "File too small to be a valid PCAP"})

        with open(path, "rb") as f:
            magic = f.read(4)
            f.seek(0)

            if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
                return _parse_pcap_classic(f, max_packets, file_size)
            elif magic in (b"\x0a\x0d\x0d\x0a",):
                return _parse_pcapng(f, max_packets, file_size)
            else:
                return _safe_json({"error": f"Unrecognized file format (magic: {magic.hex()})"})

    except Exception as e:
        return _safe_json({"error": f"Failed to parse PCAP: {str(e)}"})


def _parse_pcap_classic(f, max_packets: int, file_size: int) -> str:
    """Parse classic PCAP format."""
    # Global header: magic(4) + ver_major(2) + ver_minor(2) + thiszone(4)
    #   + sigfigs(4) + snaplen(4) + network(4) = 24 bytes
    header = f.read(24)
    magic = struct.unpack("<I", header[0:4])[0]

    if magic == 0xa1b2c3d4:
        endian = ">"
    else:
        endian = "<"

    link_type = struct.unpack(f"{endian}I", header[20:24])[0]
    packets = []
    proto_stats = {}
    total_bytes = 0
    count = 0

    while count < max_packets:
        pkt_header = f.read(16)
        if len(pkt_header) < 16:
            break

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            f"{endian}IIII", pkt_header
        )

        pkt_data = f.read(incl_len)
        if len(pkt_data) < incl_len:
            break

        total_bytes += orig_len
        count += 1

        pkt_info = _parse_ethernet_packet(pkt_data, link_type)
        pkt_info["packet_num"] = count
        pkt_info["timestamp"] = ts_sec + ts_usec / 1_000_000
        pkt_info["length"] = orig_len

        proto = pkt_info.get("protocol", "Unknown")
        proto_stats[proto] = proto_stats.get(proto, 0) + 1
        packets.append(pkt_info)

    result = {
        "file": str(file_path),
        "file_size_bytes": file_size,
        "format": "PCAP (classic)",
        "link_type": link_type,
        "packets_parsed": count,
        "total_bytes_captured": total_bytes,
        "protocol_distribution": proto_stats,
        "packets": packets,
    }
    return _safe_json(result)


def _parse_pcapng(f, max_packets: int, file_size: int) -> str:
    """Parse PCAPNG format (simplified - handles Section Header + Interface
    Description + Enhanced Packet blocks)."""
    packets = []
    proto_stats = {}
    total_bytes = 0
    count = 0
    link_type = 1  # Default Ethernet

    f.seek(0)

    while count < max_packets:
        block_header = f.read(8)
        if len(block_header) < 8:
            break

        block_type, block_total_len = struct.unpack("<II", block_header)

        if block_total_len < 12:
            break

        block_body = f.read(block_total_len - 8)
        if len(block_body) < block_total_len - 8:
            break

        # Section Header Block (0x0A0D0D0A)
        if block_type == 0x0A0D0D0A:
            continue

        # Interface Description Block (0x00000001)
        elif block_type == 0x00000001:
            if len(block_body) >= 4:
                link_type = struct.unpack("<H", block_body[0:2])[0]

        # Enhanced Packet Block (0x00000006)
        elif block_type == 0x00000006:
            if len(block_body) < 20:
                continue
            _iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                "<IIIII", block_body[0:20]
            )
            pkt_data = block_body[20:20 + cap_len]
            total_bytes += orig_len
            count += 1

            pkt_info = _parse_ethernet_packet(pkt_data, link_type)
            pkt_info["packet_num"] = count
            ts = (ts_high << 32) | ts_low
            pkt_info["timestamp_us"] = ts
            pkt_info["length"] = orig_len

            proto = pkt_info.get("protocol", "Unknown")
            proto_stats[proto] = proto_stats.get(proto, 0) + 1
            packets.append(pkt_info)

    result = {
        "file": str(file_path),
        "file_size_bytes": file_size,
        "format": "PCAPNG",
        "packets_parsed": count,
        "total_bytes_captured": total_bytes,
        "protocol_distribution": proto_stats,
        "packets": packets,
    }
    return _safe_json(result)


def _parse_ethernet_packet(data: bytes, link_type: int = 1) -> dict:
    """Parse Ethernet frame and extract IP/TCP/UDP info."""
    info = {}

    if link_type == 1:  # Ethernet
        if len(data) < 14:
            return {"protocol": "TooShort"}
        ethertype = struct.unpack("!H", data[12:14])[0]

        if ethertype == 0x0800:  # IPv4
            return _parse_ipv4(data[14:])
        elif ethertype == 0x86DD:  # IPv6
            info["protocol"] = "IPv6"
            if len(data) >= 54:
                # Simplified IPv6: next header at offset 6
                nh = data[14 + 6]
                info["next_header"] = PROTO_MAP.get(nh, str(nh))
            return info
        elif ethertype == 0x0806:
            info["protocol"] = "ARP"
            return info
        else:
            info["protocol"] = f"Ether-0x{ethertype:04x}"
            return info

    elif link_type == 101:  # Raw IP
        if len(data) >= 1:
            version = (data[0] >> 4) & 0xF
            if version == 4:
                return _parse_ipv4(data)
        info["protocol"] = "RawIP"
        return info

    else:
        info["protocol"] = f"LinkType-{link_type}"
        return info


def _parse_ipv4(data: bytes) -> dict:
    """Parse IPv4 header and transport layer."""
    info = {}
    if len(data) < 20:
        return {"protocol": "IPv4-TooShort"}

    ihl = (data[0] & 0x0F) * 4
    total_len = struct.unpack("!H", data[2:4])[0]
    proto_num = data[9]
    src_ip = _ip_from_bytes(data[12:16])
    dst_ip = _ip_from_bytes(data[16:20])

    proto_name = PROTO_MAP.get(proto_num, f"IP-{proto_num}")
    info["protocol"] = proto_name
    info["src_ip"] = src_ip
    info["dst_ip"] = dst_ip

    transport_data = data[ihl:]

    if proto_num == 6 and len(transport_data) >= 4:  # TCP
        src_port, dst_port = struct.unpack("!HH", transport_data[0:4])
        info["src_port"] = src_port
        info["dst_port"] = dst_port
        info["src_service"] = WELL_KNOWN_PORTS.get(src_port, "")
        info["dst_service"] = WELL_KNOWN_PORTS.get(dst_port, "")
        if len(transport_data) >= 14:
            flags_byte = transport_data[13]
            flag_names = []
            if flags_byte & 0x02:
                flag_names.append("SYN")
            if flags_byte & 0x10:
                flag_names.append("ACK")
            if flags_byte & 0x01:
                flag_names.append("FIN")
            if flags_byte & 0x04:
                flag_names.append("RST")
            if flags_byte & 0x08:
                flag_names.append("PSH")
            if flags_byte & 0x20:
                flag_names.append("URG")
            info["tcp_flags"] = ",".join(flag_names)

    elif proto_num == 17 and len(transport_data) >= 4:  # UDP
        src_port, dst_port = struct.unpack("!HH", transport_data[0:4])
        info["src_port"] = src_port
        info["dst_port"] = dst_port
        info["src_service"] = WELL_KNOWN_PORTS.get(src_port, "")
        info["dst_service"] = WELL_KNOWN_PORTS.get(dst_port, "")

    elif proto_num == 1 and len(transport_data) >= 2:  # ICMP
        icmp_type, icmp_code = struct.unpack("!BB", transport_data[0:2])
        info["icmp_type"] = icmp_type
        info["icmp_code"] = icmp_code

    return info


# ---------------------------------------------------------------------------
# Tool 2: analyze_zeek_logs
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_zeek_logs(log_path: str, log_type: str = "conn") -> str:
    """Parse Zeek (Bro) TSV log files and detect suspicious patterns.
    Supports conn.log, dns.log, http.log, ssl.log, and files.log.
    Detects: long connections, unusual ports, DNS tunneling indicators,
    suspicious HTTP methods, expired/self-signed certs, etc.
    """
    try:
        path = Path(log_path)
        if not path.exists():
            return _safe_json({"error": f"File not found: {log_path}"})

        lines = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                lines.append(line.rstrip("\n"))

        # Parse Zeek header
        separator = "\t"
        fields = []
        header_lines = []
        data_lines = []

        for line in lines:
            if line.startswith("#separator"):
                sep_value = line.split(" ", 1)[1] if " " in line else "\\x09"
                if sep_value == "\\x09":
                    separator = "\t"
                else:
                    separator = sep_value.encode().decode("unicode_escape")
                header_lines.append(line)
            elif line.startswith("#fields"):
                fields = line.split(separator)[1:]
                # Clean field names
                fields = [f.strip().lstrip("#fields").strip() if i == 0 else f.strip()
                          for i, f in enumerate(line.split(separator))]
                fields = fields[1:]  # Remove '#fields' prefix
                header_lines.append(line)
            elif line.startswith("#"):
                header_lines.append(line)
            elif line.strip():
                data_lines.append(line)

        if not fields:
            return _safe_json({"error": "Could not parse Zeek header (no #fields line found)"})

        # Parse records
        records = []
        for line in data_lines:
            values = line.split(separator)
            if len(values) >= len(fields):
                record = {}
                for i, field in enumerate(fields):
                    val = values[i] if i < len(values) else "-"
                    record[field] = val if val != "-" else None
                records.append(record)

        # Analyze based on log type
        analysis = {
            "file": str(log_path),
            "log_type": log_type,
            "total_records": len(records),
            "fields": fields,
        }

        suspicious = []

        if log_type == "conn":
            analysis.update(_analyze_conn_log(records, suspicious))
        elif log_type == "dns":
            analysis.update(_analyze_dns_log(records, suspicious))
        elif log_type == "http":
            analysis.update(_analyze_http_log(records, suspicious))
        elif log_type == "ssl":
            analysis.update(_analyze_ssl_log(records, suspicious))
        elif log_type == "files":
            analysis.update(_analyze_files_log(records, suspicious))
        else:
            analysis["sample_records"] = records[:20]

        analysis["suspicious_findings"] = suspicious
        analysis["suspicious_count"] = len(suspicious)

        return _safe_json(analysis)

    except Exception as e:
        return _safe_json({"error": f"Failed to analyze Zeek log: {str(e)}"})


def _analyze_conn_log(records: list, suspicious: list) -> dict:
    """Analyze Zeek conn.log records."""
    proto_counts = {}
    service_counts = {}
    long_connections = []
    large_transfers = []
    suspicious_port_conns = []

    for r in records:
        proto = r.get("proto", "unknown")
        proto_counts[proto] = proto_counts.get(proto, 0) + 1

        service = r.get("service") or "unknown"
        service_counts[service] = service_counts.get(service, 0) + 1

        # Check for long connections (> 1 hour)
        duration = r.get("duration")
        if duration:
            try:
                dur = float(duration)
                if dur > 3600:
                    long_connections.append({
                        "src": r.get("id.orig_h"),
                        "dst": r.get("id.resp_h"),
                        "port": r.get("id.resp_p"),
                        "duration_sec": dur,
                        "service": service,
                    })
            except ValueError:
                pass

        # Check for large data transfers (> 10MB)
        orig_bytes = r.get("orig_bytes") or r.get("orig_ip_bytes")
        resp_bytes = r.get("resp_bytes") or r.get("resp_ip_bytes")
        try:
            total = (int(orig_bytes) if orig_bytes else 0) + (int(resp_bytes) if resp_bytes else 0)
            if total > 10_000_000:
                large_transfers.append({
                    "src": r.get("id.orig_h"),
                    "dst": r.get("id.resp_h"),
                    "port": r.get("id.resp_p"),
                    "total_bytes": total,
                    "service": service,
                })
        except (ValueError, TypeError):
            pass

        # Check for suspicious ports
        resp_port = r.get("id.resp_p")
        if resp_port:
            try:
                port_num = int(resp_port)
                if port_num in SUSPICIOUS_PORTS:
                    suspicious_port_conns.append({
                        "src": r.get("id.orig_h"),
                        "dst": r.get("id.resp_h"),
                        "port": port_num,
                        "service": service,
                    })
            except ValueError:
                pass

    if long_connections:
        suspicious.append({
            "type": "long_connections",
            "description": f"{len(long_connections)} connections lasting over 1 hour (possible beaconing/C2)",
            "details": long_connections[:10],
        })
    if large_transfers:
        suspicious.append({
            "type": "large_transfers",
            "description": f"{len(large_transfers)} transfers over 10MB (possible exfiltration)",
            "details": large_transfers[:10],
        })
    if suspicious_port_conns:
        suspicious.append({
            "type": "suspicious_ports",
            "description": f"{len(suspicious_port_conns)} connections to commonly malicious ports",
            "details": suspicious_port_conns[:10],
        })

    return {
        "protocol_distribution": proto_counts,
        "service_distribution": service_counts,
        "long_connections_count": len(long_connections),
        "large_transfers_count": len(large_transfers),
        "sample_records": records[:10],
    }


def _analyze_dns_log(records: list, suspicious: list) -> dict:
    """Analyze Zeek dns.log records."""
    query_type_counts = {}
    top_queried = {}
    long_queries = []
    txt_queries = []
    nxdomain = []

    for r in records:
        qtype = r.get("qtype_name") or r.get("qtype") or "unknown"
        query_type_counts[qtype] = query_type_counts.get(qtype, 0) + 1

        query = r.get("query")
        if query:
            top_queried[query] = top_queried.get(query, 0) + 1

            # DNS tunneling indicator: very long domain names
            if len(query) > 60:
                long_queries.append({
                    "query": query,
                    "length": len(query),
                    "src": r.get("id.orig_h"),
                    "type": qtype,
                })

            # TXT record queries (often used for tunneling/C2)
            if qtype in ("TXT", "16"):
                txt_queries.append({
                    "query": query,
                    "src": r.get("id.orig_h"),
                })

        # NXDOMAIN responses (possible DGA)
        rcode = r.get("rcode_name") or r.get("rcode")
        if rcode and rcode.upper() == "NXDOMAIN":
            nxdomain.append({
                "query": query,
                "src": r.get("id.orig_h"),
            })

    if long_queries:
        suspicious.append({
            "type": "dns_tunneling_indicator",
            "description": f"{len(long_queries)} queries with domain names > 60 chars (possible DNS tunneling)",
            "details": long_queries[:10],
        })
    if len(txt_queries) > 5:
        suspicious.append({
            "type": "excessive_txt_queries",
            "description": f"{len(txt_queries)} TXT record queries (possible DNS tunneling/C2)",
            "details": txt_queries[:10],
        })
    if len(nxdomain) > 20:
        suspicious.append({
            "type": "excessive_nxdomain",
            "description": f"{len(nxdomain)} NXDOMAIN responses (possible DGA activity)",
            "details": nxdomain[:10],
        })

    # Top queried domains
    sorted_queries = sorted(top_queried.items(), key=lambda x: x[1], reverse=True)

    return {
        "query_type_distribution": query_type_counts,
        "top_queried_domains": sorted_queries[:20],
        "nxdomain_count": len(nxdomain),
        "txt_query_count": len(txt_queries),
        "sample_records": records[:10],
    }


def _analyze_http_log(records: list, suspicious: list) -> dict:
    """Analyze Zeek http.log records."""
    method_counts = {}
    status_counts = {}
    user_agents = {}
    suspicious_methods = []
    suspicious_uris = []

    risky_methods = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
    suspicious_uri_patterns = [
        r"/etc/passwd", r"/etc/shadow", r"\.\.[\\/]",
        r"cmd\.exe", r"powershell", r"/bin/sh", r"/bin/bash",
        r"<script", r"union\s+select", r"exec\s*\(",
    ]

    for r in records:
        method = r.get("method") or "unknown"
        method_counts[method] = method_counts.get(method, 0) + 1

        status = r.get("status_code") or "unknown"
        status_counts[status] = status_counts.get(status, 0) + 1

        ua = r.get("user_agent")
        if ua:
            user_agents[ua] = user_agents.get(ua, 0) + 1

        if method.upper() in risky_methods:
            suspicious_methods.append({
                "method": method,
                "host": r.get("host"),
                "uri": r.get("uri"),
                "src": r.get("id.orig_h"),
            })

        uri = r.get("uri") or ""
        for pattern in suspicious_uri_patterns:
            if re.search(pattern, uri, re.IGNORECASE):
                suspicious_uris.append({
                    "uri": uri,
                    "host": r.get("host"),
                    "src": r.get("id.orig_h"),
                    "pattern_matched": pattern,
                })
                break

    if suspicious_methods:
        suspicious.append({
            "type": "risky_http_methods",
            "description": f"{len(suspicious_methods)} requests using risky HTTP methods",
            "details": suspicious_methods[:10],
        })
    if suspicious_uris:
        suspicious.append({
            "type": "suspicious_uris",
            "description": f"{len(suspicious_uris)} requests with attack indicators in URI",
            "details": suspicious_uris[:10],
        })

    sorted_uas = sorted(user_agents.items(), key=lambda x: x[1], reverse=True)

    return {
        "method_distribution": method_counts,
        "status_code_distribution": status_counts,
        "top_user_agents": sorted_uas[:15],
        "sample_records": records[:10],
    }


def _analyze_ssl_log(records: list, suspicious: list) -> dict:
    """Analyze Zeek ssl.log records."""
    version_counts = {}
    expired_certs = []
    self_signed = []
    ja3_hashes = {}

    for r in records:
        version = r.get("version") or "unknown"
        version_counts[version] = version_counts.get(version, 0) + 1

        # Check validation status
        validation = r.get("validation_status")
        if validation:
            val_lower = validation.lower()
            if "expired" in val_lower:
                expired_certs.append({
                    "server": r.get("server_name") or r.get("id.resp_h"),
                    "subject": r.get("subject"),
                    "status": validation,
                })
            if "self signed" in val_lower or "self-signed" in val_lower:
                self_signed.append({
                    "server": r.get("server_name") or r.get("id.resp_h"),
                    "subject": r.get("subject"),
                    "status": validation,
                })

        ja3 = r.get("ja3")
        if ja3:
            ja3_hashes[ja3] = ja3_hashes.get(ja3, 0) + 1

    if expired_certs:
        suspicious.append({
            "type": "expired_certificates",
            "description": f"{len(expired_certs)} connections to servers with expired certificates",
            "details": expired_certs[:10],
        })
    if self_signed:
        suspicious.append({
            "type": "self_signed_certificates",
            "description": f"{len(self_signed)} connections to servers with self-signed certificates (possible MITM or C2)",
            "details": self_signed[:10],
        })

    return {
        "tls_version_distribution": version_counts,
        "unique_ja3_hashes": len(ja3_hashes),
        "top_ja3_hashes": sorted(ja3_hashes.items(), key=lambda x: x[1], reverse=True)[:10],
        "sample_records": records[:10],
    }


def _analyze_files_log(records: list, suspicious: list) -> dict:
    """Analyze Zeek files.log records."""
    mime_counts = {}
    executable_files = []
    large_files = []

    executable_mimes = {
        "application/x-dosexec", "application/x-executable",
        "application/x-mach-binary", "application/x-elf",
        "application/x-msdownload", "application/java-archive",
        "application/x-sharedlib", "application/vnd.ms-cab-compressed",
    }

    for r in records:
        mime = r.get("mime_type") or "unknown"
        mime_counts[mime] = mime_counts.get(mime, 0) + 1

        if mime in executable_mimes:
            executable_files.append({
                "filename": r.get("filename"),
                "mime": mime,
                "size": r.get("total_bytes"),
                "src": r.get("tx_hosts") or r.get("rx_hosts"),
                "md5": r.get("md5"),
                "sha1": r.get("sha1"),
                "sha256": r.get("sha256"),
            })

        total_bytes = r.get("total_bytes")
        if total_bytes:
            try:
                if int(total_bytes) > 50_000_000:
                    large_files.append({
                        "filename": r.get("filename"),
                        "mime": mime,
                        "size_bytes": int(total_bytes),
                    })
            except ValueError:
                pass

    if executable_files:
        suspicious.append({
            "type": "executable_file_transfers",
            "description": f"{len(executable_files)} executable files transferred",
            "details": executable_files[:10],
        })

    return {
        "mime_type_distribution": mime_counts,
        "executable_count": len(executable_files),
        "large_file_count": len(large_files),
        "sample_records": records[:10],
    }


# ---------------------------------------------------------------------------
# Tool 3: analyze_suricata_alerts
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_suricata_alerts(eve_json_path: str, max_alerts: int = 200) -> str:
    """Parse Suricata EVE JSON log files and extract alerts.
    Classifies alerts by severity and maps to MITRE ATT&CK tactics where possible.
    """
    try:
        path = Path(eve_json_path)
        if not path.exists():
            return _safe_json({"error": f"File not found: {eve_json_path}"})

        alerts = []
        total_events = 0
        event_type_counts = {}

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                total_events += 1
                event_type = event.get("event_type", "unknown")
                event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1

                if event_type == "alert" and len(alerts) < max_alerts:
                    alert_data = event.get("alert", {})
                    signature = alert_data.get("signature", "Unknown")
                    category = alert_data.get("category", "Unknown")
                    severity = alert_data.get("severity", 0)

                    alert_entry = {
                        "timestamp": event.get("timestamp"),
                        "src_ip": event.get("src_ip"),
                        "src_port": event.get("src_port"),
                        "dst_ip": event.get("dest_ip"),
                        "dst_port": event.get("dest_port"),
                        "proto": event.get("proto"),
                        "signature": signature,
                        "signature_id": alert_data.get("signature_id"),
                        "category": category,
                        "severity": severity,
                        "mitre_tactic": _classify_mitre(signature, category),
                    }

                    # Include metadata if present
                    metadata = alert_data.get("metadata")
                    if metadata:
                        mitre_tags = []
                        for key, values in metadata.items():
                            if "mitre" in key.lower() or "attack" in key.lower():
                                mitre_tags.extend(values if isinstance(values, list) else [values])
                        if mitre_tags:
                            alert_entry["mitre_metadata"] = mitre_tags

                    alerts.append(alert_entry)

        # Aggregate statistics
        severity_counts = {}
        category_counts = {}
        signature_counts = {}
        mitre_counts = {}
        src_ip_counts = {}
        dst_ip_counts = {}

        for a in alerts:
            sev = a["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            cat = a["category"]
            category_counts[cat] = category_counts.get(cat, 0) + 1

            sig = a["signature"]
            signature_counts[sig] = signature_counts.get(sig, 0) + 1

            mitre = a["mitre_tactic"]
            mitre_counts[mitre] = mitre_counts.get(mitre, 0) + 1

            src = a.get("src_ip")
            if src:
                src_ip_counts[src] = src_ip_counts.get(src, 0) + 1

            dst = a.get("dst_ip")
            if dst:
                dst_ip_counts[dst] = dst_ip_counts.get(dst, 0) + 1

        result = {
            "file": str(eve_json_path),
            "total_events": total_events,
            "event_type_distribution": event_type_counts,
            "total_alerts": len(alerts),
            "severity_distribution": severity_counts,
            "category_distribution": dict(
                sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:15]
            ),
            "top_signatures": dict(
                sorted(signature_counts.items(), key=lambda x: x[1], reverse=True)[:15]
            ),
            "mitre_tactic_distribution": mitre_counts,
            "top_source_ips": dict(
                sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "top_destination_ips": dict(
                sorted(dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "alerts": alerts,
        }

        return _safe_json(result)

    except Exception as e:
        return _safe_json({"error": f"Failed to analyze Suricata alerts: {str(e)}"})


# ---------------------------------------------------------------------------
# Tool 4: dns_lookup
# ---------------------------------------------------------------------------

@mcp.tool()
def dns_lookup(domain: str, record_types: str = "A,AAAA,MX,NS,TXT") -> str:
    """Perform DNS lookups for a domain. Returns results for requested record types.
    Uses socket for A/AAAA records and nslookup/subprocess for other types.
    """
    try:
        results = {
            "domain": domain,
            "records": {},
        }

        requested_types = [t.strip().upper() for t in record_types.split(",")]

        for rtype in requested_types:
            try:
                if rtype == "A":
                    addrs = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
                    ips = list(set(addr[4][0] for addr in addrs))
                    results["records"]["A"] = ips

                elif rtype == "AAAA":
                    try:
                        addrs = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
                        ips = list(set(addr[4][0] for addr in addrs))
                        results["records"]["AAAA"] = ips
                    except socket.gaierror:
                        results["records"]["AAAA"] = []

                elif rtype in ("MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV"):
                    # Use nslookup for record types beyond A/AAAA
                    records = _dns_nslookup(domain, rtype)
                    results["records"][rtype] = records

                else:
                    results["records"][rtype] = f"Unsupported record type: {rtype}"

            except socket.gaierror as e:
                results["records"][rtype] = f"Lookup failed: {str(e)}"
            except Exception as e:
                results["records"][rtype] = f"Error: {str(e)}"

        return _safe_json(results)

    except Exception as e:
        return _safe_json({"error": f"DNS lookup failed: {str(e)}"})


def _dns_nslookup(domain: str, record_type: str) -> list:
    """Use nslookup subprocess for DNS record lookups."""
    try:
        cmd = ["nslookup", "-type=" + record_type, domain]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        output = result.stdout + result.stderr
        records = []

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("Server:") or line.startswith("Address:") and not records:
                # Skip the server info lines at the start
                if line.startswith("Address:") and records:
                    pass  # Keep address lines after first section
                continue

            if record_type == "MX" and "mail exchanger" in line.lower():
                records.append(line)
            elif record_type == "NS" and "nameserver" in line.lower():
                records.append(line)
            elif record_type == "TXT" and ("text" in line.lower() or line.startswith('"')):
                records.append(line)
            elif record_type == "CNAME" and ("canonical name" in line.lower() or "alias" in line.lower()):
                records.append(line)
            elif record_type == "SOA" and ("origin" in line.lower() or "serial" in line.lower()):
                records.append(line)
            elif "=" in line or ":" in line:
                # Generic fallback for other record data
                if domain.lower() in line.lower() or record_type.lower() in line.lower():
                    records.append(line)

        return records if records else [f"No {record_type} records found (or parsing returned empty)"]

    except subprocess.TimeoutExpired:
        return [f"nslookup timed out for {record_type}"]
    except FileNotFoundError:
        return [f"nslookup not found on this system"]
    except Exception as e:
        return [f"Error: {str(e)}"]


# ---------------------------------------------------------------------------
# Tool 5: whois_lookup
# ---------------------------------------------------------------------------

@mcp.tool()
def whois_lookup(target: str) -> str:
    """Perform WHOIS lookup for a domain or IP address using raw WHOIS protocol
    over a socket connection. No external packages required.
    """
    try:
        # Determine if this is an IP or domain
        is_ip = False
        try:
            socket.inet_aton(target)
            is_ip = True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, target)
                is_ip = True
            except socket.error:
                pass

        if is_ip:
            whois_server = "whois.arin.net"
            query = f"n + {target}\r\n"
        else:
            # For domains, determine the appropriate WHOIS server
            whois_server = _get_whois_server(target)
            query = f"{target}\r\n"

        raw_response = _raw_whois_query(whois_server, query)

        # Check if we need to follow a referral
        referral = None
        for line in raw_response.splitlines():
            lower_line = line.lower().strip()
            if lower_line.startswith("refer:") or lower_line.startswith("whois server:"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    ref_server = parts[1].strip()
                    if ref_server and "." in ref_server:
                        referral = ref_server
                        break
            elif "referralserver:" in lower_line:
                parts = lower_line.split("referralserver:", 1)
                ref_url = parts[1].strip()
                # Handle whois://server format
                if ref_url.startswith("whois://"):
                    referral = ref_url[8:].split("/")[0].split(":")[0]
                elif "." in ref_url:
                    referral = ref_url
                break

        if referral:
            try:
                referral_response = _raw_whois_query(referral, f"{target}\r\n")
                raw_response = (
                    f"--- Primary WHOIS ({whois_server}) ---\n"
                    f"{raw_response}\n\n"
                    f"--- Referral WHOIS ({referral}) ---\n"
                    f"{referral_response}"
                )
            except Exception:
                pass  # Keep the original response

        # Parse key fields
        parsed = _parse_whois_response(raw_response)

        result = {
            "target": target,
            "is_ip": is_ip,
            "whois_server": whois_server,
            "referral_server": referral,
            "parsed_fields": parsed,
            "raw_response": raw_response[:10000],
        }

        return _safe_json(result)

    except Exception as e:
        return _safe_json({"error": f"WHOIS lookup failed: {str(e)}"})


def _get_whois_server(domain: str) -> str:
    """Determine the WHOIS server for a domain based on its TLD."""
    tld_whois = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "info": "whois.afilias.net",
        "io": "whois.nic.io",
        "co": "whois.nic.co",
        "us": "whois.nic.us",
        "uk": "whois.nic.uk",
        "de": "whois.denic.de",
        "fr": "whois.nic.fr",
        "nl": "whois.domain-registry.nl",
        "eu": "whois.eu",
        "ru": "whois.tcinet.ru",
        "au": "whois.auda.org.au",
        "ca": "whois.cira.ca",
        "br": "whois.registro.br",
        "in": "whois.registry.in",
        "jp": "whois.jprs.jp",
        "cn": "whois.cnnic.cn",
        "kr": "whois.kr",
        "it": "whois.nic.it",
        "es": "whois.nic.es",
        "pl": "whois.dns.pl",
        "se": "whois.iis.se",
        "be": "whois.dns.be",
        "xyz": "whois.nic.xyz",
        "top": "whois.nic.top",
        "app": "whois.nic.google",
        "dev": "whois.nic.google",
    }

    parts = domain.rstrip(".").split(".")
    tld = parts[-1].lower() if parts else ""

    return tld_whois.get(tld, "whois.iana.org")


def _raw_whois_query(server: str, query: str, timeout: int = 10) -> str:
    """Send a raw WHOIS query over TCP port 43."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((server, 43))
        sock.sendall(query.encode("utf-8"))

        response = b""
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break
    finally:
        sock.close()

    return response.decode("utf-8", errors="replace")


def _parse_whois_response(raw: str) -> dict:
    """Extract common WHOIS fields from raw response."""
    fields = {}
    patterns = {
        "registrar": r"(?:Registrar|registrar)\s*:\s*(.+)",
        "creation_date": r"(?:Creat(?:ion|ed)\s*Date|created)\s*:\s*(.+)",
        "expiration_date": r"(?:Expir(?:ation|y)\s*Date|expires)\s*:\s*(.+)",
        "updated_date": r"(?:Updated?\s*Date|modified|changed)\s*:\s*(.+)",
        "registrant_org": r"(?:Registrant\s*Organi[sz]ation|org-name)\s*:\s*(.+)",
        "registrant_country": r"(?:Registrant\s*Country|country)\s*:\s*(.+)",
        "name_servers": r"(?:Name\s*Server|nserver)\s*:\s*(.+)",
        "status": r"(?:Domain\s*Status|status)\s*:\s*(.+)",
        "dnssec": r"(?:DNSSEC)\s*:\s*(.+)",
        "netname": r"(?:NetName|netname)\s*:\s*(.+)",
        "netrange": r"(?:NetRange)\s*:\s*(.+)",
        "cidr": r"(?:CIDR)\s*:\s*(.+)",
        "org_name": r"(?:OrgName|org-name)\s*:\s*(.+)",
    }

    for field_name, pattern in patterns.items():
        matches = re.findall(pattern, raw, re.IGNORECASE)
        if matches:
            cleaned = [m.strip() for m in matches]
            fields[field_name] = cleaned if len(cleaned) > 1 else cleaned[0]

    return fields


# ---------------------------------------------------------------------------
# Tool 6: geoip_lookup
# ---------------------------------------------------------------------------

@mcp.tool()
def geoip_lookup(ip: str) -> str:
    """Perform free GeoIP lookup using ip-api.com (no API key needed).
    Rate limited to 45 requests/minute on free tier.
    Returns country, region, city, ISP, AS number, and more.
    """
    try:
        # Validate IP format
        try:
            socket.inet_aton(ip)
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
            except socket.error:
                return _safe_json({"error": f"Invalid IP address: {ip}"})

        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"

        req = urllib.request.Request(url, headers={"User-Agent": "NetworkToolsMCP/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))

        if data.get("status") == "fail":
            return _safe_json({
                "error": f"GeoIP lookup failed: {data.get('message', 'Unknown error')}",
                "ip": ip,
            })

        result = {
            "ip": ip,
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "region_code": data.get("region"),
            "city": data.get("city"),
            "zip": data.get("zip"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "timezone": data.get("timezone"),
            "isp": data.get("isp"),
            "organization": data.get("org"),
            "as_number": data.get("as"),
            "as_name": data.get("asname"),
            "reverse_dns": data.get("reverse"),
            "is_mobile": data.get("mobile"),
            "is_proxy": data.get("proxy"),
            "is_hosting": data.get("hosting"),
        }

        return _safe_json(result)

    except urllib.error.URLError as e:
        return _safe_json({"error": f"GeoIP lookup failed (network error): {str(e)}", "ip": ip})
    except Exception as e:
        return _safe_json({"error": f"GeoIP lookup failed: {str(e)}", "ip": ip})


# ---------------------------------------------------------------------------
# Tool 7: port_check
# ---------------------------------------------------------------------------

@mcp.tool()
def port_check(
    host: str,
    ports: str = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,8080,8443",
) -> str:
    """Check if common ports are open on a host using socket connect with timeout.
    This is a passive TCP connect check only - no exploitation or scanning payloads.
    """
    try:
        # Resolve hostname first
        try:
            resolved_ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            return _safe_json({"error": f"Cannot resolve host '{host}': {str(e)}"})

        port_list = []
        for p in ports.split(","):
            p = p.strip()
            if p.isdigit():
                port_list.append(int(p))

        if not port_list:
            return _safe_json({"error": "No valid ports specified"})

        open_ports = []
        closed_ports = []
        timeout_seconds = 2

        for port in port_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout_seconds)
                result = sock.connect_ex((resolved_ip, port))
                sock.close()

                service = WELL_KNOWN_PORTS.get(port, "unknown")

                if result == 0:
                    # Try to grab banner (best effort)
                    banner = _grab_banner(resolved_ip, port)
                    open_ports.append({
                        "port": port,
                        "state": "open",
                        "service": service,
                        "banner": banner,
                    })
                else:
                    closed_ports.append({
                        "port": port,
                        "state": "closed/filtered",
                        "service": service,
                    })

            except Exception:
                closed_ports.append({
                    "port": port,
                    "state": "error",
                    "service": WELL_KNOWN_PORTS.get(port, "unknown"),
                })

        result = {
            "host": host,
            "resolved_ip": resolved_ip,
            "ports_checked": len(port_list),
            "open_count": len(open_ports),
            "closed_filtered_count": len(closed_ports),
            "open_ports": open_ports,
            "closed_filtered_ports": closed_ports,
        }

        # Flag potentially risky open ports
        risky = []
        for p in open_ports:
            port_num = p["port"]
            if port_num in (23, 21, 135, 139, 445, 3389):
                risky.append({
                    "port": port_num,
                    "service": p["service"],
                    "risk": "This service is commonly targeted in attacks",
                })
            if port_num in SUSPICIOUS_PORTS:
                risky.append({
                    "port": port_num,
                    "service": p["service"],
                    "risk": "Port commonly associated with malware/backdoors",
                })

        if risky:
            result["security_notes"] = risky

        return _safe_json(result)

    except Exception as e:
        return _safe_json({"error": f"Port check failed: {str(e)}"})


def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Attempt to grab a service banner from an open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Some services send a banner immediately; for HTTP we send a request
        if port in (80, 8080, 8443, 443):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 25:
            pass  # SMTP sends banner on connect
        elif port == 22:
            pass  # SSH sends banner on connect
        else:
            # Send empty line to provoke a response
            sock.sendall(b"\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        sock.close()

        # Truncate long banners
        if len(banner) > 200:
            banner = banner[:200] + "..."

        return banner if banner else None

    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tool 8: analyze_network_iocs
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_network_iocs(text: str) -> str:
    """Extract network Indicators of Compromise (IOCs) from free-form text.
    Extracts: IPv4 addresses, IPv6 addresses, domain names, URLs,
    email addresses, and defanged indicators (e.g., hxxp://, [.], [at]).
    """
    try:
        # First, refang common defanged indicators
        refanged = text
        refanged = re.sub(r"hxxp(s?)", r"http\1", refanged, flags=re.IGNORECASE)
        refanged = re.sub(r"\[dot\]", ".", refanged, flags=re.IGNORECASE)
        refanged = re.sub(r"\[\.\]", ".", refanged)
        refanged = re.sub(r"\[at\]", "@", refanged, flags=re.IGNORECASE)
        refanged = re.sub(r"\[@\]", "@", refanged)
        refanged = re.sub(r"\[:\]", ":", refanged)

        # IPv4 addresses
        ipv4_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ipv4_matches = re.findall(ipv4_pattern, refanged)
        # Deduplicate while preserving order
        ipv4s = list(dict.fromkeys(ipv4_matches))

        # Classify IPs
        ipv4_classified = []
        for ip in ipv4s:
            classification = _classify_ip(ip)
            ipv4_classified.append({"ip": ip, "type": classification})

        # IPv6 addresses (simplified pattern)
        ipv6_pattern = r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
        ipv6_matches = re.findall(ipv6_pattern, refanged)
        ipv6s = list(dict.fromkeys(ipv6_matches))

        # URLs
        url_pattern = r"https?://[^\s<>\"'\)\]\}]+"
        url_matches = re.findall(url_pattern, refanged, re.IGNORECASE)
        urls = list(dict.fromkeys(url_matches))

        # Email addresses
        email_pattern = r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
        email_matches = re.findall(email_pattern, refanged)
        emails = list(dict.fromkeys(email_matches))

        # Domain names (extract from URLs and standalone)
        domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})\b"
        domain_matches = re.findall(domain_pattern, refanged)
        # Filter out common non-domains and IPs
        excluded_tlds = {"exe", "dll", "sys", "tmp", "log", "dat", "png", "jpg", "gif", "pdf", "doc", "zip"}
        domains = []
        seen = set()
        for d in domain_matches:
            d_lower = d.lower()
            tld = d_lower.rsplit(".", 1)[-1]
            if tld not in excluded_tlds and d_lower not in seen:
                # Verify it's not just an IP
                if not re.match(ipv4_pattern, d):
                    seen.add(d_lower)
                    domains.append(d_lower)

        # MD5 / SHA1 / SHA256 hashes (bonus - commonly found alongside network IOCs)
        md5_pattern = r"\b[a-fA-F0-9]{32}\b"
        sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
        sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

        # Extract hashes, being careful not to include substrings
        sha256_matches = list(dict.fromkeys(re.findall(sha256_pattern, refanged)))
        sha1_matches = [h for h in dict.fromkeys(re.findall(sha1_pattern, refanged))
                        if not any(h in s for s in sha256_matches)]
        md5_matches = [h for h in dict.fromkeys(re.findall(md5_pattern, refanged))
                       if not any(h in s for s in sha1_matches + sha256_matches)]

        result = {
            "summary": {
                "ipv4_count": len(ipv4_classified),
                "ipv6_count": len(ipv6s),
                "domain_count": len(domains),
                "url_count": len(urls),
                "email_count": len(emails),
                "hash_count": len(md5_matches) + len(sha1_matches) + len(sha256_matches),
                "total_iocs": (
                    len(ipv4_classified) + len(ipv6s) + len(domains) +
                    len(urls) + len(emails) +
                    len(md5_matches) + len(sha1_matches) + len(sha256_matches)
                ),
            },
            "ipv4_addresses": ipv4_classified,
            "ipv6_addresses": ipv6s,
            "domains": domains,
            "urls": urls,
            "email_addresses": emails,
            "hashes": {
                "md5": md5_matches,
                "sha1": sha1_matches,
                "sha256": sha256_matches,
            },
        }

        return _safe_json(result)

    except Exception as e:
        return _safe_json({"error": f"IOC extraction failed: {str(e)}"})


def _classify_ip(ip: str) -> str:
    """Classify an IPv4 address as private, reserved, or public."""
    try:
        octets = [int(o) for o in ip.split(".")]
        if len(octets) != 4:
            return "invalid"

        if octets[0] == 10:
            return "private (RFC1918)"
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return "private (RFC1918)"
        if octets[0] == 192 and octets[1] == 168:
            return "private (RFC1918)"
        if octets[0] == 127:
            return "loopback"
        if octets[0] == 169 and octets[1] == 254:
            return "link-local"
        if octets[0] == 0:
            return "reserved"
        if octets[0] >= 224 and octets[0] <= 239:
            return "multicast"
        if octets[0] >= 240:
            return "reserved"
        return "public"

    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    """Run the MCP server with stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
