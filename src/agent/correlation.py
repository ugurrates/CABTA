"""
Correlation Engine - Cross-analysis finding correlation for security investigations.

Identifies overlapping IOCs across multiple analysis results, maps findings to
MITRE ATT&CK TTP patterns, builds a relationship graph between entities
(IPs, domains, hashes, files), and produces severity escalation recommendations.
"""

import hashlib
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ====================================================================== #
#  IOC regex patterns
# ====================================================================== #

_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|xyz|ru|cn|info|biz|de|uk|fr|top|online|club|pro|"
    r"dev|app|cc|site|live|su|me|gov|edu|mil)\b",
    re.IGNORECASE,
)
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_URL = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
_RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_RE_MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# ====================================================================== #
#  MITRE ATT&CK TTP behavioural patterns
# ====================================================================== #

_TTP_PATTERNS: List[Tuple[str, str, str, str]] = [
    # (keyword, technique_id, technique_name, tactic)
    # Initial Access
    ("phishing", "T1566", "Phishing", "initial-access"),
    ("spearphish", "T1566.001", "Spearphishing Attachment", "initial-access"),
    ("drive-by", "T1189", "Drive-by Compromise", "initial-access"),
    # Execution
    ("powershell", "T1059.001", "PowerShell", "execution"),
    ("cmd.exe", "T1059.003", "Windows Command Shell", "execution"),
    ("wscript", "T1059.005", "Visual Basic", "execution"),
    ("cscript", "T1059.005", "Visual Basic", "execution"),
    ("macro", "T1204.002", "Malicious File", "execution"),
    ("vba", "T1204.002", "Malicious File", "execution"),
    ("shellcode", "T1059", "Command and Scripting Interpreter", "execution"),
    # Persistence
    ("registry run", "T1547.001", "Registry Run Keys", "persistence"),
    ("scheduled task", "T1053.005", "Scheduled Task", "persistence"),
    ("startup folder", "T1547.001", "Registry Run Keys", "persistence"),
    ("service", "T1543.003", "Windows Service", "persistence"),
    # Privilege Escalation
    ("uac bypass", "T1548.002", "Bypass User Account Control", "privilege-escalation"),
    ("token", "T1134", "Access Token Manipulation", "privilege-escalation"),
    # Defense Evasion
    ("obfuscation", "T1027", "Obfuscated Files or Information", "defense-evasion"),
    ("packed", "T1027.002", "Software Packing", "defense-evasion"),
    ("base64", "T1140", "Deobfuscate/Decode Files or Information", "defense-evasion"),
    ("injection", "T1055", "Process Injection", "defense-evasion"),
    ("hollow", "T1055.012", "Process Hollowing", "defense-evasion"),
    ("amsi bypass", "T1562.001", "Disable or Modify Tools", "defense-evasion"),
    # Credential Access
    ("mimikatz", "T1003.001", "LSASS Memory", "credential-access"),
    ("credential dump", "T1003", "OS Credential Dumping", "credential-access"),
    ("keylog", "T1056.001", "Keylogging", "credential-access"),
    # Discovery
    ("whoami", "T1033", "System Owner/User Discovery", "discovery"),
    ("ipconfig", "T1016", "System Network Configuration Discovery", "discovery"),
    ("net view", "T1018", "Remote System Discovery", "discovery"),
    ("systeminfo", "T1082", "System Information Discovery", "discovery"),
    # Lateral Movement
    ("psexec", "T1570", "Lateral Tool Transfer", "lateral-movement"),
    ("wmi", "T1047", "Windows Management Instrumentation", "lateral-movement"),
    ("rdp", "T1021.001", "Remote Desktop Protocol", "lateral-movement"),
    ("smb", "T1021.002", "SMB/Windows Admin Shares", "lateral-movement"),
    # Collection
    ("screenshot", "T1113", "Screen Capture", "collection"),
    ("clipboard", "T1115", "Clipboard Data", "collection"),
    # Command and Control
    ("c2", "T1071", "Application Layer Protocol", "command-and-control"),
    ("beacon", "T1071.001", "Web Protocols", "command-and-control"),
    ("dns tunnel", "T1071.004", "DNS", "command-and-control"),
    ("tor", "T1090.003", "Multi-hop Proxy", "command-and-control"),
    # Exfiltration
    ("exfiltrat", "T1041", "Exfiltration Over C2 Channel", "exfiltration"),
    ("upload", "T1567", "Exfiltration Over Web Service", "exfiltration"),
    # Impact
    ("ransom", "T1486", "Data Encrypted for Impact", "impact"),
    ("wiper", "T1485", "Data Destruction", "impact"),
    ("encrypt", "T1486", "Data Encrypted for Impact", "impact"),
]

# Private / loopback IP prefixes to filter out
_PRIVATE_IP_PREFIXES = ("10.", "127.", "192.168.", "0.", "169.254.", "172.16.",
                         "172.17.", "172.18.", "172.19.", "172.2", "172.30.",
                         "172.31.")


class CorrelationEngine:
    """Cross-analysis finding correlation engine.

    Accepts a list of finding dicts (from different analysis tools, sandbox
    results, threat-intel lookups, etc.), extracts IOCs, detects overlaps,
    maps to MITRE ATT&CK TTPs, builds a relationship graph, and returns
    severity escalation recommendations.

    Two usage modes are supported:

    1. **Stateless** -- call ``correlate(findings)`` directly::

           engine = CorrelationEngine()
           result = engine.correlate(findings_list)

    2. **Stateful** -- incrementally index findings for cross-session
       correlation using ``add_findings``, ``correlate_ioc``, etc.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or {}

        # Stateful indexes (for cross-session correlation)
        self._ioc_map: Dict[str, List[Dict]] = defaultdict(list)
        self._technique_map: Dict[str, List[str]] = defaultdict(list)
        self._session_findings: Dict[str, List[Dict]] = defaultdict(list)

    # ================================================================== #
    #  Primary entry point: correlate(findings) -> Dict
    # ================================================================== #

    def correlate(self, findings: List[Dict]) -> Dict[str, Any]:
        """Correlate findings from multiple analysis sources.

        Args:
            findings: List of finding dicts.  Each dict should have at least
                      a ``type`` key and may contain nested ``result`` dicts,
                      IOC strings, or free-text fields.

        Returns:
            Dict with keys:
              - ``ioc_overlaps``: IOCs seen across 2+ findings
              - ``ttp_matches``: detected MITRE ATT&CK techniques
              - ``entity_graph``: relationship adjacency list
              - ``severity``: computed severity (critical/high/medium/low/info)
              - ``escalation_recommendations``: list of recommended actions
              - ``statistics``: summary counts
              - ``correlated_at``: ISO timestamp
        """
        try:
            # Step 1: Extract IOCs per finding
            per_finding_iocs = self._extract_iocs_per_finding(findings)

            # Step 2: Find IOC overlaps (present in 2+ findings)
            ioc_overlaps = self._find_overlaps(per_finding_iocs)

            # Step 3: Map to MITRE ATT&CK TTPs
            ttp_matches = self._detect_ttps(findings)

            # Step 4: Build entity relationship graph
            entity_graph = self._build_entity_graph(per_finding_iocs, findings)

            # Step 5: Assess severity and generate recommendations
            severity, recommendations = self._assess_severity(
                findings, ioc_overlaps, ttp_matches,
            )

            # Step 6: Statistics
            all_iocs = self._flatten_iocs(per_finding_iocs)
            statistics = {
                "total_findings": len(findings),
                "unique_iocs": sum(len(v) for v in all_iocs.values()),
                "ioc_overlaps": len(ioc_overlaps),
                "ttp_count": len(ttp_matches),
                "entity_count": len(entity_graph),
                "ioc_breakdown": {k: len(v) for k, v in all_iocs.items()},
            }

            return {
                "ioc_overlaps": ioc_overlaps,
                "ttp_matches": ttp_matches,
                "entity_graph": entity_graph,
                "severity": severity,
                "escalation_recommendations": recommendations,
                "statistics": statistics,
                "correlated_at": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as exc:
            logger.error("[CORRELATION] correlate failed: %s", exc, exc_info=True)
            return {"error": str(exc)}

    # ================================================================== #
    #  Stateful ingestion (for cross-session use)
    # ================================================================== #

    def add_findings(self, session_id: str, findings: List[Dict]) -> int:
        """Index findings for stateful cross-session correlation.

        Returns the number of new IOC sightings indexed.
        """
        new_iocs = 0
        for idx, finding in enumerate(findings):
            enriched = {
                "session_id": session_id,
                "finding_index": idx,
                "tool": finding.get("tool", finding.get("tool_name", "unknown")),
                "timestamp": finding.get(
                    "timestamp", datetime.now(timezone.utc).isoformat()
                ),
            }

            text_blob = self._finding_to_text(finding)
            extracted = self._extract_iocs_from_text(text_blob)

            # Absorb structured IOC fields
            iocs_set: Set[str] = set()
            for ioc_type, vals in extracted.items():
                iocs_set.update(vals)

            explicit = finding.get("iocs", [])
            if isinstance(explicit, dict):
                for vals in explicit.values():
                    if isinstance(vals, list):
                        iocs_set.update(str(v).strip() for v in vals)
            elif isinstance(explicit, list):
                iocs_set.update(str(v).strip() for v in explicit)

            for ioc in iocs_set:
                if ioc:
                    self._ioc_map[ioc].append(enriched)
                    new_iocs += 1

            # MITRE techniques
            techniques = finding.get("mitre_techniques", [])
            if isinstance(techniques, list):
                for t in techniques:
                    tid = t if isinstance(t, str) else t.get("id", t.get("technique_id", ""))
                    if tid:
                        self._technique_map[tid].append(session_id)
            for tid in _RE_MITRE.findall(text_blob):
                self._technique_map[tid].append(session_id)

            self._session_findings[session_id].append({**finding, **enriched})

        logger.debug(
            "[CORR] Indexed %d findings for session %s (%d new IOCs)",
            len(findings), session_id, new_iocs,
        )
        return new_iocs

    def correlate_ioc(self, ioc: str) -> Dict:
        """Find all analyses related to a single IOC (stateful index)."""
        sightings = self._ioc_map.get(ioc, [])
        sessions = list({s["session_id"] for s in sightings})
        tools = list({s["tool"] for s in sightings})
        return {
            "ioc": ioc,
            "seen_count": len(sightings),
            "sessions": sessions,
            "tools": tools,
            "sightings": sightings,
        }

    def find_related_sessions(self, session_id: str) -> List[Dict]:
        """Find other sessions sharing IOCs with the given one."""
        my_iocs: Set[str] = set()
        for finding in self._session_findings.get(session_id, []):
            explicit = finding.get("iocs", [])
            if isinstance(explicit, dict):
                for vals in explicit.values():
                    if isinstance(vals, list):
                        my_iocs.update(str(v).strip() for v in vals)
            elif isinstance(explicit, list):
                my_iocs.update(str(v).strip() for v in explicit if v)

        if not my_iocs:
            return []

        session_scores: Dict[str, Dict] = {}
        for ioc in my_iocs:
            for sighting in self._ioc_map.get(ioc, []):
                other = sighting["session_id"]
                if other == session_id:
                    continue
                if other not in session_scores:
                    session_scores[other] = {"shared_iocs": set(), "tools": set()}
                session_scores[other]["shared_iocs"].add(ioc)
                session_scores[other]["tools"].add(sighting["tool"])

        results = []
        for other_id, info in session_scores.items():
            results.append({
                "session_id": other_id,
                "shared_ioc_count": len(info["shared_iocs"]),
                "shared_iocs": sorted(info["shared_iocs"])[:20],
                "tools": sorted(info["tools"]),
                "overlap_score": round(
                    len(info["shared_iocs"]) / max(len(my_iocs), 1) * 100, 1
                ),
            })
        results.sort(key=lambda r: r["overlap_score"], reverse=True)
        return results[:20]

    def get_stats(self) -> Dict:
        """Return stateful engine statistics."""
        return {
            "total_iocs_indexed": len(self._ioc_map),
            "total_techniques_indexed": len(self._technique_map),
            "total_sessions_indexed": len(self._session_findings),
            "total_findings_indexed": sum(
                len(f) for f in self._session_findings.values()
            ),
        }

    def clear_session(self, session_id: str) -> None:
        """Remove all indexed data for a session."""
        self._session_findings.pop(session_id, None)
        for ioc in list(self._ioc_map.keys()):
            self._ioc_map[ioc] = [
                s for s in self._ioc_map[ioc] if s["session_id"] != session_id
            ]
            if not self._ioc_map[ioc]:
                del self._ioc_map[ioc]
        for tid in list(self._technique_map.keys()):
            self._technique_map[tid] = [
                s for s in self._technique_map[tid] if s != session_id
            ]
            if not self._technique_map[tid]:
                del self._technique_map[tid]

    # ================================================================== #
    #  IOC extraction helpers
    # ================================================================== #

    def _extract_iocs_per_finding(
        self, findings: List[Dict],
    ) -> List[Dict[str, Set[str]]]:
        """Extract IOCs from each finding independently."""
        result: List[Dict[str, Set[str]]] = []
        for finding in findings:
            text = self._finding_to_text(finding)
            iocs = self._extract_iocs_from_text(text)
            if isinstance(finding.get("result"), dict):
                self._absorb_structured_iocs(finding["result"], iocs)
            self._absorb_structured_iocs(finding, iocs)
            result.append(iocs)
        return result

    @staticmethod
    def _extract_iocs_from_text(text: str) -> Dict[str, Set[str]]:
        """Apply regex patterns to extract IOCs from raw text."""
        iocs: Dict[str, Set[str]] = defaultdict(set)
        for match in _RE_IPV4.finditer(text):
            iocs["ipv4"].add(match.group(0))
        for match in _RE_DOMAIN.finditer(text):
            iocs["domain"].add(match.group(0))
        for match in _RE_SHA256.finditer(text):
            iocs["sha256"].add(match.group(0))
        for match in _RE_SHA1.finditer(text):
            iocs["sha1"].add(match.group(0))
        for match in _RE_MD5.finditer(text):
            iocs["md5"].add(match.group(0))
        for match in _RE_URL.finditer(text):
            iocs["url"].add(match.group(0).rstrip("/.,;:"))
        for match in _RE_EMAIL.finditer(text):
            iocs["email"].add(match.group(0))

        # Filter private/loopback IPs
        iocs["ipv4"] = {
            ip for ip in iocs.get("ipv4", set())
            if not any(ip.startswith(p) for p in _PRIVATE_IP_PREFIXES)
        }
        return dict(iocs)

    @staticmethod
    def _absorb_structured_iocs(data: Dict, iocs: Dict[str, Set[str]]) -> None:
        """Absorb IOCs from well-known structured fields."""
        field_map = {
            "ips": "ipv4", "ip": "ipv4", "ip_addresses": "ipv4",
            "domains": "domain", "domain": "domain",
            "urls": "url", "url": "url",
            "hashes": "sha256", "sha256": "sha256", "md5": "md5", "sha1": "sha1",
            "emails": "email",
        }
        for field, ioc_type in field_map.items():
            value = data.get(field)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item.strip():
                        iocs.setdefault(ioc_type, set()).add(item.strip())
            elif isinstance(value, str) and value.strip():
                iocs.setdefault(ioc_type, set()).add(value.strip())

    @staticmethod
    def _finding_to_text(finding: Dict) -> str:
        """Convert a finding dict to a flat text string for regex scanning."""
        parts: List[str] = []

        def _walk(obj: Any, depth: int = 0) -> None:
            if depth > 8:
                return
            if isinstance(obj, str):
                parts.append(obj)
            elif isinstance(obj, dict):
                for v in obj.values():
                    _walk(v, depth + 1)
            elif isinstance(obj, (list, tuple)):
                for item in obj:
                    _walk(item, depth + 1)

        _walk(finding)
        return " ".join(parts)

    # ================================================================== #
    #  Overlap detection
    # ================================================================== #

    @staticmethod
    def _find_overlaps(
        per_finding_iocs: List[Dict[str, Set[str]]],
    ) -> List[Dict[str, Any]]:
        """Find IOCs appearing in two or more distinct findings."""
        ioc_sources: Dict[str, Set[int]] = defaultdict(set)
        ioc_types: Dict[str, str] = {}

        for idx, iocs_by_type in enumerate(per_finding_iocs):
            for ioc_type, values in iocs_by_type.items():
                for value in values:
                    ioc_sources[value].add(idx)
                    ioc_types[value] = ioc_type

        overlaps = []
        for ioc_value, sources in ioc_sources.items():
            if len(sources) >= 2:
                overlaps.append({
                    "ioc": ioc_value,
                    "type": ioc_types.get(ioc_value, "unknown"),
                    "seen_in_findings": sorted(sources),
                    "count": len(sources),
                })

        overlaps.sort(key=lambda x: x["count"], reverse=True)
        return overlaps

    # ================================================================== #
    #  MITRE ATT&CK TTP detection
    # ================================================================== #

    def _detect_ttps(self, findings: List[Dict]) -> List[Dict[str, Any]]:
        """Scan findings for behavioural indicators and map to ATT&CK TTPs."""
        combined_text = " ".join(
            self._finding_to_text(f) for f in findings
        ).lower()

        seen: Dict[str, Dict[str, Any]] = {}

        # Keyword matching
        for keyword, tid, tname, tactic in _TTP_PATTERNS:
            if keyword in combined_text:
                if tid not in seen:
                    seen[tid] = {
                        "technique_id": tid,
                        "technique_name": tname,
                        "tactic": tactic,
                        "matched_keywords": [],
                    }
                seen[tid]["matched_keywords"].append(keyword)

        # Structured MITRE references
        for finding in findings:
            self._extract_structured_ttps(finding, seen)

        return list(seen.values())

    def _extract_structured_ttps(
        self, data: Any, seen: Dict[str, Dict[str, Any]], depth: int = 0,
    ) -> None:
        """Recursively find MITRE ATT&CK references in structured data."""
        if depth > 6:
            return
        if isinstance(data, dict):
            for key in ("mitre_attck", "mitre_attcks", "ttp", "ttps",
                        "attack_id", "technique_id", "technique"):
                value = data.get(key)
                if isinstance(value, str) and value.startswith("T"):
                    if value not in seen:
                        seen[value] = {
                            "technique_id": value,
                            "technique_name": data.get("technique_name", data.get("name", "")),
                            "tactic": data.get("tactic", ""),
                            "matched_keywords": ["structured_data"],
                        }
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item.startswith("T"):
                            if item not in seen:
                                seen[item] = {
                                    "technique_id": item,
                                    "technique_name": "",
                                    "tactic": "",
                                    "matched_keywords": ["structured_data"],
                                }
                        elif isinstance(item, dict):
                            self._extract_structured_ttps(item, seen, depth + 1)
            for v in data.values():
                self._extract_structured_ttps(v, seen, depth + 1)
        elif isinstance(data, list):
            for item in data:
                self._extract_structured_ttps(item, seen, depth + 1)

    # ================================================================== #
    #  Entity relationship graph
    # ================================================================== #

    def _build_entity_graph(
        self,
        per_finding_iocs: List[Dict[str, Set[str]]],
        findings: List[Dict],
    ) -> Dict[str, List[Dict[str, str]]]:
        """Build an adjacency-list relationship graph between IOC entities.

        Two entities are linked if they co-occur in the same finding.
        """
        graph: Dict[str, List[Dict[str, str]]] = defaultdict(list)

        for idx, iocs_by_type in enumerate(per_finding_iocs):
            all_values: List[Tuple[str, str]] = []
            for ioc_type, values in iocs_by_type.items():
                for v in values:
                    all_values.append((v, ioc_type))

            # Also link to file identifiers from the finding
            for key in ("file_name", "file_hash", "sha256", "md5"):
                val = self._deep_get(findings[idx], key)
                if val and isinstance(val, str):
                    all_values.append((val, key))

            # Pairwise edges (capped to avoid combinatorial explosion)
            capped = all_values[:200]
            for i, (v1, t1) in enumerate(capped):
                for v2, t2 in capped[i + 1:]:
                    if v1 != v2:
                        graph[v1].append({
                            "related": v2, "type": t2,
                            "relation": "co-occurred", "finding_idx": idx,
                        })
                        graph[v2].append({
                            "related": v1, "type": t1,
                            "relation": "co-occurred", "finding_idx": idx,
                        })

        # Deduplicate edges
        for entity in graph:
            seen_edges: set = set()
            unique: List[Dict[str, str]] = []
            for edge in graph[entity]:
                key = (edge["related"], edge["relation"])
                if key not in seen_edges:
                    seen_edges.add(key)
                    unique.append(edge)
            graph[entity] = unique

        return dict(graph)

    @staticmethod
    def _deep_get(data: Dict, key: str) -> Any:
        """Recursively search for *key* in nested dicts."""
        if key in data:
            return data[key]
        for v in data.values():
            if isinstance(v, dict):
                result = CorrelationEngine._deep_get(v, key)
                if result is not None:
                    return result
        return None

    # ================================================================== #
    #  Severity assessment & escalation recommendations
    # ================================================================== #

    def _assess_severity(
        self,
        findings: List[Dict],
        overlaps: List[Dict],
        ttps: List[Dict],
    ) -> Tuple[str, List[str]]:
        """Compute overall severity and generate escalation recommendations.

        Returns:
            (severity_string, list_of_recommendation_strings)
        """
        score = 0
        recommendations: List[str] = []

        # ---- Overlap scoring ----
        high_overlap = sum(1 for o in overlaps if o["count"] >= 3)
        if high_overlap >= 3:
            score += 30
            recommendations.append(
                f"{high_overlap} IOCs appear in 3+ analyses -- "
                "strong correlation indicates a coordinated campaign."
            )
        elif overlaps:
            score += 10 * min(len(overlaps), 5)

        # ---- TTP scoring ----
        tactics_seen = {t["tactic"] for t in ttps if t.get("tactic")}
        if "impact" in tactics_seen:
            score += 25
            recommendations.append(
                "Impact-phase TTPs detected (ransomware/wiper). "
                "Escalate to Incident Response immediately."
            )
        if "credential-access" in tactics_seen:
            score += 15
            recommendations.append(
                "Credential access TTPs detected. "
                "Reset affected credentials and audit access logs."
            )
        if "lateral-movement" in tactics_seen:
            score += 15
            recommendations.append(
                "Lateral movement TTPs detected. "
                "Isolate affected hosts and check neighbour systems."
            )
        if "command-and-control" in tactics_seen:
            score += 15
            recommendations.append(
                "C2 communication TTPs detected. "
                "Block identified C2 infrastructure at the perimeter."
            )
        if len(tactics_seen) >= 4:
            score += 10
            recommendations.append(
                f"Attack spans {len(tactics_seen)} MITRE ATT&CK tactics -- "
                "full kill-chain coverage suggests an advanced threat."
            )

        # ---- Finding verdicts ----
        verdicts: List[str] = []
        for f in findings:
            for key in ("verdict", "threat_level", "score"):
                v = self._deep_get(f, key) if isinstance(f, dict) else None
                if v is not None:
                    verdicts.append(str(v).lower())

        malicious_count = sum(
            1 for v in verdicts
            if v in ("malicious", "malware", "high", "critical")
            or (v.isdigit() and int(v) >= 70)
        )
        if malicious_count >= 2:
            score += 20
            recommendations.append(
                f"{malicious_count} sources report malicious verdict. "
                "High confidence of true positive."
            )
        elif malicious_count == 1:
            score += 10

        # ---- Map score to severity ----
        if score >= 60:
            severity = "critical"
        elif score >= 40:
            severity = "high"
        elif score >= 20:
            severity = "medium"
        elif score >= 10:
            severity = "low"
        else:
            severity = "info"

        if not recommendations:
            recommendations.append(
                "No significant correlations found. Continue monitoring."
            )

        return severity, recommendations

    # ================================================================== #
    #  Utility
    # ================================================================== #

    @staticmethod
    def _flatten_iocs(
        per_finding: List[Dict[str, Set[str]]],
    ) -> Dict[str, Set[str]]:
        """Merge per-finding IOC sets into global sets by type."""
        merged: Dict[str, Set[str]] = defaultdict(set)
        for iocs_by_type in per_finding:
            for ioc_type, values in iocs_by_type.items():
                merged[ioc_type].update(values)
        return dict(merged)
