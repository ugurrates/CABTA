"""
Blue Team Assistant - Standardized Analysis Result Models.
Author: Ugur Ates

Provides a unified data structure for all analyzer outputs.
Each analyzer can convert its native output to this format
via the adapter pattern (to_analysis_result class method).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any


class FindingSeverity(Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IOCType(Enum):
    """Supported IOC types."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"
    MUTEX = "mutex"
    REGISTRY = "registry"
    FILEPATH = "filepath"
    ONION = "onion"
    JA3 = "ja3"
    JARM = "jarm"
    BITCOIN = "bitcoin"
    ETHEREUM = "ethereum"
    UNKNOWN = "unknown"


class Verdict(Enum):
    """Analysis verdict."""
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


@dataclass
class Finding:
    """A single finding from analysis."""
    severity: FindingSeverity
    category: str          # e.g. "persistence", "injection", "obfuscation"
    description: str
    evidence: str = ""     # specific data supporting this finding
    source_tool: str = ""  # which tool/analyzer produced this finding
    mitre_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'severity': self.severity.value,
            'category': self.category,
            'description': self.description,
            'evidence': self.evidence,
            'source_tool': self.source_tool,
            'mitre_ids': self.mitre_ids,
        }


@dataclass
class IOCEntry:
    """A single IOC extracted during analysis."""
    ioc_type: IOCType
    value: str
    context: str = ""       # where/how this IOC was found
    verdict: str = ""       # clean/suspicious/malicious
    score: int = 0          # 0-100 threat score
    sources: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.ioc_type.value,
            'value': self.value,
            'context': self.context,
            'verdict': self.verdict,
            'score': self.score,
            'sources': self.sources,
        }


@dataclass
class MITRETechnique:
    """A mapped MITRE ATT&CK technique."""
    technique_id: str       # e.g. "T1055" or "T1059.001"
    technique_name: str
    tactic: str             # e.g. "defense-evasion", "execution"
    confidence: str = "medium"  # low/medium/high
    source: str = ""        # which analyzer mapped this
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'technique_id': self.technique_id,
            'technique_name': self.technique_name,
            'tactic': self.tactic,
            'confidence': self.confidence,
            'source': self.source,
            'evidence': self.evidence,
        }


@dataclass
class AnalysisMetadata:
    """Metadata about the analysis run."""
    analyzer_name: str
    analyzer_version: str = "1.0.0"
    analysis_type: str = ""       # "file", "ioc", "email"
    file_type: str = ""           # "PE", "ELF", "PDF", etc.
    file_name: str = ""
    file_size: int = 0
    analysis_duration_ms: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tools_used: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'analyzer_name': self.analyzer_name,
            'analyzer_version': self.analyzer_version,
            'analysis_type': self.analysis_type,
            'file_type': self.file_type,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'analysis_duration_ms': self.analysis_duration_ms,
            'timestamp': self.timestamp,
            'tools_used': self.tools_used,
        }


@dataclass
class AnalysisResult:
    """
    Unified analysis result structure.

    All analyzers can produce this format via their
    ``to_analysis_result()`` adapter method.
    """
    verdict: Verdict
    threat_score: int               # 0-100
    confidence: float               # 0.0-1.0
    summary: str                    # one-line human readable summary

    findings: List[Finding] = field(default_factory=list)
    iocs: List[IOCEntry] = field(default_factory=list)
    mitre_techniques: List[MITRETechnique] = field(default_factory=list)

    hashes: Dict[str, str] = field(default_factory=dict)     # md5, sha1, sha256
    detection_rules: Dict[str, str] = field(default_factory=dict)  # kql, sigma, yara...
    recommendations: List[str] = field(default_factory=list)

    metadata: AnalysisMetadata = field(
        default_factory=lambda: AnalysisMetadata(analyzer_name="unknown")
    )
    raw_data: Dict[str, Any] = field(default_factory=dict)

    # ---------------------------------------------------------------
    # Helper properties
    # ---------------------------------------------------------------

    @property
    def is_malicious(self) -> bool:
        return self.verdict == Verdict.MALICIOUS

    @property
    def is_suspicious(self) -> bool:
        return self.verdict == Verdict.SUSPICIOUS

    @property
    def is_clean(self) -> bool:
        return self.verdict == Verdict.CLEAN

    @property
    def critical_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == FindingSeverity.CRITICAL]

    @property
    def high_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == FindingSeverity.HIGH]

    @property
    def unique_mitre_ids(self) -> List[str]:
        return sorted(set(t.technique_id for t in self.mitre_techniques))

    # ---------------------------------------------------------------
    # Serialization
    # ---------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary (JSON-friendly)."""
        return {
            'verdict': self.verdict.value,
            'threat_score': self.threat_score,
            'confidence': self.confidence,
            'summary': self.summary,
            'findings': [f.to_dict() for f in self.findings],
            'iocs': [i.to_dict() for i in self.iocs],
            'mitre_techniques': [m.to_dict() for m in self.mitre_techniques],
            'hashes': self.hashes,
            'detection_rules': self.detection_rules,
            'recommendations': self.recommendations,
            'metadata': self.metadata.to_dict(),
        }

    @classmethod
    def from_verdict_score(cls, verdict_str: str, score: int,
                           summary: str = "",
                           **kwargs) -> 'AnalysisResult':
        """Quick factory from a verdict string and score."""
        verdict_map = {
            'MALICIOUS': Verdict.MALICIOUS,
            'SUSPICIOUS': Verdict.SUSPICIOUS,
            'CLEAN': Verdict.CLEAN,
        }
        verdict = verdict_map.get(verdict_str.upper(), Verdict.UNKNOWN)

        confidence = 0.0
        if score >= 70:
            confidence = min(1.0, score / 100)
        elif score >= 40:
            confidence = 0.5
        elif score > 0:
            confidence = 0.3

        return cls(
            verdict=verdict,
            threat_score=score,
            confidence=confidence,
            summary=summary or f"Threat score: {score}/100 - {verdict.value}",
            **kwargs,
        )
