"""
Tests for standardized AnalysisResult data models.
"""

import pytest

from src.models.analysis_result import (
    AnalysisResult,
    AnalysisMetadata,
    Finding,
    FindingSeverity,
    IOCEntry,
    IOCType,
    MITRETechnique,
    Verdict,
)


class TestFinding:
    """Test Finding dataclass."""

    def test_creation(self):
        f = Finding(
            severity=FindingSeverity.HIGH,
            category="injection",
            description="Process injection via VirtualAllocEx",
            evidence="VirtualAllocEx + WriteProcessMemory + CreateRemoteThread",
            source_tool="pe_analyzer",
            mitre_ids=["T1055"],
        )
        assert f.severity == FindingSeverity.HIGH
        assert f.category == "injection"
        assert "T1055" in f.mitre_ids

    def test_to_dict(self):
        f = Finding(
            severity=FindingSeverity.CRITICAL,
            category="c2",
            description="C2 callback detected",
        )
        d = f.to_dict()
        assert d['severity'] == 'critical'
        assert d['category'] == 'c2'

    def test_default_fields(self):
        f = Finding(severity=FindingSeverity.LOW, category="info", description="test")
        assert f.evidence == ""
        assert f.source_tool == ""
        assert f.mitre_ids == []


class TestIOCEntry:
    """Test IOCEntry dataclass."""

    def test_creation(self):
        ioc = IOCEntry(
            ioc_type=IOCType.IPV4,
            value="185.220.101.1",
            context="Found in PE strings",
            verdict="malicious",
            score=85,
            sources=["virustotal", "abuseipdb"],
        )
        assert ioc.ioc_type == IOCType.IPV4
        assert ioc.score == 85

    def test_to_dict(self):
        ioc = IOCEntry(ioc_type=IOCType.DOMAIN, value="evil.com")
        d = ioc.to_dict()
        assert d['type'] == 'domain'
        assert d['value'] == 'evil.com'

    def test_all_ioc_types_exist(self):
        """Ensure we have common IOC types."""
        expected = ['IPV4', 'DOMAIN', 'URL', 'EMAIL', 'MD5', 'SHA1', 'SHA256', 'CVE']
        for name in expected:
            assert hasattr(IOCType, name), f"IOCType.{name} missing"


class TestMITRETechnique:
    """Test MITRETechnique dataclass."""

    def test_creation(self):
        t = MITRETechnique(
            technique_id="T1055.001",
            technique_name="Dynamic-link Library Injection",
            tactic="defense-evasion",
            confidence="high",
            source="capa",
        )
        assert t.technique_id == "T1055.001"
        assert t.tactic == "defense-evasion"

    def test_to_dict(self):
        t = MITRETechnique(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="execution",
        )
        d = t.to_dict()
        assert d['technique_id'] == 'T1059'
        assert d['confidence'] == 'medium'  # default


class TestAnalysisResult:
    """Test AnalysisResult main dataclass."""

    def test_creation_minimal(self):
        r = AnalysisResult(
            verdict=Verdict.CLEAN,
            threat_score=0,
            confidence=0.0,
            summary="No threats found",
        )
        assert r.is_clean
        assert not r.is_malicious
        assert r.threat_score == 0

    def test_malicious_result(self):
        r = AnalysisResult(
            verdict=Verdict.MALICIOUS,
            threat_score=90,
            confidence=0.95,
            summary="High-confidence malware detection",
            findings=[
                Finding(
                    severity=FindingSeverity.CRITICAL,
                    category="trojan",
                    description="Known Cobalt Strike beacon",
                )
            ],
        )
        assert r.is_malicious
        assert len(r.critical_findings) == 1
        assert r.threat_score == 90

    def test_to_dict(self):
        r = AnalysisResult(
            verdict=Verdict.SUSPICIOUS,
            threat_score=55,
            confidence=0.6,
            summary="Suspicious behavior",
            hashes={'md5': 'abc123', 'sha256': 'def456'},
        )
        d = r.to_dict()
        assert d['verdict'] == 'SUSPICIOUS'
        assert d['threat_score'] == 55
        assert d['hashes']['md5'] == 'abc123'

    def test_from_verdict_score(self):
        r = AnalysisResult.from_verdict_score("MALICIOUS", 85)
        assert r.verdict == Verdict.MALICIOUS
        assert r.threat_score == 85
        assert r.confidence > 0.8

    def test_from_verdict_score_unknown(self):
        r = AnalysisResult.from_verdict_score("UNKNOWN", 10)
        assert r.verdict == Verdict.UNKNOWN

    def test_unique_mitre_ids(self):
        r = AnalysisResult(
            verdict=Verdict.SUSPICIOUS,
            threat_score=50,
            confidence=0.5,
            summary="test",
            mitre_techniques=[
                MITRETechnique(technique_id="T1055", technique_name="Injection",
                               tactic="defense-evasion"),
                MITRETechnique(technique_id="T1059", technique_name="Scripting",
                               tactic="execution"),
                MITRETechnique(technique_id="T1055", technique_name="Injection",
                               tactic="privilege-escalation"),  # duplicate ID
            ],
        )
        assert r.unique_mitre_ids == ["T1055", "T1059"]

    def test_high_findings_filter(self):
        r = AnalysisResult(
            verdict=Verdict.SUSPICIOUS,
            threat_score=50,
            confidence=0.5,
            summary="test",
            findings=[
                Finding(severity=FindingSeverity.HIGH, category="a", description="a"),
                Finding(severity=FindingSeverity.LOW, category="b", description="b"),
                Finding(severity=FindingSeverity.HIGH, category="c", description="c"),
            ],
        )
        assert len(r.high_findings) == 2


class TestAnalysisMetadata:
    """Test AnalysisMetadata dataclass."""

    def test_creation(self):
        m = AnalysisMetadata(
            analyzer_name="pe_analyzer",
            analysis_type="file",
            file_type="PE",
            file_name="malware.exe",
            file_size=102400,
            tools_used=["pefile", "capa", "yara"],
        )
        assert m.analyzer_name == "pe_analyzer"
        assert m.file_size == 102400
        assert len(m.tools_used) == 3

    def test_to_dict(self):
        m = AnalysisMetadata(analyzer_name="test")
        d = m.to_dict()
        assert d['analyzer_name'] == 'test'
        assert 'timestamp' in d

    def test_default_timestamp(self):
        m = AnalysisMetadata(analyzer_name="test")
        assert m.timestamp is not None
        assert len(m.timestamp) > 10  # ISO format
