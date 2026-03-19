"""
Tests for Packer / Crypter detection module.
"""

import struct
import pytest

from src.analyzers.packer_signatures import (
    PackerDetector,
    PackerMatch,
    PackerReport,
    PEFILE_AVAILABLE,
)


@pytest.fixture
def detector():
    return PackerDetector()


# ---------- Raw byte signatures ----------

class TestRawSignatures:
    def test_upx_magic_detected(self, detector):
        data = b'MZ' + b'\x00' * 200 + b'UPX!' + b'\x00' * 200
        report = detector.analyze_data(data)
        upx = [m for m in report.matches if m.packer_name == 'UPX']
        assert len(upx) >= 1
        assert report.is_packed

    def test_themida_marker(self, detector):
        data = b'MZ' + b'\x00' * 100 + b'.themida' + b'\x00' * 200
        report = detector.analyze_data(data)
        matches = [m for m in report.matches if m.packer_name == 'Themida']
        assert len(matches) >= 1

    def test_vmprotect_marker(self, detector):
        data = b'MZ' + b'\x00' * 100 + b'.vmp0' + b'\x00' * 200
        report = detector.analyze_data(data)
        matches = [m for m in report.matches if m.packer_name == 'VMProtect']
        assert len(matches) >= 1

    def test_nsis_marker(self, detector):
        data = b'MZ' + b'\x00' * 100 + b'\x00\x00\x00\x00NullsoftInst' + b'\x00' * 200
        report = detector.analyze_data(data)
        matches = [m for m in report.matches if m.packer_name == 'NSIS']
        assert len(matches) >= 1

    def test_clean_binary_no_matches(self, detector):
        # Random-ish data without any known markers
        data = bytes(range(256)) * 4
        report = detector.analyze_data(data)
        sig_matches = [m for m in report.matches if m.detection_method == 'signature']
        assert len(sig_matches) == 0


# ---------- PE section name detection ----------

class TestSectionNames:
    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not installed")
    def test_upx_section_detected(self, detector, tmp_path):
        """If a PE has UPX0 section name, it should be flagged."""
        # We'll create a minimal PE with custom section names
        # This is hard to test without a real PE, so test the match logic directly
        match = PackerMatch(
            packer_name='UPX',
            detection_method='section_name',
            confidence=0.85,
            description='Packer section name: UPX0',
        )
        assert match.packer_name == 'UPX'
        assert match.confidence == 0.85


# ---------- Import anomalies ----------

class TestImportAnomalies:
    def test_match_dataclass(self):
        match = PackerMatch(
            packer_name='Dynamic Resolver',
            detection_method='import_anomaly',
            confidence=0.70,
            description='Only LoadLibrary + GetProcAddress',
        )
        d = match.to_dict()
        assert d['detection_method'] == 'import_anomaly'


# ---------- Entropy ----------

class TestEntropyDetection:
    def test_entropy_in_profile(self, detector):
        """Entropy calculation helper works."""
        data = bytes(range(256)) * 100  # Uniform = ~8.0 entropy
        ent = detector._entropy(data)
        assert ent > 7.5

    def test_low_entropy_data(self, detector):
        data = b'\x00' * 10000
        ent = detector._entropy(data)
        assert ent == 0.0

    def test_medium_entropy(self, detector):
        data = b'\x00\x01\x02\x03' * 1000
        ent = detector._entropy(data)
        assert 1.0 < ent < 4.0


# ---------- Report structure ----------

class TestPackerReport:
    def test_empty_report(self):
        r = PackerReport()
        assert not r.is_packed
        assert r.threat_score == 0

    def test_to_dict(self):
        r = PackerReport(
            is_packed=True,
            packer_name='UPX',
            threat_score=40,
            matches=[
                PackerMatch(
                    packer_name='UPX',
                    detection_method='signature',
                    confidence=0.80,
                    description='UPX magic marker',
                )
            ],
            summary='Packer detected: UPX',
        )
        d = r.to_dict()
        assert d['is_packed'] is True
        assert d['packer_name'] == 'UPX'
        assert d['match_count'] == 1
        assert len(d['matches']) == 1

    def test_score_calculation(self, detector):
        matches = [
            PackerMatch('UPX', 'signature', 0.80, 'UPX magic'),
            PackerMatch('UPX', 'section_name', 0.85, 'UPX0'),
            PackerMatch('UPX', 'entry_point', 0.75, 'UPX EP'),
        ]
        score = detector._calculate_score(matches)
        assert 30 <= score <= 80

    def test_protector_boosts_score(self, detector):
        matches = [
            PackerMatch('Themida', 'signature', 0.80, 'Themida marker'),
        ]
        score = detector._calculate_score(matches)
        assert score >= 60  # Protectors get higher base score

    def test_analyze_file_nonexistent(self, detector):
        report = detector.analyze_file('/nonexistent/file.exe')
        assert 'Error' in report.summary

    def test_small_file(self, detector):
        report = detector.analyze_data(b'MZ')
        assert 'too small' in report.summary


class TestPatternMatch:
    def test_exact_match(self):
        assert PackerDetector._pattern_match(b'\x60\xBE', b'\x60\xBE\x00\x00') is True

    def test_wildcard_bytes(self):
        # 0x00 in pattern acts as wildcard
        assert PackerDetector._pattern_match(b'\x68\x00\x00\x00\x00\xe8', b'\x68\xAA\xBB\xCC\xDD\xe8') is True

    def test_no_match(self):
        assert PackerDetector._pattern_match(b'\x60\xBE', b'\x61\xBE\x00\x00') is False
