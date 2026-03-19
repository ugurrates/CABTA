"""
Tests for FuzzyHashAnalyzer - database loading and hash management.
"""

import json
import pytest
from pathlib import Path

from src.analyzers.fuzzy_hash_analyzer import FuzzyHashAnalyzer, SimilarityResult


class TestDatabaseLoading:
    """Test loading/saving of the hash database."""

    def test_default_db_loads(self):
        """Bundled data/fuzzy_hash_db.json should load successfully."""
        analyzer = FuzzyHashAnalyzer()
        assert len(analyzer.KNOWN_FAMILIES) >= 40

    def test_known_families_have_imphashes(self):
        """Each loaded family should have at least one imphash."""
        analyzer = FuzzyHashAnalyzer()
        for name, info in analyzer.KNOWN_FAMILIES.items():
            assert len(info['imphashes']) >= 1, f"{name} has no imphashes"

    def test_known_families_structure(self):
        """Each family entry must have the expected keys."""
        analyzer = FuzzyHashAnalyzer()
        required_keys = {'imphashes', 'ssdeep_patterns', 'tlsh_patterns'}
        for name, info in analyzer.KNOWN_FAMILIES.items():
            for key in required_keys:
                assert key in info, f"{name} missing key: {key}"

    def test_custom_db_path(self, tmp_path):
        """Load from a custom JSON database."""
        db = tmp_path / "custom_db.json"
        db.write_text(json.dumps({
            'families': {
                'test_family': {
                    'imphashes': ['aabbccdd' * 4],
                    'ssdeep_patterns': [],
                    'tlsh_patterns': [],
                }
            }
        }))
        analyzer = FuzzyHashAnalyzer(db_path=str(db))
        assert 'test_family' in analyzer.KNOWN_FAMILIES
        assert 'aabbccdd' * 4 in analyzer.KNOWN_FAMILIES['test_family']['imphashes']

    def test_missing_db_falls_back(self, tmp_path):
        """Missing database file should not crash, just return 0 families."""
        analyzer = FuzzyHashAnalyzer.__new__(FuzzyHashAnalyzer)
        analyzer.algorithms = []
        analyzer.KNOWN_FAMILIES = {}
        analyzer.db_path = tmp_path / "nonexistent.json"
        count = analyzer.load_database()
        assert count == 0

    def test_malformed_db_handled(self, tmp_path):
        """Malformed JSON should not crash."""
        db = tmp_path / "bad.json"
        db.write_text("not valid json {{{")
        analyzer = FuzzyHashAnalyzer.__new__(FuzzyHashAnalyzer)
        analyzer.algorithms = []
        analyzer.KNOWN_FAMILIES = {}
        analyzer.db_path = db
        count = analyzer.load_database()
        assert count == 0


class TestDatabaseUpdate:
    """Test update_database and persistence."""

    def test_add_new_family(self, tmp_path):
        """update_database should add a new family entry."""
        db = tmp_path / "db.json"
        db.write_text(json.dumps({'families': {}}))
        analyzer = FuzzyHashAnalyzer(db_path=str(db))
        analyzer.update_database(
            'new_malware',
            imphashes=['1234567890abcdef' * 2],
            description='Test family',
            persist=False,
        )
        assert 'new_malware' in analyzer.KNOWN_FAMILIES
        assert '1234567890abcdef' * 2 in analyzer.KNOWN_FAMILIES['new_malware']['imphashes']

    def test_append_to_existing_family(self, tmp_path):
        """update_database should append hashes, not replace them."""
        db = tmp_path / "db.json"
        db.write_text(json.dumps({
            'families': {
                'existing': {
                    'imphashes': ['aaa'],
                    'ssdeep_patterns': [],
                    'tlsh_patterns': [],
                }
            }
        }))
        analyzer = FuzzyHashAnalyzer(db_path=str(db))
        analyzer.update_database('existing', imphashes=['bbb'], persist=False)
        imps = analyzer.KNOWN_FAMILIES['existing']['imphashes']
        assert 'aaa' in imps
        assert 'bbb' in imps

    def test_persist_writes_to_disk(self, tmp_path):
        """persist=True should save to disk."""
        db = tmp_path / "db.json"
        db.write_text(json.dumps({'families': {}}))
        analyzer = FuzzyHashAnalyzer(db_path=str(db))
        analyzer.update_database(
            'persisted',
            imphashes=['deadbeef' * 4],
            persist=True,
        )
        # Reload and verify
        reloaded = json.loads(db.read_text())
        assert 'persisted' in reloaded['families']


class TestSimilarityResult:
    """Test the SimilarityResult dataclass."""

    def test_defaults(self):
        r = SimilarityResult()
        assert r.ssdeep_score == 0
        assert r.tlsh_score == 0
        assert r.imphash_match is False
        assert r.combined_score == 0
        assert r.is_similar is False

    def test_family_match(self):
        r = SimilarityResult(family_match='emotet', is_similar=True, combined_score=90)
        assert r.family_match == 'emotet'
        assert r.is_similar is True


class TestKnownFamilyCheck:
    """Test _check_known_families against loaded DB."""

    def test_imphash_match_found(self):
        analyzer = FuzzyHashAnalyzer()
        # Use the emotet imphash from the DB
        emotet_imphash = analyzer.KNOWN_FAMILIES.get('emotet', {}).get('imphashes', [''])[0]
        if not emotet_imphash:
            pytest.skip("Emotet imphash not in DB")
        matches = analyzer._check_known_families({'imphash': emotet_imphash})
        assert len(matches) >= 1
        assert matches[0]['family'] == 'emotet'

    def test_no_match_for_random_hash(self):
        analyzer = FuzzyHashAnalyzer()
        matches = analyzer._check_known_families({'imphash': 'ffffffffffffffffffffffffffffffff'})
        assert len(matches) == 0

    def test_no_match_without_imphash(self):
        analyzer = FuzzyHashAnalyzer()
        matches = analyzer._check_known_families({'imphash': ''})
        assert len(matches) == 0


class TestAnalyzeFile:
    """Test file analysis (traditional hashes always work)."""

    def test_analyze_generates_traditional_hashes(self, tmp_path):
        target = tmp_path / "sample.bin"
        target.write_bytes(b"A" * 1024)
        analyzer = FuzzyHashAnalyzer()
        result = analyzer.analyze_file(str(target))
        assert result['hashes']['md5']
        assert result['hashes']['sha1']
        assert result['hashes']['sha256']
        assert result['file_size'] == 1024

    def test_analyze_nonexistent_file(self):
        analyzer = FuzzyHashAnalyzer()
        result = analyzer.analyze_file('/nonexistent/file.bin')
        assert 'error' in result
