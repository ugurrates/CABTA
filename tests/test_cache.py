"""
Tests for IOC Cache and Analysis Cache (Faz 3.2).
"""

import json
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from src.cache.ioc_cache import IOCCache
from src.cache.analysis_cache import AnalysisCache


# ========== IOC Cache ==========

class TestIOCCache:
    @pytest.fixture(autouse=True)
    def setup_cache(self, tmp_path):
        db = str(tmp_path / 'test_ioc.db')
        self.cache = IOCCache(db_path=db, default_ttl_hours=24)

    def test_set_and_get(self):
        self.cache.set('8.8.8.8', 'ip', 'virustotal', {'score': 0, 'status': 'clean'})
        result = self.cache.get('8.8.8.8', 'ip', 'virustotal')
        assert result is not None
        assert result['score'] == 0

    def test_cache_miss(self):
        result = self.cache.get('1.2.3.4', 'ip', 'virustotal')
        assert result is None

    def test_different_sources_separate(self):
        self.cache.set('evil.com', 'domain', 'vt', {'score': 80})
        self.cache.set('evil.com', 'domain', 'abuseipdb', {'score': 90})
        vt = self.cache.get('evil.com', 'domain', 'vt')
        abuse = self.cache.get('evil.com', 'domain', 'abuseipdb')
        assert vt['score'] == 80
        assert abuse['score'] == 90

    def test_overwrite_existing(self):
        self.cache.set('8.8.8.8', 'ip', 'vt', {'score': 0})
        self.cache.set('8.8.8.8', 'ip', 'vt', {'score': 50})
        result = self.cache.get('8.8.8.8', 'ip', 'vt')
        assert result['score'] == 50

    def test_invalidate(self):
        self.cache.set('8.8.8.8', 'ip', 'vt', {'score': 0})
        deleted = self.cache.invalidate('8.8.8.8', 'ip', 'vt')
        assert deleted == 1
        assert self.cache.get('8.8.8.8', 'ip', 'vt') is None

    def test_count(self):
        assert self.cache.count() == 0
        self.cache.set('a', 'ip', 's1', {'x': 1})
        self.cache.set('b', 'ip', 's1', {'x': 2})
        assert self.cache.count() == 2

    def test_clear(self):
        self.cache.set('a', 'ip', 's1', {'x': 1})
        self.cache.set('b', 'ip', 's1', {'x': 2})
        self.cache.clear()
        assert self.cache.count() == 0

    def test_stats(self):
        self.cache.set('a', 'ip', 's1', {'x': 1})
        self.cache.get('a', 'ip', 's1')  # hit
        self.cache.get('b', 'ip', 's1')  # miss
        stats = self.cache.get_stats()
        assert stats['hits'] == 1
        assert stats['misses'] == 1
        assert stats['sets'] == 1
        assert stats['hit_rate'] == 0.5

    def test_custom_ttl(self):
        # Set with very short TTL - it shouldn't expire immediately though
        self.cache.set('x', 'ip', 's', {'v': 1}, ttl_hours=1)
        result = self.cache.get('x', 'ip', 's')
        assert result is not None


# ========== Analysis Cache ==========

class TestAnalysisCache:
    @pytest.fixture(autouse=True)
    def setup_cache(self, tmp_path):
        db = str(tmp_path / 'test_analysis.db')
        self.cache = AnalysisCache(db_path=db, max_age_days=30)

    def test_set_and_get(self):
        result = {'verdict': 'CLEAN', 'score': 10, 'tools': ['capa', 'yara']}
        self.cache.set('abc123', result)
        cached = self.cache.get('abc123')
        assert cached is not None
        assert cached['verdict'] == 'CLEAN'

    def test_cache_miss(self):
        assert self.cache.get('nonexistent') is None

    def test_has(self):
        self.cache.set('abc', {'v': 1})
        assert self.cache.has('abc') is True
        assert self.cache.has('xyz') is False

    def test_invalidate(self):
        self.cache.set('abc', {'v': 1})
        assert self.cache.invalidate('abc') is True
        assert self.cache.get('abc') is None

    def test_count(self):
        assert self.cache.count() == 0
        self.cache.set('a', {'x': 1})
        self.cache.set('b', {'x': 2})
        assert self.cache.count() == 2

    def test_clear(self):
        self.cache.set('a', {'x': 1})
        self.cache.clear()
        assert self.cache.count() == 0

    def test_stats(self):
        self.cache.set('a', {'x': 1})
        self.cache.get('a')  # hit
        self.cache.get('b')  # miss
        stats = self.cache.get_stats()
        assert stats['hits'] == 1
        assert stats['misses'] == 1
        assert stats['entries'] == 1

    def test_overwrite(self):
        self.cache.set('abc', {'v': 1})
        self.cache.set('abc', {'v': 2})
        result = self.cache.get('abc')
        assert result['v'] == 2
