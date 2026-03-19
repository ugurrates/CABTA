"""
Tests for Adaptive Scoring Engine (Faz 3.1).
"""

import math
from datetime import datetime, timezone, timedelta

import pytest

from src.scoring.adaptive_scoring import (
    AdaptiveScoringEngine,
    AdaptiveScore,
    KILL_CHAIN_STAGES,
    COMBO_RULES,
)


@pytest.fixture
def engine():
    return AdaptiveScoringEngine()


SAMPLE_WEIGHTS = {
    'capa': 0.25,
    'floss': 0.15,
    'yara': 0.15,
    'pe_analysis': 0.15,
    'threat_intel': 0.20,
    'strings': 0.10,
}


# ========== Weight Redistribution ==========

class TestWeightRedistribution:
    def test_all_present(self, engine):
        scores = {'capa': 50, 'floss': 30, 'yara': 40}
        w = {'capa': 0.3, 'floss': 0.3, 'yara': 0.4}
        new_w = engine._redistribute_weights(scores, w)
        # All present, no redistribution needed
        assert abs(sum(new_w.values()) - 1.0) < 0.001

    def test_missing_tool_redistributes(self, engine):
        scores = {'capa': 80}  # only capa present
        w = {'capa': 0.3, 'floss': 0.3, 'yara': 0.4}
        new_w = engine._redistribute_weights(scores, w)
        # Capa should get all weight
        assert abs(new_w['capa'] - 1.0) < 0.001

    def test_partial_presence(self, engine):
        scores = {'capa': 60, 'yara': 70}
        w = {'capa': 0.3, 'floss': 0.3, 'yara': 0.4}
        new_w = engine._redistribute_weights(scores, w)
        # floss's 0.3 should be split between capa and yara
        assert new_w['capa'] > 0.3
        assert new_w['yara'] > 0.4
        assert abs(sum(new_w.values()) - 1.0) < 0.001


# ========== Logarithmic Escalation ==========

class TestLogEscalation:
    def test_zero_indicators(self, engine):
        assert engine._log_escalation(0) == 0

    def test_positive_indicators(self, engine):
        result = engine._log_escalation(10)
        expected = int(math.log2(11) * 5.0)
        assert result == expected

    def test_scales_with_count(self, engine):
        low = engine._log_escalation(2)
        high = engine._log_escalation(20)
        assert high > low


# ========== Freshness Factor ==========

class TestFreshness:
    def test_fresh_data_boost(self, engine):
        now = datetime.now(timezone.utc)
        ts = {'vt': now - timedelta(hours=1)}
        factor = engine._freshness_factor(ts)
        assert factor == 1.2

    def test_week_old_data(self, engine):
        now = datetime.now(timezone.utc)
        ts = {'vt': now - timedelta(days=3)}
        factor = engine._freshness_factor(ts)
        assert factor == 1.1

    def test_month_old_data(self, engine):
        now = datetime.now(timezone.utc)
        ts = {'vt': now - timedelta(days=15)}
        factor = engine._freshness_factor(ts)
        assert factor == 1.0

    def test_old_data_penalty(self, engine):
        now = datetime.now(timezone.utc)
        ts = {'vt': now - timedelta(days=60)}
        factor = engine._freshness_factor(ts)
        assert factor == 0.85

    def test_very_old_data(self, engine):
        now = datetime.now(timezone.utc)
        ts = {'vt': now - timedelta(days=120)}
        factor = engine._freshness_factor(ts)
        assert factor == 0.7

    def test_no_timestamps(self, engine):
        assert engine._freshness_factor({}) == 1.0

    def test_multiple_sources_uses_freshest(self, engine):
        now = datetime.now(timezone.utc)
        ts = {
            'vt': now - timedelta(days=60),  # old
            'abuseipdb': now - timedelta(hours=2),  # fresh
        }
        factor = engine._freshness_factor(ts)
        assert factor == 1.2  # Uses the freshest source


# ========== Kill Chain Detection ==========

class TestKillChain:
    def test_empty_content(self, engine):
        assert engine._detect_kill_chain('') == []

    def test_single_stage(self, engine):
        stages = engine._detect_kill_chain('invoke-webrequest http://evil.com')
        assert 'delivery' in stages

    def test_multiple_stages(self, engine):
        content = "downloadstring from base64 invoke-expression schtasks"
        stages = engine._detect_kill_chain(content)
        assert 'delivery' in stages
        assert 'decode' in stages
        assert 'execution' in stages
        assert 'persistence' in stages

    def test_kill_chain_bonus_none(self, engine):
        assert engine._kill_chain_bonus([]) == 0
        assert engine._kill_chain_bonus(['delivery']) == 0

    def test_kill_chain_bonus_two(self, engine):
        bonus = engine._kill_chain_bonus(['delivery', 'decode'])
        assert bonus == 5

    def test_kill_chain_bonus_three(self, engine):
        bonus = engine._kill_chain_bonus(['delivery', 'decode', 'execution'])
        assert bonus == 12

    def test_kill_chain_bonus_four(self, engine):
        bonus = engine._kill_chain_bonus(['delivery', 'decode', 'execution', 'persistence'])
        assert bonus == 20


# ========== Combo Detection ==========

class TestComboDetection:
    def test_no_combos(self, engine):
        combos = engine._check_combos([])
        assert combos == []

    def test_persistence_c2_combo(self, engine):
        combos = engine._check_combos(['persistence', 'delivery'])
        names = [c['name'] for c in combos]
        assert 'persistence_c2' in names

    def test_full_killchain_combo(self, engine):
        stages = ['delivery', 'decode', 'execution', 'persistence']
        combos = engine._check_combos(stages)
        names = [c['name'] for c in combos]
        assert 'full_killchain' in names
        assert 'obfuscation_download_exec' in names


# ========== Full Scoring ==========

class TestFullScoring:
    def test_clean_scores(self, engine):
        scores = {'capa': 0, 'yara': 0, 'pe_analysis': 5}
        result = engine.score(scores, SAMPLE_WEIGHTS)
        assert result.verdict == 'CLEAN'
        assert result.final_score < 40

    def test_malicious_scores(self, engine):
        scores = {'capa': 90, 'yara': 80, 'pe_analysis': 85, 'threat_intel': 95}
        result = engine.score(scores, SAMPLE_WEIGHTS)
        assert result.verdict == 'MALICIOUS'
        assert result.final_score >= 70

    def test_content_with_killchain(self, engine):
        scores = {'capa': 60, 'yara': 50}
        content = "downloadstring frombase64string invoke-expression schtasks"
        result = engine.score(scores, SAMPLE_WEIGHTS, content=content)
        # Should have kill-chain bonus and combo bonus
        assert result.kill_chain_bonus > 0 or result.combo_bonus > 0
        assert len(result.kill_chain_stages) > 0

    def test_result_structure(self, engine):
        scores = {'capa': 50}
        result = engine.score(scores, SAMPLE_WEIGHTS)
        assert isinstance(result, AdaptiveScore)
        d = result.to_dict()
        assert 'final_score' in d
        assert 'verdict' in d
        assert 'confidence' in d
        assert 'contributing_tools' in d

    def test_extra_indicators_escalate(self, engine):
        scores = {'capa': 50}
        result_base = engine.score(scores, SAMPLE_WEIGHTS, extra_indicators=0)
        result_high = engine.score(scores, SAMPLE_WEIGHTS, extra_indicators=20)
        assert result_high.final_score >= result_base.final_score

    def test_freshness_affects_score(self, engine):
        scores = {'capa': 50, 'threat_intel': 60}
        now = datetime.now(timezone.utc)
        fresh_ts = {'vt': now - timedelta(hours=1)}
        old_ts = {'vt': now - timedelta(days=120)}
        r_fresh = engine.score(scores, SAMPLE_WEIGHTS, ti_timestamps=fresh_ts)
        r_old = engine.score(scores, SAMPLE_WEIGHTS, ti_timestamps=old_ts)
        assert r_fresh.final_score >= r_old.final_score

    def test_score_capped_at_100(self, engine):
        scores = {'capa': 100, 'yara': 100, 'threat_intel': 100}
        content = "downloadstring frombase64string invoke-expression schtasks mimikatz"
        result = engine.score(
            scores, SAMPLE_WEIGHTS,
            content=content, extra_indicators=50,
        )
        assert result.final_score <= 100
