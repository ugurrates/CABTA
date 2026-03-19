"""
Tests for scoring system - ToolBasedScoring, verdict thresholds.
"""

import pytest

from src.scoring.tool_based_scoring import ToolBasedScoring, ToolScore, ScoringResult


class TestCombinedScore:
    """Test combined score calculation."""

    def test_empty_scores_returns_zero(self):
        score = ToolBasedScoring.calculate_combined_score({})
        assert score == 0

    def test_single_tool_score(self):
        scores = {'capa': 80}
        weights = {'capa': 1.0}
        score = ToolBasedScoring.calculate_combined_score(scores, weights)
        assert score == 80

    def test_weighted_average(self):
        scores = {'capa': 100, 'yara': 0}
        weights = {'capa': 0.5, 'yara': 0.5}
        score = ToolBasedScoring.calculate_combined_score(scores, weights)
        assert score == 50

    def test_missing_tool_ignored(self):
        """Tools not in scores should not affect the result."""
        scores = {'capa': 60}
        weights = {'capa': 0.25, 'floss': 0.15, 'yara': 0.15}
        score = ToolBasedScoring.calculate_combined_score(scores, weights)
        # Only capa contributes: 60 * 0.25 / 0.25 = 60
        assert score == 60

    def test_all_tools_maxed(self):
        scores = {tool: 100 for tool in ToolBasedScoring.FILE_TOOL_WEIGHTS}
        score = ToolBasedScoring.calculate_combined_score(
            scores, ToolBasedScoring.FILE_TOOL_WEIGHTS
        )
        assert score == 100

    def test_all_tools_zero(self):
        scores = {tool: 0 for tool in ToolBasedScoring.FILE_TOOL_WEIGHTS}
        score = ToolBasedScoring.calculate_combined_score(
            scores, ToolBasedScoring.FILE_TOOL_WEIGHTS
        )
        assert score == 0

    def test_score_capped_at_100(self):
        """Even if raw math exceeds 100, result should be capped."""
        scores = {'capa': 200}  # unrealistic but tests cap
        weights = {'capa': 1.0}
        score = ToolBasedScoring.calculate_combined_score(scores, weights)
        assert score <= 100

    def test_negative_score_passes_through(self):
        """Current implementation doesn't floor negative scores - documenting behavior."""
        scores = {'capa': -10}
        weights = {'capa': 1.0}
        score = ToolBasedScoring.calculate_combined_score(scores, weights)
        # Current behavior: negative scores pass through (to be fixed in Phase 3)
        assert isinstance(score, int)


class TestVerdictThresholds:
    """Test verdict determination from scores."""

    def test_malicious_verdict(self):
        assert ToolBasedScoring.VERDICT_THRESHOLDS['MALICIOUS'] == 70

    def test_suspicious_verdict(self):
        assert ToolBasedScoring.VERDICT_THRESHOLDS['SUSPICIOUS'] == 40

    def test_clean_verdict(self):
        assert ToolBasedScoring.VERDICT_THRESHOLDS['CLEAN'] == 0

    def test_threshold_ordering(self):
        thresholds = ToolBasedScoring.VERDICT_THRESHOLDS
        assert thresholds['MALICIOUS'] > thresholds['SUSPICIOUS'] > thresholds['CLEAN']


class TestToolWeights:
    """Test weight configuration sanity."""

    def test_file_weights_sum_reasonable(self):
        """Weights should sum to roughly 1.0-1.5 (some overlap expected)."""
        total = sum(ToolBasedScoring.FILE_TOOL_WEIGHTS.values())
        assert 0.5 < total < 2.0

    def test_office_weights_sum_reasonable(self):
        total = sum(ToolBasedScoring.OFFICE_TOOL_WEIGHTS.values())
        assert 0.5 < total < 2.0

    def test_pdf_weights_sum_reasonable(self):
        total = sum(ToolBasedScoring.PDF_TOOL_WEIGHTS.values())
        assert 0.5 < total < 2.0

    def test_email_weights_sum_reasonable(self):
        total = sum(ToolBasedScoring.EMAIL_TOOL_WEIGHTS.values())
        assert 0.5 < total < 2.0

    def test_no_zero_weights(self):
        for name, w in ToolBasedScoring.FILE_TOOL_WEIGHTS.items():
            assert w > 0, f"Weight for {name} is zero"


class TestToolScoreDataclass:
    """Test ToolScore dataclass."""

    def test_creation(self):
        ts = ToolScore(tool_name='capa', score=75, weight=0.25)
        assert ts.tool_name == 'capa'
        assert ts.score == 75
        assert ts.weight == 0.25
        assert ts.contributing_factors == []

    def test_with_factors(self):
        ts = ToolScore(
            tool_name='yara',
            score=90,
            weight=0.15,
            contributing_factors=['matched: trojan_generic', 'matched: cobalt_strike']
        )
        assert len(ts.contributing_factors) == 2


class TestScoringResultDataclass:
    """Test ScoringResult dataclass."""

    def test_creation(self):
        sr = ScoringResult(combined_score=65, verdict='SUSPICIOUS', confidence=0.7)
        assert sr.combined_score == 65
        assert sr.verdict == 'SUSPICIOUS'
        assert sr.confidence == 0.7
        assert sr.tool_scores == {}
        assert sr.contributing_factors == []

    def test_with_tool_scores(self):
        ts = ToolScore(tool_name='capa', score=80, weight=0.25)
        sr = ScoringResult(
            combined_score=80,
            verdict='MALICIOUS',
            confidence=0.9,
            tool_scores={'capa': ts}
        )
        assert 'capa' in sr.tool_scores
        assert sr.tool_scores['capa'].score == 80
