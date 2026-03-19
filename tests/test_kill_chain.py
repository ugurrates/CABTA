"""
Tests for MITRE ATT&CK Kill Chain Analyzer (Faz 3.4).
"""

import pytest

from src.utils.mitre_kill_chain import (
    KillChainAnalyzer,
    KillChainAnalysis,
    PHASES,
    PHASE_SEVERITY,
)


@pytest.fixture
def analyzer():
    return KillChainAnalyzer()


def _make_tech(technique_id: str, name: str, tactic: str) -> dict:
    return {'technique_id': technique_id, 'technique_name': name, 'tactic': tactic}


class TestKillChainBasic:
    def test_no_techniques(self, analyzer):
        result = analyzer.analyze([])
        assert result.phases_detected == []
        assert result.progression_score == 0

    def test_single_phase(self, analyzer):
        techs = [_make_tech('T1059.001', 'PowerShell', 'Execution')]
        result = analyzer.analyze(techs)
        assert 'Execution' in result.phases_detected
        assert result.coverage_ratio > 0

    def test_multiple_phases(self, analyzer):
        techs = [
            _make_tech('T1059.001', 'PowerShell', 'Execution'),
            _make_tech('T1547.001', 'Registry Run Keys', 'Persistence'),
            _make_tech('T1105', 'Ingress Tool Transfer', 'Command and Control'),
        ]
        result = analyzer.analyze(techs)
        assert len(result.phases_detected) == 3

    def test_all_phases(self, analyzer):
        techs = [
            _make_tech(f'T{i}', f'Tech{i}', phase)
            for i, phase in enumerate(PHASES)
        ]
        result = analyzer.analyze(techs)
        assert result.coverage_ratio == 1.0


class TestConsecutiveChain:
    def test_two_consecutive(self, analyzer):
        techs = [
            _make_tech('T1', 'Exec', 'Execution'),
            _make_tech('T2', 'Persist', 'Persistence'),
        ]
        result = analyzer.analyze(techs)
        assert result.longest_chain >= 2

    def test_three_consecutive(self, analyzer):
        techs = [
            _make_tech('T1', 'Exec', 'Execution'),
            _make_tech('T2', 'Persist', 'Persistence'),
            _make_tech('T3', 'PrivEsc', 'Privilege Escalation'),
        ]
        result = analyzer.analyze(techs)
        assert result.longest_chain >= 3

    def test_non_consecutive(self, analyzer):
        techs = [
            _make_tech('T1', 'IA', 'Initial Access'),
            _make_tech('T2', 'Disc', 'Discovery'),
        ]
        result = analyzer.analyze(techs)
        assert result.longest_chain == 1


class TestProgressionScore:
    def test_minimal_is_low(self, analyzer):
        techs = [_make_tech('T1', 'Disc', 'Discovery')]
        result = analyzer.analyze(techs)
        assert result.progression_score < 40

    def test_full_chain_is_high(self, analyzer):
        techs = [
            _make_tech(f'T{i}', f'Tech{i}', phase)
            for i, phase in enumerate(PHASES)
        ]
        result = analyzer.analyze(techs)
        assert result.progression_score >= 70


class TestAssessment:
    def test_no_activity(self, analyzer):
        result = analyzer.analyze([])
        assert 'No techniques' in result.assessment

    def test_minimal_activity(self, analyzer):
        techs = [_make_tech('T1', 'Disc', 'Discovery')]
        result = analyzer.analyze(techs)
        assert 'Minimal' in result.assessment or 'isolated' in result.assessment

    def test_significant_activity(self, analyzer):
        techs = [
            _make_tech('T1', 'IA', 'Initial Access'),
            _make_tech('T2', 'Exec', 'Execution'),
            _make_tech('T3', 'Persist', 'Persistence'),
            _make_tech('T4', 'PrivEsc', 'Privilege Escalation'),
            _make_tech('T5', 'DE', 'Defense Evasion'),
        ]
        result = analyzer.analyze(techs)
        assert result.longest_chain >= 4
        assert 'Significant' in result.assessment or 'advanced' in result.assessment


class TestToDict:
    def test_structure(self, analyzer):
        techs = [
            _make_tech('T1059.001', 'PowerShell', 'Execution'),
            _make_tech('T1547.001', 'Run Keys', 'Persistence'),
        ]
        result = analyzer.analyze(techs)
        d = result.to_dict()
        assert 'phases_detected' in d
        assert 'phase_count' in d
        assert 'total_phases' in d
        assert 'coverage_ratio' in d
        assert 'assessment' in d
        assert 'phase_techniques' in d


class TestPhaseSeverity:
    def test_all_phases_have_severity(self):
        for phase in PHASES:
            assert phase in PHASE_SEVERITY

    def test_impact_is_highest(self):
        assert PHASE_SEVERITY['Impact'] >= max(
            v for k, v in PHASE_SEVERITY.items() if k != 'Impact'
        )
