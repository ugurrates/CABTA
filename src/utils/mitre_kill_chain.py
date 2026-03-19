"""
Author: Ugur Ates
MITRE ATT&CK Kill Chain Analyzer.

Tespit edilen tekniklerden saldiri ilerleme asamasini tanimlar
ve tehdit seviyesini belirler.

Kill-chain asamalari (Unified Kill Chain modeli):
  Initial Access -> Execution -> Persistence -> Privilege Escalation
  -> Defense Evasion -> Credential Access -> Discovery
  -> Lateral Movement -> Collection -> C2 -> Exfiltration -> Impact
"""

import logging
from typing import Dict, List, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Kill Chain phases in order
PHASES = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact',
]

# Risk severity per phase (later stages = higher risk)
PHASE_SEVERITY = {
    'Initial Access': 0.3,
    'Execution': 0.5,
    'Persistence': 0.7,
    'Privilege Escalation': 0.8,
    'Defense Evasion': 0.6,
    'Credential Access': 0.9,
    'Discovery': 0.4,
    'Lateral Movement': 0.9,
    'Collection': 0.7,
    'Command and Control': 0.8,
    'Exfiltration': 0.95,
    'Impact': 1.0,
}


@dataclass
class KillChainAnalysis:
    """Kill chain analysis result."""
    phases_detected: List[str] = field(default_factory=list)
    phase_techniques: Dict[str, List[Dict]] = field(default_factory=dict)
    coverage_ratio: float = 0.0
    max_severity: float = 0.0
    progression_score: int = 0
    longest_chain: int = 0
    assessment: str = ''

    def to_dict(self) -> Dict:
        return {
            'phases_detected': self.phases_detected,
            'phase_count': len(self.phases_detected),
            'total_phases': len(PHASES),
            'coverage_ratio': round(self.coverage_ratio, 3),
            'max_severity': round(self.max_severity, 3),
            'progression_score': self.progression_score,
            'longest_chain': self.longest_chain,
            'assessment': self.assessment,
            'phase_techniques': {
                phase: [
                    {'id': t.get('technique_id', ''), 'name': t.get('technique_name', '')}
                    for t in techs
                ]
                for phase, techs in self.phase_techniques.items()
            },
        }


class KillChainAnalyzer:
    """Analyze MITRE ATT&CK techniques for kill-chain progression.

    Usage::

        analyzer = KillChainAnalyzer()
        result = analyzer.analyze(detected_techniques)
        print(result.assessment)
    """

    def analyze(self, techniques: List[Dict]) -> KillChainAnalysis:
        """Analyze detected MITRE techniques for kill-chain coverage.

        Args:
            techniques: List of technique dicts, each containing at
                        least 'technique_id', 'technique_name', 'tactic'.

        Returns:
            :class:`KillChainAnalysis`
        """
        if not techniques:
            return KillChainAnalysis(assessment='No techniques detected')

        # Group techniques by tactic (= kill-chain phase)
        phase_techs: Dict[str, List[Dict]] = {}
        for tech in techniques:
            tactic = tech.get('tactic', '')
            if tactic in PHASES:
                phase_techs.setdefault(tactic, []).append(tech)

        detected_phases = [p for p in PHASES if p in phase_techs]
        coverage = len(detected_phases) / len(PHASES)
        max_sev = max((PHASE_SEVERITY.get(p, 0) for p in detected_phases), default=0)
        longest = self._longest_consecutive_chain(detected_phases)
        progression = self._progression_score(detected_phases, longest)
        assessment = self._assess(detected_phases, longest, max_sev)

        return KillChainAnalysis(
            phases_detected=detected_phases,
            phase_techniques=phase_techs,
            coverage_ratio=coverage,
            max_severity=max_sev,
            progression_score=progression,
            longest_chain=longest,
            assessment=assessment,
        )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _longest_consecutive_chain(detected: List[str]) -> int:
        """Find the longest consecutive kill-chain sequence."""
        if not detected:
            return 0
        indices = sorted(PHASES.index(p) for p in detected if p in PHASES)
        if not indices:
            return 0
        longest = current = 1
        for i in range(1, len(indices)):
            if indices[i] - indices[i - 1] <= 1:
                current += 1
                longest = max(longest, current)
            else:
                current = 1
        return longest

    @staticmethod
    def _progression_score(detected: List[str], longest_chain: int) -> int:
        """Compute a 0-100 score representing attack progression risk.

        Factors:
          - Number of distinct phases (breadth)
          - Longest consecutive chain (depth)
          - Phase severity weighting
        """
        if not detected:
            return 0

        breadth = min(40, len(detected) * (40 // len(PHASES) + 1))
        depth = min(40, longest_chain * 10)
        severity = int(
            sum(PHASE_SEVERITY.get(p, 0) for p in detected)
            / len(detected) * 20
        )
        return min(100, breadth + depth + severity)

    @staticmethod
    def _assess(detected: List[str], longest: int, max_sev: float) -> str:
        n = len(detected)
        if n == 0:
            return 'No kill-chain activity detected'
        if n <= 2 and longest <= 2:
            return 'Minimal kill-chain activity - isolated techniques'
        if n <= 4 and longest <= 3:
            return 'Partial kill-chain coverage - possible targeted activity'
        if longest >= 4 or n >= 6:
            return 'Significant kill-chain progression - likely advanced threat'
        if max_sev >= 0.9:
            return 'High-severity phases detected - credential/lateral/exfil activity'
        return 'Moderate kill-chain activity - warrants investigation'
