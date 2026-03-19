"""
Author: Ugur Ates
Adaptive Scoring Engine - Akilli Karar.

Gelismis skorlama ozellikleri:
- Adaptif agirliklar: Bos donen araclarin agirligi digerlere dagilir
- Logaritmik eskalasyon: score = base + log2(1 + ek_gostergeler) * carpan
- Guncellik agirliklama: Yeni TI verileri daha yuksek agirlik
- Combo scoring: Pattern-based threat escalation
- Kill-chain detection: download -> decode -> execute -> persist
"""

import math
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AdaptiveScore:
    """Adaptive scoring sonucu."""
    final_score: int
    base_score: int
    combo_bonus: int
    kill_chain_bonus: int
    freshness_factor: float
    confidence: float
    verdict: str
    contributing_tools: List[str] = field(default_factory=list)
    active_combos: List[str] = field(default_factory=list)
    kill_chain_stages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'final_score': self.final_score,
            'base_score': self.base_score,
            'combo_bonus': self.combo_bonus,
            'kill_chain_bonus': self.kill_chain_bonus,
            'freshness_factor': round(self.freshness_factor, 3),
            'confidence': round(self.confidence, 3),
            'verdict': self.verdict,
            'contributing_tools': self.contributing_tools,
            'active_combos': self.active_combos,
            'kill_chain_stages': self.kill_chain_stages,
        }


# ---------------------------------------------------------------------------
# Kill-chain stage definitions
# ---------------------------------------------------------------------------

KILL_CHAIN_STAGES = {
    'delivery': {
        'indicators': [
            'download', 'invoke-webrequest', 'webclient', 'downloadstring',
            'downloadfile', 'bitsadmin', 'certutil', 'curl', 'wget',
            'urldownloadtofile', 'xmlhttp', 'start-bitstransfer',
        ],
        'order': 0,
    },
    'decode': {
        'indicators': [
            'base64', 'encodedcommand', '-enc', 'frombase64string',
            'decompress', 'gunzip', 'xor', 'obfusc', 'chr(',
            'fromcharcode', 'unescape', 'atob',
        ],
        'order': 1,
    },
    'execution': {
        'indicators': [
            'invoke-expression', 'iex', 'start-process', 'eval',
            'execute', 'wscript.shell', '.run(', '.exec(',
            'createobject', 'function(', 'cmd /c', 'powershell',
        ],
        'order': 2,
    },
    'persistence': {
        'indicators': [
            'currentversion\\run', 'schtasks', 'new-service',
            'register-scheduledjob', 'startup', 'winlogon',
            'new-itemproperty', 'sc create',
        ],
        'order': 3,
    },
    'evasion': {
        'indicators': [
            'amsi', 'disablerealtimemonitoring', 'set-mppreference',
            'bypass', '-windowstyle hidden', 'out-null',
            'virtualalloc', 'virtualprotect',
        ],
        'order': 4,
    },
    'exfiltration': {
        'indicators': [
            'compress-archive', '7z', 'rar', 'send-mailmessage',
            'invoke-restmethod', 'upload', 'exfil',
        ],
        'order': 5,
    },
}


# ---------------------------------------------------------------------------
# Combo definitions  (pattern_name -> required categories -> bonus)
# ---------------------------------------------------------------------------

COMBO_RULES = [
    {
        'name': 'persistence_c2',
        'description': 'Persistence + C2 Communication',
        'required': ['persistence', 'delivery'],
        'bonus': 15,
    },
    {
        'name': 'obfuscation_download_exec',
        'description': 'Obfuscation + Download + Execution',
        'required': ['decode', 'delivery', 'execution'],
        'bonus': 25,
    },
    {
        'name': 'evasion_persistence',
        'description': 'Defense Evasion + Persistence',
        'required': ['evasion', 'persistence'],
        'bonus': 15,
    },
    {
        'name': 'full_killchain',
        'description': 'Full Kill Chain (delivery -> decode -> execute -> persist)',
        'required': ['delivery', 'decode', 'execution', 'persistence'],
        'bonus': 35,
    },
    {
        'name': 'credential_exfil',
        'description': 'Credential Access + Exfiltration',
        'required': ['credential_access', 'exfiltration'],
        'bonus': 20,
    },
]


class AdaptiveScoringEngine:
    """Gelismis adaptif skorlama motoru.

    Usage::

        engine = AdaptiveScoringEngine()
        result = engine.score(tool_scores, weights, context)
    """

    # Verdict thresholds (can be overridden)
    THRESHOLDS = {'MALICIOUS': 70, 'SUSPICIOUS': 40, 'CLEAN': 0}

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def score(
        self,
        tool_scores: Dict[str, int],
        weights: Dict[str, float],
        *,
        content: str = '',
        ti_timestamps: Optional[Dict[str, datetime]] = None,
        extra_indicators: int = 0,
    ) -> AdaptiveScore:
        """Compute adaptive score.

        Args:
            tool_scores: ``{tool_name: score_0_100}``
            weights: Base weight map ``{tool_name: float}``.
            content: Optional raw text content for kill-chain analysis.
            ti_timestamps: ``{source_name: last_updated_datetime}`` for freshness.
            extra_indicators: Count of additional indicators (IOC hits, etc.).

        Returns:
            :class:`AdaptiveScore`
        """
        # Step 1: Redistribute weights for missing tools
        active_weights = self._redistribute_weights(tool_scores, weights)

        # Step 2: Weighted average (base score)
        base_score = self._weighted_average(tool_scores, active_weights)

        # Step 3: Logarithmic escalation for extra indicators
        escalation = self._log_escalation(extra_indicators)
        base_score = min(100, base_score + escalation)

        # Step 4: Freshness factor
        freshness = self._freshness_factor(ti_timestamps) if ti_timestamps else 1.0
        base_score = int(base_score * freshness)

        # Step 5: Kill-chain detection
        detected_stages = self._detect_kill_chain(content) if content else []
        kill_chain_bonus = self._kill_chain_bonus(detected_stages)

        # Step 6: Combo scoring
        active_combos = self._check_combos(detected_stages, content)
        combo_bonus = sum(c['bonus'] for c in active_combos)

        # Final
        final_score = min(100, base_score + combo_bonus + kill_chain_bonus)
        verdict = self._verdict(final_score)
        confidence = self._confidence(tool_scores, active_weights, detected_stages)

        return AdaptiveScore(
            final_score=final_score,
            base_score=base_score,
            combo_bonus=combo_bonus,
            kill_chain_bonus=kill_chain_bonus,
            freshness_factor=freshness,
            confidence=confidence,
            verdict=verdict,
            contributing_tools=[t for t in tool_scores if tool_scores[t] > 0],
            active_combos=[c['name'] for c in active_combos],
            kill_chain_stages=[s for s in detected_stages],
        )

    # ------------------------------------------------------------------ #
    # Weight redistribution
    # ------------------------------------------------------------------ #

    @staticmethod
    def _redistribute_weights(
        tool_scores: Dict[str, int],
        weights: Dict[str, float],
    ) -> Dict[str, float]:
        """Redistribute weight from absent tools to present tools.

        If a tool has no score entry, its weight is spread proportionally
        among the tools that *did* produce a score.
        """
        present = {t for t in tool_scores if t in weights}
        absent_weight = sum(w for t, w in weights.items() if t not in present)

        if not present or absent_weight == 0:
            return {t: weights.get(t, 0.05) for t in tool_scores}

        present_total = sum(weights[t] for t in present)
        if present_total == 0:
            return {t: 1.0 / len(present) for t in present}

        new_weights: Dict[str, float] = {}
        for t in present:
            base_w = weights[t]
            # Each present tool gets a proportional share of the absent weight
            extra = absent_weight * (base_w / present_total)
            new_weights[t] = base_w + extra

        return new_weights

    # ------------------------------------------------------------------ #
    # Core scoring helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _weighted_average(scores: Dict[str, int], weights: Dict[str, float]) -> int:
        total_w = sum(weights.get(t, 0) for t in scores)
        if total_w == 0:
            return 0
        s = sum(scores[t] * weights.get(t, 0) for t in scores)
        return min(100, int(s / total_w))

    @staticmethod
    def _log_escalation(extra_indicators: int, multiplier: float = 5.0) -> int:
        """``floor(log2(1 + extra_indicators) * multiplier)``."""
        if extra_indicators <= 0:
            return 0
        return int(math.log2(1 + extra_indicators) * multiplier)

    # ------------------------------------------------------------------ #
    # Freshness
    # ------------------------------------------------------------------ #

    @staticmethod
    def _freshness_factor(
        timestamps: Dict[str, datetime],
        max_age_days: int = 90,
    ) -> float:
        """Return a multiplier [0.7 .. 1.2] based on TI data freshness.

        - Data less than 1 day old  -> 1.2x
        - Data 1-7 days old         -> 1.1x
        - Data 7-30 days old        -> 1.0x
        - Data 30-90 days old       -> 0.85x
        - Data older than 90 days   -> 0.7x

        If multiple sources exist, use the freshest.
        """
        if not timestamps:
            return 1.0

        now = datetime.now(timezone.utc)
        freshest_age = None

        for ts in timestamps.values():
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            age = (now - ts).total_seconds() / 86400  # days
            if freshest_age is None or age < freshest_age:
                freshest_age = age

        if freshest_age is None:
            return 1.0
        if freshest_age < 1:
            return 1.2
        if freshest_age < 7:
            return 1.1
        if freshest_age < 30:
            return 1.0
        if freshest_age < max_age_days:
            return 0.85
        return 0.7

    # ------------------------------------------------------------------ #
    # Kill-chain analysis
    # ------------------------------------------------------------------ #

    @staticmethod
    def _detect_kill_chain(content: str) -> List[str]:
        """Detect which kill-chain stages are present in *content*."""
        if not content:
            return []
        lower = content.lower()
        detected: List[str] = []
        for stage, info in KILL_CHAIN_STAGES.items():
            for indicator in info['indicators']:
                if indicator in lower:
                    detected.append(stage)
                    break
        # Sort by kill-chain order
        detected.sort(key=lambda s: KILL_CHAIN_STAGES.get(s, {}).get('order', 99))
        return detected

    @staticmethod
    def _kill_chain_bonus(stages: List[str]) -> int:
        """Grant bonus points for consecutive kill-chain stages.

        - 2 consecutive stages: +5
        - 3 consecutive stages: +12
        - 4+ consecutive stages: +20
        """
        if len(stages) < 2:
            return 0

        # Check for consecutive chains
        orders = sorted(KILL_CHAIN_STAGES[s]['order'] for s in stages
                        if s in KILL_CHAIN_STAGES)
        max_chain = 1
        current_chain = 1
        for i in range(1, len(orders)):
            if orders[i] - orders[i - 1] <= 1:
                current_chain += 1
                max_chain = max(max_chain, current_chain)
            else:
                current_chain = 1

        if max_chain >= 4:
            return 20
        if max_chain >= 3:
            return 12
        if max_chain >= 2:
            return 5
        return 0

    # ------------------------------------------------------------------ #
    # Combo detection
    # ------------------------------------------------------------------ #

    @staticmethod
    def _check_combos(
        stages: List[str],
        content: str = '',
    ) -> List[Dict]:
        """Return a list of active combo rules."""
        active: List[Dict] = []
        content_lower = content.lower() if content else ''

        # Build an extended category set from stages + content keywords
        categories = set(stages)

        # Add credential_access from content keywords
        credential_keywords = ['mimikatz', 'sekurlsa', 'lsass', 'get-credential', 'procdump']
        if any(kw in content_lower for kw in credential_keywords):
            categories.add('credential_access')

        for rule in COMBO_RULES:
            if all(req in categories for req in rule['required']):
                active.append(rule)

        return active

    # ------------------------------------------------------------------ #
    # Verdict & confidence
    # ------------------------------------------------------------------ #

    def _verdict(self, score: int) -> str:
        if score >= self.THRESHOLDS['MALICIOUS']:
            return 'MALICIOUS'
        if score >= self.THRESHOLDS['SUSPICIOUS']:
            return 'SUSPICIOUS'
        return 'CLEAN'

    @staticmethod
    def _confidence(
        tool_scores: Dict[str, int],
        weights: Dict[str, float],
        stages: List[str],
    ) -> float:
        """Compute analysis confidence [0..1].

        Factors:
          - Tool coverage (weight ratio)
          - Score consistency (low variance = more confident)
          - Kill-chain evidence
        """
        if not tool_scores:
            return 0.0

        total_w = sum(weights.values())
        covered_w = sum(weights.get(t, 0) for t in tool_scores)
        coverage = covered_w / total_w if total_w else 0

        scores = list(tool_scores.values())
        if len(scores) >= 2:
            avg = sum(scores) / len(scores)
            var = sum((s - avg) ** 2 for s in scores) / len(scores)
            consistency = max(0.0, 1.0 - var / 2500)
        else:
            consistency = 0.5

        chain_bonus = min(0.15, len(stages) * 0.05)

        return min(1.0, coverage * 0.55 + consistency * 0.30 + chain_bonus)
