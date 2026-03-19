"""
BEC (Business Email Compromise) Detection Module
Detects wire fraud, CEO impersonation, financial phishing patterns

Author: Ugur Ates
"""
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

import logging

logger = logging.getLogger(__name__)


@dataclass
class BECIndicator:
    category: str        # urgency, financial, impersonation, reply_mismatch, auth_failure
    pattern: str         # matched pattern
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW
    score: int           # 0-100
    description: str
    mitre_technique: str = ""


class BECDetector:
    """Detects Business Email Compromise indicators in email content"""

    # VIP titles for impersonation detection
    VIP_TITLES = [
        'ceo', 'cfo', 'cto', 'coo', 'ciso', 'president', 'vice president',
        'director', 'managing director', 'chairman', 'founder', 'partner',
        'general manager', 'head of', 'chief', 'executive', 'treasurer',
        'controller', 'comptroller'
    ]

    # Urgency patterns (BEC always creates urgency)
    URGENCY_PATTERNS = [
        (r'(?i)\b(urgent|immediately|asap|right\s+away|time[\s\-]?sensitive)\b', 'urgency_pressure', 5),
        (r'(?i)\b(confidential|do\s+not\s+share|keep\s+this\s+between\s+us|private\s+matter)\b', 'secrecy_request', 8),
        (r'(?i)\b(act\s+now|deadline\s+today|end\s+of\s+(business\s+)?day|by\s+close\s+of\s+business|eod|cob)\b', 'deadline_pressure', 5),
        (r'(?i)\b(don\'?t\s+tell|between\s+you\s+and\s+me|off\s+the\s+record|discreet(ly)?)\b', 'secrecy_language', 8),
        (r'(?i)\b(i\s+need\s+this\s+done|handle\s+this\s+personally|take\s+care\s+of\s+this|i\'m\s+counting\s+on\s+you)\b', 'authority_pressure', 6),
    ]

    # Financial patterns (the actual fraud indicators)
    FINANCIAL_PATTERNS = [
        (r'(?i)\b(wire\s+transfer|bank\s+transfer|fund\s+transfer|money\s+transfer)\b', 'wire_transfer', 15),
        (r'(?i)\b(routing\s+number|account\s+number|swift\s+code|iban|aba\s+number)\b', 'banking_details', 15),
        (r'(?i)\b(gift\s+card|itunes\s+card|google\s+play\s+card|amazon\s+card|steam\s+card)\b', 'gift_card_fraud', 20),
        (r'(?i)\b(bitcoin|btc|crypto(currency)?|ethereum|eth|western\s+union|moneygram)\b', 'crypto_payment', 15),
        (r'(?i)\b(invoice\s+(attached|enclosed|due|overdue|pending))\b', 'invoice_fraud', 10),
        (r'(?i)\b(payment\s+(due|overdue|pending|required|needed|update))\b', 'payment_pressure', 10),
        (r'(?i)\b(change.{0,20}(bank|account|payment|routing|vendor|beneficiary))\b', 'account_change', 20),
        (r'(?i)\b(new\s+(bank|account|payment)\s+(details|information|instructions))\b', 'new_payment_info', 18),
        (r'(?i)\b(ach\s+(transfer|payment|deposit)|direct\s+deposit)\b', 'ach_fraud', 12),
        (r'(?i)\b(update.{0,15}(payment|billing|bank)\s+(info|information|details|method))\b', 'billing_update', 12),
    ]

    # CEO/Executive impersonation patterns
    IMPERSONATION_PATTERNS = [
        (r'(?i)\b(ceo|cfo|president|chairman)\s+(asked|requested|needs|wants|instructed|directed)\b', 'executive_directive', 15),
        (r'(?i)\b(on\s+behalf\s+of\s+(the\s+)?(ceo|cfo|president|director|board))\b', 'on_behalf', 12),
        (r'(?i)\b(i\'?m\s+(in\s+a\s+meeting|traveling|on\s+a\s+flight|unavailable|out\s+of\s+office))\b', 'unavailability_excuse', 8),
        (r'(?i)\b(can\'?t\s+(call|talk|reach\s+me)|don\'?t\s+call|email\s+only|reply\s+to\s+this\s+email)\b', 'communication_restriction', 10),
        (r'(?i)\b(i\s+need\s+you\s+to|please\s+handle|can\s+you\s+process|kindly\s+(process|handle|complete))\b', 'task_delegation', 5),
    ]

    def __init__(self, vip_names: Optional[List[str]] = None):
        """
        Args:
            vip_names: Optional list of VIP names to check for impersonation
        """
        self.vip_names = [n.lower() for n in (vip_names or [])]

    def analyze(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run full BEC analysis on email data.

        Args:
            email_data: Dict with keys: from, reply_to, subject, body,
                       display_name, auth_results, headers
        """
        indicators: List[BECIndicator] = []

        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        from_addr = email_data.get('from', '')
        reply_to = email_data.get('reply_to', '')
        display_name = email_data.get('display_name', '')
        auth_results = email_data.get('auth_results', '')

        combined_text = f"{subject} {body}"

        # 1. Urgency pattern detection
        urgency_indicators = self._detect_patterns(combined_text, self.URGENCY_PATTERNS, 'urgency')
        indicators.extend(urgency_indicators)

        # 2. Financial pattern detection
        financial_indicators = self._detect_patterns(combined_text, self.FINANCIAL_PATTERNS, 'financial')
        indicators.extend(financial_indicators)

        # 3. Impersonation pattern detection
        impersonation_indicators = self._detect_patterns(combined_text, self.IMPERSONATION_PATTERNS, 'impersonation')
        indicators.extend(impersonation_indicators)

        # 4. Display name spoofing
        spoof_indicators = self._check_display_name_spoofing(display_name, from_addr)
        indicators.extend(spoof_indicators)

        # 5. Reply-To mismatch
        reply_indicators = self._check_reply_to_mismatch(from_addr, reply_to)
        indicators.extend(reply_indicators)

        # 6. Authentication failures
        auth_indicators = self._check_auth_failures(auth_results)
        indicators.extend(auth_indicators)

        # 7. Free email provider impersonation
        free_indicators = self._check_free_email_executive(from_addr, display_name)
        indicators.extend(free_indicators)

        # Calculate BEC score
        bec_score = self._calculate_bec_score(indicators)

        # Determine verdict
        if bec_score >= 70:
            verdict = 'CRITICAL'
        elif bec_score >= 50:
            verdict = 'HIGH'
        elif bec_score >= 30:
            verdict = 'MEDIUM'
        else:
            verdict = 'LOW'

        # Category breakdown
        category_scores: Dict[str, int] = {}
        for ind in indicators:
            cat = ind.category
            if cat not in category_scores:
                category_scores[cat] = 0
            category_scores[cat] += ind.score

        return {
            'bec_score': min(bec_score, 100),
            'verdict': verdict,
            'indicator_count': len(indicators),
            'indicators': [
                {
                    'category': i.category,
                    'pattern': i.pattern,
                    'severity': i.severity,
                    'score': i.score,
                    'description': i.description,
                    'mitre_technique': i.mitre_technique
                }
                for i in indicators
            ],
            'category_scores': category_scores,
            'has_financial_indicators': any(i.category == 'financial' for i in indicators),
            'has_urgency_indicators': any(i.category == 'urgency' for i in indicators),
            'has_impersonation_indicators': any(i.category == 'impersonation' for i in indicators),
            'has_auth_failures': any(i.category == 'auth_failure' for i in indicators),
            'mitre_techniques': list(set(i.mitre_technique for i in indicators if i.mitre_technique))
        }

    def _detect_patterns(self, text: str, patterns: list, category: str) -> List[BECIndicator]:
        """Detect regex patterns in text"""
        indicators = []
        for pattern, name, score in patterns:
            matches = re.findall(pattern, text)
            if matches:
                severity = 'CRITICAL' if score >= 15 else ('HIGH' if score >= 10 else 'MEDIUM')
                mitre = 'T1566.001' if category == 'financial' else ('T1566.002' if category == 'impersonation' else '')
                indicators.append(BECIndicator(
                    category=category,
                    pattern=name,
                    severity=severity,
                    score=min(score * len(matches), score * 3),  # cap at 3x
                    description=f"Detected {name.replace('_', ' ')}: {len(matches)} match(es)",
                    mitre_technique=mitre
                ))
        return indicators

    def _check_display_name_spoofing(self, display_name: str, from_addr: str) -> List[BECIndicator]:
        """Check if display name impersonates VIP"""
        indicators = []
        if not display_name:
            return indicators

        dn_lower = display_name.lower()

        # Check VIP titles
        for title in self.VIP_TITLES:
            if title in dn_lower:
                indicators.append(BECIndicator(
                    category='impersonation',
                    pattern='vip_title_in_display_name',
                    severity='HIGH',
                    score=15,
                    description=f"Executive title '{title}' found in display name: {display_name}",
                    mitre_technique='T1566.002'
                ))
                break

        # Check VIP names
        for name in self.vip_names:
            if name in dn_lower:
                indicators.append(BECIndicator(
                    category='impersonation',
                    pattern='vip_name_spoofing',
                    severity='CRITICAL',
                    score=30,
                    description=f"VIP name '{name}' found in display name but sent from {from_addr}",
                    mitre_technique='T1566.002'
                ))
                break

        return indicators

    def _check_reply_to_mismatch(self, from_addr: str, reply_to: str) -> List[BECIndicator]:
        """Check Reply-To domain differs from From domain"""
        indicators = []
        if not reply_to or not from_addr:
            return indicators

        from_domain = from_addr.split('@')[-1].lower() if '@' in from_addr else ''
        reply_domain = reply_to.split('@')[-1].lower() if '@' in reply_to else ''

        if from_domain and reply_domain and from_domain != reply_domain:
            indicators.append(BECIndicator(
                category='reply_mismatch',
                pattern='reply_to_domain_mismatch',
                severity='HIGH',
                score=20,
                description=f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})",
                mitre_technique='T1566.001'
            ))

        return indicators

    def _check_auth_failures(self, auth_results: str) -> List[BECIndicator]:
        """Check SPF/DKIM/DMARC failures"""
        indicators = []
        if not auth_results:
            return indicators

        auth_lower = auth_results.lower()

        if 'spf=fail' in auth_lower or 'spf=softfail' in auth_lower:
            indicators.append(BECIndicator(
                category='auth_failure',
                pattern='spf_failure',
                severity='HIGH',
                score=25,
                description='SPF authentication failed - sender domain not authorized',
                mitre_technique='T1566.001'
            ))

        if 'dkim=fail' in auth_lower:
            indicators.append(BECIndicator(
                category='auth_failure',
                pattern='dkim_failure',
                severity='HIGH',
                score=20,
                description='DKIM authentication failed - email signature invalid',
                mitre_technique='T1566.001'
            ))

        if 'dmarc=fail' in auth_lower:
            indicators.append(BECIndicator(
                category='auth_failure',
                pattern='dmarc_failure',
                severity='HIGH',
                score=15,
                description='DMARC policy check failed',
                mitre_technique='T1566.001'
            ))

        return indicators

    def _check_free_email_executive(self, from_addr: str, display_name: str) -> List[BECIndicator]:
        """Check if executive title comes from free email provider"""
        indicators = []
        FREE_PROVIDERS = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
                         'aol.com', 'protonmail.com', 'mail.com', 'yandex.com']

        if not from_addr or not display_name:
            return indicators

        from_domain = from_addr.split('@')[-1].lower() if '@' in from_addr else ''
        dn_lower = display_name.lower()

        if from_domain in FREE_PROVIDERS:
            for title in self.VIP_TITLES:
                if title in dn_lower:
                    indicators.append(BECIndicator(
                        category='impersonation',
                        pattern='free_email_executive',
                        severity='CRITICAL',
                        score=25,
                        description=f"Executive title '{title}' in display name but sent from free provider ({from_domain})",
                        mitre_technique='T1566.002'
                    ))
                    break

        return indicators

    def _calculate_bec_score(self, indicators: List[BECIndicator]) -> int:
        """Calculate overall BEC risk score"""
        if not indicators:
            return 0

        raw_score = sum(i.score for i in indicators)

        # Combo bonus: financial + urgency = very likely BEC
        has_financial = any(i.category == 'financial' for i in indicators)
        has_urgency = any(i.category == 'urgency' for i in indicators)
        has_impersonation = any(i.category == 'impersonation' for i in indicators)
        has_auth_fail = any(i.category == 'auth_failure' for i in indicators)

        combo_bonus = 0
        if has_financial and has_urgency:
            combo_bonus += 15
        if has_financial and has_impersonation:
            combo_bonus += 20
        if has_urgency and has_impersonation and has_financial:
            combo_bonus += 10  # triple combo
        if has_auth_fail and (has_financial or has_impersonation):
            combo_bonus += 10

        return min(raw_score + combo_bonus, 100)
