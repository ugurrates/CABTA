"""
Author: Ugur Ates
Advanced Phishing Detection Engine
Integrated from Blue Team Tools (Sooty, ThePhish patterns)
 Enhancement
"""

import re
import logging
from typing import Dict, List, Tuple
from datetime import datetime
from .email_threat_indicators import EmailThreatIndicators
from .bec_detector import BECDetector

logger = logging.getLogger(__name__)
class AdvancedPhishingDetector:
    """
    Advanced phishing detection using Blue Team patterns.
    
    Integrated from:
    - Sooty phishing analysis
    - ThePhish indicators
    - Email-header-analyzer patterns
    """
    
    # Phishing keywords (from Sooty + expanded)
    PHISHING_KEYWORDS = [
        'verify', 'account', 'suspended', 'click here', 'urgent', 
        'immediate action', 'confirm', 'update', 'secure', 'password',
        'bank', 'credit card', 'social security', 'tax', 'refund',
        'expire', 'locked', 'unusual activity', 'verify identity',
        'congratulations', 'winner', 'prize', 'claim', 'free',
        'act now', 'limited time', 'don\'t delay', 're:',
        'payment', 'invoice', 'transfer', 'bitcoin', 'cryptocurrency',
        'covid', 'vaccine', 'pandemic', 'donation', 'charity'
    ]
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
        '.top', '.xyz', '.club', '.work', '.click',
        '.loan', '.download', '.racing', '.accountant'
    ]
    
    # Brand impersonation patterns
    BRAND_PATTERNS = [
        r'paypal', r'amazon', r'microsoft', r'apple', r'google',
        r'facebook', r'netflix', r'dropbox', r'adobe', r'bank',
        r'fedex', r'ups', r'dhl', r'usps', r'irs', r'security',
        r'support', r'helpdesk', r'admin', r'noreply'
    ]
    
    @staticmethod
    def analyze_email_for_phishing(email_data: Dict) -> Dict:
        """
        Comprehensive phishing analysis.
        
        Args:
            email_data: Email analysis data
        
        Returns:
            Phishing analysis results
        """
        result = {
            'phishing_score': 0,
            'indicators': [],
            'risk_level': 'LOW',
            'reasons': []
        }
        
        try:
            score = 0
            
            # 1. Subject Analysis
            subject_score, subject_indicators = AdvancedPhishingDetector._analyze_subject(
                email_data.get('subject', '')
            )
            score += subject_score
            result['indicators'].extend(subject_indicators)
            
            # 2. Sender Analysis
            sender_score, sender_indicators = AdvancedPhishingDetector._analyze_sender(
                email_data.get('from', ''),
                email_data.get('reply_to', '')
            )
            score += sender_score
            result['indicators'].extend(sender_indicators)
            
            # 3. Body Analysis
            body_score, body_indicators = AdvancedPhishingDetector._analyze_body(
                email_data.get('body', '')
            )
            score += body_score
            result['indicators'].extend(body_indicators)
            
            # 4. URL Analysis
            url_score, url_indicators = AdvancedPhishingDetector._analyze_urls(
                email_data.get('urls', [])
            )
            score += url_score
            result['indicators'].extend(url_indicators)
            
            # 5. Attachment Analysis
            attachment_score, attachment_indicators = AdvancedPhishingDetector._analyze_attachments(
                email_data.get('attachments', [])
            )
            score += attachment_score
            result['indicators'].extend(attachment_indicators)
            
            # 6. Header Analysis
            header_score, header_indicators = AdvancedPhishingDetector._analyze_headers(
                email_data.get('headers', {})
            )
            score += header_score
            result['indicators'].extend(header_indicators)

            # 7. Enhanced Threat Indicator Checks
            enhanced_score, enhanced_indicators = AdvancedPhishingDetector._run_enhanced_checks(
                email_data
            )
            score += enhanced_score
            result['indicators'].extend(enhanced_indicators)
            result['enhanced_threat_indicators'] = email_data.get('_threat_indicator_results', {})

            # 8. BEC (Business Email Compromise) Detection
            bec_score, bec_indicators = AdvancedPhishingDetector._run_bec_checks(email_data)
            score += bec_score
            result['indicators'].extend(bec_indicators)
            result['bec_analysis'] = email_data.get('_bec_results', {})

            # Calculate final score
            result['phishing_score'] = min(score, 100)
            
            # Determine risk level
            if result['phishing_score'] >= 70:
                result['risk_level'] = 'CRITICAL'
            elif result['phishing_score'] >= 50:
                result['risk_level'] = 'HIGH'
            elif result['phishing_score'] >= 30:
                result['risk_level'] = 'MEDIUM'
            else:
                result['risk_level'] = 'LOW'
            
            # Generate reasons
            result['reasons'] = [ind['reason'] for ind in result['indicators']]
            
        except Exception as e:
            logger.error(f"[PHISHING] Analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    @staticmethod
    def _analyze_subject(subject: str) -> Tuple[int, List[Dict]]:
        """Analyze email subject for phishing indicators."""
        score = 0
        indicators = []
        
        subject_lower = subject.lower()
        
        # Check for phishing keywords
        for keyword in AdvancedPhishingDetector.PHISHING_KEYWORDS:
            if keyword in subject_lower:
                score += 5
                indicators.append({
                    'type': 'SUBJECT_KEYWORD',
                    'keyword': keyword,
                    'reason': f'Phishing keyword in subject: "{keyword}"'
                })
        
        # Check for urgency indicators
        urgency_patterns = [
            r'urgent', r'immediate', r'action required', r'expires?',
            r'suspended', r'locked', r'verify now'
        ]
        for pattern in urgency_patterns:
            if re.search(pattern, subject_lower):
                score += 10
                indicators.append({
                    'type': 'URGENCY',
                    'pattern': pattern,
                    'reason': f'Urgency indicator in subject'
                })
        
        # Check for fake Re:
        if subject.lower().startswith('re:') and 'fwd' not in subject.lower():
            score += 8
            indicators.append({
                'type': 'FAKE_REPLY',
                'reason': 'Suspicious "Re:" without previous conversation'
            })
        
        return score, indicators
    
    @staticmethod
    def _analyze_sender(sender: str, reply_to: str) -> Tuple[int, List[Dict]]:
        """Analyze sender for phishing indicators."""
        score = 0
        indicators = []
        
        sender_lower = sender.lower()
        
        # Check for brand impersonation
        for pattern in AdvancedPhishingDetector.BRAND_PATTERNS:
            if re.search(pattern, sender_lower):
                # Check if it's actually from that brand
                if not (pattern in sender_lower and '@' + pattern in sender_lower):
                    score += 15
                    indicators.append({
                        'type': 'BRAND_IMPERSONATION',
                        'brand': pattern,
                        'reason': f'Possible {pattern} impersonation'
                    })
        
        # Check for sender/reply-to mismatch
        if reply_to and sender != reply_to:
            score += 10
            indicators.append({
                'type': 'SENDER_MISMATCH',
                'reason': 'Sender and Reply-To addresses differ'
            })
        
        # Check for suspicious sender patterns
        if re.search(r'\d{5,}', sender):  # Many numbers in email
            score += 5
            indicators.append({
                'type': 'SUSPICIOUS_SENDER',
                'reason': 'Sender contains excessive numbers'
            })
        
        return score, indicators
    
    @staticmethod
    def _analyze_body(body: str) -> Tuple[int, List[Dict]]:
        """Analyze email body for phishing indicators."""
        score = 0
        indicators = []
        
        body_lower = body.lower()
        
        # Check for credential harvesting
        credential_patterns = [
            r'enter.*password', r'verify.*account', r'confirm.*identity',
            r'click.*link', r'update.*information', r'reset.*password'
        ]
        for pattern in credential_patterns:
            if re.search(pattern, body_lower):
                score += 15
                indicators.append({
                    'type': 'CREDENTIAL_HARVESTING',
                    'pattern': pattern,
                    'reason': 'Potential credential harvesting attempt'
                })
        
        # Check for threats/urgency
        threat_patterns = [
            r'account.*suspend', r'will.*close', r'within.*hours',
            r'immediate.*action', r'verify.*now'
        ]
        for pattern in threat_patterns:
            if re.search(pattern, body_lower):
                score += 10
                indicators.append({
                    'type': 'THREAT',
                    'pattern': pattern,
                    'reason': 'Threatening or urgent language'
                })
        
        return score, indicators
    
    @staticmethod
    def _analyze_urls(urls: List[str]) -> Tuple[int, List[Dict]]:
        """Analyze URLs for phishing indicators."""
        score = 0
        indicators = []
        
        for url in urls:
            url_lower = url.lower()
            
            # Check for suspicious TLDs
            for tld in AdvancedPhishingDetector.SUSPICIOUS_TLDS:
                if tld in url_lower:
                    score += 10
                    indicators.append({
                        'type': 'SUSPICIOUS_TLD',
                        'tld': tld,
                        'url': url,
                        'reason': f'Suspicious TLD: {tld}'
                    })
            
            # Check for IP address URLs
            if re.search(r'http://\d+\.\d+\.\d+\.\d+', url):
                score += 20
                indicators.append({
                    'type': 'IP_URL',
                    'url': url,
                    'reason': 'URL uses IP address instead of domain'
                })
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']
            if any(short in url_lower for short in shorteners):
                score += 8
                indicators.append({
                    'type': 'URL_SHORTENER',
                    'url': url,
                    'reason': 'URL shortener detected (obscures destination)'
                })
        
        return score, indicators
    
    @staticmethod
    def _analyze_attachments(attachments: List[str]) -> Tuple[int, List[Dict]]:
        """Analyze attachments for phishing indicators."""
        score = 0
        indicators = []
        
        suspicious_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js',
            '.jar', '.com', '.pif', '.lnk', '.hta'
        ]
        
        for attachment in attachments:
            attachment_lower = attachment.lower()
            
            # Check for suspicious extensions
            for ext in suspicious_extensions:
                if attachment_lower.endswith(ext):
                    score += 25
                    indicators.append({
                        'type': 'SUSPICIOUS_ATTACHMENT',
                        'extension': ext,
                        'filename': attachment,
                        'reason': f'Potentially malicious attachment: {ext}'
                    })
            
            # Check for double extensions
            if attachment.count('.') > 1:
                score += 15
                indicators.append({
                    'type': 'DOUBLE_EXTENSION',
                    'filename': attachment,
                    'reason': 'Double extension (possible file type obfuscation)'
                })
        
        return score, indicators

    @staticmethod
    def _run_enhanced_checks(email_data: Dict) -> Tuple[int, List[Dict]]:
        """Run enhanced threat indicator checks and convert to phishing indicators."""
        score = 0
        indicators = []

        html_body = email_data.get('body_html', email_data.get('body', ''))
        body_text = email_data.get('body_text', email_data.get('body', ''))
        subject = email_data.get('subject', '')
        from_addr = email_data.get('from', '')
        urls = email_data.get('urls', [])
        attachments = email_data.get('attachments', [])
        msg = email_data.get('_msg', None)

        checks_to_run = [
            ('html_forms', lambda: EmailThreatIndicators.detect_html_forms(html_body, '')),
            ('url_shorteners', lambda: EmailThreatIndicators.detect_url_shorteners(urls)),
            ('data_uris', lambda: EmailThreatIndicators.detect_data_uris(html_body)),
            ('ip_urls', lambda: EmailThreatIndicators.detect_ip_urls(urls)),
            ('double_extensions', lambda: EmailThreatIndicators.detect_double_extensions(attachments)),
            ('javascript', lambda: EmailThreatIndicators.detect_javascript_in_body(html_body)),
            ('free_provider', lambda: EmailThreatIndicators.detect_free_provider_impersonation(
                from_addr, subject, body_text)),
            ('callback_phishing', lambda: EmailThreatIndicators.detect_callback_phishing(
                body_text, subject, urls, attachments)),
            ('tracking_pixels', lambda: EmailThreatIndicators.detect_tracking_pixels(html_body)),
        ]

        # Run X-Mailer check only if msg object is available
        if msg is not None:
            checks_to_run.append(
                ('xmailer', lambda: EmailThreatIndicators.analyze_xmailer(msg))
            )

        all_results = {}
        for check_name, check_fn in checks_to_run:
            try:
                result = check_fn()
                all_results[check_name] = result
                if result.get('severity', 'NONE') != 'NONE' and result.get('score_impact', 0) > 0:
                    score += result['score_impact']
                    indicators.append({
                        'type': f'ENHANCED_{check_name.upper()}',
                        'severity': result['severity'],
                        'reason': result.get('explanation', f'{check_name} check triggered'),
                    })
            except Exception as e:
                logger.debug(f"Enhanced check {check_name} skipped: {e}")

        # Store full results for reference
        email_data['_threat_indicator_results'] = all_results

        # Cap enhanced checks contribution
        score = min(score, 40)

        return score, indicators

    @staticmethod
    def _analyze_headers(headers: Dict) -> Tuple[int, List[Dict]]:
        """Analyze email headers for phishing indicators."""
        score = 0
        indicators = []
        
        # Check for missing SPF/DKIM/DMARC
        if not headers.get('spf_pass'):
            score += 15
            indicators.append({
                'type': 'SPF_FAIL',
                'reason': 'SPF authentication failed'
            })
        
        if not headers.get('dkim_pass'):
            score += 15
            indicators.append({
                'type': 'DKIM_FAIL',
                'reason': 'DKIM authentication failed'
            })
        
        # Check for suspicious received headers
        received_count = headers.get('received_count', 0)
        if received_count > 10:
            score += 10
            indicators.append({
                'type': 'EXCESSIVE_HOPS',
                'count': received_count,
                'reason': f'Excessive mail hops ({received_count})'
            })
        
        return score, indicators
    @staticmethod
    def _run_bec_checks(email_data: Dict) -> Tuple[int, List[Dict]]:
        """Run BEC detection and convert to phishing indicators."""
        score = 0
        indicators = []

        try:
            from email.utils import parseaddr
            from_name, _ = parseaddr(email_data.get('from', ''))

            bec_data = {
                'from': email_data.get('from', ''),
                'reply_to': email_data.get('reply_to', ''),
                'subject': email_data.get('subject', ''),
                'body': email_data.get('body_text', email_data.get('body', '')),
                'display_name': from_name,
                'auth_results': email_data.get('auth_results', ''),
            }

            detector = BECDetector()
            bec_results = detector.analyze(bec_data)

            # Store full results for reference
            email_data['_bec_results'] = bec_results

            bec_score = bec_results.get('bec_score', 0)

            if bec_score >= 70:
                score += 25
                indicators.append({
                    'type': 'BEC_CRITICAL',
                    'severity': 'CRITICAL',
                    'reason': f'BEC detection: CRITICAL risk (score {bec_score}/100)',
                })
            elif bec_score >= 50:
                score += 15
                indicators.append({
                    'type': 'BEC_HIGH',
                    'severity': 'HIGH',
                    'reason': f'BEC detection: HIGH risk (score {bec_score}/100)',
                })
            elif bec_score >= 30:
                score += 8
                indicators.append({
                    'type': 'BEC_MEDIUM',
                    'severity': 'MEDIUM',
                    'reason': f'BEC detection: MEDIUM risk (score {bec_score}/100)',
                })

            # Add specific BEC indicators
            if bec_results.get('has_financial_indicators'):
                indicators.append({
                    'type': 'BEC_FINANCIAL',
                    'severity': 'HIGH',
                    'reason': 'BEC: Financial/wire transfer language detected',
                })
            if bec_results.get('has_impersonation_indicators'):
                indicators.append({
                    'type': 'BEC_IMPERSONATION',
                    'severity': 'HIGH',
                    'reason': 'BEC: Executive impersonation patterns detected',
                })

            # Cap BEC contribution
            score = min(score, 30)

        except Exception as e:
            logger.debug(f"BEC check skipped: {e}")

        return score, indicators

def detect_phishing(email_data: Dict) -> Dict:
    """
    Main entry point for phishing detection.
    
    Args:
        email_data: Email analysis data
    
    Returns:
        Phishing analysis results
    """
    return AdvancedPhishingDetector.analyze_email_for_phishing(email_data)
