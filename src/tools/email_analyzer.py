"""
Author: Ugur AtesEmail Analysis Tool - SOC-GRADE with Advanced Features."""

import email
from email import policy
from email.utils import parseaddr
from pathlib import Path
import asyncio
import tempfile
from typing import Dict, List
import logging
from ..utils.ioc_extractor import IOCExtractor
from ..integrations.llm_analyzer import LLMAnalyzer
from ..scoring.intelligent_scoring import IntelligentScoring
from ..analyzers.advanced_email_analyzer import AdvancedEmailAnalyzer
from ..analyzers.email_forensics import EmailForensics  # NEW: DFIR-grade forensics
from ..analyzers.email_threat_indicators import EmailThreatIndicators  # Enhanced threat checks
from ..analyzers.bec_detector import BECDetector  # BEC detection
from ..detection.rule_generator import RuleGenerator
from ..reporting.raw_output_collector import RawOutputCollector

logger = logging.getLogger(__name__)
class EmailAnalyzer:
    """
    SOC-GRADE Email Security Analysis Tool.
    
    Features:
    - Basic parsing & authentication (SPF/DKIM/DMARC)
    - **Advanced header analysis** (Received chain, Return-Path mismatch, Message-ID validation)
    - **Link-text mismatch detection** (phishing)
    - **Lookalike domain detection** (homograph, typosquatting)
    - **HTML obfuscation analysis** (hidden text, zero-size fonts, suspicious CSS)
    - **QR code detection** (modern phishing trend)
    - **Brand impersonation detection** (PayPal, Microsoft, Apple, Amazon, etc.)
    - **Email template fingerprinting** (campaign detection)
    - IOC extraction → Cross-tool integration
    - Attachment extraction → File analyzer integration
    - **Composite scoring** (email + IOCs + attachments)
    """
    
    def __init__(self, config: Dict):
        """Initialize email analyzer."""
        self.config = config
        self.llm_analyzer = LLMAnalyzer(config)
        self.advanced_analyzer = AdvancedEmailAnalyzer()
        self.bec_detector = BECDetector()

        # Cross-tool integration (set by parent)
        self.ioc_investigator = None
        self.file_analyzer = None
    
    async def analyze(self, email_path: str) -> Dict:
        """
        Comprehensive email analysis with SOC-grade techniques.
        
        Args:
            email_path: Path to .eml file
        
        Returns:
            Comprehensive analysis results
        """
        logger.info(f"[EMAIL] Analyzing: {Path(email_path).name}")
        
        # Initialize Raw Output Collector
        raw_collector = RawOutputCollector()
        raw_collector.record_pipeline_step('init', 'email_analysis_start', 'started')
        
        try:
            # Parse email
            with open(email_path, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
            
            # ==================== BASIC EXTRACTION ====================
            email_data = await self._extract_email_data(msg)
            raw_collector.record_pipeline_step('parsing', 'basic_extraction', 'completed')
            
            # ==================== ADVANCED ANALYSIS ====================
            
            # 1. Advanced Header Analysis
            logger.info("[EMAIL] Performing advanced header analysis...")
            header_analysis = self.advanced_analyzer.analyze_headers(msg)
            
            # Capture headers for raw output
            raw_collector.capture_email_headers({
                'from': email_data.get('from', ''),
                'to': [email_data.get('to', '')],
                'subject': email_data.get('subject', ''),
                'date': email_data.get('date', ''),
                'message_id': email_data.get('message_id', ''),
                'reply_to': email_data.get('reply_to', ''),
                'return_path': email_data.get('return_path', ''),
                'received': header_analysis.get('received_chain', []),
                'x_headers': header_analysis.get('x_headers', {}),
                'raw': str(msg)[:5000]
            })
            raw_collector.record_pipeline_step('headers', 'header_analysis', 'completed')
            
            # 2. DFIR-Grade Email Forensics (NEW!)
            logger.info("[EMAIL] Performing DFIR-grade forensics...")
            forensics = EmailForensics.perform_full_forensics(
                msg, 
                email_data['from'],
                email_data.get('from_domain', '')
            )
            raw_collector.capture_forensics_results(forensics)
            raw_collector.record_pipeline_step('forensics', 'dfir_forensics', 'completed')
            
            # 3. Authentication Check
            email_data['spf'] = self._check_spf(msg)
            email_data['dkim'] = self._check_dkim(msg)
            email_data['dmarc'] = self._check_dmarc(msg)
            
            # Capture authentication results
            raw_collector.capture_authentication_results({
                'spf': {'result': email_data['spf']},
                'dkim': {'result': email_data['dkim']},
                'dmarc': {'result': email_data['dmarc']},
                'overall_pass': all(r.lower() == 'pass' for r in [email_data['spf'], email_data['dkim'], email_data['dmarc']] if r)
            })
            raw_collector.record_pipeline_step('auth', 'authentication_check', 'completed')
            
            # 3. Link-Text Mismatch Detection
            logger.info("[EMAIL] Detecting link-text mismatches...")
            link_mismatches = self.advanced_analyzer.detect_link_text_mismatch(email_data['body_html'])
            
            # 4. Lookalike Domain Detection
            logger.info("[EMAIL] Detecting lookalike domains...")
            all_domains = email_data['domains'] + [
                url.split('/')[2] if '//' in url else url 
                for url in email_data['urls']
            ]
            lookalike_domains = self.advanced_analyzer.detect_lookalike_domains(list(set(all_domains)))
            
            # 5. HTML Obfuscation Analysis
            logger.info("[EMAIL] Analyzing HTML obfuscation...")
            html_obfuscation = self.advanced_analyzer.analyze_html_obfuscation(email_data['body_html'])
            
            # 6. QR Code Detection
            logger.info("[EMAIL] Detecting QR codes...")
            qr_detection = self.advanced_analyzer.detect_qr_codes(
                email_data['body_html'], 
                email_data['attachments']
            )
            
            # 7. Brand Impersonation Detection
            logger.info("[EMAIL] Detecting brand impersonation...")
            brand_impersonation = self.advanced_analyzer.detect_brand_impersonation(
                email_data['from'],
                email_data['subject'],
                email_data['body_html'] + email_data['body_text'],
                all_domains
            )
            
            # 8. Email Template Fingerprinting
            logger.info("[EMAIL] Fingerprinting email template...")
            template_fingerprint = self.advanced_analyzer.fingerprint_email_template(
                email_data['body_html'],
                email_data['subject']
            )
            
            # 9. Transfer forensics score to email_data for base scoring
            email_data['forensics_score'] = forensics.get('forensics_score', 0)
            logger.info(f"[EMAIL] Forensics risk score: {email_data['forensics_score']}/100")

            # 10. Enhanced Threat Indicator Checks (10 new checks)
            logger.info("[EMAIL] Running enhanced threat indicator checks...")
            threat_indicators = EmailThreatIndicators.run_all_checks(
                msg=msg,
                html_body=email_data['body_html'],
                body_text=email_data['body_text'],
                subject=email_data['subject'],
                from_address=email_data['from'],
                urls=email_data['urls'],
                attachments=email_data['attachments'],
                from_domain=email_data.get('from_domain', ''),
            )
            logger.info(
                f"[EMAIL] Threat indicators: {threat_indicators['checks_run']} checks, "
                f"severity={threat_indicators['overall_severity']}, "
                f"score_impact=+{threat_indicators['total_score_impact']}"
            )
            raw_collector.record_pipeline_step('threat_indicators', 'enhanced_checks', 'completed')

            # 11. BEC (Business Email Compromise) Detection
            logger.info("[EMAIL] Running BEC detection...")
            from_name, from_email_addr = parseaddr(email_data['from'])
            auth_results_header = msg.get('Authentication-Results', '')
            bec_email_data = {
                'from': email_data['from'],
                'reply_to': email_data.get('reply_to', ''),
                'subject': email_data['subject'],
                'body': email_data['body_text'],
                'display_name': from_name,
                'auth_results': auth_results_header,
            }
            bec_results = self.bec_detector.analyze(bec_email_data)
            logger.info(
                f"[EMAIL] BEC detection: score={bec_results['bec_score']}, "
                f"verdict={bec_results['verdict']}, "
                f"indicators={bec_results['indicator_count']}"
            )
            raw_collector.record_pipeline_step('bec_detection', 'bec_analysis', 'completed')

            # ==================== BASE SCORING ====================
            base_score = self._calculate_base_phishing_score(
                email_data,
                header_analysis,
                link_mismatches,
                lookalike_domains,
                html_obfuscation,
                qr_detection,
                brand_impersonation,
                threat_indicators,
                bec_results
            )
            
            # ==================== CROSS-TOOL INTEGRATION ====================
            
            # Investigate IOCs
            ioc_results = []
            if self.ioc_investigator:
                ioc_results = await self._investigate_iocs(email_data)
            
            # Analyze attachments
            attachment_results = []
            if self.file_analyzer:
                attachment_results = await self._analyze_attachments(msg, email_data)
            
            # ==================== COMPOSITE SCORING ====================
            composite_score = IntelligentScoring.calculate_email_score(
                base_score=base_score,
                ioc_results=ioc_results,
                attachment_results=attachment_results
            )
            
            # Determine verdict
            if composite_score >= 85:
                verdict = 'PHISHING'
            elif composite_score >= 60:
                verdict = 'SUSPICIOUS'
            elif composite_score >= 30:
                verdict = 'SPAM'
            else:
                verdict = 'CLEAN'
            
            # ==================== LLM ANALYSIS ====================
            llm_analysis = {}
            if self.config.get('analysis', {}).get('enable_llm', True):
                email_context = {
                    **email_data,
                    'header_anomalies': header_analysis.get('anomalies', []),
                    'link_mismatches': len(link_mismatches),
                    'lookalike_domains': len(lookalike_domains),
                    'html_obfuscation_score': html_obfuscation.get('risk_score', 0),
                    'qr_codes_found': qr_detection.get('qr_codes_found', 0),
                    'brand_impersonation': len(brand_impersonation),
                    'ioc_count': len(ioc_results),
                    'malicious_iocs': sum(1 for r in ioc_results if r.get('verdict') in ['MALICIOUS', 'SUSPICIOUS']),
                    'attachment_count': len(attachment_results),
                    'malicious_attachments': sum(1 for r in attachment_results if r.get('verdict') in ['MALICIOUS', 'SUSPICIOUS']),
                    'threat_indicator_severity': threat_indicators.get('overall_severity', 'NONE'),
                    'threat_indicator_score': threat_indicators.get('total_score_impact', 0),
                    'threat_indicator_active_checks': threat_indicators.get('active_checks', []),
                    'bec_score': bec_results.get('bec_score', 0),
                    'bec_verdict': bec_results.get('verdict', 'LOW'),
                    'bec_has_financial': bec_results.get('has_financial_indicators', False),
                    'bec_has_impersonation': bec_results.get('has_impersonation_indicators', False),
                }
                llm_analysis = await self.llm_analyzer.analyze_email(email_context)
            
            # ==================== FINAL RESULT ====================
            result = {
                'email_data': email_data,
                'advanced_analysis': {
                    'header_analysis': header_analysis,
                    'link_mismatches': link_mismatches,
                    'lookalike_domains': lookalike_domains,
                    'html_obfuscation': html_obfuscation,
                    'qr_detection': qr_detection,
                    'brand_impersonation': brand_impersonation,
                    'template_fingerprint': template_fingerprint,
                    'threat_indicators': threat_indicators,
                    'bec_analysis': bec_results,
                },
                'forensics': forensics,  # NEW: DFIR-grade forensics
                'base_phishing_score': base_score,
                'composite_score': composite_score,
                'verdict': verdict,
                'ioc_analysis': {
                    'total_iocs': len(ioc_results),
                    'malicious_iocs': sum(1 for r in ioc_results if r.get('verdict') == 'MALICIOUS'),
                    'suspicious_iocs': sum(1 for r in ioc_results if r.get('verdict') == 'SUSPICIOUS'),
                    'results': ioc_results
                },
                'attachment_analysis': {
                    'total_attachments': len(attachment_results),
                    'malicious_attachments': sum(1 for r in attachment_results if r.get('verdict') == 'MALICIOUS'),
                    'suspicious_attachments': sum(1 for r in attachment_results if r.get('verdict') == 'SUSPICIOUS'),
                    'results': attachment_results
                },
                'llm_analysis': llm_analysis,
                'iocs_found': {
                    'urls': len(email_data['urls']),
                    'ips': len(email_data['ips']),
                    'domains': len(email_data['domains'])
                },
                'detection_rules': RuleGenerator.generate_email_rules({
                    'from': email_data.get('from', ''),
                    'subject': email_data.get('subject', ''),
                    'sender_domain': email_data.get('from', '').split('@')[-1].split('>')[0] if '@' in email_data.get('from', '') else '',
                    'urls': email_data.get('urls', [])[:5],
                    'malicious_iocs': [r.get('ioc') for r in ioc_results if r.get('verdict') == 'MALICIOUS'][:10]
                })
            }
            
            # ==================== RAW OUTPUT CAPTURE ====================
            # Capture content
            raw_collector.capture_email_content({
                'text': email_data.get('body_text', '')[:5000],
                'html': email_data.get('body_html', '')[:10000],
                'urls': email_data.get('urls', []),
                'suspicious_keywords': [],
                'urgency': []
            })
            
            # Capture attachments
            raw_collector.capture_email_attachments(email_data.get('attachments', []))
            
            # Capture advanced analysis
            raw_collector.capture_advanced_analysis({
                'link_mismatches': link_mismatches,
                'lookalike_domains': lookalike_domains,
                'html_obfuscation': html_obfuscation,
                'qr_detection': qr_detection,
                'brand_impersonation': brand_impersonation,
                'template_fingerprint': template_fingerprint,
                'threat_indicators': threat_indicators,
                'bec_analysis': bec_results,
            })

            # Capture IOC results
            raw_collector.capture_ioc_results(ioc_results)
            
            # Capture scoring
            raw_collector.capture_scoring_details({
                'composite': composite_score,
                'base_phishing': base_score,
                'authentication': 0 if all(r.lower() == 'pass' for r in [email_data['spf'], email_data['dkim'], email_data['dmarc']] if r) else 30,
                'forensics': forensics.get('forensics_score', 0),
                'ioc': sum(1 for r in ioc_results if r.get('verdict') == 'MALICIOUS') * 15,
                'verdict': verdict
            })
            
            # Capture detection rules
            raw_collector.capture_detection_rules(result.get('detection_rules', {}))
            
            # Finalize
            raw_collector.finalize()
            
            # Add raw output to result
            result['raw_output'] = raw_collector.get_all_raw_data()
            
            logger.info(f"[EMAIL] Analysis complete: {verdict} (base: {base_score}, composite: {composite_score}/100)")
            
            return result
        
        except Exception as e:
            logger.error(f"[EMAIL] Analysis failed: {e}", exc_info=True)
            return {'error': str(e)}
    
    async def _extract_email_data(self, msg: email.message.Message) -> Dict:
        """Extract basic email data."""
        email_data = {
            'from': msg.get('From', ''),
            'to': msg.get('To', ''),
            'subject': msg.get('Subject', ''),
            'date': msg.get('Date', ''),
            'reply_to': msg.get('Reply-To', ''),
            'body_text': '',
            'body_html': '',
            'attachments': [],
            'urls': [],
            'ips': [],
            'domains': []
        }
        
        # Extract body
        body_parts = []
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    try:
                        body_parts.append(part.get_payload(decode=True).decode('utf-8', errors='ignore'))
                    except:
                        pass
                elif content_type == 'text/html':
                    try:
                        email_data['body_html'] += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        pass
                # Extract attachments
                elif part.get_filename():
                    email_data['attachments'].append({
                        'filename': part.get_filename(),
                        'content_type': content_type,
                        'size': len(part.get_payload(decode=True) or b'')
                    })
        else:
            try:
                body_parts.append(msg.get_payload(decode=True).decode('utf-8', errors='ignore'))
            except:
                pass
        
        email_data['body_text'] = '\n'.join(body_parts)
        
        # Extract IOCs
        all_text = f"{email_data['from']} {email_data['subject']} {email_data['body_text']} {email_data['body_html']}"
        iocs = IOCExtractor.extract_all(all_text)
        email_data['urls'] = iocs['urls']
        email_data['ips'] = iocs['ipv4']
        email_data['domains'] = iocs['domains']
        
        return email_data
    
    def _calculate_base_phishing_score(
        self,
        email_data: Dict,
        header_analysis: Dict,
        link_mismatches: List,
        lookalike_domains: List,
        html_obfuscation: Dict,
        qr_detection: Dict,
        brand_impersonation: List,
        threat_indicators: Dict = None,
        bec_results: Dict = None
    ) -> int:
        """
        Calculate base phishing score (email-only, before IOC/attachment analysis).
        
        Scoring factors:
        - Authentication failures (30%)
        - SPAM indicators (15%)
        - Forensics score (10%)
        - Header anomalies (10%)
        - Link-text mismatches (15%)
        - Lookalike domains (20%)
        - HTML obfuscation (10%)
        - QR codes (5%)
        - Brand impersonation (20%)
        - Phishing keywords (10%)
        """
        score = 0
        
        # ==================== AUTHENTICATION (max 30) ====================
        spf = email_data.get('spf', 'unknown').lower()
        dkim = email_data.get('dkim', 'unknown').lower()
        dmarc = email_data.get('dmarc', 'unknown').lower()
        
        # SPF scoring
        if spf == 'fail':
            score += 15  # Critical
        elif spf in ['softfail', 'none', 'unknown']:
            score += 10  # Suspicious
        
        # DKIM scoring
        if dkim == 'fail':
            score += 15  # Critical
        elif dkim in ['none', 'unknown']:
            score += 5  # Suspicious
        
        # ==================== SPAM INDICATORS (max 15) ====================
        # Check for X-Spam-* headers
        spam_headers = email_data.get('spam_headers', {})
        if spam_headers.get('x_spam_flag') == 'YES':
            score += 15  # Clear SPAM indicator
        elif spam_headers.get('x_spam_score', 0) > 5:
            score += 10
        
        # ==================== FORENSICS SCORE (max 35) ====================
        # Use forensics analysis risk score - HIGH = BAD
        forensics_score = email_data.get('forensics_score', 0)
        if forensics_score >= 80:
            score += 35  # Critical forensics findings
        elif forensics_score >= 60:
            score += 25  # High forensics risk
        elif forensics_score >= 40:
            score += 15  # Medium forensics risk
        elif forensics_score > 0:
            score += 5   # Low forensics risk
        
        # ==================== HEADER ANOMALIES (max 10) ====================
        anomaly_count = len(header_analysis.get('anomalies', []))
        score += min(10, anomaly_count * 5)
        
        # ==================== LINK-TEXT MISMATCHES (max 15) ====================
        if link_mismatches:
            score += min(15, len(link_mismatches) * 8)
        
        # ==================== LOOKALIKE DOMAINS (max 20) ====================
        if lookalike_domains:
            score += 20  # Critical indicator
        
        # ==================== HTML OBFUSCATION (max 10) ====================
        obfuscation_score = html_obfuscation.get('risk_score', 0)
        score += min(10, obfuscation_score // 5)
        
        # ==================== QR CODES (max 5) ====================
        if qr_detection.get('qr_codes_found', 0) > 0:
            score += 5
        
        # ==================== BRAND IMPERSONATION (max 20) ====================
        if brand_impersonation:
            score += 20  # Critical indicator
        
        # ==================== PHISHING KEYWORDS (max 10) ====================
        phishing_keywords = [
            'urgent', 'verify', 'suspend', 'click here', 'account', 'password',
            'confirm', 'security alert', 'unusual activity', 'update payment',
            'suspended', 'locked', 'expire', 'act now', 'limited time'
        ]
        body_text = email_data.get('body_text', '').lower()
        subject = email_data.get('subject', '').lower()
        combined_text = body_text + ' ' + subject
        
        keyword_matches = sum(1 for keyword in phishing_keywords if keyword in combined_text)
        score += min(10, keyword_matches * 2)
        
        # ==================== SPAM IN SUBJECT (v1.0.0: ağırlık artırıldı) ====================
        if '[spam]' in subject:
            score += 40  # Gateway already flagged as SPAM - very strong indicator!
        elif 'spam' in subject:
            score += 20  # Spam keyword in subject
        
        # ==================== RETURN-PATH MISMATCH (NEW) ====================
        from_domain = email_data.get('from', '').split('@')[-1].split('>')[0].lower() if '@' in email_data.get('from', '') else ''
        return_path = email_data.get('return_path', '').split('@')[-1].split('>')[0].lower() if '@' in email_data.get('return_path', '') else ''
        
        if from_domain and return_path and from_domain != return_path:
            score += 10  # Potential spoofing
        
        # ==================== SUSPICIOUS DOMAIN TLDs (NEW) ====================
        suspicious_tlds = ['.bid', '.xyz', '.top', '.win', '.click', '.loan', '.work', '.gq', '.tk', '.ml', '.ga', '.cf']
        if from_domain:
            for tld in suspicious_tlds:
                if from_domain.endswith(tld):
                    score += 15  # Suspicious TLD often used in spam/phishing
                    break

        # ==================== ENHANCED THREAT INDICATORS ====================
        if threat_indicators:
            # Add aggregated score impact from all 10 enhanced checks
            # Capped to prevent single category from dominating
            ti_score = threat_indicators.get('total_score_impact', 0)
            score += min(40, ti_score)  # Cap contribution at 40 points

        # ==================== BEC DETECTION (max 30) ====================
        if bec_results:
            bec_score = bec_results.get('bec_score', 0)
            if bec_score >= 70:
                score += 30  # Critical BEC risk
            elif bec_score >= 50:
                score += 20  # High BEC risk
            elif bec_score >= 30:
                score += 10  # Medium BEC risk

        return min(100, score)
    
    async def _investigate_iocs(self, email_data: Dict) -> List[Dict]:
        """Investigate extracted IOCs."""
        ioc_results = []
        
        if not self.ioc_investigator:
            return ioc_results
        
        logger.info(f"[EMAIL] Found {len(email_data['urls'])} URLs, {len(email_data['ips'])} IPs, {len(email_data['domains'])} domains")
        
        # Investigate URLs (max 5)
        for url in email_data['urls'][:5]:
            try:
                logger.info(f"[EMAIL] Investigating URL: {url}")
                result = await self.ioc_investigator.investigate(url)
                ioc_results.append(result)
            except Exception as e:
                logger.error(f"[EMAIL] IOC investigation failed for {url}: {e}")
        
        # Investigate IPs (max 3)
        for ip in email_data['ips'][:3]:
            try:
                logger.info(f"[EMAIL] Investigating IP: {ip}")
                result = await self.ioc_investigator.investigate(ip)
                ioc_results.append(result)
            except Exception as e:
                logger.error(f"[EMAIL] IOC investigation failed for {ip}: {e}")
        
        # Investigate domains (max 3)
        for domain in email_data['domains'][:3]:
            try:
                logger.info(f"[EMAIL] Investigating domain: {domain}")
                result = await self.ioc_investigator.investigate(domain)
                ioc_results.append(result)
            except Exception as e:
                logger.error(f"[EMAIL] IOC investigation failed for {domain}: {e}")
        
        return ioc_results
    
    async def _analyze_attachments(self, msg: email.message.Message, email_data: Dict) -> List[Dict]:
        """Analyze email attachments."""
        attachment_results = []
        
        if not self.file_analyzer:
            return attachment_results
        
        logger.info(f"[EMAIL] Found {len(email_data['attachments'])} attachments")
        
        # Extract and analyze attachments (max 3)
        for attachment_info in email_data['attachments'][:3]:
            try:
                # Extract attachment to temp file
                for part in msg.walk():
                    if part.get_filename() == attachment_info['filename']:
                        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(attachment_info['filename']).suffix) as tmp:
                            tmp.write(part.get_payload(decode=True))
                            tmp_path = tmp.name
                        
                        logger.info(f"[EMAIL] Analyzing attachment: {attachment_info['filename']}")
                        result = await self.file_analyzer.analyze(tmp_path)
                        result['filename'] = attachment_info['filename']
                        attachment_results.append(result)
                        
                        # Cleanup
                        try:
                            Path(tmp_path).unlink()
                        except:
                            pass
                        break
            except Exception as e:
                logger.error(f"[EMAIL] Attachment analysis failed for {attachment_info['filename']}: {e}")
        
        return attachment_results
    
    def _check_spf(self, msg: email.message.Message) -> str:
        """Check SPF status from headers."""
        received_spf = msg.get('Received-SPF', '').lower()
        if 'pass' in received_spf:
            return 'pass'
        elif 'fail' in received_spf:
            return 'fail'
        elif 'softfail' in received_spf:
            return 'softfail'
        else:
            return 'none'
    
    def _check_dkim(self, msg: email.message.Message) -> str:
        """Check DKIM status from headers."""
        auth_results = msg.get('Authentication-Results', '').lower()
        if 'dkim=pass' in auth_results:
            return 'pass'
        elif 'dkim=fail' in auth_results:
            return 'fail'
        else:
            return 'none'
    
    def _check_dmarc(self, msg: email.message.Message) -> str:
        """Check DMARC status from headers."""
        auth_results = msg.get('Authentication-Results', '').lower()
        if 'dmarc=pass' in auth_results:
            return 'pass'
        elif 'dmarc=fail' in auth_results:
            return 'fail'
        else:
            return 'none'
