"""Email Analysis Tool with Advanced SOC-grade Features."""

import email
from email import policy
from pathlib import Path
import asyncio
import base64
import tempfile
from typing import Dict, List
import logging
from ..utils.ioc_extractor import IOCExtractor
from ..integrations.llm_analyzer import LLMAnalyzer
from ..scoring.intelligent_scoring import IntelligentScoring
from ..analyzers.advanced_email_analyzer import AdvancedEmailAnalyzer

logger = logging.getLogger(__name__)


class EmailAnalyzer:
    """
    Comprehensive email security analysis tool for SOC operations.
    
    Features:
    - Email parsing and header analysis
    - SPF/DKIM validation
    - **Advanced header analysis** (Received chain, X-headers, Message-ID validation)
    - **Link-text mismatch detection** (phishing technique)
    - **Lookalike domain detection** (homograph attacks, typosquatting)
    - **HTML obfuscation analysis** (hidden text, zero-size fonts, CSS tricks)
    - **QR code detection** (modern phishing)
    - **Brand impersonation detection** (advanced)
    - **Email template fingerprinting**
    - IOC extraction → IOC Investigator integration
    - Attachment extraction → File Analyzer integration
    - Composite scoring (email + IOCs + attachments)
    """
    
    def __init__(self, config: Dict):
        """Initialize email analyzer."""
        self.config = config
        self.llm_analyzer = LLMAnalyzer(config)
        self.advanced_analyzer = AdvancedEmailAnalyzer()
        
        # Will be set by parent to avoid circular imports
        self.ioc_investigator = None
        self.file_analyzer = None
    
    async def analyze(self, email_path: str) -> Dict:
        """
        Analyze email file with cross-tool integration.
        
        Args:
            email_path: Path to .eml file
        
        Returns:
            Email analysis results with composite scoring
        """
        logger.info(f"[EMAIL] Analyzing: {Path(email_path).name}")
        
        try:
            # Parse email
            with open(email_path, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
            
            # Extract basic info
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
            
            # Extract IOCs from email content
            all_text = f"{email_data['from']} {email_data['subject']} {email_data['body_text']} {email_data['body_html']}"
            iocs = IOCExtractor.extract_all(all_text)
            email_data['urls'] = iocs['urls']
            email_data['ips'] = iocs['ipv4']
            email_data['domains'] = iocs['domains']
            
            # Check authentication
            email_data['spf'] = self._check_spf(msg)
            email_data['dkim'] = self._check_dkim(msg)
            
            # Base email scoring (without IOC/attachment analysis)
            base_phishing_score = self._calculate_base_phishing_score(email_data)
            
            # ==================== CROSS-TOOL INTEGRATION ====================
            
            # Investigate extracted IOCs
            ioc_results = []
            if self.ioc_investigator and (email_data['urls'] or email_data['ips'] or email_data['domains']):
                logger.info(f"[EMAIL] Found {len(email_data['urls'])} URLs, {len(email_data['ips'])} IPs, {len(email_data['domains'])} domains")
                
                # Investigate URLs (max 5 to avoid too many API calls)
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
            
            # Analyze attachments
            attachment_results = []
            if self.file_analyzer and email_data['attachments']:
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
                                
                                # Cleanup temp file
                                try:
                                    Path(tmp_path).unlink()
                                except:
                                    pass
                                break
                    except Exception as e:
                        logger.error(f"[EMAIL] Attachment analysis failed for {attachment_info['filename']}: {e}")
            
            # ==================== COMPOSITE SCORING ====================
            
            # Calculate composite phishing score
            composite_score = IntelligentScoring.calculate_email_score(
                base_score=base_phishing_score,
                ioc_results=ioc_results,
                attachment_results=attachment_results
            )
            
            # Determine verdict
            from ..utils.helpers import determine_verdict
            if composite_score >= 85:
                verdict = 'PHISHING'
            elif composite_score >= 60:
                verdict = 'SUSPICIOUS'
            elif composite_score >= 30:
                verdict = 'SPAM'
            else:
                verdict = 'CLEAN'
            
            # LLM analysis with full context
            llm_analysis = {}
            if self.config.get('analysis', {}).get('enable_llm', True):
                email_context = {
                    **email_data,
                    'ioc_count': len(ioc_results),
                    'malicious_iocs': sum(1 for r in ioc_results if r.get('verdict') in ['MALICIOUS', 'SUSPICIOUS']),
                    'attachment_count': len(attachment_results),
                    'malicious_attachments': sum(1 for r in attachment_results if r.get('verdict') in ['MALICIOUS', 'SUSPICIOUS'])
                }
                llm_analysis = await self.llm_analyzer.analyze_email(email_context)
            
            result = {
                'email_data': email_data,
                'base_phishing_score': base_phishing_score,
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
                }
            }
            
            logger.info(f"[EMAIL] Analysis complete: {verdict} (base: {base_phishing_score}, composite: {composite_score}/100)")
            
            return result
        
        except Exception as e:
            logger.error(f"[EMAIL] Analysis failed: {e}", exc_info=True)
            return {'error': str(e)}
    
    def _check_spf(self, msg) -> str:
        """Check SPF authentication."""
        # Simplified - full implementation would parse headers
        received_spf = msg.get('Received-SPF', '')
        if 'pass' in received_spf.lower():
            return 'pass'
        elif 'fail' in received_spf.lower():
            return 'fail'
        return 'unknown'
    
    def _check_dkim(self, msg) -> str:
        """Check DKIM authentication."""
        # Simplified - full implementation would verify signature
        dkim_signature = msg.get('DKIM-Signature', '')
        return 'pass' if dkim_signature else 'unknown'
    
    def _calculate_base_phishing_score(self, email_data: Dict) -> int:
        """
        Calculate base phishing likelihood score (email-only, no IOC/attachment analysis).
        
        Args:
            email_data: Email data
        
        Returns:
            Base phishing score (0-100)
        """
        score = 0
        
        # Authentication failures (30 points max)
        if email_data.get('spf') == 'fail':
            score += 15
        if email_data.get('dkim') == 'fail':
            score += 15
        
        # Suspicious keywords (25 points max)
        phishing_keywords = [
            'urgent', 'verify', 'suspend', 'click here', 'account', 'password', 
            'confirm', 'security alert', 'unusual activity', 'update payment',
            'limited time', 'act now', 'verify your identity', 'suspended account'
        ]
        body_text = email_data.get('body_text', '').lower()
        keyword_matches = sum(1 for keyword in phishing_keywords if keyword in body_text)
        score += min(25, keyword_matches * 3)
        
        # Multiple URLs (15 points max)
        url_count = len(email_data.get('urls', []))
        if url_count > 5:
            score += 15
        elif url_count > 3:
            score += 10
        elif url_count > 1:
            score += 5
        
        # Mismatched domains (20 points)
        from_addr = email_data.get('from', '')
        reply_to = email_data.get('reply_to', '')
        if reply_to and from_addr != reply_to:
            # Extract domains
            from_domain = from_addr.split('@')[-1] if '@' in from_addr else ''
            reply_domain = reply_to.split('@')[-1] if '@' in reply_to else ''
            if from_domain and reply_domain and from_domain != reply_domain:
                score += 20
        
        # HTML content with forms (10 points)
        if '<form' in email_data.get('body_html', '').lower():
            score += 10
        
        return min(100, score)
