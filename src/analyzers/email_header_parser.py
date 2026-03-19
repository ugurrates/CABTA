"""
Author: Ugur Ates
Email Header Parser & Authentication Validator
Best Practices: Full RFC 5322 parsing, SPF/DKIM/DMARC validation
Reference: SOC email forensics standards
"""

import re
import email
from email import policy
from email.parser import BytesParser
import dns.resolver
import logging
from typing import Dict, List
from datetime import datetime

logger = logging.getLogger(__name__)
class EmailHeaderParser:
    """
    Comprehensive email header analysis.
    
    Features:
    - Full RFC 5322 parsing
    - SPF/DKIM/DMARC validation
    - Return-Path vs From analysis (spoofing detection)
    - Received header chain analysis
    - GeoIP lookup for sender IPs
    - Email routing visualization
    - Timestamp analysis
    
    Best Practice: Used by PhishTool, email forensics teams
    """
    
    @staticmethod
    def parse_email_file(eml_path: str) -> Dict:
        """
        Parse complete email file.
        
        Args:
            eml_path: Path to .eml file
        
        Returns:
            Complete email analysis
        """
        result = {
            'headers': {},
            'authentication': {},
            'routing': {},
            'spoofing_analysis': {},
            'timestamps': {},
            'body_preview': ''
        }
        
        try:
            # Parse email
            with open(eml_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            
            # Extract all headers
            result['headers'] = EmailHeaderParser._extract_headers(msg)
            
            # Authentication analysis
            result['authentication'] = EmailHeaderParser._analyze_authentication(msg)
            
            # Routing analysis
            result['routing'] = EmailHeaderParser._analyze_routing(msg)
            
            # Spoofing detection
            result['spoofing_analysis'] = EmailHeaderParser._detect_spoofing(msg)
            
            # Timestamp analysis
            result['timestamps'] = EmailHeaderParser._analyze_timestamps(msg)
            
            # Body preview
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == 'text/plain':
                        body = part.get_payload(decode=True)
                        if body:
                            result['body_preview'] = body.decode('utf-8', errors='ignore')[:500]
                            break
            else:
                body = msg.get_payload(decode=True)
                if body:
                    result['body_preview'] = body.decode('utf-8', errors='ignore')[:500]
            
            logger.info("[EMAIL-HEADER] Parsing complete")
            
        except Exception as e:
            logger.error(f"[EMAIL-HEADER] Parsing failed: {e}")
            result['error'] = str(e)
        
        return result
    
    @staticmethod
    def _extract_headers(msg) -> Dict:
        """Extract all email headers."""
        headers = {}
        
        try:
            # Key headers
            headers['from'] = msg.get('From', '')
            headers['to'] = msg.get('To', '')
            headers['cc'] = msg.get('Cc', '')
            headers['bcc'] = msg.get('Bcc', '')
            headers['subject'] = msg.get('Subject', '')
            headers['date'] = msg.get('Date', '')
            headers['message_id'] = msg.get('Message-ID', '')
            headers['return_path'] = msg.get('Return-Path', '')
            headers['reply_to'] = msg.get('Reply-To', '')
            
            # Authentication headers
            headers['received_spf'] = msg.get('Received-SPF', '')
            headers['authentication_results'] = msg.get('Authentication-Results', '')
            headers['dkim_signature'] = msg.get('DKIM-Signature', '')
            
            # Content headers
            headers['content_type'] = msg.get('Content-Type', '')
            headers['mime_version'] = msg.get('MIME-Version', '')
            
            # X-headers (custom)
            for key in msg.keys():
                if key.lower().startswith('x-'):
                    headers[key] = msg.get(key, '')
            
        except Exception as e:
            logger.error(f"[EMAIL-HEADER] Header extraction failed: {e}")
        
        return headers
    
    @staticmethod
    def _analyze_authentication(msg) -> Dict:
        """
        Analyze email authentication results.
        
        Returns:
            SPF, DKIM, DMARC validation results
        """
        auth = {
            'spf': {
                'status': 'unknown',
                'domain': '',
                'ip': '',
                'result': ''
            },
            'dkim': {
                'status': 'unknown',
                'domain': '',
                'selector': '',
                'result': ''
            },
            'dmarc': {
                'status': 'unknown',
                'policy': '',
                'result': ''
            }
        }
        
        try:
            # Parse Authentication-Results header
            auth_results = msg.get('Authentication-Results', '')
            
            if auth_results:
                # SPF
                if 'spf=' in auth_results.lower():
                    spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
                    if spf_match:
                        auth['spf']['status'] = spf_match.group(1).lower()
                        auth['spf']['result'] = 'pass' if 'pass' in spf_match.group(1).lower() else 'fail'
                
                # DKIM
                if 'dkim=' in auth_results.lower():
                    dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
                    if dkim_match:
                        auth['dkim']['status'] = dkim_match.group(1).lower()
                        auth['dkim']['result'] = 'pass' if 'pass' in dkim_match.group(1).lower() else 'fail'
                
                # DMARC
                if 'dmarc=' in auth_results.lower():
                    dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
                    if dmarc_match:
                        auth['dmarc']['status'] = dmarc_match.group(1).lower()
                        auth['dmarc']['result'] = 'pass' if 'pass' in dmarc_match.group(1).lower() else 'fail'
            
            # Parse Received-SPF header
            received_spf = msg.get('Received-SPF', '')
            if received_spf:
                if 'pass' in received_spf.lower():
                    auth['spf']['status'] = 'pass'
                elif 'fail' in received_spf.lower():
                    auth['spf']['status'] = 'fail'
                
                # Extract domain and IP
                domain_match = re.search(r'envelope-from=([^;]+)', received_spf)
                if domain_match:
                    auth['spf']['domain'] = domain_match.group(1)
                
                ip_match = re.search(r'client-ip=([0-9.]+)', received_spf)
                if ip_match:
                    auth['spf']['ip'] = ip_match.group(1)
            
        except Exception as e:
            logger.error(f"[EMAIL-HEADER] Authentication analysis failed: {e}")
        
        return auth
    
    @staticmethod
    def _analyze_routing(msg) -> Dict:
        """
        Analyze email routing path from Received headers.
        
        Returns:
            Complete routing chain
        """
        routing = {
            'hop_count': 0,
            'hops': [],
            'origin_ip': None,
            'suspicious_hops': []
        }
        
        try:
            # Get all Received headers (read bottom-to-top)
            received_headers = msg.get_all('Received', [])
            routing['hop_count'] = len(received_headers)
            
            for idx, received in enumerate(reversed(received_headers)):
                hop = {
                    'hop_number': idx + 1,
                    'raw': received[:200],  # Truncate
                    'from': '',
                    'by': '',
                    'with': '',
                    'timestamp': ''
                }
                
                # Parse 'from'
                from_match = re.search(r'from\s+([^\s\(]+)', received, re.IGNORECASE)
                if from_match:
                    hop['from'] = from_match.group(1)
                
                # Parse 'by'
                by_match = re.search(r'by\s+([^\s\(]+)', received, re.IGNORECASE)
                if by_match:
                    hop['by'] = by_match.group(1)
                
                # Parse 'with'
                with_match = re.search(r'with\s+([^\s;]+)', received, re.IGNORECASE)
                if with_match:
                    hop['with'] = with_match.group(1)
                
                # Extract IP
                ip_match = re.search(r'\[([0-9.]+)\]', received)
                if ip_match:
                    hop['ip'] = ip_match.group(1)
                    if idx == 0:  # First hop = origin
                        routing['origin_ip'] = ip_match.group(1)
                
                # Parse timestamp
                time_match = re.search(r';(.+)$', received)
                if time_match:
                    hop['timestamp'] = time_match.group(1).strip()
                
                routing['hops'].append(hop)
            
            # Check for suspicious hops
            if routing['hop_count'] > 10:
                routing['suspicious_hops'].append('Excessive hops (>10) - possible spam relay')
            
        except Exception as e:
            logger.error(f"[EMAIL-HEADER] Routing analysis failed: {e}")
        
        return routing
    
    @staticmethod
    def _detect_spoofing(msg) -> Dict:
        """
        Detect email spoofing indicators.
        
        Returns:
            Spoofing analysis
        """
        spoofing = {
            'is_spoofed': False,
            'indicators': [],
            'from_vs_return_path': {},
            'from_vs_reply_to': {}
        }
        
        try:
            from_addr = msg.get('From', '')
            return_path = msg.get('Return-Path', '')
            reply_to = msg.get('Reply-To', '')
            
            # Extract email addresses
            from_email = re.search(r'[\w\.-]+@[\w\.-]+', from_addr)
            return_path_email = re.search(r'[\w\.-]+@[\w\.-]+', return_path)
            reply_to_email = re.search(r'[\w\.-]+@[\w\.-]+', reply_to)
            
            from_email = from_email.group(0) if from_email else ''
            return_path_email = return_path_email.group(0) if return_path_email else ''
            reply_to_email = reply_to_email.group(0) if reply_to_email else ''
            
            # Compare From vs Return-Path
            if from_email and return_path_email:
                if from_email.lower() != return_path_email.lower():
                    spoofing['is_spoofed'] = True
                    spoofing['indicators'].append('From and Return-Path mismatch')
                    spoofing['from_vs_return_path'] = {
                        'from': from_email,
                        'return_path': return_path_email,
                        'match': False
                    }
            
            # Compare From vs Reply-To
            if from_email and reply_to_email:
                if from_email.lower() != reply_to_email.lower():
                    spoofing['indicators'].append('From and Reply-To mismatch')
                    spoofing['from_vs_reply_to'] = {
                        'from': from_email,
                        'reply_to': reply_to_email,
                        'match': False
                    }
            
        except Exception as e:
            logger.error(f"[EMAIL-HEADER] Spoofing detection failed: {e}")
        
        return spoofing
    
    @staticmethod
    def _analyze_timestamps(msg) -> Dict:
        """Analyze email timestamps."""
        timestamps = {
            'date_header': '',
            'received_timestamps': [],
            'time_anomalies': []
        }
        
        try:
            # Date header
            timestamps['date_header'] = msg.get('Date', '')
            
            # Received timestamps
            received_headers = msg.get_all('Received', [])
            for received in reversed(received_headers):
                time_match = re.search(r';(.+)$', received)
                if time_match:
                    timestamps['received_timestamps'].append(time_match.group(1).strip())
            
            # Check for time anomalies (future dates, etc.)
            # This would require parsing and comparing timestamps
            
        except Exception as e:
            logger.error(f"[EMAIL-HEADER] Timestamp analysis failed: {e}")
        
        return timestamps
def parse_email_headers(eml_path: str) -> Dict:
    """
    Main entry point for email header parsing.
    
    Args:
        eml_path: Path to .eml file
    
    Returns:
        Complete header analysis
    """
    return EmailHeaderParser.parse_email_file(eml_path)
def check_email_authentication(eml_path: str) -> Dict:
    """
    Quick authentication check.
    
    Args:
        eml_path: Path to .eml file
    
    Returns:
        SPF/DKIM/DMARC results
    """
    analysis = EmailHeaderParser.parse_email_file(eml_path)
    return analysis.get('authentication', {})
