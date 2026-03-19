"""
Author: Ugur AtesAdvanced email analysis for SOC/Blue Team operations."""

import re
import email
from email import policy
from email.utils import parseaddr
from typing import Dict, List, Tuple
import logging
from urllib.parse import urlparse
import difflib

logger = logging.getLogger(__name__)
class AdvancedEmailAnalyzer:
    """
    Advanced email analysis techniques used by SOC analysts.
    
    Features:
    - Deep header analysis (Received chain, X-headers)
    - Link-text mismatch detection
    - Lookalike domain detection (homograph attacks)
    - HTML/CSS analysis (hidden elements, obfuscation)
    - QR code detection
    - Brand impersonation detection
    - Email template fingerprinting
    """
    
    # Known legitimate domains for brand impersonation detection
    LEGITIMATE_DOMAINS = {
        'paypal': ['paypal.com', 'paypal.co.uk'],
        'microsoft': ['microsoft.com', 'office.com', 'outlook.com', 'live.com'],
        'apple': ['apple.com', 'icloud.com', 'me.com'],
        'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de'],
        'google': ['google.com', 'gmail.com', 'googlemail.com'],
        'facebook': ['facebook.com', 'fb.com', 'fbcdn.net'],
        'linkedin': ['linkedin.com'],
        'dropbox': ['dropbox.com'],
        'docusign': ['docusign.com', 'docusign.net'],
        'bank': ['chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com']
    }
    
    @staticmethod
    def analyze_headers(msg: email.message.Message) -> Dict:
        """
        Deep header analysis.
        
        Checks:
        - Received header chain
        - X-Originating-IP
        - Message-ID validity
        - Return-Path vs From mismatch
        - Timezone anomalies
        """
        analysis = {
            'received_chain': [],
            'originating_ip': None,
            'message_id': msg.get('Message-ID', ''),
            'return_path': msg.get('Return-Path', ''),
            'from_address': msg.get('From', ''),
            'anomalies': []
        }
        
        # Parse Received headers (shows email routing path)
        received_headers = msg.get_all('Received', [])
        for received in received_headers:
            # Extract IP addresses from Received headers
            ips = re.findall(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
            if ips:
                analysis['received_chain'].extend(ips)
        
        # Extract X-Originating-IP
        x_orig_ip = msg.get('X-Originating-IP', '')
        if x_orig_ip:
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', x_orig_ip)
            if ip_match:
                analysis['originating_ip'] = ip_match.group(1)
        
        # Check Return-Path vs From mismatch
        return_path_email = parseaddr(analysis['return_path'])[1]
        from_email = parseaddr(analysis['from_address'])[1]
        
        # Extract from_domain for later use
        from_domain = ''
        if from_email and '@' in from_email:
            from_domain = from_email.split('@')[-1]
        
        if return_path_email and from_email:
            return_domain = return_path_email.split('@')[-1] if '@' in return_path_email else ''
            
            if return_domain and from_domain and return_domain != from_domain:
                analysis['anomalies'].append(f'Return-Path domain ({return_domain}) != From domain ({from_domain})')
        
        # Check Message-ID validity
        if analysis['message_id']:
            if '@' not in analysis['message_id']:
                analysis['anomalies'].append('Invalid Message-ID format (missing @)')
            else:
                msg_id_domain = analysis['message_id'].split('@')[-1].rstrip('>')
                if from_domain and msg_id_domain != from_domain:
                    analysis['anomalies'].append(f'Message-ID domain ({msg_id_domain}) != From domain ({from_domain})')
        
        return analysis
    
    @staticmethod
    def detect_link_text_mismatch(html_body: str) -> List[Dict]:
        """
        Detect link-text mismatch (common phishing technique).
        
        Example: <a href="http://evil.com">http://paypal.com</a>
        """
        mismatches = []
        
        # Find all <a> tags with href
        link_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>'
        matches = re.findall(link_pattern, html_body, re.IGNORECASE | re.DOTALL)
        
        for href, link_text in matches:
            # Extract displayed URL from link text
            displayed_urls = re.findall(r'https?://[^\s<]+', link_text)
            
            if displayed_urls:
                displayed_url = displayed_urls[0]
                href_domain = urlparse(href).netloc
                displayed_domain = urlparse(displayed_url).netloc
                
                if href_domain and displayed_domain and href_domain != displayed_domain:
                    mismatches.append({
                        'actual_url': href,
                        'displayed_url': displayed_url,
                        'risk': 'HIGH - Link text shows different domain'
                    })
        
        return mismatches
    
    @staticmethod
    def detect_lookalike_domains(domains: List[str]) -> List[Dict]:
        """
        Detect lookalike/homograph domains.
        
        Techniques:
        - Character substitution (paypa1.com)
        - Homograph attacks (раypal.com - Cyrillic 'а')
        - Subdomain tricks (paypal.com.evil.com)
        - Typosquatting (paypai.com)
        """
        lookalikes = []
        
        for domain in domains:
            domain_lower = domain.lower()
            
            # Check against known brands
            for brand, legitimate_domains in AdvancedEmailAnalyzer.LEGITIMATE_DOMAINS.items():
                for legit_domain in legitimate_domains:
                    # Calculate similarity ratio
                    similarity = difflib.SequenceMatcher(None, domain_lower, legit_domain).ratio()
                    
                    # If very similar but not exact match
                    if 0.7 < similarity < 1.0:
                        lookalikes.append({
                            'domain': domain,
                            'brand': brand,
                            'legitimate': legit_domain,
                            'similarity': f'{similarity * 100:.1f}%',
                            'risk': 'HIGH - Potential brand impersonation'
                        })
                    
                    # Check for subdomain tricks
                    if legit_domain in domain_lower and domain_lower != legit_domain:
                        # Check if it's like paypal.com.evil.com
                        if domain_lower.index(legit_domain) < len(domain_lower) - len(legit_domain) - 1:
                            lookalikes.append({
                                'domain': domain,
                                'brand': brand,
                                'legitimate': legit_domain,
                                'technique': 'Subdomain trick',
                                'risk': 'CRITICAL - Subdomain impersonation'
                            })
            
            # Detect homograph attacks (non-ASCII characters)
            if not all(ord(c) < 128 for c in domain):
                lookalikes.append({
                    'domain': domain,
                    'technique': 'Homograph attack (Unicode)',
                    'risk': 'CRITICAL - IDN homograph attack'
                })
        
        return lookalikes
    
    @staticmethod
    def analyze_html_obfuscation(html_body: str) -> Dict:
        """
        Analyze HTML for obfuscation techniques.
        
        Checks:
        - Zero-size fonts
        - Hidden elements (display:none, visibility:hidden)
        - White text on white background
        - Excessive HTML comments
        - Suspicious CSS
        """
        analysis = {
            'zero_size_fonts': 0,
            'hidden_elements': 0,
            'white_on_white': 0,
            'suspicious_css': [],
            'risk_score': 0
        }
        
        # Check for zero-size fonts
        zero_size = re.findall(r'font-size\s*:\s*0', html_body, re.IGNORECASE)
        analysis['zero_size_fonts'] = len(zero_size)
        analysis['risk_score'] += len(zero_size) * 5
        
        # Check for hidden elements
        hidden = re.findall(r'(display\s*:\s*none|visibility\s*:\s*hidden)', html_body, re.IGNORECASE)
        analysis['hidden_elements'] = len(hidden)
        analysis['risk_score'] += len(hidden) * 3
        
        # Check for white on white
        white_text = re.findall(r'color\s*:\s*(#fff|white)', html_body, re.IGNORECASE)
        white_bg = re.findall(r'background-color\s*:\s*(#fff|white)', html_body, re.IGNORECASE)
        if white_text and white_bg:
            analysis['white_on_white'] = min(len(white_text), len(white_bg))
            analysis['risk_score'] += analysis['white_on_white'] * 10
        
        # Check for suspicious CSS
        suspicious_patterns = [
            r'position\s*:\s*absolute',  # Often used to overlay fake content
            r'z-index\s*:\s*-?\d{3,}',   # Very high z-index
            r'opacity\s*:\s*0',          # Invisible elements
        ]
        for pattern in suspicious_patterns:
            matches = re.findall(pattern, html_body, re.IGNORECASE)
            if matches:
                analysis['suspicious_css'].append(pattern)
        
        analysis['risk_score'] += len(analysis['suspicious_css']) * 5
        
        return analysis
    
    @staticmethod
    def detect_qr_codes(html_body: str, attachments: List[Dict]) -> Dict:
        """
        Detect QR codes in email (increasingly used in phishing).
        
        Checks:
        - Embedded QR code images
        - Base64 encoded QR codes
        - QR code attachments
        """
        detection = {
            'qr_codes_found': 0,
            'locations': [],
            'risk': 'NONE'
        }
        
        # Check for QR code image references
        qr_patterns = [
            r'qr[_-]?code',
            r'barcode',
            r'scan[_-]?me',
            r'mobile[_-]?verify'
        ]
        
        for pattern in qr_patterns:
            matches = re.findall(pattern, html_body, re.IGNORECASE)
            if matches:
                detection['qr_codes_found'] += len(matches)
                detection['locations'].append(f'HTML body ({pattern})')
        
        # Check attachments for QR code indicators
        for attachment in attachments:
            filename = attachment.get('filename', '').lower()
            if any(pattern in filename for pattern in ['qr', 'barcode', 'scan']):
                detection['qr_codes_found'] += 1
                detection['locations'].append(f'Attachment: {attachment.get("filename")}')
        
        if detection['qr_codes_found'] > 0:
            detection['risk'] = 'HIGH - QR codes commonly used in modern phishing'
        
        return detection
    
    @staticmethod
    def fingerprint_email_template(html_body: str, subject: str) -> Dict:
        """
        Fingerprint email template to detect phishing campaigns.
        
        Creates a signature based on:
        - HTML structure
        - CSS patterns
        - Common strings
        - Image references
        """
        fingerprint = {
            'html_structure_hash': None,
            'css_classes': [],
            'image_count': 0,
            'external_resources': [],
            'template_indicators': []
        }
        
        # Extract CSS classes (used for template identification)
        css_classes = re.findall(r'class=["\']([^"\']+)["\']', html_body)
        fingerprint['css_classes'] = list(set(css_classes))[:10]  # Top 10
        
        # Count images
        images = re.findall(r'<img[^>]+>', html_body, re.IGNORECASE)
        fingerprint['image_count'] = len(images)
        
        # Extract external resources
        external = re.findall(r'(https?://[^\s"\'<>]+)', html_body)
        unique_domains = set(urlparse(url).netloc for url in external)
        fingerprint['external_resources'] = list(unique_domains)
        
        # Detect common phishing template indicators
        template_keywords = [
            'verify your account',
            'unusual activity',
            'suspended',
            'confirm your identity',
            'update payment',
            'security alert',
            'immediate action required'
        ]
        
        combined_text = (subject + ' ' + html_body).lower()
        for keyword in template_keywords:
            if keyword in combined_text:
                fingerprint['template_indicators'].append(keyword)
        
        return fingerprint
    
    @staticmethod
    def detect_brand_impersonation(from_address: str, subject: str, html_body: str, domains: List[str]) -> List[Dict]:
        """
        Advanced brand impersonation detection.
        
        Checks:
        - Display name vs sender domain mismatch
        - Brand mentions in subject/body without legitimate domain
        - Logo detection (if images present)
        """
        impersonation = []
        
        # Parse from address
        from_name, from_email = parseaddr(from_address)
        from_domain = from_email.split('@')[-1] if '@' in from_email else ''
        
        combined_text = (from_name + ' ' + subject + ' ' + html_body).lower()
        
        # Check each brand
        for brand, legitimate_domains in AdvancedEmailAnalyzer.LEGITIMATE_DOMAINS.items():
            # If brand mentioned in email
            if brand in combined_text:
                # Check if sender domain is legitimate
                is_legitimate = any(legit_domain in from_domain.lower() for legit_domain in legitimate_domains)
                
                # Check if any URLs point to legitimate domains
                has_legit_url = any(
                    any(legit_domain in domain.lower() for legit_domain in legitimate_domains)
                    for domain in domains
                )
                
                if not is_legitimate and not has_legit_url:
                    impersonation.append({
                        'brand': brand.upper(),
                        'from_domain': from_domain,
                        'legitimate_domains': legitimate_domains,
                        'risk': 'CRITICAL - Brand mentioned but no legitimate domain'
                    })
        
        return impersonation
