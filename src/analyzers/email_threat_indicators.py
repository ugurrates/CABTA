"""
Author: Ugur Ates
Enhanced Email Threat Indicators Module.

Provides 10 critical threat detection checks for email analysis:
1. Tracking Pixel Detection
2. HTML Form Detection (credential harvesting)
3. URL Shortener Detection
4. Data URI Detection
5. IP-based URL Detection
6. Double Extension Detection (attachments)
7. X-Mailer / User-Agent Analysis
8. Free Email Provider Business Impersonation Check
9. JavaScript in Email Body Detection
10. Callback Phishing Detection (BazarCall-style)
"""

import re
import logging
from typing import Dict, List, Tuple
from urllib.parse import urlparse, unquote

logger = logging.getLogger(__name__)


class EmailThreatIndicators:
    """
    Enhanced email threat indicator detection for SOC/Blue Team operations.

    Each check returns structured data with:
    - findings: list of detected items
    - severity: CRITICAL / HIGH / MEDIUM / LOW / NONE
    - score_impact: integer points to add to phishing score
    - explanation: human-readable description
    """

    # ------------------------------------------------------------------ #
    # Known tracking domains (major ESPs and analytics platforms)
    # ------------------------------------------------------------------ #
    TRACKING_DOMAINS = [
        'mailchimp.com', 'list-manage.com', 'sendgrid.net', 'mailgun.net',
        'constantcontact.com', 'hubspot.com', 'pardot.com', 'marketo.com',
        'click.mlsend.com', 'open.convertkit-mail.com', 'track.customer.io',
        'pixel.monitor.', 'tracking.', 'analytics.', 'beacon.', 'open.',
        'r.krxd.net', 'bat.bing.com', 'ad.doubleclick.net',
        'www.facebook.com/tr', 'connect.facebook.net',
    ]

    # Tracking URL parameter names
    TRACKING_PARAMS = [
        'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
        'pixel', 'track', 'open', 'beacon', 'trk', 'cid', 'eid',
        'mc_eid', 'mc_cid', '__s', 'svc', 'sqi',
    ]

    # Known URL shortener domains
    URL_SHORTENERS = [
        'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
        'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'short.io',
        'bl.ink', 'lnkd.in', 'db.tt', 'adf.ly', 'qr.ae',
        'tiny.cc', 'shorte.st', 'v.gd', 'tr.im', 'cli.gs',
        'soo.gd', 'su.pr', 'mcaf.ee', 'snip.ly', 'po.st',
        'rb.gy', 'shorturl.at', 'tny.im', 'hyperurl.co',
    ]

    # Suspicious X-Mailer / User-Agent values
    SUSPICIOUS_MAILERS = [
        (r'php/?mail', 'PHP mail() function - common in phishing scripts'),
        (r'swiftmailer', 'SwiftMailer PHP library - often used in mass phishing'),
        (r'phpmailer', 'PHPMailer library - frequently abused by phishers'),
        (r'python-requests', 'Python requests library - automated sending'),
        (r'python\s*smtp', 'Python SMTP - scripted email sender'),
        (r'powershell', 'PowerShell - scripted email sender'),
        (r'curl/', 'cURL - automated HTTP client sending email'),
        (r'perl\s*mail', 'Perl mail script - automated sender'),
        (r'mass.?mail', 'Mass mailing software'),
        (r'bulk.?mail', 'Bulk mailing software'),
        (r'mailking', 'MailKing mass mailer'),
        (r'atomic.?mail', 'Atomic Mail Sender - mass mailer'),
        (r'gammadyne', 'Gammadyne Mailer - mass mailer'),
        (r'sendy', 'Sendy - self-hosted email marketing (check legitimacy)'),
    ]

    # Free email providers
    FREE_EMAIL_PROVIDERS = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
        'mail.com', 'aol.com', 'protonmail.com', 'proton.me',
        'zoho.com', 'yandex.com', 'gmx.com', 'icloud.com',
        'live.com', 'msn.com', 'inbox.com', 'mail.ru',
        'tutanota.com', 'fastmail.com', 'hushmail.com',
    ]

    # Urgency keywords for callback phishing detection
    URGENCY_KEYWORDS = [
        'urgent', 'immediate', 'action required', 'expire', 'suspend',
        'unauthorized', 'charge', 'transaction', 'cancel', 'refund',
        'subscription', 'renewal', 'billing', 'invoice', 'payment',
        'confirm', 'verify', 'dispute', 'fraudulent',
    ]

    # Phone number regex patterns
    PHONE_PATTERNS = [
        # US/Canada: (123) 456-7890, 123-456-7890, +1-123-456-7890
        r'(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
        # International: +44 20 7123 4567
        r'\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}',
        # Toll-free: 1-800-XXX-XXXX
        r'1[-.\s]?8(?:00|44|55|66|77|88)[-.\s]?\d{3}[-.\s]?\d{4}',
    ]

    # Dangerous JavaScript function patterns to detect in email HTML
    # NOTE: These are string patterns for DETECTION only, not for execution
    DANGEROUS_JS_PATTERNS = [
        r'(?:eval|document\.write|document\.cookie|window\.location|\.innerHTML)\s*\(',
    ]

    # ================================================================== #
    # 1. Tracking Pixel Detection
    # ================================================================== #
    @staticmethod
    def detect_tracking_pixels(html_body: str) -> Dict:
        """
        Detect tracking pixels in HTML email body.

        Identifies:
        - 1x1 pixel images or zero-height/width images
        - Images with tracking parameters in URL
        - Images hosted on known tracking domains

        Returns:
            Dict with findings, severity, score_impact, explanation
        """
        findings = []

        if not html_body:
            return {
                'check': 'tracking_pixel_detection',
                'findings': [],
                'severity': 'NONE',
                'score_impact': 0,
                'explanation': 'No HTML body to analyze',
            }

        # Find all <img> tags
        img_pattern = r'<img\b[^>]*>'
        img_tags = re.findall(img_pattern, html_body, re.IGNORECASE)

        for img_tag in img_tags:
            pixel_indicators = []

            # Check for 1x1 or zero-dimension images
            width_match = re.search(r'width\s*[=:]\s*["\']?\s*(0|1)\s*(px)?\s*["\']?', img_tag, re.IGNORECASE)
            height_match = re.search(r'height\s*[=:]\s*["\']?\s*(0|1)\s*(px)?\s*["\']?', img_tag, re.IGNORECASE)
            if width_match or height_match:
                pixel_indicators.append('Tiny/zero-dimension image')

            # Check for hidden style
            if re.search(r'display\s*:\s*none|visibility\s*:\s*hidden', img_tag, re.IGNORECASE):
                pixel_indicators.append('Hidden image via CSS')

            # Extract src URL
            src_match = re.search(r'src\s*=\s*["\']([^"\']+)["\']', img_tag, re.IGNORECASE)
            if src_match:
                src_url = src_match.group(1)

                # Check for tracking parameters in URL
                src_lower = src_url.lower()
                for param in EmailThreatIndicators.TRACKING_PARAMS:
                    if param in src_lower:
                        pixel_indicators.append(f'Tracking parameter: {param}')
                        break

                # Check for known tracking domains
                try:
                    parsed = urlparse(src_url)
                    domain = parsed.netloc.lower()
                    for tracking_domain in EmailThreatIndicators.TRACKING_DOMAINS:
                        if tracking_domain in domain:
                            pixel_indicators.append(f'Known tracking domain: {tracking_domain}')
                            break
                except Exception:
                    pass

                if pixel_indicators:
                    findings.append({
                        'url': src_url[:200],
                        'indicators': pixel_indicators,
                        'raw_tag': img_tag[:300],
                    })

        severity = 'NONE'
        if findings:
            severity = 'LOW'  # Tracking pixels are common, not inherently malicious

        return {
            'check': 'tracking_pixel_detection',
            'findings': findings,
            'count': len(findings),
            'severity': severity,
            'score_impact': min(5, len(findings)),  # Low impact, informational
            'explanation': (
                f'Found {len(findings)} potential tracking pixel(s). '
                'Tracking pixels are used to monitor if/when an email is opened.'
            ) if findings else 'No tracking pixels detected',
        }

    # ================================================================== #
    # 2. HTML Form Detection (Credential Harvesting)
    # ================================================================== #
    @staticmethod
    def detect_html_forms(html_body: str, from_domain: str = '') -> Dict:
        """
        Detect HTML forms in email body (credential harvesting indicator).

        Identifies:
        - <form> tags with action URLs
        - <input type="password"> fields
        - <input type="text"> fields
        - Forms posting to external domains

        Returns:
            Dict with findings, severity, score_impact, explanation
        """
        findings = []

        if not html_body:
            return {
                'check': 'html_form_detection',
                'findings': [],
                'severity': 'NONE',
                'score_impact': 0,
                'explanation': 'No HTML body to analyze',
            }

        # Find all <form> tags
        form_pattern = r'<form\b([^>]*)>(.*?)</form>'
        form_matches = re.findall(form_pattern, html_body, re.IGNORECASE | re.DOTALL)

        for form_attrs, form_content in form_matches:
            form_info = {
                'action_url': None,
                'method': 'GET',
                'input_fields': [],
                'has_password_field': False,
                'is_external': False,
            }

            # Extract action URL
            action_match = re.search(r'action\s*=\s*["\']([^"\']+)["\']', form_attrs, re.IGNORECASE)
            if action_match:
                form_info['action_url'] = action_match.group(1)

                # Check if action points to external domain
                try:
                    action_domain = urlparse(action_match.group(1)).netloc.lower()
                    if action_domain and from_domain and action_domain != from_domain.lower():
                        form_info['is_external'] = True
                except Exception:
                    pass

            # Extract method
            method_match = re.search(r'method\s*=\s*["\']([^"\']+)["\']', form_attrs, re.IGNORECASE)
            if method_match:
                form_info['method'] = method_match.group(1).upper()

            # Find input fields
            input_pattern = r'<input\b([^>]*)>'
            input_matches = re.findall(input_pattern, form_content, re.IGNORECASE)

            for input_attrs in input_matches:
                field = {}
                type_match = re.search(r'type\s*=\s*["\']([^"\']+)["\']', input_attrs, re.IGNORECASE)
                name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', input_attrs, re.IGNORECASE)

                if type_match:
                    field['type'] = type_match.group(1).lower()
                if name_match:
                    field['name'] = name_match.group(1)

                if field.get('type') == 'password':
                    form_info['has_password_field'] = True

                if field:
                    form_info['input_fields'].append(field)

            findings.append(form_info)

        # Also detect standalone password inputs outside forms
        standalone_password = re.findall(
            r'<input\b[^>]*type\s*=\s*["\']password["\'][^>]*>',
            html_body, re.IGNORECASE,
        )
        if standalone_password and not findings:
            findings.append({
                'action_url': None,
                'method': 'unknown',
                'input_fields': [{'type': 'password', 'name': 'standalone'}],
                'has_password_field': True,
                'is_external': False,
            })

        severity = 'NONE'
        score = 0
        if findings:
            has_password = any(f.get('has_password_field') for f in findings)
            has_external = any(f.get('is_external') for f in findings)

            if has_password and has_external:
                severity = 'CRITICAL'
                score = 30
            elif has_password:
                severity = 'HIGH'
                score = 25
            elif has_external:
                severity = 'HIGH'
                score = 20
            else:
                severity = 'MEDIUM'
                score = 15

        return {
            'check': 'html_form_detection',
            'findings': findings,
            'count': len(findings),
            'severity': severity,
            'score_impact': score,
            'explanation': (
                f'Found {len(findings)} HTML form(s) in email body. '
                'HTML forms in emails are a strong credential harvesting indicator.'
            ) if findings else 'No HTML forms detected in email body',
        }

    # ================================================================== #
    # 3. URL Shortener Detection
    # ================================================================== #
    @staticmethod
    def detect_url_shorteners(urls: List[str]) -> Dict:
        """
        Detect known URL shorteners in email URLs.

        Shortened URLs obscure the true destination and require
        expansion/investigation before clicking.

        Returns:
            Dict with findings, severity, score_impact, explanation
        """
        findings = []

        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower().lstrip('www.')
            except Exception:
                domain = url.lower()

            for shortener in EmailThreatIndicators.URL_SHORTENERS:
                if shortener in domain:
                    findings.append({
                        'url': url,
                        'shortener_domain': shortener,
                        'requires_expansion': True,
                    })
                    break  # One match per URL is enough

        severity = 'NONE'
        score = 0
        if findings:
            severity = 'MEDIUM'
            score = min(30, len(findings) * 10)  # +10 per shortened URL

        return {
            'check': 'url_shortener_detection',
            'findings': findings,
            'count': len(findings),
            'severity': severity,
            'score_impact': score,
            'explanation': (
                f'Found {len(findings)} shortened URL(s). '
                'Shortened URLs hide the true destination and should be expanded before investigation.'
            ) if findings else 'No URL shorteners detected',
        }

    # ================================================================== #
    # 4. Data URI Detection
    # ================================================================== #
    @staticmethod
    def detect_data_uris(html_body: str) -> Dict:
        """
        Detect data: URIs in href or src attributes.

        data: URIs can embed entire phishing pages inline
        (e.g., data:text/html;base64,...) without any external URL.
        This is a HIGH severity indicator.

        Returns:
            Dict with findings, severity, score_impact, explanation
        """
        findings = []

        if not html_body:
            return {
                'check': 'data_uri_detection',
                'findings': [],
                'severity': 'NONE',
                'score_impact': 0,
                'explanation': 'No HTML body to analyze',
            }

        # Match data: URIs in href and src attributes
        data_uri_pattern = r'(?:href|src|action)\s*=\s*["\']?(data:[^"\'>\s]+)["\']?'
        matches = re.findall(data_uri_pattern, html_body, re.IGNORECASE)

        for data_uri in matches:
            uri_info = {
                'uri_preview': data_uri[:100] + ('...' if len(data_uri) > 100 else ''),
                'uri_length': len(data_uri),
                'is_base64': ';base64,' in data_uri.lower(),
                'mime_type': None,
            }

            # Extract MIME type
            mime_match = re.match(r'data:([^;,]+)', data_uri, re.IGNORECASE)
            if mime_match:
                uri_info['mime_type'] = mime_match.group(1)

            # text/html data URIs are especially dangerous
            if uri_info['mime_type'] and 'html' in uri_info['mime_type'].lower():
                uri_info['is_html_payload'] = True
            else:
                uri_info['is_html_payload'] = False

            findings.append(uri_info)

        severity = 'NONE'
        score = 0
        if findings:
            has_html_payload = any(f.get('is_html_payload') for f in findings)
            has_base64 = any(f.get('is_base64') for f in findings)

            if has_html_payload:
                severity = 'CRITICAL'
                score = 30
            elif has_base64:
                severity = 'HIGH'
                score = 25
            else:
                severity = 'MEDIUM'
                score = 15

        return {
            'check': 'data_uri_detection',
            'findings': findings,
            'count': len(findings),
            'severity': severity,
            'score_impact': score,
            'explanation': (
                f'Found {len(findings)} data: URI(s) in email HTML. '
                'Data URIs can embed entire phishing pages inline without external URLs.'
            ) if findings else 'No data: URIs detected',
        }

    # ================================================================== #
    # 5. IP-based URL Detection
    # ================================================================== #
    @staticmethod
    def detect_ip_urls(urls: List[str]) -> Dict:
        """
        Detect URLs using raw IP addresses instead of domain names.

        Legitimate services use domain names; raw IPs are highly
        suspicious in email context.

        Returns:
            Dict with findings, severity, score_impact, explanation
        """
        findings = []

        # Match both IPv4 in URL and IPv4 with port
        ip_url_pattern = re.compile(
            r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?(/|$|\?)',
            re.IGNORECASE,
        )

        for url in urls:
            match = ip_url_pattern.search(url)
            if match:
                ip_addr = match.group(1)
                port = match.group(2) or ''

                # Validate IP octets
                octets = ip_addr.split('.')
                try:
                    if all(0 <= int(o) <= 255 for o in octets):
                        is_private = (
                            ip_addr.startswith('10.')
                            or ip_addr.startswith('192.168.')
                            or ip_addr.startswith('172.16.')
                            or ip_addr.startswith('172.17.')
                            or ip_addr.startswith('172.18.')
                            or ip_addr.startswith('172.19.')
                            or ip_addr.startswith('172.2')
                            or ip_addr.startswith('172.30.')
                            or ip_addr.startswith('172.31.')
                            or ip_addr.startswith('127.')
                        )
                        findings.append({
                            'url': url,
                            'ip_address': ip_addr,
                            'port': port.lstrip(':') if port else None,
                            'is_private_ip': is_private,
                        })
                except ValueError:
                    pass

        severity = 'NONE'
        score = 0
        if findings:
            severity = 'HIGH'
            score = min(45, len(findings) * 15)  # +15 per IP-based URL

        return {
            'check': 'ip_url_detection',
            'findings': findings,
            'count': len(findings),
            'severity': severity,
            'score_impact': score,
            'explanation': (
                f'Found {len(findings)} URL(s) using raw IP addresses. '
                'Legitimate services use domain names; IP-based URLs are highly suspicious.'
            ) if findings else 'No IP-based URLs detected',
        }

    # ================================================================== #
    # 6. Double Extension Detection (Attachments)
    # ================================================================== #
    @staticmethod
    def detect_double_extensions(attachments: List[Dict]) -> Dict:
        """
        Detect attachments with double extensions (e.g., invoice.pdf.exe).

        The real extension is the last one; earlier extensions are used
        to trick users into opening malicious files.

        Returns:
            Dict with findings, severity, score_impact, explanation
        """
        findings = []

        # Dangerous final extensions that indicate malicious intent
        dangerous_extensions = {
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe',
            '.js', '.jse', '.wsf', '.wsh', '.msi', '.msp', '.hta', '.cpl',
            '.inf', '.reg', '.ps1', '.lnk', '.jar', '.py', '.rb',
        }

        # Common document extensions used as decoy (first extension)
        decoy_extensions = {
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.txt', '.csv', '.jpg', '.jpeg', '.png', '.gif', '.bmp',
            '.mp3', '.mp4', '.avi', '.mov', '.zip', '.rar',
        }

        for attachment in attachments:
            filename = attachment.get('filename', '') if isinstance(attachment, dict) else str(attachment)
            if not filename:
                continue

            # Split on dots, ignoring leading dot
            parts = filename.rsplit('.', 2)  # Get up to last 2 extensions
            if len(parts) < 3:
                continue  # Need at least name.ext1.ext2

            # The real extension
            real_ext = '.' + parts[-1].lower()
            # The decoy extension
            decoy_ext = '.' + parts[-2].lower()

            is_suspicious = False
            risk_detail = ''

            if real_ext in dangerous_extensions:
                is_suspicious = True
                if decoy_ext in decoy_extensions:
                    risk_detail = f'Decoy "{decoy_ext}" hides dangerous "{real_ext}"'
                else:
                    risk_detail = f'Multiple extensions with dangerous final extension "{real_ext}"'
            elif decoy_ext in decoy_extensions and real_ext != decoy_ext:
                # Even non-dangerous final ext is suspicious with document decoy
                is_suspicious = True
                risk_detail = f'Document extension "{decoy_ext}" used as decoy before "{real_ext}"'

            if is_suspicious:
                findings.append({
                    'filename': filename,
                    'apparent_extension': decoy_ext,
                    'real_extension': real_ext,
                    'risk_detail': risk_detail,
                })

        severity = 'NONE'
        score = 0
        if findings:
            has_dangerous = any(
                f['real_extension'] in dangerous_extensions for f in findings
            )
            if has_dangerous:
                severity = 'CRITICAL'
                score = 30
            else:
                severity = 'HIGH'
                score = 20

        return {
            'check': 'double_extension_detection',
            'findings': findings,
            'count': len(findings),
            'severity': severity,
            'score_impact': score,
            'explanation': (
                f'Found {len(findings)} attachment(s) with double extensions. '
                'Double extensions trick users into thinking a file is a safe document '
                'when it is actually executable.'
            ) if findings else 'No double-extension attachments detected',
        }

    # ================================================================== #
    # 7. X-Mailer / User-Agent Analysis
    # ================================================================== #
    @staticmethod
    def analyze_xmailer(msg) -> Dict:
        """
        Extract and analyze X-Mailer and User-Agent headers.

        Flags:
        - Known suspicious mailers (PHPMailer, custom scripts)
        - Mismatch between claimed platform and sending infrastructure
        - Absence of mailer info (common in scripted senders)

        Args:
            msg: email.message.Message object

        Returns:
            Dict with findings, severity, score_impact, explanation
        """
        findings = []

        x_mailer = msg.get('X-Mailer', '') if hasattr(msg, 'get') else ''
        user_agent = msg.get('User-Agent', '') if hasattr(msg, 'get') else ''
        mailer_value = x_mailer or user_agent

        if not mailer_value:
            # No mailer header is mildly suspicious for external emails
            return {
                'check': 'xmailer_analysis',
                'x_mailer': None,
                'user_agent': None,
                'findings': [],
                'severity': 'LOW',
                'score_impact': 0,
                'explanation': 'No X-Mailer or User-Agent header present (common in scripted senders)',
            }

        mailer_lower = mailer_value.lower()

        # Check against known suspicious mailers
        for pattern, description in EmailThreatIndicators.SUSPICIOUS_MAILERS:
            if re.search(pattern, mailer_lower, re.IGNORECASE):
                findings.append({
                    'matched_pattern': pattern,
                    'description': description,
                    'mailer_value': mailer_value[:200],
                })

        # Check for platform mismatch hints
        # E.g., X-Mailer claims Outlook but X-PHP-Originating-Script is present
        x_php = msg.get('X-PHP-Originating-Script', '') if hasattr(msg, 'get') else ''
        if x_php:
            findings.append({
                'matched_pattern': 'X-PHP-Originating-Script present',
                'description': 'Email was sent via PHP script on a web server',
                'mailer_value': x_php[:200],
            })
            # If X-Mailer claims a desktop client, that is a mismatch
            desktop_clients = ['outlook', 'thunderbird', 'apple mail', 'lotus']
            if any(client in mailer_lower for client in desktop_clients):
                findings.append({
                    'matched_pattern': 'platform_mismatch',
                    'description': (
                        f'X-Mailer claims "{mailer_value[:60]}" but '
                        f'X-PHP-Originating-Script indicates PHP web sender'
                    ),
                    'mailer_value': mailer_value[:200],
                })

        severity = 'NONE'
        score = 0
        if findings:
            has_mismatch = any(f.get('matched_pattern') == 'platform_mismatch' for f in findings)
            if has_mismatch:
                severity = 'HIGH'
                score = 20
            else:
                severity = 'MEDIUM'
                score = 10

        return {
            'check': 'xmailer_analysis',
            'x_mailer': x_mailer or None,
            'user_agent': user_agent or None,
            'findings': findings,
            'count': len(findings),
            'severity': severity,
            'score_impact': score,
            'explanation': (
                f'X-Mailer/User-Agent analysis found {len(findings)} suspicious indicator(s). '
                f'Mailer: {mailer_value[:80]}'
            ) if findings else f'X-Mailer/User-Agent appears normal: {mailer_value[:80]}',
        }

    # ================================================================== #
    # 8. Free Email Provider for Business Impersonation
    # ================================================================== #
    @staticmethod
    def detect_free_provider_impersonation(
        from_address: str,
        subject: str,
        body_text: str,
        brand_names: List[str] = None,
    ) -> Dict:
        """
        Detect emails claiming to be from a company but using a free email provider.

        If email mentions a brand/company name in subject or body but the
        sender uses gmail.com/yahoo.com/etc., this is a strong phishing indicator.

        Returns:
            Dict with findings, severity, score_impact, explanation
        """
        findings = []

        # Parse sender email address
        from_email = ''
        email_match = re.search(r'[\w.+-]+@[\w.-]+', from_address)
        if email_match:
            from_email = email_match.group(0)

        from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''

        if not from_domain or from_domain not in EmailThreatIndicators.FREE_EMAIL_PROVIDERS:
            return {
                'check': 'free_provider_impersonation',
                'findings': [],
                'severity': 'NONE',
                'score_impact': 0,
                'explanation': 'Sender does not use a free email provider',
            }

        # Default brand names to check
        if brand_names is None:
            brand_names = [
                'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
                'meta', 'netflix', 'dropbox', 'adobe', 'fedex', 'ups', 'dhl',
                'usps', 'chase', 'wells fargo', 'bank of america', 'citibank',
                'american express', 'amex', 'docusign', 'linkedin', 'twitter',
                'instagram', 'whatsapp', 'coinbase', 'binance', 'square',
                'stripe', 'shopify', 'ebay', 'walmart', 'target',
                'irs', 'social security', 'department of', 'government',
            ]

        combined_text = (subject + ' ' + body_text).lower()

        for brand in brand_names:
            if brand in combined_text:
                findings.append({
                    'brand_mentioned': brand,
                    'sender_domain': from_domain,
                    'sender_email': from_email,
                })

        severity = 'NONE'
        score = 0
        if findings:
            severity = 'HIGH'
            score = 20

        return {
            'check': 'free_provider_impersonation',
            'findings': findings,
            'count': len(findings),
            'sender_domain': from_domain,
            'severity': severity,
            'score_impact': score,
            'explanation': (
                f'Sender uses free provider ({from_domain}) but mentions '
                f'{len(findings)} brand(s): {", ".join(f["brand_mentioned"] for f in findings[:5])}. '
                'Legitimate companies use their own domain.'
            ) if findings else 'No brand impersonation from free email provider detected',
        }

    # ================================================================== #
    # 9. JavaScript in Email Body Detection
    # ================================================================== #
    @staticmethod
    def detect_javascript_in_body(html_body: str) -> Dict:
        """
        Detect JavaScript in email HTML body.

        JavaScript in emails should NEVER be present in legitimate email.
        Detects:
        - <script> tags
        - Event handlers (onload, onclick, onerror, onmouseover, etc.)
        - javascript: protocol in href/src

        Returns:
            Dict with findings, severity, score_impact, explanation
        """
        findings = []

        if not html_body:
            return {
                'check': 'javascript_detection',
                'findings': [],
                'severity': 'NONE',
                'score_impact': 0,
                'explanation': 'No HTML body to analyze',
            }

        # 1. Detect <script> tags
        script_pattern = r'<script\b[^>]*>(.*?)</script>'
        script_matches = re.findall(script_pattern, html_body, re.IGNORECASE | re.DOTALL)
        for script_content in script_matches:
            findings.append({
                'type': 'script_tag',
                'preview': script_content[:200].strip() if script_content.strip() else '<empty script>',
            })

        # Also catch self-closing or unclosed script tags
        if not script_matches:
            if re.search(r'<script\b', html_body, re.IGNORECASE):
                findings.append({
                    'type': 'script_tag',
                    'preview': '<unclosed or malformed script tag>',
                })

        # 2. Detect event handlers
        event_handler_pattern = (
            r'\bon(load|click|error|mouseover|mouseout|mousemove|mouseenter|'
            r'focus|blur|submit|change|keyup|keydown|keypress|dblclick|'
            r'contextmenu|abort|beforeunload|unload)'
            r'\s*=\s*["\']([^"\']{0,300})["\']'
        )
        event_matches = re.findall(event_handler_pattern, html_body, re.IGNORECASE)
        for event_name, handler_code in event_matches:
            findings.append({
                'type': 'event_handler',
                'event': f'on{event_name}',
                'preview': handler_code[:200],
            })

        # 3. Detect javascript: protocol in attributes
        js_proto_pattern = r'(?:href|src|action)\s*=\s*["\']?\s*javascript\s*:'
        js_proto_matches = re.findall(js_proto_pattern, html_body, re.IGNORECASE)
        for _ in js_proto_matches:
            findings.append({
                'type': 'javascript_protocol',
                'preview': 'javascript: protocol in attribute',
            })

        # 4. Detect dangerous JS function calls in HTML content
        for dangerous_pattern in EmailThreatIndicators.DANGEROUS_JS_PATTERNS:
            dangerous_matches = re.findall(dangerous_pattern, html_body, re.IGNORECASE)
            for match in dangerous_matches:
                findings.append({
                    'type': 'dangerous_js_function',
                    'preview': match[:200],
                })

        severity = 'NONE'
        score = 0
        if findings:
            has_script_tag = any(f['type'] == 'script_tag' for f in findings)
            has_dangerous_fn = any(f['type'] == 'dangerous_js_function' for f in findings)

            if has_script_tag or has_dangerous_fn:
                severity = 'CRITICAL'
                score = 35
            else:
                severity = 'HIGH'
                score = 25

        return {
            'check': 'javascript_detection',
            'findings': findings,
            'count': len(findings),
            'severity': severity,
            'score_impact': score,
            'explanation': (
                f'Found {len(findings)} JavaScript indicator(s) in email body. '
                'JavaScript in email is a CRITICAL threat indicator - '
                'legitimate emails never contain executable scripts.'
            ) if findings else 'No JavaScript detected in email body',
        }

    # ================================================================== #
    # 10. Callback Phishing Detection (BazarCall-style)
    # ================================================================== #
    @staticmethod
    def detect_callback_phishing(
        body_text: str,
        subject: str,
        urls: List[str],
        attachments: List[Dict],
    ) -> Dict:
        """
        Detect callback phishing (BazarCall/BazaCall-style attacks).

        Pattern:
        - Email contains NO clickable links and NO attachments
        - Email contains phone number(s)
        - Email uses urgency language (cancel subscription, unauthorized charge)

        Returns:
            Dict with findings, severity, score_impact, explanation
        """
        findings = []

        combined_text = (subject + ' ' + body_text)
        combined_lower = combined_text.lower()

        # Extract phone numbers
        phone_numbers = []
        for pattern in EmailThreatIndicators.PHONE_PATTERNS:
            matches = re.findall(pattern, combined_text)
            for match in matches:
                cleaned = re.sub(r'[^\d+]', '', match)
                # Filter out numbers too short (likely not real phone numbers)
                if len(cleaned) >= 7:
                    phone_numbers.append(match.strip())

        # Deduplicate
        phone_numbers = list(set(phone_numbers))

        if not phone_numbers:
            return {
                'check': 'callback_phishing_detection',
                'findings': [],
                'severity': 'NONE',
                'score_impact': 0,
                'explanation': 'No phone numbers found in email',
            }

        # Check for urgency keywords
        urgency_matches = []
        for keyword in EmailThreatIndicators.URGENCY_KEYWORDS:
            if keyword in combined_lower:
                urgency_matches.append(keyword)

        # Check for absence of links and attachments
        has_urls = bool(urls)
        has_attachments = bool(attachments)
        no_links_no_attachments = not has_urls and not has_attachments

        # Build finding
        callback_indicators = {
            'phone_numbers': phone_numbers,
            'urgency_keywords': urgency_matches,
            'has_urls': has_urls,
            'has_attachments': has_attachments,
            'no_links_no_attachments': no_links_no_attachments,
        }

        # Determine if this looks like callback phishing
        is_callback_phishing = False

        if no_links_no_attachments and phone_numbers and len(urgency_matches) >= 2:
            is_callback_phishing = True
            callback_indicators['assessment'] = (
                'STRONG callback phishing indicator: no links/attachments, '
                'phone number present, urgency language detected'
            )
        elif phone_numbers and len(urgency_matches) >= 3 and not has_attachments:
            is_callback_phishing = True
            callback_indicators['assessment'] = (
                'Probable callback phishing: phone number with strong urgency language'
            )
        elif phone_numbers and urgency_matches:
            callback_indicators['assessment'] = (
                'Possible callback phishing: phone number with some urgency language'
            )

        findings.append(callback_indicators)

        severity = 'NONE'
        score = 0
        if is_callback_phishing:
            severity = 'HIGH'
            score = 25
        elif phone_numbers and urgency_matches:
            severity = 'MEDIUM'
            score = 10

        return {
            'check': 'callback_phishing_detection',
            'findings': findings,
            'count': len(phone_numbers),
            'phone_numbers_found': phone_numbers,
            'urgency_keywords': urgency_matches,
            'is_callback_phishing': is_callback_phishing,
            'severity': severity,
            'score_impact': score,
            'explanation': (
                f'Callback phishing detected: {len(phone_numbers)} phone number(s) '
                f'with {len(urgency_matches)} urgency keyword(s). '
                'BazarCall-style attacks instruct victims to call a phone number.'
            ) if is_callback_phishing else (
                f'Found {len(phone_numbers)} phone number(s) with some urgency language. '
                'Monitor for callback phishing patterns.'
            ) if phone_numbers and urgency_matches else (
                f'Found {len(phone_numbers)} phone number(s) but no strong callback phishing indicators.'
            ),
        }

    # ================================================================== #
    # Aggregate: Run All Checks
    # ================================================================== #
    @staticmethod
    def run_all_checks(
        msg,
        html_body: str,
        body_text: str,
        subject: str,
        from_address: str,
        urls: List[str],
        attachments: List[Dict],
        from_domain: str = '',
    ) -> Dict:
        """
        Run all 10 enhanced threat indicator checks.

        Args:
            msg: email.message.Message object (for header access)
            html_body: HTML body of the email
            body_text: Plain text body of the email
            subject: Email subject
            from_address: Full From header value
            urls: List of extracted URLs
            attachments: List of attachment dicts (with 'filename' key)
            from_domain: Sender domain (optional, extracted from from_address if empty)

        Returns:
            Dict with all check results, total score impact, and severity summary
        """
        if not from_domain and from_address:
            email_match = re.search(r'[\w.+-]+@([\w.-]+)', from_address)
            from_domain = email_match.group(1) if email_match else ''

        results = {}

        # 1. Tracking Pixels
        results['tracking_pixels'] = EmailThreatIndicators.detect_tracking_pixels(html_body)

        # 2. HTML Forms
        results['html_forms'] = EmailThreatIndicators.detect_html_forms(html_body, from_domain)

        # 3. URL Shorteners
        results['url_shorteners'] = EmailThreatIndicators.detect_url_shorteners(urls)

        # 4. Data URIs
        results['data_uris'] = EmailThreatIndicators.detect_data_uris(html_body)

        # 5. IP-based URLs
        results['ip_urls'] = EmailThreatIndicators.detect_ip_urls(urls)

        # 6. Double Extensions
        results['double_extensions'] = EmailThreatIndicators.detect_double_extensions(attachments)

        # 7. X-Mailer Analysis
        results['xmailer'] = EmailThreatIndicators.analyze_xmailer(msg)

        # 8. Free Provider Impersonation
        results['free_provider_impersonation'] = EmailThreatIndicators.detect_free_provider_impersonation(
            from_address, subject, body_text,
        )

        # 9. JavaScript Detection
        results['javascript'] = EmailThreatIndicators.detect_javascript_in_body(html_body)

        # 10. Callback Phishing
        results['callback_phishing'] = EmailThreatIndicators.detect_callback_phishing(
            body_text, subject, urls, attachments,
        )

        # Aggregate
        total_score_impact = sum(r.get('score_impact', 0) for r in results.values())
        severity_counts = {}
        for r in results.values():
            sev = r.get('severity', 'NONE')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Overall severity = highest found
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']
        overall_severity = 'NONE'
        for sev in severity_order:
            if severity_counts.get(sev, 0) > 0:
                overall_severity = sev
                break

        # Collect all non-NONE findings for summary
        active_checks = [
            name for name, r in results.items()
            if r.get('severity', 'NONE') != 'NONE'
        ]

        return {
            'checks': results,
            'total_score_impact': total_score_impact,
            'overall_severity': overall_severity,
            'severity_counts': severity_counts,
            'active_checks': active_checks,
            'checks_run': len(results),
        }
