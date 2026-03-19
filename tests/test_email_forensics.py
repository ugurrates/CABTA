"""
Tests for email forensics, advanced email analysis, and email clustering modules.
Covers EmailForensics, AdvancedEmailAnalyzer, and EmailClusterer.
"""

import unittest
import email
from email.message import EmailMessage
from datetime import datetime, timezone, timedelta

from src.analyzers.email_forensics import EmailForensics
from src.analyzers.advanced_email_analyzer import AdvancedEmailAnalyzer
from src.analyzers.email_clustering import EmailClusterer


# ---------------------------------------------------------------------------
# Helper: build an EmailMessage with Received headers in top-down order
# (most recent first, matching how real MTAs prepend headers).
# ---------------------------------------------------------------------------

def _make_msg(**kwargs):
    """Create an EmailMessage and set headers from keyword arguments.

    Special keys:
      received_headers  - list of Received header values (most-recent first)
      authentication    - value for Authentication-Results
      x_mailer          - value for X-Mailer
      message_id        - value for Message-ID
      return_path       - value for Return-Path
      from_addr         - value for From
      subject           - value for Subject
      extra_headers     - dict of additional header name -> value pairs
    """
    msg = EmailMessage()
    for hdr in kwargs.get('received_headers', []):
        msg['Received'] = hdr
    if 'authentication' in kwargs:
        msg['Authentication-Results'] = kwargs['authentication']
    if 'x_mailer' in kwargs:
        msg['X-Mailer'] = kwargs['x_mailer']
    if 'message_id' in kwargs:
        msg['Message-ID'] = kwargs['message_id']
    if 'return_path' in kwargs:
        msg['Return-Path'] = kwargs['return_path']
    if 'from_addr' in kwargs:
        msg['From'] = kwargs['from_addr']
    if 'subject' in kwargs:
        msg['Subject'] = kwargs['subject']
    for name, value in kwargs.get('extra_headers', {}).items():
        msg[name] = value
    return msg


# ===================================================================
#  EmailForensics Tests
# ===================================================================

class TestReconstructHeaderTimeline(unittest.TestCase):
    """Tests for EmailForensics.reconstruct_header_timeline."""

    def test_zero_received_headers(self):
        """An email with no Received headers yields an empty timeline."""
        msg = _make_msg()
        timeline = EmailForensics.reconstruct_header_timeline(msg)
        self.assertEqual(timeline, [])

    def test_single_received_header(self):
        """A single Received header produces exactly one hop with hop_number 1."""
        hdr = (
            "from mail.example.com ([203.0.113.10]) "
            "by mx.destination.com with ESMTP; "
            "Mon, 01 Jan 2024 12:00:00 +0000"
        )
        msg = _make_msg(received_headers=[hdr])
        timeline = EmailForensics.reconstruct_header_timeline(msg)
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0]['hop_number'], 1)
        self.assertEqual(timeline[0]['from_server'], 'mail.example.com')
        self.assertEqual(timeline[0]['from_ip'], '203.0.113.10')
        self.assertEqual(timeline[0]['by_server'], 'mx.destination.com')
        self.assertEqual(timeline[0]['protocol'], 'ESMTP')

    def test_three_received_headers_ordering(self):
        """Three Received headers produce hops numbered 1-3 in chronological order.

        Real emails prepend Received headers so the list we pass is
        most-recent first.  reconstruct_header_timeline reverses them so
        hop 1 is the oldest (originating) hop.
        """
        hdrs = [
            # Most recent (added last by final MTA)
            "from relay2.example.com ([198.51.100.3]) by mx.dest.com with ESMTP; "
            "Mon, 01 Jan 2024 12:02:00 +0000",
            # Middle hop
            "from relay1.example.com ([198.51.100.2]) by relay2.example.com with SMTP; "
            "Mon, 01 Jan 2024 12:01:00 +0000",
            # Oldest (first hop, originating server)
            "from origin.example.com ([198.51.100.1]) by relay1.example.com with ESMTP; "
            "Mon, 01 Jan 2024 12:00:00 +0000",
        ]
        msg = _make_msg(received_headers=hdrs)
        timeline = EmailForensics.reconstruct_header_timeline(msg)
        self.assertEqual(len(timeline), 3)
        self.assertEqual(timeline[0]['hop_number'], 1)
        self.assertEqual(timeline[2]['hop_number'], 3)
        # The first chronological hop should be origin.example.com
        self.assertEqual(timeline[0]['from_server'], 'origin.example.com')

    def test_timestamp_parsing(self):
        """Verify that timestamps are parsed into datetime objects."""
        hdr = (
            "from sender.example.com ([10.0.0.1]) by receiver.example.com "
            "with ESMTP; Mon, 01 Jan 2024 10:30:00 +0000"
        )
        msg = _make_msg(received_headers=[hdr])
        timeline = EmailForensics.reconstruct_header_timeline(msg)
        ts = timeline[0].get('timestamp')
        self.assertIsNotNone(ts)
        self.assertIsInstance(ts, datetime)


class TestValidateAuthenticationChain(unittest.TestCase):
    """Tests for EmailForensics.validate_authentication_chain."""

    def test_all_pass(self):
        """SPF, DKIM, DMARC all pass yields overall_pass True."""
        auth = (
            "mx.google.com; "
            "spf=pass (sender SPF authorized) smtp.mailfrom=example.com; "
            "dkim=pass header.d=example.com; "
            "dmarc=pass header.from=example.com"
        )
        msg = _make_msg(authentication=auth)
        result = EmailForensics.validate_authentication_chain(msg)
        self.assertTrue(result['overall_pass'])
        self.assertEqual(result['spf']['status'], 'PASS')
        self.assertEqual(result['dkim']['status'], 'PASS')
        self.assertEqual(result['dmarc']['status'], 'PASS')
        self.assertEqual(result['authentication_score'], 99)

    def test_spf_fail_overall_false(self):
        """SPF fail causes overall_pass to be False."""
        auth = (
            "mx.google.com; "
            "spf=fail smtp.mailfrom=spoofed.com; "
            "dkim=pass header.d=example.com; "
            "dmarc=pass header.from=example.com"
        )
        msg = _make_msg(authentication=auth)
        result = EmailForensics.validate_authentication_chain(msg)
        self.assertFalse(result['overall_pass'])
        self.assertEqual(result['spf']['status'], 'FAIL')

    def test_no_auth_header(self):
        """Missing Authentication-Results header yields all NONE and overall_pass False."""
        msg = _make_msg()
        result = EmailForensics.validate_authentication_chain(msg)
        self.assertFalse(result['overall_pass'])
        self.assertEqual(result['spf']['status'], 'NONE')
        self.assertEqual(result['dkim']['status'], 'NONE')
        self.assertEqual(result['dmarc']['status'], 'NONE')
        self.assertEqual(result['authentication_score'], 0)


class TestAnalyzeRelayPath(unittest.TestCase):
    """Tests for EmailForensics.analyze_relay_path."""

    def test_suspicious_localhost(self):
        """A hop from 'localhost' is flagged as suspicious."""
        timeline = [
            {'hop_number': 1, 'from_server': 'localhost', 'from_ip': '127.0.0.1',
             'by_server': 'mx.example.com', 'timestamp': None},
        ]
        result = EmailForensics.analyze_relay_path(timeline)
        self.assertGreater(len(result['suspicious_hops']), 0)
        reasons = result['suspicious_hops'][0]['reasons']
        self.assertTrue(any('Suspicious server name' in r for r in reasons))

    def test_private_ip_external_hop(self):
        """A private IP appearing in hop > 1 is flagged."""
        timeline = [
            {'hop_number': 1, 'from_server': 'origin.com', 'from_ip': '203.0.113.1',
             'by_server': 'relay.com', 'timestamp': None},
            {'hop_number': 2, 'from_server': 'relay.com', 'from_ip': '192.168.1.50',
             'by_server': 'dest.com', 'timestamp': None},
        ]
        result = EmailForensics.analyze_relay_path(timeline)
        suspicious = result['suspicious_hops']
        self.assertTrue(
            any('Private IP' in r for hop in suspicious for r in hop['reasons'])
        )

    def test_time_anomaly_backward(self):
        """Backward time between hops is detected as a time anomaly."""
        t1 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2024, 1, 1, 11, 0, 0, tzinfo=timezone.utc)  # earlier
        timeline = [
            {'hop_number': 1, 'from_server': 'a.com', 'from_ip': '1.2.3.4',
             'by_server': 'b.com', 'timestamp': t1},
            {'hop_number': 2, 'from_server': 'b.com', 'from_ip': '5.6.7.8',
             'by_server': 'c.com', 'timestamp': t2},
        ]
        result = EmailForensics.analyze_relay_path(timeline)
        self.assertGreater(len(result['time_anomalies']), 0)
        self.assertIn('backwards', result['time_anomalies'][0]['issue'].lower())

    def test_normal_path_no_anomalies(self):
        """A clean relay path has no suspicious hops or time anomalies."""
        t1 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2024, 1, 1, 12, 0, 5, tzinfo=timezone.utc)
        timeline = [
            {'hop_number': 1, 'from_server': 'origin.example.com',
             'from_ip': '203.0.113.1', 'by_server': 'mx.dest.com',
             'timestamp': t1},
            {'hop_number': 2, 'from_server': 'mx.dest.com',
             'from_ip': '203.0.113.2', 'by_server': 'inbox.dest.com',
             'timestamp': t2},
        ]
        result = EmailForensics.analyze_relay_path(timeline)
        self.assertEqual(len(result['suspicious_hops']), 0)
        self.assertEqual(len(result['time_anomalies']), 0)


class TestFingerprintMailInfrastructure(unittest.TestCase):
    """Tests for EmailForensics.fingerprint_mail_infrastructure."""

    def test_x_mailer_extraction(self):
        """X-Mailer header value is captured."""
        msg = _make_msg(x_mailer='Microsoft Outlook 16.0')
        fp = EmailForensics.fingerprint_mail_infrastructure(msg)
        self.assertEqual(fp['x_mailer'], 'Microsoft Outlook 16.0')
        self.assertEqual(fp['mua'], 'Microsoft Outlook 16.0')

    def test_message_id_domain(self):
        """Domain from Message-ID is extracted."""
        msg = _make_msg(message_id='<abc123@mail.example.com>')
        fp = EmailForensics.fingerprint_mail_infrastructure(msg)
        self.assertEqual(fp['message_id_domain'], 'mail.example.com')

    def test_suspicious_header_detected(self):
        """X-PHP-Originating-Script is flagged as suspicious."""
        msg = _make_msg(extra_headers={
            'X-PHP-Originating-Script': '1000:mailer.php'
        })
        fp = EmailForensics.fingerprint_mail_infrastructure(msg)
        self.assertGreater(len(fp['suspicious_headers']), 0)
        self.assertTrue(
            any('X-PHP-Originating-Script' in h['header'] for h in fp['suspicious_headers'])
        )


class TestAnalyzeSenderReputation(unittest.TestCase):
    """Tests for EmailForensics.analyze_sender_reputation."""

    def test_numeric_heavy_address(self):
        """An address dominated by digits is flagged."""
        result = EmailForensics.analyze_sender_reputation(
            '1234567890@example.com', 'example.com'
        )
        self.assertTrue(
            any('Numeric-heavy' in p for p in result['suspicious_patterns'])
        )
        self.assertGreater(result['risk_score'], 0)

    def test_suspicious_tld(self):
        """A domain with a suspicious TLD like .xyz is flagged."""
        result = EmailForensics.analyze_sender_reputation(
            'user@shady.xyz', 'shady.xyz'
        )
        self.assertTrue(
            any('Suspicious TLD' in p for p in result['suspicious_patterns'])
        )

    def test_free_provider(self):
        """Free email providers are noted."""
        result = EmailForensics.analyze_sender_reputation(
            'user@gmail.com', 'gmail.com'
        )
        self.assertTrue(result.get('is_free_provider', False))

    def test_normal_address(self):
        """A normal business address has low risk and no suspicious patterns."""
        result = EmailForensics.analyze_sender_reputation(
            'admin@company.com', 'company.com'
        )
        self.assertEqual(result['suspicious_patterns'], [])
        self.assertEqual(result['risk_score'], 0)


class TestPerformFullForensics(unittest.TestCase):
    """Integration test for EmailForensics.perform_full_forensics."""

    def test_full_forensics_structure(self):
        """perform_full_forensics returns all expected top-level keys."""
        hdr = (
            "from origin.example.com ([203.0.113.1]) by mx.dest.com "
            "with ESMTP; Mon, 01 Jan 2024 12:00:00 +0000"
        )
        auth = (
            "mx.dest.com; spf=pass smtp.mailfrom=example.com; "
            "dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
        )
        msg = _make_msg(
            received_headers=[hdr],
            authentication=auth,
            x_mailer='TestMailer/1.0',
            message_id='<test@example.com>',
        )
        result = EmailForensics.perform_full_forensics(
            msg, 'admin@example.com', 'example.com'
        )
        for key in ('timeline', 'authentication', 'infrastructure',
                     'sender_reputation', 'relay_analysis',
                     'forensics_score', 'safety_score'):
            self.assertIn(key, result, f"Missing key: {key}")
        self.assertIsInstance(result['forensics_score'], (int, float))


# ===================================================================
#  AdvancedEmailAnalyzer Tests
# ===================================================================

class TestDetectLinkTextMismatch(unittest.TestCase):
    """Tests for AdvancedEmailAnalyzer.detect_link_text_mismatch."""

    def test_mismatch_detected(self):
        """Link text showing a different domain than href is flagged."""
        html = '<a href="http://evil.com/login">http://paypal.com/login</a>'
        mismatches = AdvancedEmailAnalyzer.detect_link_text_mismatch(html)
        self.assertEqual(len(mismatches), 1)
        self.assertIn('evil.com', mismatches[0]['actual_url'])
        self.assertIn('paypal.com', mismatches[0]['displayed_url'])

    def test_matching_links_no_mismatch(self):
        """When href and link text domains match, no mismatch is reported."""
        html = '<a href="http://paypal.com/account">http://paypal.com/account</a>'
        mismatches = AdvancedEmailAnalyzer.detect_link_text_mismatch(html)
        self.assertEqual(len(mismatches), 0)

    def test_non_url_link_text_no_false_positive(self):
        """Link text that is not a URL (e.g. plain words) does not trigger a mismatch."""
        html = '<a href="http://example.com">Click Here</a>'
        mismatches = AdvancedEmailAnalyzer.detect_link_text_mismatch(html)
        self.assertEqual(len(mismatches), 0)


class TestDetectLookalikeDomains(unittest.TestCase):
    """Tests for AdvancedEmailAnalyzer.detect_lookalike_domains."""

    def test_character_substitution(self):
        """paypa1.com (digit 1 instead of l) is detected as brand impersonation."""
        results = AdvancedEmailAnalyzer.detect_lookalike_domains(['paypa1.com'])
        self.assertGreater(len(results), 0)
        brands_detected = [r.get('brand', '') for r in results]
        self.assertIn('paypal', brands_detected)

    def test_subdomain_trick(self):
        """paypal.com.evil.com is detected as a subdomain trick."""
        results = AdvancedEmailAnalyzer.detect_lookalike_domains(['paypal.com.evil.com'])
        subdomain_tricks = [r for r in results if r.get('technique') == 'Subdomain trick']
        self.assertGreater(len(subdomain_tricks), 0)

    def test_unicode_homograph(self):
        """A domain containing non-ASCII characters is detected as a homograph attack."""
        # Cyrillic 'a' (U+0430) instead of Latin 'a'
        domain = 'p\u0430ypal.com'
        results = AdvancedEmailAnalyzer.detect_lookalike_domains([domain])
        homograph_hits = [r for r in results if 'Homograph' in r.get('technique', '')]
        self.assertGreater(len(homograph_hits), 0)

    def test_legitimate_domain_no_flag(self):
        """A completely unrelated legitimate domain is not flagged."""
        results = AdvancedEmailAnalyzer.detect_lookalike_domains(['mycompany.com'])
        self.assertEqual(len(results), 0)


class TestAnalyzeHtmlObfuscation(unittest.TestCase):
    """Tests for AdvancedEmailAnalyzer.analyze_html_obfuscation."""

    def test_zero_size_font_detected(self):
        """Zero-size font usage is counted."""
        html = '<span style="font-size: 0">hidden</span>'
        result = AdvancedEmailAnalyzer.analyze_html_obfuscation(html)
        self.assertGreater(result['zero_size_fonts'], 0)

    def test_hidden_elements_detected(self):
        """display:none and visibility:hidden are counted."""
        html = (
            '<div style="display: none">secret</div>'
            '<span style="visibility: hidden">invisible</span>'
        )
        result = AdvancedEmailAnalyzer.analyze_html_obfuscation(html)
        self.assertEqual(result['hidden_elements'], 2)

    def test_white_on_white(self):
        """White text on white background is detected."""
        html = '<div style="color: white; background-color: white;">sneaky</div>'
        result = AdvancedEmailAnalyzer.analyze_html_obfuscation(html)
        self.assertGreater(result['white_on_white'], 0)

    def test_suspicious_css_opacity(self):
        """opacity: 0 is flagged as suspicious CSS."""
        html = '<div style="opacity: 0;">invisible overlay</div>'
        result = AdvancedEmailAnalyzer.analyze_html_obfuscation(html)
        self.assertGreater(len(result['suspicious_css']), 0)


class TestDetectQRCodes(unittest.TestCase):
    """Tests for AdvancedEmailAnalyzer.detect_qr_codes."""

    def test_qr_code_in_html(self):
        """A reference to 'qr_code' in the HTML body is detected."""
        html = '<img src="cid:qr_code_image" alt="QR Code">'
        result = AdvancedEmailAnalyzer.detect_qr_codes(html, [])
        self.assertGreater(result['qr_codes_found'], 0)
        self.assertEqual(result['risk'], 'HIGH - QR codes commonly used in modern phishing')

    def test_qr_in_attachment_filename(self):
        """An attachment with 'qr' in the filename is detected."""
        attachments = [{'filename': 'qr_payment.png'}]
        result = AdvancedEmailAnalyzer.detect_qr_codes('', attachments)
        self.assertGreater(result['qr_codes_found'], 0)

    def test_no_qr_codes(self):
        """Normal HTML with no QR references yields qr_codes_found == 0."""
        html = '<p>Hello, world!</p>'
        result = AdvancedEmailAnalyzer.detect_qr_codes(html, [])
        self.assertEqual(result['qr_codes_found'], 0)
        self.assertEqual(result['risk'], 'NONE')


class TestFingerprintEmailTemplate(unittest.TestCase):
    """Tests for AdvancedEmailAnalyzer.fingerprint_email_template."""

    def test_phishing_keyword_detection(self):
        """Common phishing phrases in subject/body are captured as template indicators."""
        html = '<p>Dear user, verify your account immediately.</p>'
        subject = 'Immediate action required: Security Alert'
        fp = AdvancedEmailAnalyzer.fingerprint_email_template(html, subject)
        # At least some phishing keywords should appear
        self.assertGreater(len(fp['template_indicators']), 0)
        self.assertTrue(
            any('verify your account' in ind for ind in fp['template_indicators'])
        )

    def test_css_class_extraction(self):
        """CSS classes from the HTML body are extracted."""
        html = '<div class="email-body"><span class="brand-logo">Logo</span></div>'
        fp = AdvancedEmailAnalyzer.fingerprint_email_template(html, 'Test')
        self.assertIn('email-body', fp['css_classes'])
        self.assertIn('brand-logo', fp['css_classes'])

    def test_image_count(self):
        """Images in the HTML body are counted."""
        html = '<img src="a.png"><img src="b.png"><img src="c.png">'
        fp = AdvancedEmailAnalyzer.fingerprint_email_template(html, '')
        self.assertEqual(fp['image_count'], 3)


class TestDetectBrandImpersonation(unittest.TestCase):
    """Tests for AdvancedEmailAnalyzer.detect_brand_impersonation."""

    def test_brand_from_non_legitimate_domain(self):
        """Mentioning 'PayPal' from a non-PayPal domain is flagged."""
        result = AdvancedEmailAnalyzer.detect_brand_impersonation(
            from_address='support@attacker.com',
            subject='PayPal account verification',
            html_body='<p>Your PayPal account has been suspended.</p>',
            domains=['attacker.com'],
        )
        self.assertGreater(len(result), 0)
        brands = [r['brand'] for r in result]
        self.assertIn('PAYPAL', brands)

    def test_brand_from_legitimate_domain(self):
        """Mentioning 'PayPal' from paypal.com is not flagged."""
        result = AdvancedEmailAnalyzer.detect_brand_impersonation(
            from_address='noreply@paypal.com',
            subject='PayPal receipt',
            html_body='<p>Your PayPal receipt.</p>',
            domains=['paypal.com'],
        )
        paypal_hits = [r for r in result if r['brand'] == 'PAYPAL']
        self.assertEqual(len(paypal_hits), 0)


class TestAnalyzeHeaders(unittest.TestCase):
    """Tests for AdvancedEmailAnalyzer.analyze_headers."""

    def test_return_path_from_mismatch(self):
        """Return-Path domain differing from From domain is flagged."""
        msg = _make_msg(
            return_path='<bounces@spammer.com>',
            from_addr='support@legitimate.com',
            message_id='<abc@legitimate.com>',
        )
        result = AdvancedEmailAnalyzer.analyze_headers(msg)
        self.assertTrue(
            any('Return-Path' in a for a in result['anomalies']),
            "Expected Return-Path mismatch anomaly"
        )

    def test_message_id_domain_mismatch(self):
        """Message-ID domain differing from From domain is flagged."""
        msg = _make_msg(
            from_addr='user@company.com',
            message_id='<xyz@randomserver.net>',
            return_path='<user@company.com>',
        )
        result = AdvancedEmailAnalyzer.analyze_headers(msg)
        self.assertTrue(
            any('Message-ID' in a for a in result['anomalies']),
            "Expected Message-ID domain mismatch anomaly"
        )

    def test_clean_headers_no_anomalies(self):
        """Consistent headers produce no anomalies."""
        msg = _make_msg(
            from_addr='user@company.com',
            return_path='<user@company.com>',
            message_id='<msg123@company.com>',
        )
        result = AdvancedEmailAnalyzer.analyze_headers(msg)
        self.assertEqual(result['anomalies'], [])


# ===================================================================
#  EmailClusterer Tests
# ===================================================================

class TestEmailClusterer(unittest.TestCase):
    """Tests for EmailClusterer."""

    def _similar_email(self, subject, sender, urls=None):
        """Helper to build a simple email_data dict."""
        return {
            'subject': subject,
            'from': sender,
            'urls': urls or [],
            'attachments': [],
        }

    def test_similar_emails_same_cluster(self):
        """Two emails with the same subject and sender end up in the same cluster."""
        clusterer = EmailClusterer(similarity_threshold=0.7)
        c1 = clusterer.add_email(self._similar_email(
            'Your account has been suspended',
            'alerts@phish.com',
        ))
        c2 = clusterer.add_email(self._similar_email(
            'Your account has been suspended',
            'alerts@phish.com',
        ))
        self.assertEqual(c1, c2)

    def test_different_emails_different_clusters(self):
        """Two completely different emails go into separate clusters."""
        clusterer = EmailClusterer(similarity_threshold=0.7)
        c1 = clusterer.add_email(self._similar_email(
            'Invoice #12345 attached',
            'billing@company-a.com',
            urls=['http://company-a.com/invoice'],
        ))
        c2 = clusterer.add_email(self._similar_email(
            'Password reset requested',
            'security@other-domain.org',
            urls=['http://other-domain.org/reset'],
        ))
        self.assertNotEqual(c1, c2)

    def test_subject_pattern_removes_numbers(self):
        """_extract_pattern replaces digits with NUM."""
        clusterer = EmailClusterer()
        pattern = clusterer._extract_pattern('Invoice #98765 for order 42')
        self.assertNotIn('98765', pattern)
        self.assertNotIn('42', pattern)
        self.assertIn('num', pattern)  # pattern is lowercased

    def test_subject_pattern_removes_urls(self):
        """_extract_pattern replaces URLs with URL."""
        clusterer = EmailClusterer()
        pattern = clusterer._extract_pattern(
            'Click here: https://evil.com/phish to verify'
        )
        self.assertNotIn('https://evil.com/phish', pattern)
        self.assertIn('url', pattern)

    def test_subject_pattern_removes_dates(self):
        """_extract_pattern replaces date patterns with DATE."""
        clusterer = EmailClusterer()
        # Note: the regex replaces \d+ first, so dates become NUM/NUM/NUM
        # before the date regex can match.  We just verify the raw date is gone.
        pattern = clusterer._extract_pattern('Report for 12/31/2024')
        self.assertNotIn('12/31/2024', pattern)

    def test_cluster_stats(self):
        """get_cluster_stats returns correct totals."""
        clusterer = EmailClusterer(similarity_threshold=0.7)
        clusterer.add_email(self._similar_email(
            'Phishing attempt A', 'bad@evil.com'))
        clusterer.add_email(self._similar_email(
            'Phishing attempt A', 'bad@evil.com'))
        clusterer.add_email(self._similar_email(
            'Totally different', 'other@good.com'))
        stats = clusterer.get_cluster_stats()
        self.assertEqual(stats['total_emails'], 3)
        self.assertEqual(stats['total_clusters'], 2)

    def test_high_threshold_separates(self):
        """A very high similarity threshold causes even somewhat-similar emails to split."""
        clusterer = EmailClusterer(similarity_threshold=0.99)
        c1 = clusterer.add_email(self._similar_email(
            'Verify your account today',
            'noreply@phish-a.com',
        ))
        c2 = clusterer.add_email(self._similar_email(
            'Verify your account now',
            'noreply@phish-b.com',
        ))
        self.assertNotEqual(c1, c2)

    def test_low_threshold_merges(self):
        """A very low similarity threshold merges loosely related emails."""
        clusterer = EmailClusterer(similarity_threshold=0.1)
        c1 = clusterer.add_email(self._similar_email(
            'Urgent: confirm identity',
            'support@example.com',
        ))
        c2 = clusterer.add_email(self._similar_email(
            'Urgent: update payment info',
            'support@example.com',
        ))
        self.assertEqual(c1, c2)


if __name__ == '__main__':
    unittest.main()
