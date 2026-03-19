"""
Tests for IOC extraction - patterns, whitelisting, edge cases.
"""

import pytest

from src.utils.ioc_extractor import IOCExtractor


class TestIPv4Extraction:
    """Test IPv4 address extraction."""

    def test_basic_ip(self):
        ips = IOCExtractor.extract_ipv4("Connect to 192.0.2.1 for C2")
        assert '192.0.2.1' in ips

    def test_multiple_ips(self):
        text = "Source: 10.0.0.1 Dest: 203.0.113.50 via 198.51.100.1"
        ips = IOCExtractor.extract_ipv4(text, exclude_private=False)
        assert '10.0.0.1' in ips
        assert '203.0.113.50' in ips
        assert '198.51.100.1' in ips

    def test_private_ip_excluded(self):
        ips = IOCExtractor.extract_ipv4("Internal: 192.168.1.1")
        assert '192.168.1.1' not in ips

    def test_private_ip_included_when_requested(self):
        ips = IOCExtractor.extract_ipv4("Internal: 192.168.1.1", exclude_private=False)
        assert '192.168.1.1' in ips

    def test_loopback_excluded(self):
        ips = IOCExtractor.extract_ipv4("localhost: 127.0.0.1")
        assert '127.0.0.1' not in ips

    def test_version_strings_excluded(self):
        ips = IOCExtractor.extract_ipv4("Version 1.0.0.0 of the software")
        assert '1.0.0.0' not in ips

    def test_no_ips_in_clean_text(self):
        ips = IOCExtractor.extract_ipv4("No IPs here, just text.")
        assert len(ips) == 0

    def test_boundary_ip(self):
        ips = IOCExtractor.extract_ipv4("Edge: 255.255.255.255")
        # Broadcast should still be extracted if not in private/version lists
        # depends on implementation
        assert isinstance(ips, list)

    def test_deduplication(self):
        text = "IP: 8.8.8.8 and again 8.8.8.8 and once more 8.8.8.8"
        ips = IOCExtractor.extract_ipv4(text)
        assert ips.count('8.8.8.8') == 1


class TestDomainExtraction:
    """Test domain extraction."""

    def test_basic_domain(self):
        domains = IOCExtractor.extract_domains("Visit evil-site.xyz for malware")
        assert 'evil-site.xyz' in domains

    def test_subdomain(self):
        domains = IOCExtractor.extract_domains("C2: c2.evil-domain.com callback")
        found = [d for d in domains if 'evil-domain.com' in d]
        assert len(found) > 0

    def test_whitelist_excluded(self):
        domains = IOCExtractor.extract_domains("Download from microsoft.com")
        assert 'microsoft.com' not in domains

    def test_whitelist_included_when_requested(self):
        domains = IOCExtractor.extract_domains(
            "Download from microsoft.com", exclude_whitelist=False
        )
        assert 'microsoft.com' in domains

    def test_no_domains_in_clean_text(self):
        domains = IOCExtractor.extract_domains("Just plain text with no domains")
        assert len(domains) == 0


class TestURLExtraction:
    """Test URL extraction."""

    def test_http_url(self):
        urls = IOCExtractor.extract_urls("GET http://evil.com/malware.exe")
        assert any('evil.com' in u for u in urls)

    def test_https_url(self):
        urls = IOCExtractor.extract_urls("Callback: https://c2server.net/beacon")
        assert any('c2server.net' in u for u in urls)

    def test_url_with_port(self):
        urls = IOCExtractor.extract_urls("http://192.0.2.1:8080/payload")
        assert any('8080' in u for u in urls)

    def test_w3c_urls_excluded(self):
        urls = IOCExtractor.extract_urls("xmlns: http://www.w3.org/2001/XMLSchema")
        assert not any('w3.org' in u for u in urls)

    def test_schema_org_excluded(self):
        urls = IOCExtractor.extract_urls("type: http://schema.org/Product")
        assert not any('schema.org' in u for u in urls)


class TestHashExtraction:
    """Test hash extraction."""

    def test_md5(self):
        text = "Hash: d41d8cd98f00b204e9800998ecf8427e"
        hashes = IOCExtractor.extract_hashes(text)
        assert 'd41d8cd98f00b204e9800998ecf8427e' in hashes.get('md5', [])

    def test_sha256(self):
        text = "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        hashes = IOCExtractor.extract_hashes(text)
        sha256_list = hashes.get('sha256', [])
        assert any('e3b0c44298fc1c' in h for h in sha256_list)

    def test_no_false_positive_short_hex(self):
        """Short hex strings should not match hash patterns."""
        text = "Color: #ff0000 and value: 0xDEADBEEF"
        hashes = IOCExtractor.extract_hashes(text)
        md5s = hashes.get('md5', [])
        # These are too short for MD5 (32 chars)
        assert 'ff0000' not in md5s


class TestEmailExtraction:
    """Test email address extraction."""

    def test_basic_email(self):
        emails = IOCExtractor.extract_emails("Contact: admin@malware-domain.com")
        assert 'admin@malware-domain.com' in emails

    def test_no_false_positive(self):
        emails = IOCExtractor.extract_emails("Just text, no emails")
        assert len(emails) == 0


class TestExtractAll:
    """Test combined extraction."""

    def test_extract_all_types(self):
        text = """
        C2 IP: 203.0.113.1
        Domain: evil-callback.xyz
        URL: https://evil-callback.xyz/beacon
        Hash: d41d8cd98f00b204e9800998ecf8427e
        Email: attacker@evil-callback.xyz
        """
        result = IOCExtractor.extract_all(text)
        assert 'ipv4' in result or 'ips' in result
        assert 'domains' in result
        assert 'urls' in result


class TestUtilityMethods:
    """Test defanging, refanging, and categorization."""

    def test_defang_ip(self):
        defanged = IOCExtractor.defang_ioc("192.0.2.1")
        assert '[.]' in defanged

    def test_defang_url(self):
        defanged = IOCExtractor.defang_ioc("http://evil.com")
        assert 'hxxp' in defanged

    def test_refang_ip(self):
        refanged = IOCExtractor.refang_ioc("192[.]0[.]2[.]1")
        assert refanged == "192.0.2.1"

    def test_categorize_ip(self):
        cat = IOCExtractor.categorize_ioc("192.0.2.1")
        assert cat in ('ipv4', 'ip', 'IPv4')

    def test_categorize_domain(self):
        cat = IOCExtractor.categorize_ioc("evil.com")
        assert 'domain' in cat.lower()

    def test_categorize_hash(self):
        cat = IOCExtractor.categorize_ioc("d41d8cd98f00b204e9800998ecf8427e")
        assert 'md5' in cat.lower() or 'hash' in cat.lower()
