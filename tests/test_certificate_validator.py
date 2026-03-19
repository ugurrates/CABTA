"""
Tests for Certificate Validator module.
"""

import pytest
from datetime import datetime, timezone, timedelta

from src.analyzers.certificate_validator import (
    CertificateValidator,
    CRYPTO_AVAILABLE,
    PEFILE_AVAILABLE,
    analyze_certificate,
)


class TestCertificateValidation:
    """Test _validate_certificate logic (doesn't need real PE/cert)."""

    def test_valid_certificate(self):
        cert = {
            'valid_from': datetime.now(timezone.utc) - timedelta(days=30),
            'valid_until': datetime.now(timezone.utc) + timedelta(days=365),
            'key_size': 4096,
            'signature_algorithm': 'sha256',
            'is_self_signed': False,
        }
        result = CertificateValidator._validate_certificate(cert)
        assert result['is_valid'] is True
        assert len(result['issues']) == 0

    def test_expired_certificate(self):
        cert = {
            'valid_from': datetime.now(timezone.utc) - timedelta(days=400),
            'valid_until': datetime.now(timezone.utc) - timedelta(days=1),
            'key_size': 2048,
            'signature_algorithm': 'sha256',
            'is_self_signed': False,
        }
        result = CertificateValidator._validate_certificate(cert)
        assert result['is_valid'] is False
        assert 'Certificate expired' in result['issues']

    def test_not_yet_valid_certificate(self):
        cert = {
            'valid_from': datetime.now(timezone.utc) + timedelta(days=30),
            'valid_until': datetime.now(timezone.utc) + timedelta(days=365),
            'key_size': 2048,
            'signature_algorithm': 'sha256',
            'is_self_signed': False,
        }
        result = CertificateValidator._validate_certificate(cert)
        assert result['is_valid'] is False
        assert 'not yet valid' in result['issues'][0]

    def test_weak_key_size(self):
        cert = {
            'valid_from': datetime.now(timezone.utc) - timedelta(days=30),
            'valid_until': datetime.now(timezone.utc) + timedelta(days=365),
            'key_size': 1024,
            'signature_algorithm': 'sha256',
            'is_self_signed': False,
        }
        result = CertificateValidator._validate_certificate(cert)
        assert any('Weak key' in i for i in result['issues'])

    def test_md5_algorithm_warning(self):
        cert = {
            'valid_from': datetime.now(timezone.utc) - timedelta(days=30),
            'valid_until': datetime.now(timezone.utc) + timedelta(days=365),
            'key_size': 2048,
            'signature_algorithm': 'md5WithRSAEncryption',
            'is_self_signed': False,
        }
        result = CertificateValidator._validate_certificate(cert)
        assert any('MD5' in i for i in result['issues'])

    def test_sha1_algorithm_warning(self):
        cert = {
            'valid_from': datetime.now(timezone.utc) - timedelta(days=30),
            'valid_until': datetime.now(timezone.utc) + timedelta(days=365),
            'key_size': 2048,
            'signature_algorithm': 'sha1',
            'is_self_signed': False,
        }
        result = CertificateValidator._validate_certificate(cert)
        assert any('SHA-1' in i for i in result['issues'])

    def test_self_signed_warning(self):
        cert = {
            'valid_from': datetime.now(timezone.utc) - timedelta(days=30),
            'valid_until': datetime.now(timezone.utc) + timedelta(days=365),
            'key_size': 2048,
            'signature_algorithm': 'sha256',
            'is_self_signed': True,
        }
        result = CertificateValidator._validate_certificate(cert)
        assert any('Self-signed' in i for i in result['issues'])

    def test_naive_datetime_handled(self):
        """Naive (non-timezone-aware) datetimes should not crash."""
        cert = {
            'valid_from': datetime(2020, 1, 1),
            'valid_until': datetime(2030, 12, 31),
            'key_size': 2048,
            'signature_algorithm': 'sha256',
            'is_self_signed': False,
        }
        result = CertificateValidator._validate_certificate(cert)
        assert isinstance(result['is_valid'], bool)

    def test_zero_key_size_no_warning(self):
        """key_size=0 means unknown, should not trigger weak key warning."""
        cert = {
            'valid_from': datetime.now(timezone.utc) - timedelta(days=30),
            'valid_until': datetime.now(timezone.utc) + timedelta(days=365),
            'key_size': 0,
            'signature_algorithm': 'sha256',
            'is_self_signed': False,
        }
        result = CertificateValidator._validate_certificate(cert)
        assert not any('Weak key' in i for i in result['issues'])


class TestUnsignedPE:
    """Test behavior with unsigned or non-PE files."""

    def test_nonexistent_file(self):
        result = CertificateValidator.validate_pe_signature('/nonexistent/file.exe')
        assert result['signed'] is False

    def test_analyze_certificate_nonexistent(self):
        result = analyze_certificate('/nonexistent/file.exe')
        assert 'certificate_analysis' in result
        assert result['certificate_analysis']['signature']['signed'] is False

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not installed")
    def test_non_pe_file(self, tmp_path):
        f = tmp_path / "not_a_pe.txt"
        f.write_text("This is not a PE file")
        result = CertificateValidator.validate_pe_signature(str(f))
        assert result['signed'] is False


class TestTrustCheck:
    """Test certificate trust checking logic."""

    def test_unsigned_not_trusted(self):
        result = CertificateValidator.check_certificate_trust('/nonexistent.exe')
        assert result['trusted'] is False
        assert 'No digital signature' in result['reason']


class TestX509ToDict:
    """Test _x509_to_dict with real certificate objects (if cryptography available)."""

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="cryptography not installed")
    def test_self_signed_cert(self):
        """Create a self-signed certificate and verify dict conversion."""
        from cryptography import x509 as cx509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = cx509.Name([
            cx509.NameAttribute(NameOID.COMMON_NAME, 'Test Self Signed'),
        ])
        cert = (
            cx509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(cx509.random_serial_number())
            .not_valid_before(datetime(2024, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
            .sign(key, hashes.SHA256())
        )

        info = CertificateValidator._x509_to_dict(cert)
        assert 'Test Self Signed' in info['subject']
        assert info['key_size'] == 2048
        assert info['is_self_signed'] is True
        assert info['thumbprint']  # Non-empty SHA-256 hex
        assert len(info['thumbprint']) == 64  # SHA-256 = 32 bytes = 64 hex chars

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="cryptography not installed")
    def test_non_self_signed_cert(self):
        """Certificate with different subject/issuer is not self-signed."""
        from cryptography import x509 as cx509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes

        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, 'Subject')])
        issuer = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, 'Issuer CA')])
        cert = (
            cx509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(cx509.random_serial_number())
            .not_valid_before(datetime(2024, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
            .sign(key, hashes.SHA256())
        )

        info = CertificateValidator._x509_to_dict(cert)
        assert info['is_self_signed'] is False
        assert info['key_size'] == 4096
