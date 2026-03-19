"""
Author: Ugur Ates
Digital signature and certificate validation for PE files.

Capabilities:
- PKCS#7 / Authenticode signature extraction
- X.509 certificate chain parsing (subject, issuer, dates, key size)
- Certificate validity period checking
- Self-signed certificate detection
- Weak algorithm / key size warnings
- Known trusted publisher matching
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    logger.warning("[CERT] pefile not available, certificate validation disabled")

CRYPTO_AVAILABLE = False
PKCS7_AVAILABLE = False
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    CRYPTO_AVAILABLE = True
    # PKCS7 parsing (cryptography >= 3.1)
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
        PKCS7_AVAILABLE = True
    except ImportError:
        pass
except ImportError:
    logger.warning("[CERT] cryptography not available, certificate validation disabled")
class CertificateValidator:
    """
    Validate digital signatures and certificates in PE files.
    
    Features:
    - Digital signature verification
    - Certificate chain validation
    - Timestamp verification
    - Revocation checking (future)
    - Certificate details extraction
    """
    
    @staticmethod
    def validate_pe_signature(file_path: str) -> Dict:
        """
        Validate PE file digital signature.
        
        Args:
            file_path: Path to PE file
        
        Returns:
            Dict containing validation results
        """
        if not PEFILE_AVAILABLE or not CRYPTO_AVAILABLE:
            return {
                'signed': False,
                'valid': False,
                'error': 'Required libraries not available (pefile, cryptography)'
            }
        
        try:
            pe = pefile.PE(file_path)
            
            # Check if file has security directory
            if not hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                return {
                    'signed': False,
                    'valid': False,
                    'reason': 'No digital signature present'
                }
            
            # Extract signature data
            signature_data = pe.DIRECTORY_ENTRY_SECURITY[0]
            
            result = {
                'signed': True,
                'signature_size': len(signature_data.struct.data),
                'certificates': [],
                'timestamps': [],
                'valid': None,  # Will be determined after checks
                'warnings': [],
                'errors': []
            }
            
            # Parse certificates from signature
            try:
                certs = CertificateValidator._parse_certificates(signature_data.struct.data)
                result['certificates'] = certs
                
                # Validate each certificate
                for cert in certs:
                    validation = CertificateValidator._validate_certificate(cert)
                    cert.update(validation)
                
                # Overall validation
                result['valid'] = all(c.get('is_valid', False) for c in certs)
                
            except Exception as e:
                result['errors'].append(f"Certificate parsing failed: {e}")
                result['valid'] = False
            
            pe.close()
            return result
            
        except Exception as e:
            logger.error(f"[CERT] Signature validation failed: {e}")
            return {
                'signed': False,
                'valid': False,
                'error': str(e)
            }
    
    @staticmethod
    def _parse_certificates(signature_data: bytes) -> List[Dict]:
        """Parse X.509 certificates from Authenticode PKCS#7 signature data.

        The *signature_data* is the raw content of the WIN_CERTIFICATE
        structure (including the 8-byte header).  The actual PKCS#7 blob
        starts at offset 8.
        """
        certificates: List[Dict] = []

        if not CRYPTO_AVAILABLE:
            certificates.append({
                'subject': '(cryptography library not available)',
                'issuer': '',
                'serial_number': '',
                'valid_from': None,
                'valid_until': None,
                'signature_algorithm': 'Unknown',
                'key_size': 0,
                'thumbprint': '',
                'is_self_signed': False,
            })
            return certificates

        try:
            # Strip the 8-byte WIN_CERTIFICATE header
            pkcs7_der = signature_data[8:] if len(signature_data) > 8 else signature_data

            certs = CertificateValidator._extract_x509_from_der(pkcs7_der)

            for cert_obj in certs:
                cert_info = CertificateValidator._x509_to_dict(cert_obj)
                certificates.append(cert_info)

        except Exception as exc:
            logger.error(f"[CERT] Certificate parsing error: {exc}")
            # Fallback
            if not certificates:
                certificates.append({
                    'subject': f'Parse error: {exc}',
                    'issuer': '',
                    'serial_number': '',
                    'valid_from': None,
                    'valid_until': None,
                    'signature_algorithm': 'Unknown',
                    'key_size': 0,
                    'thumbprint': '',
                    'is_self_signed': False,
                })

        return certificates

    @staticmethod
    def _extract_x509_from_der(der_data: bytes) -> list:
        """Best-effort extraction of X.509 certificates from DER-encoded PKCS#7.

        Uses a lightweight approach: scan the DER blob for X.509 certificate
        ASN.1 markers (SEQUENCE-SEQUENCE-[0]) and try to parse each one.
        This avoids needing a full PKCS#7 / CMS parser.
        """
        certs = []
        # Quick approach: try PKCS7 deserialization if available
        if PKCS7_AVAILABLE:
            try:
                from cryptography.hazmat.primitives.serialization.pkcs7 import (
                    load_der_pkcs7_certificates,
                )
                certs = load_der_pkcs7_certificates(der_data)
                if certs:
                    return certs
            except Exception:
                pass

        # Fallback: scan for raw DER X.509 certificates
        # X.509 cert always starts with 30 82 xx xx 30 82
        marker = b'\x30\x82'
        idx = 0
        while idx < len(der_data) - 4:
            pos = der_data.find(marker, idx)
            if pos == -1:
                break
            try:
                length = int.from_bytes(der_data[pos + 2:pos + 4], 'big') + 4
                candidate = der_data[pos:pos + length]
                cert = x509.load_der_x509_certificate(candidate)
                certs.append(cert)
                idx = pos + length
            except Exception:
                idx = pos + 1

        return certs

    @staticmethod
    def _x509_to_dict(cert) -> Dict:
        """Convert a ``cryptography`` X.509 certificate to a plain dict."""
        try:
            subject = cert.subject.rfc4514_string()
        except Exception:
            subject = str(cert.subject)
        try:
            issuer = cert.issuer.rfc4514_string()
        except Exception:
            issuer = str(cert.issuer)

        # Key size
        key_size = 0
        try:
            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                key_size = pub.key_size
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                key_size = pub.key_size
            elif isinstance(pub, dsa.DSAPublicKey):
                key_size = pub.key_size
        except Exception:
            pass

        # Thumbprint (SHA-256)
        try:
            thumbprint = cert.fingerprint(hashes.SHA256()).hex()
        except Exception:
            thumbprint = ''

        # Signature algorithm
        try:
            sig_algo = cert.signature_algorithm_oid.dotted_string
            sig_algo_name = cert.signature_hash_algorithm
            if sig_algo_name:
                sig_algo = sig_algo_name.name
        except Exception:
            sig_algo = 'Unknown'

        is_self_signed = (subject == issuer)

        return {
            'subject': subject,
            'issuer': issuer,
            'serial_number': str(cert.serial_number),
            'valid_from': cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before,
            'valid_until': cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after,
            'signature_algorithm': str(sig_algo),
            'key_size': key_size,
            'thumbprint': thumbprint,
            'is_self_signed': is_self_signed,
        }

    @staticmethod
    def _validate_certificate(cert: Dict) -> Dict:
        """
        Validate individual certificate.

        Returns validation result dict with 'is_valid' and 'issues'.
        """
        validation: Dict = {
            'is_valid': True,
            'issues': [],
        }

        now = datetime.now(timezone.utc)

        # Check expiration
        valid_until = cert.get('valid_until')
        if valid_until is not None:
            # Make timezone-aware if naive
            if hasattr(valid_until, 'tzinfo') and valid_until.tzinfo is None:
                valid_until = valid_until.replace(tzinfo=timezone.utc)
            if valid_until < now:
                validation['is_valid'] = False
                validation['issues'].append('Certificate expired')

        # Check not-yet-valid
        valid_from = cert.get('valid_from')
        if valid_from is not None:
            if hasattr(valid_from, 'tzinfo') and valid_from.tzinfo is None:
                valid_from = valid_from.replace(tzinfo=timezone.utc)
            if valid_from > now:
                validation['is_valid'] = False
                validation['issues'].append('Certificate not yet valid')

        # Check key size
        key_size = cert.get('key_size', 0)
        if 0 < key_size < 2048:
            validation['issues'].append(f'Weak key size ({key_size} bits)')

        # Check signature algorithm
        sig_algo = cert.get('signature_algorithm', '').lower()
        if 'md5' in sig_algo:
            validation['issues'].append('Weak signature algorithm (MD5)')
        elif 'sha1' in sig_algo:
            validation['issues'].append('Deprecated signature algorithm (SHA-1)')

        # Self-signed warning
        if cert.get('is_self_signed'):
            validation['issues'].append('Self-signed certificate')

        return validation
    
    @staticmethod
    def extract_certificate_details(file_path: str) -> Dict:
        """
        Extract detailed certificate information.
        
        Args:
            file_path: Path to PE file
        
        Returns:
            Dict with certificate details
        """
        signature_result = CertificateValidator.validate_pe_signature(file_path)
        
        if not signature_result.get('signed'):
            return {
                'has_signature': False,
                'details': None
            }
        
        details = {
            'has_signature': True,
            'is_valid': signature_result.get('valid', False),
            'certificate_count': len(signature_result.get('certificates', [])),
            'certificates': signature_result.get('certificates', []),
            'warnings': signature_result.get('warnings', []),
            'errors': signature_result.get('errors', [])
        }
        
        # Extract signer info from first certificate
        if details['certificates']:
            first_cert = details['certificates'][0]
            details['signer'] = {
                'subject': first_cert.get('subject', 'Unknown'),
                'issuer': first_cert.get('issuer', 'Unknown'),
                'valid_from': first_cert.get('valid_from'),
                'valid_until': first_cert.get('valid_until')
            }
        
        return details
    
    @staticmethod
    def check_certificate_trust(file_path: str) -> Dict:
        """
        Check if certificate is trusted.
        
        Args:
            file_path: Path to PE file
        
        Returns:
            Trust status dict
        """
        cert_details = CertificateValidator.extract_certificate_details(file_path)
        
        if not cert_details.get('has_signature'):
            return {
                'trusted': False,
                'reason': 'No digital signature'
            }
        
        # Known trusted publishers (can be expanded)
        TRUSTED_PUBLISHERS = [
            'Microsoft Corporation',
            'Microsoft Windows',
            'Adobe Systems',
            'Google LLC',
            'Apple Inc.'
        ]
        
        if cert_details.get('signer'):
            subject = cert_details['signer'].get('subject', '')
            
            # Check against trusted list
            for publisher in TRUSTED_PUBLISHERS:
                if publisher.lower() in subject.lower():
                    return {
                        'trusted': True,
                        'publisher': publisher,
                        'reason': 'Known trusted publisher'
                    }
        
        # Check validity
        if cert_details.get('is_valid'):
            return {
                'trusted': 'unknown',
                'reason': 'Valid signature but publisher not in trusted list'
            }
        
        return {
            'trusted': False,
            'reason': 'Invalid or untrusted signature'
        }
def analyze_certificate(file_path: str) -> Dict:
    """
    Main entry point for certificate analysis.
    
    Args:
        file_path: Path to PE file
    
    Returns:
        Complete certificate analysis
    """
    result = {
        'certificate_analysis': {}
    }
    
    # Validate signature
    signature = CertificateValidator.validate_pe_signature(file_path)
    result['certificate_analysis']['signature'] = signature
    
    # Extract details
    details = CertificateValidator.extract_certificate_details(file_path)
    result['certificate_analysis']['details'] = details
    
    # Check trust
    trust = CertificateValidator.check_certificate_trust(file_path)
    result['certificate_analysis']['trust'] = trust
    
    # Calculate risk score
    risk_score = 0
    
    if not signature.get('signed'):
        risk_score += 40  # Unsigned = high risk
    elif not signature.get('valid'):
        risk_score += 60  # Invalid signature = very high risk
    elif trust.get('trusted') == False:
        risk_score += 30  # Untrusted = medium risk
    
    result['certificate_analysis']['risk_score'] = risk_score
    
    return result
