"""
Author: Ugur Ates
Windows Authenticode Signature Verification.

v1.0.0 Features:
- Verify PE file digital signatures
- Extract signer information (CN, O, OU)
- Validate certificate chain
- Check timestamp (countersignature)
- Match against trusted vendors
- Cross-platform support (Windows signtool, Linux osslsigncode, pefile fallback)

Best Practice: Used for false positive reduction - trusted vendors get reduced scores
"""

import subprocess
import logging
import platform
import struct
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)
@dataclass
class SignatureInfo:
    """Digital signature information."""
    signed: bool = False
    valid: bool = False
    signer: str = ""
    signer_cn: str = ""  # Common Name
    signer_o: str = ""   # Organization
    issuer: str = ""
    issuer_cn: str = ""
    serial_number: str = ""
    timestamp: str = ""
    timestamp_signer: str = ""
    certificate_chain: List[str] = field(default_factory=list)
    trust_level: str = "UNKNOWN"
    trust_score: int = 0
    details: List[str] = field(default_factory=list)
class SignatureVerifier:
    """
    Windows PE file Authenticode signature verification.
    
    Uses:
    - signtool.exe (Windows SDK)
    - sigcheck.exe (Sysinternals)
    - osslsigncode (Linux/Mac)
    - pefile + cryptography (cross-platform fallback)
    
    Best Practice:
    - Signed by trusted vendor → reduce threat score
    - Unsigned → neutral or slight penalty
    - Invalid signature → increase threat score
    """
    
    # Comprehensive trusted vendor list
    TRUSTED_VENDORS = [
        # Operating System Vendors
        'Microsoft Corporation',
        'Microsoft Windows',
        'Microsoft Windows Publisher',
        'Microsoft Code Signing PCA',
        'Apple Inc.',
        'Apple Computer, Inc.',
        'Google LLC',
        'Google Inc.',
        
        # Security Vendors
        'Symantec Corporation',
        'McAfee, Inc.',
        'Kaspersky Lab',
        'ESET, spol. s r.o.',
        'Trend Micro',
        'Avast Software',
        'AVG Technologies',
        'Bitdefender',
        'Malwarebytes',
        'CrowdStrike, Inc.',
        'Carbon Black, Inc.',
        'Palo Alto Networks',
        'Fortinet, Inc.',
        'Sophos Limited',
        'F-Secure Corporation',
        'SentinelOne',
        
        # Hardware Vendors
        'Intel Corporation',
        'Advanced Micro Devices',
        'AMD',
        'NVIDIA Corporation',
        'Realtek Semiconductor',
        'Logitech',
        'Dell Inc.',
        'Dell Technologies',
        'HP Inc.',
        'Hewlett-Packard',
        'Lenovo',
        'ASUS',
        'ASUSTeK Computer Inc.',
        'Samsung Electronics',
        'Qualcomm',
        'Broadcom Corporation',
        'Razer Inc.',
        'Corsair',
        'SteelSeries',
        
        # Software Vendors
        'Adobe Inc.',
        'Adobe Systems Incorporated',
        'Oracle Corporation',
        'Oracle America, Inc.',
        'VMware, Inc.',
        'Citrix Systems, Inc.',
        'Cisco Systems, Inc.',
        'Salesforce.com',
        'SAP SE',
        'IBM Corporation',
        'Red Hat, Inc.',
        
        # Development Tools
        'JetBrains s.r.o.',
        'GitHub, Inc.',
        'Atlassian Pty Ltd',
        'Docker Inc.',
        'HashiCorp, Inc.',
        'Sublime HQ Pty Ltd',
        'Don HO',  # Notepad++ developer
        
        # Communication & Productivity
        'Zoom Video Communications, Inc.',
        'Slack Technologies, Inc.',
        'Discord Inc.',
        'Spotify AB',
        'Dropbox, Inc.',
        'Mozilla Corporation',
        'Mozilla Foundation',
        'Opera Software',
        'Brave Software, Inc.',
        
        # Gaming
        'Valve Corporation',
        'Riot Games, Inc.',
        'Electronic Arts',
        'Blizzard Entertainment',
        'Epic Games, Inc.',
        'Ubisoft',
        'Take-Two Interactive',
        'Rockstar Games',
        'Unity Technologies',
        'NVIDIA GeForce',
        
        # Utilities
        'WinRAR GmbH',
        '7-Zip',
        'Igor Pavlov',  # 7-Zip developer
        'VideoLAN',
        'GIMP',
        'Audacity',
        'voidtools',  # Everything.exe
        'Piriform Software',  # CCleaner
        'NirSoft',
        
        # Enterprise
        'Autodesk, Inc.',
        'SolidWorks Corporation',
        'Siemens',
        'PTC Inc.',
        'ANSYS, Inc.',
        'MathWorks',
    ]
    
    def __init__(self):
        """Initialize verifier and detect available tools."""
        self.is_windows = platform.system() == 'Windows'
        self.signtool_available = False
        self.sigcheck_available = False
        self.osslsigncode_available = False
        self.pefile_available = False
        self.cryptography_available = False
        
        self._detect_tools()
    
    def _detect_tools(self):
        """Detect available signature verification tools."""
        # Check for signtool (Windows SDK)
        if self.is_windows:
            try:
                result = subprocess.run(
                    ['signtool', '/?'],
                    capture_output=True,
                    timeout=5
                )
                self.signtool_available = True
                logger.debug("[SIGVER] signtool available")
            except:
                pass
            
            # Check for sigcheck (Sysinternals)
            try:
                result = subprocess.run(
                    ['sigcheck', '-?'],
                    capture_output=True,
                    timeout=5
                )
                self.sigcheck_available = True
                logger.debug("[SIGVER] sigcheck available")
            except:
                pass
        else:
            # Check for osslsigncode (Linux/Mac)
            try:
                result = subprocess.run(
                    ['osslsigncode', '--help'],
                    capture_output=True,
                    timeout=5
                )
                self.osslsigncode_available = True
                logger.debug("[SIGVER] osslsigncode available")
            except:
                pass
        
        # Check for pefile (cross-platform)
        try:
            import pefile
            self.pefile_available = True
            logger.debug("[SIGVER] pefile available")
        except ImportError:
            pass
        
        # Check for cryptography
        try:
            from cryptography.hazmat.primitives.serialization import pkcs7
            self.cryptography_available = True
            logger.debug("[SIGVER] cryptography available")
        except ImportError:
            pass
    
    def verify_signature(self, file_path: str) -> SignatureInfo:
        """
        Verify digital signature of PE file.
        
        Args:
            file_path: Path to PE file
        
        Returns:
            SignatureInfo with verification results
        """
        result = SignatureInfo()
        
        file_path = Path(file_path)
        if not file_path.exists():
            result.details.append('File not found')
            return result
        
        # Check if it's a PE file
        if not self._is_pe_file(str(file_path)):
            result.details.append('Not a PE file')
            return result
        
        # Try verification methods in order of preference
        if self.is_windows and self.signtool_available:
            result = self._verify_with_signtool(str(file_path))
        elif self.is_windows and self.sigcheck_available:
            result = self._verify_with_sigcheck(str(file_path))
        elif self.osslsigncode_available:
            result = self._verify_with_osslsigncode(str(file_path))
        
        # Fallback to pefile if no external tool succeeded
        if not result.signed and self.pefile_available:
            result = self._verify_with_pefile(str(file_path))
        
        # Calculate trust score and level
        result.trust_score = self._calculate_trust_score(result)
        result.trust_level = self._determine_trust_level(result)
        
        return result
    
    def _is_pe_file(self, file_path: str) -> bool:
        """Check if file is a PE file."""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(2)
                if magic != b'MZ':
                    return False
                
                # Check PE signature
                f.seek(60)
                pe_offset = struct.unpack('<I', f.read(4))[0]
                f.seek(pe_offset)
                pe_sig = f.read(4)
                return pe_sig == b'PE\x00\x00'
        except:
            return False
    
    def _verify_with_signtool(self, file_path: str) -> SignatureInfo:
        """Verify using Windows signtool."""
        result = SignatureInfo()
        
        try:
            proc = subprocess.run(
                ['signtool', 'verify', '/pa', '/v', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = proc.stdout + proc.stderr
            
            if proc.returncode == 0:
                result.signed = True
                result.valid = True
                
                # Parse output
                for line in output.split('\n'):
                    line = line.strip()
                    if 'Issued to:' in line:
                        signer = line.split('Issued to:')[1].strip()
                        if not result.signer:
                            result.signer = signer
                            result.signer_cn = signer
                        result.certificate_chain.append(signer)
                    elif 'Issued by:' in line:
                        result.issuer = line.split('Issued by:')[1].strip()
                        result.issuer_cn = result.issuer
                    elif 'Serial Number:' in line:
                        result.serial_number = line.split('Serial Number:')[1].strip()
                    elif 'Timestamp:' in line and 'SHA' not in line:
                        result.timestamp = line.strip()
                
                result.details.append('Valid Authenticode signature (signtool)')
                
            elif 'is not signed' in output.lower() or 'no signature' in output.lower():
                result.details.append('File is not digitally signed')
            else:
                result.signed = True
                result.valid = False
                result.details.append(f'Invalid signature: {output[:100]}')
        
        except subprocess.TimeoutExpired:
            result.details.append('Signature verification timeout')
        except FileNotFoundError:
            result.details.append('signtool not available')
        except Exception as e:
            result.details.append(f'Verification error: {str(e)[:50]}')
        
        return result
    
    def _verify_with_sigcheck(self, file_path: str) -> SignatureInfo:
        """Verify using Sysinternals sigcheck."""
        result = SignatureInfo()
        
        try:
            proc = subprocess.run(
                ['sigcheck', '-nobanner', '-c', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proc.returncode == 0:
                output = proc.stdout
                lines = output.strip().split('\n')
                
                if len(lines) >= 2:
                    # Parse CSV output
                    data = lines[1].split(',')
                    
                    if len(data) >= 4:
                        verified = data[1].strip('"').lower()
                        publisher = data[3].strip('"') if len(data) > 3 else ''
                        company = data[4].strip('"') if len(data) > 4 else ''
                        
                        if verified == 'signed':
                            result.signed = True
                            result.valid = True
                            result.signer = publisher or company
                            result.signer_cn = result.signer
                            result.details.append('Valid signature (sigcheck)')
                        elif verified == 'unsigned':
                            result.details.append('File is not digitally signed')
                        else:
                            result.signed = True
                            result.valid = False
                            result.details.append(f'Invalid signature: {verified}')
        
        except Exception as e:
            result.details.append(f'sigcheck error: {str(e)[:50]}')
        
        return result
    
    def _verify_with_osslsigncode(self, file_path: str) -> SignatureInfo:
        """Verify using osslsigncode (Linux/Mac)."""
        result = SignatureInfo()
        
        try:
            proc = subprocess.run(
                ['osslsigncode', 'verify', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = proc.stdout + proc.stderr
            
            if 'Signature verification: ok' in output:
                result.signed = True
                result.valid = True
                
                # Parse signer info
                for line in output.split('\n'):
                    if 'Subject:' in line:
                        result.signer = line.split('Subject:')[1].strip()
                        if 'CN=' in result.signer:
                            cn_part = result.signer.split('CN=')[1]
                            result.signer_cn = cn_part.split(',')[0].strip()
                    elif 'Issuer:' in line:
                        result.issuer = line.split('Issuer:')[1].strip()
                
                result.details.append('Valid signature (osslsigncode)')
                
            elif 'No signature found' in output:
                result.details.append('File is not digitally signed')
            else:
                result.signed = True
                result.valid = False
                result.details.append('Invalid signature')
        
        except Exception as e:
            result.details.append(f'osslsigncode error: {str(e)[:50]}')
        
        return result
    
    def _verify_with_pefile(self, file_path: str) -> SignatureInfo:
        """Verify using pefile + cryptography (cross-platform fallback)."""
        result = SignatureInfo()
        
        try:
            import pefile
            
            pe = pefile.PE(file_path)
            
            # Check for SECURITY directory
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                result.signed = True
                result.details.append('Has embedded signature (SECURITY directory)')
                
                if self.cryptography_available:
                    for entry in pe.DIRECTORY_ENTRY_SECURITY:
                        self._parse_certificate(entry.data, result)
                        break
            else:
                result.details.append('No embedded signature')
            
            pe.close()
            
        except ImportError:
            result.details.append('pefile not installed')
        except Exception as e:
            result.details.append(f'PE parse error: {str(e)[:50]}')
        
        return result
    
    def _parse_certificate(self, cert_data: bytes, result: SignatureInfo):
        """Parse certificate data using cryptography library."""
        try:
            from cryptography.hazmat.primitives.serialization import pkcs7
            from cryptography import x509
            
            # Skip WIN_CERTIFICATE header (8 bytes)
            pkcs7_data = cert_data[8:]
            
            try:
                certs = pkcs7.load_der_pkcs7_certificates(pkcs7_data)
                
                for cert in certs:
                    for attr in cert.subject:
                        oid = attr.oid.dotted_string
                        if oid == '2.5.4.3':  # CN
                            result.signer_cn = attr.value
                            if not result.signer:
                                result.signer = attr.value
                        elif oid == '2.5.4.10':  # O
                            result.signer_o = attr.value
                    
                    for attr in cert.issuer:
                        oid = attr.oid.dotted_string
                        if oid == '2.5.4.3':  # CN
                            result.issuer_cn = attr.value
                            result.issuer = attr.value
                    
                    result.serial_number = format(cert.serial_number, 'x')
                    
                    chain_entry = result.signer_cn or result.signer_o or "Unknown"
                    result.certificate_chain.append(chain_entry)
                    
                    result.valid = True
                    result.details.append('Certificate parsed successfully')
                    break
                    
            except Exception as e:
                result.details.append(f'PKCS7 parse error: {str(e)[:30]}')
                
        except ImportError:
            result.details.append('cryptography not installed')
        except Exception as e:
            result.details.append(f'Certificate parse error: {str(e)[:30]}')
    
    def _calculate_trust_score(self, result: SignatureInfo) -> int:
        """Calculate trust score based on signature verification."""
        score = 0
        
        if not result.signed:
            return -10  # Slight penalty for unsigned
        
        if result.valid:
            score += 20
            
            signer = result.signer or result.signer_cn or result.signer_o
            if signer and self.is_trusted_vendor(signer):
                score += 30  # Trusted vendor bonus
            
            if result.timestamp:
                score += 5
        else:
            return -30  # Invalid signature is suspicious
        
        return score
    
    def _determine_trust_level(self, result: SignatureInfo) -> str:
        """Determine trust level string."""
        if not result.signed:
            return 'UNSIGNED'
        
        if not result.valid:
            return 'INVALID'
        
        signer = result.signer or result.signer_cn or result.signer_o
        if signer and self.is_trusted_vendor(signer):
            return 'TRUSTED'
        
        return 'SIGNED'
    
    def is_trusted_vendor(self, signer: str) -> bool:
        """Check if signer is a trusted vendor."""
        if not signer:
            return False
        
        signer_lower = signer.lower()
        for trusted in self.TRUSTED_VENDORS:
            if trusted.lower() in signer_lower:
                return True
        return False
    
    @staticmethod
    def get_trust_adjustment(file_path: str) -> Tuple[int, str, Dict]:
        """
        Get trust score adjustment for a file.
        
        Returns:
            Tuple of (score_adjustment, trust_level, full_info)
        """
        verifier = SignatureVerifier()
        info = verifier.verify_signature(file_path)
        
        return (
            info.trust_score,
            info.trust_level,
            {
                'signed': info.signed,
                'valid': info.valid,
                'signer': info.signer,
                'signer_cn': info.signer_cn,
                'signer_o': info.signer_o,
                'issuer': info.issuer,
                'timestamp': info.timestamp,
                'trust_level': info.trust_level,
                'trust_score': info.trust_score,
                'certificate_chain': info.certificate_chain,
                'details': info.details
            }
        )
# ==================== HELPER FUNCTIONS ====================

def verify_pe_signature(file_path: str) -> Dict:
    """Verify PE file signature."""
    verifier = SignatureVerifier()
    info = verifier.verify_signature(file_path)
    
    return {
        'signed': info.signed,
        'valid': info.valid,
        'signer': info.signer,
        'issuer': info.issuer,
        'timestamp': info.timestamp,
        'trust_level': info.trust_level,
        'trust_score': info.trust_score,
        'details': info.details
    }
def is_trusted_publisher(file_path: str) -> bool:
    """Check if file is signed by a trusted publisher."""
    verifier = SignatureVerifier()
    info = verifier.verify_signature(file_path)
    return info.trust_level == 'TRUSTED'
