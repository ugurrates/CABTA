"""
Ransomware-Specific Analysis Module
Detects ransomware indicators: crypto constants, ransom notes, bitcoin/onion URLs,
known ransomware extensions, encryption mechanism analysis.
"""
import re
import struct
import math
import os
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class RansomwareIndicator:
    indicator_type: str    # crypto_constant, ransom_extension, ransom_note, bitcoin_addr, onion_url, encryption_detected
    name: str
    severity: str          # CRITICAL, HIGH, MEDIUM
    confidence: int        # 0-100
    details: str
    offset: Optional[int] = None
    mitre_technique: str = ""


class RansomwareAnalyzer:
    """Analyzes files for ransomware-specific indicators"""

    # Known ransomware file extensions (25+)
    RANSOMWARE_EXTENSIONS = {
        '.lockbit': 'LockBit', '.lockbit3': 'LockBit 3.0',
        '.BlackCat': 'BlackCat/ALPHV', '.cl0p': 'Cl0p', '.clop': 'Cl0p',
        '.royal': 'Royal', '.akira': 'Akira', '.rhysida': 'Rhysida',
        '.blacksuit': 'BlackSuit', '.medusa': 'MedusaLocker',
        '.8base': '8Base', '.bianlian': 'BianLian',
        '.encrypted': 'Generic', '.locked': 'Generic', '.crypt': 'Generic',
        '.enc': 'Generic', '.ryk': 'Ryuk', '.conti': 'Conti',
        '.hive': 'Hive', '.maze': 'Maze', '.revil': 'REvil/Sodinokibi',
        '.sodinokibi': 'REvil/Sodinokibi', '.darkside': 'DarkSide',
        '.babuk': 'Babuk', '.phobos': 'Phobos', '.dharma': 'Dharma',
        '.stop': 'STOP/Djvu', '.djvu': 'STOP/Djvu',
        '.play': 'Play', '.trigona': 'Trigona', '.noescape': 'NoEscape',
        '.monti': 'Monti', '.blackbasta': 'Black Basta',
    }

    # Ransom note filename patterns
    RANSOM_NOTE_PATTERNS = [
        r'README[\w\-]*\.txt', r'DECRYPT[\w\-]*\.txt', r'HOW[\s_\-]?TO[\s_\-]?RECOVER[\w\-]*',
        r'RESTORE[\s_\-]?FILES[\w\-]*', r'!README![\w\-]*', r'_readme\.txt',
        r'RECOVER[\s_\-]?YOUR[\s_\-]?FILES', r'YOUR[\s_\-]?FILES[\s_\-]?ARE[\s_\-]?ENCRYPTED',
        r'ATTENTION[\s_\-]?[\w\-]*\.txt', r'HELP[\s_\-]?DECRYPT[\w\-]*',
        r'[\w]*RANSOM[\w\-]*\.txt', r'UNLOCK[\s_\-]?FILES[\w\-]*',
        r'[\w]*PAYMENT[\s_\-]?INFO[\w\-]*\.txt',
    ]

    # AES S-Box (first 16 bytes are enough for detection)
    AES_SBOX_PARTIAL = bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                              0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76])

    # AES Inverse S-Box (first 16 bytes)
    AES_INV_SBOX_PARTIAL = bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
                                   0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB])

    # RSA markers
    RSA_MARKER = bytes([0x30, 0x82])

    # ChaCha20/Salsa20 constant
    CHACHA_CONSTANT = b"expand 32-byte k"

    # SHA-256 initial hash values (H0)
    SHA256_INIT = struct.pack(">I", 0x6a09e667)

    # RC4 state init pattern
    RC4_STATE_INIT = bytes(range(8))

    def __init__(self):
        self.crypto_constants = [
            ('AES S-Box', self.AES_SBOX_PARTIAL, 'CRITICAL', 90, 'T1486'),
            ('AES Inverse S-Box', self.AES_INV_SBOX_PARTIAL, 'CRITICAL', 90, 'T1486'),
            ('RSA Public Key Marker', self.RSA_MARKER, 'MEDIUM', 40, 'T1486'),
            ('ChaCha20/Salsa20', self.CHACHA_CONSTANT, 'CRITICAL', 95, 'T1486'),
            ('SHA-256 Init', self.SHA256_INIT, 'LOW', 30, 'T1486'),
            ('RC4 State Init', self.RC4_STATE_INIT, 'MEDIUM', 50, 'T1486'),
        ]

    def analyze_file(self, file_path: str, file_data: Optional[bytes] = None) -> Dict[str, Any]:
        """Full ransomware analysis of a file"""
        indicators: List[RansomwareIndicator] = []

        if file_data is None:
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
            except Exception as e:
                return {'error': str(e), 'is_ransomware': False, 'indicators': []}

        # 1. Check file entropy (encryption detection)
        entropy_result = self._analyze_encryption_entropy(file_data)
        indicators.extend(entropy_result)

        # 2. Scan for crypto constants
        crypto_indicators = self._scan_crypto_constants(file_data)
        indicators.extend(crypto_indicators)

        # 3. Check for ransomware extension references in strings
        ext_indicators = self._scan_ransomware_extensions(file_data)
        indicators.extend(ext_indicators)

        # 4. Check for ransom note filename patterns
        note_indicators = self._scan_ransom_note_patterns(file_data)
        indicators.extend(note_indicators)

        # 5. Extract bitcoin addresses
        btc_indicators = self._extract_bitcoin_addresses(file_data)
        indicators.extend(btc_indicators)

        # 6. Extract onion URLs
        onion_indicators = self._extract_onion_urls(file_data)
        indicators.extend(onion_indicators)

        # 7. Check for ransom-related strings
        string_indicators = self._scan_ransom_strings(file_data)
        indicators.extend(string_indicators)

        # 8. Volume shadow copy deletion patterns
        vss_indicators = self._scan_vss_deletion(file_data)
        indicators.extend(vss_indicators)

        # Calculate ransomware score
        ransomware_score = self._calculate_score(indicators)

        # Determine family
        family = self._guess_family(indicators)

        # Determine encryption type from entropy
        overall_entropy = self._shannon_entropy(file_data)
        if overall_entropy > 7.9:
            encryption_type = 'full'
        elif overall_entropy > 6.0:
            encryption_type = 'partial'
        else:
            encryption_type = 'none'

        is_ransomware = ransomware_score >= 40

        return {
            'is_ransomware': is_ransomware,
            'ransomware_score': min(ransomware_score, 100),
            'verdict': 'RANSOMWARE' if ransomware_score >= 70 else ('SUSPECTED_RANSOMWARE' if ransomware_score >= 40 else 'NOT_RANSOMWARE'),
            'family': family,
            'encryption_type': encryption_type,
            'overall_entropy': round(overall_entropy, 4),
            'indicator_count': len(indicators),
            'indicators': [
                {
                    'type': i.indicator_type,
                    'name': i.name,
                    'severity': i.severity,
                    'confidence': i.confidence,
                    'details': i.details,
                    'offset': i.offset,
                    'mitre_technique': i.mitre_technique
                }
                for i in indicators
            ],
            'crypto_constants_found': [i.name for i in indicators if i.indicator_type == 'crypto_constant'],
            'bitcoin_addresses': [i.details.split(': ')[-1] for i in indicators if i.indicator_type == 'bitcoin_addr'],
            'onion_urls': [i.details.split(': ')[-1] for i in indicators if i.indicator_type == 'onion_url'],
            'ransomware_extensions_referenced': [i.name for i in indicators if i.indicator_type == 'ransom_extension'],
            'mitre_techniques': list(set(i.mitre_technique for i in indicators if i.mitre_technique))
        }

    # Implement all the helper methods:

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def _analyze_encryption_entropy(self, data: bytes) -> List[RansomwareIndicator]:
        indicators = []
        entropy = self._shannon_entropy(data)
        if entropy > 7.9:
            indicators.append(RansomwareIndicator(
                indicator_type='encryption_detected',
                name='Full File Encryption',
                severity='CRITICAL',
                confidence=85,
                details=f'Overall entropy {entropy:.4f} indicates full encryption',
                mitre_technique='T1486'
            ))
        elif entropy > 7.0:
            indicators.append(RansomwareIndicator(
                indicator_type='encryption_detected',
                name='Partial/Intermittent Encryption',
                severity='HIGH',
                confidence=60,
                details=f'Overall entropy {entropy:.4f} suggests partial encryption',
                mitre_technique='T1486'
            ))
        return indicators

    def _scan_crypto_constants(self, data: bytes) -> List[RansomwareIndicator]:
        indicators = []
        for name, pattern, severity, confidence, mitre in self.crypto_constants:
            offset = data.find(pattern)
            if offset != -1:
                # RSA marker is very common, only flag if near other indicators
                if name == 'RSA Public Key Marker':
                    # Check for actual RSA key structure (length field after marker)
                    if offset + 4 < len(data):
                        key_len = struct.unpack(">H", data[offset+2:offset+4])[0]
                        if key_len < 100 or key_len > 4096:
                            continue  # Not a real RSA key

                indicators.append(RansomwareIndicator(
                    indicator_type='crypto_constant',
                    name=name,
                    severity=severity,
                    confidence=confidence,
                    details=f'{name} found at offset 0x{offset:X}',
                    offset=offset,
                    mitre_technique=mitre
                ))
        return indicators

    def _scan_ransomware_extensions(self, data: bytes) -> List[RansomwareIndicator]:
        indicators = []
        try:
            text = data.decode('utf-8', errors='ignore')
        except Exception:
            text = data.decode('latin-1', errors='ignore')

        for ext, family in self.RANSOMWARE_EXTENSIONS.items():
            if ext in text:
                indicators.append(RansomwareIndicator(
                    indicator_type='ransom_extension',
                    name=f'{ext} ({family})',
                    severity='CRITICAL',
                    confidence=80,
                    details=f'Ransomware extension {ext} ({family} family) found in file strings',
                    mitre_technique='T1486'
                ))
        return indicators

    def _scan_ransom_note_patterns(self, data: bytes) -> List[RansomwareIndicator]:
        indicators = []
        try:
            text = data.decode('utf-8', errors='ignore')
        except Exception:
            text = data.decode('latin-1', errors='ignore')

        for pattern in self.RANSOM_NOTE_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                indicators.append(RansomwareIndicator(
                    indicator_type='ransom_note',
                    name=matches[0] if matches else pattern,
                    severity='HIGH',
                    confidence=75,
                    details=f'Ransom note filename pattern detected: {matches[0] if matches else pattern}',
                    mitre_technique='T1486'
                ))
        return indicators

    def _extract_bitcoin_addresses(self, data: bytes) -> List[RansomwareIndicator]:
        indicators = []
        try:
            text = data.decode('utf-8', errors='ignore')
        except Exception:
            text = data.decode('latin-1', errors='ignore')

        # Bitcoin address: starts with 1 or 3, 25-34 chars base58
        btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
        matches = re.findall(btc_pattern, text)
        seen = set()
        for addr in matches:
            if addr not in seen:
                seen.add(addr)
                indicators.append(RansomwareIndicator(
                    indicator_type='bitcoin_addr',
                    name='Bitcoin Address',
                    severity='HIGH',
                    confidence=70,
                    details=f'Bitcoin address found: {addr}',
                    mitre_technique='T1486'
                ))
        # Also check for bc1 (bech32) addresses
        bc1_pattern = r'\bbc1[a-zA-HJ-NP-Za-km-z0-9]{25,87}\b'
        bc1_matches = re.findall(bc1_pattern, text)
        for addr in bc1_matches:
            if addr not in seen:
                seen.add(addr)
                indicators.append(RansomwareIndicator(
                    indicator_type='bitcoin_addr',
                    name='Bitcoin Bech32 Address',
                    severity='HIGH',
                    confidence=70,
                    details=f'Bitcoin bech32 address found: {addr}',
                    mitre_technique='T1486'
                ))
        return indicators

    def _extract_onion_urls(self, data: bytes) -> List[RansomwareIndicator]:
        indicators = []
        try:
            text = data.decode('utf-8', errors='ignore')
        except Exception:
            text = data.decode('latin-1', errors='ignore')

        onion_pattern = r'[\w]{16,56}\.onion'
        matches = re.findall(onion_pattern, text)
        seen = set()
        for url in matches:
            if url not in seen:
                seen.add(url)
                indicators.append(RansomwareIndicator(
                    indicator_type='onion_url',
                    name='Tor Onion URL',
                    severity='HIGH',
                    confidence=80,
                    details=f'Onion URL found: {url}',
                    mitre_technique='T1486'
                ))
        return indicators

    def _scan_ransom_strings(self, data: bytes) -> List[RansomwareIndicator]:
        """Scan for ransom-related strings"""
        indicators = []
        try:
            text = data.decode('utf-8', errors='ignore')
        except Exception:
            text = data.decode('latin-1', errors='ignore')

        ransom_patterns = [
            (r'(?i)your\s+files\s+(have\s+been|are)\s+encrypted', 'encryption_notice', 'CRITICAL', 85),
            (r'(?i)pay\s+(the\s+)?ransom', 'ransom_demand', 'CRITICAL', 90),
            (r'(?i)decrypt(ion)?\s+(key|tool|software)', 'decryption_reference', 'HIGH', 70),
            (r'(?i)all\s+your\s+(files|data|documents)\s+(have\s+been|are|were)', 'data_threat', 'HIGH', 65),
            (r'(?i)(contact\s+us|write\s+to\s+us|send\s+email).{0,50}(decrypt|restore|recover)', 'contact_ransom', 'HIGH', 75),
            (r'(?i)do\s+not\s+(try\s+to\s+)?(rename|move|delete|modify)\s+(the\s+)?(encrypted|locked)\s+files', 'warning_notice', 'HIGH', 80),
            (r'(?i)(unique\s+)?decryption\s+(id|key|code|token)', 'decryption_id', 'HIGH', 70),
        ]

        for pattern, name, severity, confidence in ransom_patterns:
            if re.search(pattern, text):
                indicators.append(RansomwareIndicator(
                    indicator_type='ransom_string',
                    name=name,
                    severity=severity,
                    confidence=confidence,
                    details=f'Ransom-related string pattern detected: {name}',
                    mitre_technique='T1486'
                ))
        return indicators

    def _scan_vss_deletion(self, data: bytes) -> List[RansomwareIndicator]:
        """Scan for Volume Shadow Copy deletion patterns"""
        indicators = []
        try:
            text = data.decode('utf-8', errors='ignore')
        except Exception:
            text = data.decode('latin-1', errors='ignore')

        vss_patterns = [
            (r'(?i)vssadmin\s+(delete\s+shadows|resize\s+shadowstorage)', 'vss_delete', 'CRITICAL', 90),
            (r'(?i)wmic\s+shadowcopy\s+delete', 'wmic_vss_delete', 'CRITICAL', 90),
            (r'(?i)bcdedit\s+.*(/set|/delete).*recoveryenabled', 'bcdedit_recovery', 'CRITICAL', 85),
            (r'(?i)wbadmin\s+delete\s+(catalog|systemstatebackup)', 'wbadmin_delete', 'CRITICAL', 85),
            (r'(?i)cipher\s+/w:', 'cipher_wipe', 'HIGH', 70),
        ]

        for pattern, name, severity, confidence in vss_patterns:
            if re.search(pattern, text):
                indicators.append(RansomwareIndicator(
                    indicator_type='recovery_inhibition',
                    name=name,
                    severity=severity,
                    confidence=confidence,
                    details=f'Recovery inhibition pattern detected: {name}',
                    mitre_technique='T1490'
                ))
        return indicators

    def _calculate_score(self, indicators: List[RansomwareIndicator]) -> int:
        if not indicators:
            return 0

        score = 0
        has_crypto = any(i.indicator_type == 'crypto_constant' for i in indicators)
        has_extension = any(i.indicator_type == 'ransom_extension' for i in indicators)
        has_note = any(i.indicator_type == 'ransom_note' for i in indicators)
        has_btc = any(i.indicator_type == 'bitcoin_addr' for i in indicators)
        has_onion = any(i.indicator_type == 'onion_url' for i in indicators)
        has_strings = any(i.indicator_type == 'ransom_string' for i in indicators)
        has_vss = any(i.indicator_type == 'recovery_inhibition' for i in indicators)
        has_encryption = any(i.indicator_type == 'encryption_detected' for i in indicators)

        # Base scores
        if has_crypto: score += 20
        if has_extension: score += 20
        if has_note: score += 15
        if has_btc: score += 15
        if has_onion: score += 15
        if has_strings: score += 15
        if has_vss: score += 20
        if has_encryption: score += 10

        # Combo bonuses
        if has_crypto and has_strings: score += 10
        if has_btc and has_onion: score += 10
        if has_vss and (has_crypto or has_strings): score += 10
        if has_extension and has_note: score += 10

        return min(score, 100)

    def _guess_family(self, indicators: List[RansomwareIndicator]) -> str:
        """Guess ransomware family from indicators"""
        families = []
        for ind in indicators:
            if ind.indicator_type == 'ransom_extension':
                # Extract family from name like ".lockbit (LockBit)"
                if '(' in ind.name:
                    family = ind.name.split('(')[-1].rstrip(')')
                    families.append(family)

        if families:
            # Return most specific family
            for f in families:
                if f != 'Generic':
                    return f
            return families[0]
        return 'Unknown'
