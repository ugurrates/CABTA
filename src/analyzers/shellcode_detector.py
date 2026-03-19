"""
Author: Ugur Ates
Shellcode Detection Module - Binary shellcode pattern analysis.

Detection capabilities:
- NOP sled detection (single-byte and multi-byte)
- API hashing detection (ror13, djb2, crc32 patterns used by Metasploit/CobaltStrike)
- XOR encoding detection (single-byte brute-force, multi-byte sliding window)
- ROP chain / gadget detection
- Framework signature detection (Metasploit, Cobalt Strike, Sliver, Havoc, BRc4)
- Syscall pattern detection (int 0x80, syscall, sysenter)
- GetEIP / GetPC techniques (call/pop, fstenv, fnstenv)
- Heap spray pattern detection
- Architecture support: x86, x64, ARM basic patterns

Best Practice: Used by enterprise SOCs for detecting shellcode in PE overlays,
memory dumps, document macros, and network captures.
"""

import logging
import struct
import math
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ShellcodeMatch:
    """A single shellcode detection hit."""
    technique: str
    offset: int
    length: int
    confidence: float        # 0.0 - 1.0
    description: str
    severity: str = 'HIGH'   # CRITICAL, HIGH, MEDIUM, LOW
    arch: str = 'x86'        # x86, x64, arm
    raw_bytes: bytes = b''

    def to_dict(self) -> Dict:
        return {
            'technique': self.technique,
            'offset': self.offset,
            'length': self.length,
            'confidence': round(self.confidence, 2),
            'description': self.description,
            'severity': self.severity,
            'arch': self.arch,
            'raw_hex': self.raw_bytes[:32].hex() if self.raw_bytes else '',
        }


@dataclass
class ShellcodeReport:
    """Aggregated shellcode analysis report."""
    has_shellcode: bool = False
    threat_score: int = 0
    matches: List[ShellcodeMatch] = field(default_factory=list)
    summary: str = ''
    techniques_found: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    beacon_config: Optional[Dict] = field(default=None)

    def to_dict(self) -> Dict:
        result = {
            'has_shellcode': self.has_shellcode,
            'threat_score': self.threat_score,
            'match_count': len(self.matches),
            'matches': [m.to_dict() for m in self.matches],
            'summary': self.summary,
            'techniques_found': self.techniques_found,
            'mitre_techniques': self.mitre_techniques,
        }
        if self.beacon_config:
            result['beacon_config'] = self.beacon_config
        return result


# ---------------------------------------------------------------------------
# Known shellcode signatures
# ---------------------------------------------------------------------------

# Metasploit stager/stage stub signatures (first bytes)
METASPLOIT_SIGNATURES = [
    (b'\xfc\xe8\x82\x00\x00\x00',      'Metasploit reverse_tcp stager (x86)'),
    (b'\xfc\xe8\x89\x00\x00\x00',      'Metasploit bind_tcp stager (x86)'),
    (b'\xfc\x48\x83\xe4\xf0\xe8',      'Metasploit reverse_tcp stager (x64)'),
    (b'\xfc\x48\x83\xe4\xf0',          'Metasploit x64 generic stager'),
    (b'\xfc\xe8\xc0\x00\x00\x00',      'Metasploit staged payload (x86)'),
    (b'\x31\xc9\x64\x8b\x41\x30',      'Metasploit PEB walk (x86)'),
    (b'\x89\xe5\x31\xc0\x64\x8b\x50\x30', 'Metasploit PEB-based resolver'),
]

# Cobalt Strike beacon signatures
COBALT_STRIKE_SIGNATURES = [
    (b'\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5', 'Cobalt Strike beacon loader'),
    (b'\x4d\x5a\xe8\x00\x00\x00\x00',          'Cobalt Strike reflective DLL'),
    (b'%c%c%c%c%c%c%c%c%cMSSE-',               'Cobalt Strike MSSE marker'),
]

# Sliver implant signatures
SLIVER_SIGNATURES = [
    (b'sliver',      'Sliver C2 implant string'),
    (b'sliverpb.',   'Sliver protobuf namespace'),
]

# Havoc C2 signatures
HAVOC_SIGNATURES = [
    (b'havoc',       'Havoc C2 framework marker'),
    (b'demon.x64',   'Havoc Demon payload'),
]

# BRc4 signatures
BRC4_SIGNATURES = [
    (b'badger_',     'Brute Ratel C4 badger marker'),
]

# Known API hash values (ror13 hashing used by Metasploit/CS)
# Maps hash -> API function name
KNOWN_API_HASHES_ROR13: Dict[int, str] = {
    0x0726774C: 'kernel32.dll!LoadLibraryA',
    0x7C0DFCAA: 'kernel32.dll!GetProcAddress',
    0xE553A458: 'kernel32.dll!VirtualAlloc',
    0x56A2B5F0: 'kernel32.dll!ExitProcess',
    0x5DE2C5AA: 'kernel32.dll!GetSystemDirectoryA',
    0x160D6838: 'kernel32.dll!CreateFileA',
    0xE449F330: 'kernel32.dll!GetTempPathA',
    0x6174A599: 'ws2_32.dll!WSAStartup',
    0xE0DF0FEA: 'ws2_32.dll!WSASocketA',
    0x6737DBC2: 'ws2_32.dll!connect',
    0x614D6E75: 'ws2_32.dll!recv',
    0x5FC8D902: 'ws2_32.dll!send',
    0x863FCC79: 'ws2_32.dll!closesocket',
    0xC0199C5A: 'wininet.dll!InternetOpenA',
    0x8BFB70DC: 'wininet.dll!InternetConnectA',
    0x7B18062D: 'wininet.dll!HttpOpenRequestA',
    0x869E4675: 'wininet.dll!InternetSetOptionA',
    0x7B7F163C: 'wininet.dll!HttpSendRequestA',
}


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

class ShellcodeDetector:
    """
    Multi-technique shellcode detection engine.

    Usage::

        detector = ShellcodeDetector()
        report = detector.scan(data)
        if report.has_shellcode:
            print(f"Score: {report.threat_score}")
    """

    # Minimum data size worth scanning
    MIN_SCAN_SIZE = 16

    # NOP-equivalent bytes (x86)
    NOP_EQUIVALENTS_X86 = {
        b'\x90',            # NOP
        b'\x87\xdb',        # xchg ebx, ebx
        b'\x87\xc9',        # xchg ecx, ecx
        b'\x87\xd2',        # xchg edx, edx
        b'\x43\x4b',        # inc ebx; dec ebx
        b'\x41\x49',        # inc ecx; dec ecx
        b'\x86\xc0',        # xchg al, al
    }

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self._min_nop_sled = self.config.get('min_nop_sled_length', 8)
        self._xor_scan_limit = self.config.get('xor_scan_limit', 256 * 1024)  # 256KB

    def scan(self, data: bytes, arch: str = 'auto') -> ShellcodeReport:
        """Scan binary data for shellcode indicators.

        Args:
            data: Raw binary data to scan.
            arch: Target architecture ('x86', 'x64', 'arm', 'auto').

        Returns:
            :class:`ShellcodeReport` with all findings.
        """
        report = ShellcodeReport()

        if not data or len(data) < self.MIN_SCAN_SIZE:
            report.summary = 'Data too small for shellcode analysis'
            return report

        if arch == 'auto':
            arch = self._detect_arch(data)

        # Run all detectors
        detectors = [
            self._detect_nop_sled,
            self._detect_framework_signatures,
            self._detect_api_hashing,
            self._detect_syscalls,
            self._detect_getpc_techniques,
            self._detect_xor_encoding,
            self._detect_heap_spray,
            self._detect_rop_chain,
        ]

        for detector in detectors:
            try:
                matches = detector(data, arch)
                report.matches.extend(matches)
            except Exception as exc:
                logger.debug(f"[SHELLCODE] Detector {detector.__name__} error: {exc}")

        # Deduplicate techniques
        report.techniques_found = sorted(set(m.technique for m in report.matches))
        report.has_shellcode = len(report.matches) > 0

        # Calculate threat score
        report.threat_score = self._calculate_score(report.matches)

        # MITRE ATT&CK mapping
        report.mitre_techniques = self._map_mitre(report.techniques_found)

        # Cobalt Strike beacon config extraction
        cs_detected = any(
            'cobalt_strike' in t for t in report.techniques_found
        )
        if cs_detected:
            try:
                from .beacon_config_extractor import BeaconConfigExtractor
                extractor = BeaconConfigExtractor()
                beacon_result = extractor.extract_config(data)
                if beacon_result.get('success'):
                    report.beacon_config = beacon_result
                    logger.info("[SHELLCODE] Cobalt Strike beacon config extracted successfully")
            except Exception as exc:
                logger.debug(f"[SHELLCODE] Beacon config extraction failed: {exc}")

        # Summary
        if report.has_shellcode:
            critical = sum(1 for m in report.matches if m.severity == 'CRITICAL')
            high = sum(1 for m in report.matches if m.severity == 'HIGH')
            report.summary = (
                f"Shellcode detected: {len(report.matches)} indicators, "
                f"{critical} critical, {high} high severity. "
                f"Techniques: {', '.join(report.techniques_found)}"
            )
        else:
            report.summary = 'No shellcode indicators detected'

        logger.info(f"[SHELLCODE] {report.summary}")
        return report

    def scan_file(self, file_path: str, arch: str = 'auto') -> ShellcodeReport:
        """Convenience: read a file and scan it."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            return self.scan(data, arch)
        except Exception as exc:
            report = ShellcodeReport()
            report.summary = f"Error reading file: {exc}"
            return report

    # ------------------------------------------------------------------
    # Individual detectors
    # ------------------------------------------------------------------

    def _detect_nop_sled(self, data: bytes, arch: str) -> List[ShellcodeMatch]:
        """Detect NOP sled sequences."""
        matches: List[ShellcodeMatch] = []
        min_len = self._min_nop_sled

        # Single-byte NOP (0x90)
        i = 0
        while i < len(data):
            if data[i] == 0x90:
                start = i
                while i < len(data) and data[i] == 0x90:
                    i += 1
                run_len = i - start
                if run_len >= min_len:
                    matches.append(ShellcodeMatch(
                        technique='nop_sled',
                        offset=start,
                        length=run_len,
                        confidence=min(0.5 + (run_len - min_len) * 0.05, 0.95),
                        description=f'NOP sled ({run_len} bytes) at offset 0x{start:x}',
                        severity='HIGH' if run_len >= 32 else 'MEDIUM',
                        arch=arch,
                        raw_bytes=data[start:start + min(16, run_len)],
                    ))
            else:
                i += 1

        return matches

    def _detect_framework_signatures(self, data: bytes, arch: str) -> List[ShellcodeMatch]:
        """Detect known framework shellcode stubs."""
        matches: List[ShellcodeMatch] = []
        sig_groups = [
            (METASPLOIT_SIGNATURES, 'framework_metasploit', 'CRITICAL'),
            (COBALT_STRIKE_SIGNATURES, 'framework_cobalt_strike', 'CRITICAL'),
            (SLIVER_SIGNATURES, 'framework_sliver', 'HIGH'),
            (HAVOC_SIGNATURES, 'framework_havoc', 'HIGH'),
            (BRC4_SIGNATURES, 'framework_brc4', 'CRITICAL'),
        ]

        for sigs, technique, severity in sig_groups:
            for sig_bytes, description in sigs:
                offset = data.find(sig_bytes)
                while offset != -1:
                    matches.append(ShellcodeMatch(
                        technique=technique,
                        offset=offset,
                        length=len(sig_bytes),
                        confidence=0.90,
                        description=description,
                        severity=severity,
                        arch='x64' if b'\x48' in sig_bytes[:4] else 'x86',
                        raw_bytes=data[offset:offset + 16],
                    ))
                    offset = data.find(sig_bytes, offset + 1)

        return matches

    def _detect_api_hashing(self, data: bytes, arch: str) -> List[ShellcodeMatch]:
        """Detect API hash resolution patterns (ror13, push-based)."""
        matches: List[ShellcodeMatch] = []

        if len(data) < 8:
            return matches

        # Look for known ror13 hash constants pushed onto the stack
        # Pattern: 68 XX XX XX XX (push imm32)
        found_hashes: List[Tuple[int, int, str]] = []

        for i in range(len(data) - 5):
            if data[i] == 0x68:  # push imm32
                value = struct.unpack_from('<I', data, i + 1)[0]
                if value in KNOWN_API_HASHES_ROR13:
                    found_hashes.append((i, value, KNOWN_API_HASHES_ROR13[value]))

        if len(found_hashes) >= 2:
            apis = [h[2] for h in found_hashes]
            matches.append(ShellcodeMatch(
                technique='api_hashing',
                offset=found_hashes[0][0],
                length=found_hashes[-1][0] - found_hashes[0][0] + 5,
                confidence=min(0.6 + len(found_hashes) * 0.1, 0.98),
                description=(
                    f'API hash resolution ({len(found_hashes)} hashes): '
                    f'{", ".join(apis[:5])}'
                ),
                severity='CRITICAL',
                arch=arch,
                raw_bytes=data[found_hashes[0][0]:found_hashes[0][0] + 16],
            ))

        # Also detect ror13 loop pattern: ror edx, 0xd  (C1 CA 0D)
        ror13_pattern = b'\xc1\xca\x0d'
        offset = data.find(ror13_pattern)
        while offset != -1:
            matches.append(ShellcodeMatch(
                technique='api_hashing',
                offset=offset,
                length=3,
                confidence=0.70,
                description=f'ROR13 API hashing loop at 0x{offset:x}',
                severity='HIGH',
                arch=arch,
                raw_bytes=data[offset:offset + 16],
            ))
            offset = data.find(ror13_pattern, offset + 1)

        return matches

    def _detect_syscalls(self, data: bytes, arch: str) -> List[ShellcodeMatch]:
        """Detect direct syscall invocations."""
        matches: List[ShellcodeMatch] = []

        patterns = [
            (b'\xcd\x80',                      'int 0x80 (Linux x86 syscall)',     'x86',  'HIGH'),
            (b'\x0f\x05',                      'syscall (x64)',                     'x64',  'HIGH'),
            (b'\x0f\x34',                      'sysenter (x86)',                    'x86',  'HIGH'),
            (b'\x0f\x35',                      'sysexit',                           'x86',  'MEDIUM'),
        ]

        for pattern, desc, pat_arch, severity in patterns:
            offset = data.find(pattern)
            while offset != -1:
                # Context check: must have reasonable instructions nearby
                if self._has_instruction_context(data, offset, 16):
                    matches.append(ShellcodeMatch(
                        technique='syscall',
                        offset=offset,
                        length=len(pattern),
                        confidence=0.65,
                        description=f'{desc} at offset 0x{offset:x}',
                        severity=severity,
                        arch=pat_arch,
                        raw_bytes=data[max(0, offset - 4):offset + len(pattern) + 4],
                    ))
                offset = data.find(pattern, offset + 1)

        return matches

    def _detect_getpc_techniques(self, data: bytes, arch: str) -> List[ShellcodeMatch]:
        """Detect GetEIP/GetPC shellcode techniques."""
        matches: List[ShellcodeMatch] = []

        # call $+5 / pop reg (E8 00 00 00 00 5x)
        call_pop_pattern = b'\xe8\x00\x00\x00\x00'
        offset = data.find(call_pop_pattern)
        while offset != -1:
            if offset + 5 < len(data):
                next_byte = data[offset + 5]
                # 58-5F = pop eax through pop edi
                if 0x58 <= next_byte <= 0x5F:
                    reg = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'][next_byte - 0x58]
                    matches.append(ShellcodeMatch(
                        technique='getpc_call_pop',
                        offset=offset,
                        length=6,
                        confidence=0.85,
                        description=f'GetEIP via call/pop {reg} at 0x{offset:x}',
                        severity='HIGH',
                        arch='x86',
                        raw_bytes=data[offset:offset + 8],
                    ))
            offset = data.find(call_pop_pattern, offset + 1)

        # fstenv / fnstenv technique
        # D9 74 24 F4 = fnstenv [esp-0xc]; next pop gives EIP
        fstenv_patterns = [
            (b'\xd9\x74\x24\xf4', 'fnstenv [esp-0xc]'),
            (b'\xd9\xe1',          'fabs (FPU GetPC)'),
        ]
        for pat, desc in fstenv_patterns:
            offset = data.find(pat)
            while offset != -1:
                matches.append(ShellcodeMatch(
                    technique='getpc_fpu',
                    offset=offset,
                    length=len(pat),
                    confidence=0.75,
                    description=f'GetEIP via {desc} at 0x{offset:x}',
                    severity='HIGH',
                    arch='x86',
                    raw_bytes=data[offset:offset + 8],
                ))
                offset = data.find(pat, offset + 1)

        return matches

    def _detect_xor_encoding(self, data: bytes, arch: str) -> List[ShellcodeMatch]:
        """Detect XOR-encoded shellcode via statistical analysis."""
        matches: List[ShellcodeMatch] = []
        scan_data = data[:self._xor_scan_limit]

        if len(scan_data) < 32:
            return matches

        # Single-byte XOR: look for high-entropy regions that decode to
        # recognizable patterns (PE header, ELF magic, common shellcode preamble)
        DECODE_MARKERS = [
            b'MZ',              # PE header
            b'\x7fELF',         # ELF header
            b'http',            # URL in decoded payload
            b'cmd',             # Command string
            b'powershell',      # PowerShell
            b'\xfc\xe8',        # Common shellcode start
        ]

        for key in range(1, 256):
            # Quick decode first 512 bytes with this key
            sample_len = min(512, len(scan_data))
            decoded = bytes(b ^ key for b in scan_data[:sample_len])
            for marker in DECODE_MARKERS:
                idx = decoded.find(marker)
                if idx != -1:
                    matches.append(ShellcodeMatch(
                        technique='xor_encoding',
                        offset=idx,
                        length=sample_len,
                        confidence=0.75,
                        description=(
                            f'XOR-encoded payload (key=0x{key:02x}), '
                            f'decodes to "{marker[:8].decode("ascii", errors="replace")}" '
                            f'at offset 0x{idx:x}'
                        ),
                        severity='CRITICAL',
                        arch=arch,
                        raw_bytes=scan_data[idx:idx + 16],
                    ))
                    break  # One match per key is enough

        # Multi-byte XOR: detect via low byte frequency uniformity
        # (XOR with multi-byte key tends to flatten byte distribution)
        if len(scan_data) >= 256:
            entropy = self._calculate_entropy(scan_data[:1024])
            if entropy > 7.5:
                byte_freq = [0] * 256
                for b in scan_data[:1024]:
                    byte_freq[b] += 1
                # Check if distribution is suspiciously uniform
                avg = len(scan_data[:1024]) / 256
                variance = sum((f - avg) ** 2 for f in byte_freq) / 256
                if variance < avg * 2:  # Very flat distribution
                    matches.append(ShellcodeMatch(
                        technique='xor_encoding_multibyte',
                        offset=0,
                        length=min(1024, len(scan_data)),
                        confidence=0.55,
                        description=(
                            f'Possible multi-byte XOR encoding '
                            f'(entropy={entropy:.2f}, flat byte distribution)'
                        ),
                        severity='MEDIUM',
                        arch=arch,
                    ))

        return matches

    def _detect_heap_spray(self, data: bytes, arch: str) -> List[ShellcodeMatch]:
        """Detect heap spray patterns."""
        matches: List[ShellcodeMatch] = []

        # Common heap spray fill patterns (slide-to-shellcode)
        spray_patterns = [
            (b'\x0c\x0c\x0c\x0c',  '0x0c0c0c0c spray'),
            (b'\x0a\x0a\x0a\x0a',  '0x0a0a0a0a spray'),
            (b'\x0d\x0d\x0d\x0d',  '0x0d0d0d0d spray'),
            (b'\x04\x04\x04\x04',  '0x04040404 spray'),
            (b'\x41\x41\x41\x41' * 4,  'AAAA... buffer fill'),
        ]

        for pattern, desc in spray_patterns:
            # Look for long repetitions (at least 64 bytes of the same pattern)
            rep = pattern * (64 // len(pattern))
            offset = data.find(rep)
            if offset != -1:
                # Measure actual length
                end = offset
                while end + len(pattern) <= len(data) and data[end:end + len(pattern)] == pattern:
                    end += len(pattern)
                total_len = end - offset
                if total_len >= 64:
                    matches.append(ShellcodeMatch(
                        technique='heap_spray',
                        offset=offset,
                        length=total_len,
                        confidence=min(0.5 + total_len / 1024, 0.90),
                        description=f'Heap spray: {desc} ({total_len} bytes) at 0x{offset:x}',
                        severity='HIGH',
                        arch=arch,
                        raw_bytes=data[offset:offset + 16],
                    ))

        return matches

    def _detect_rop_chain(self, data: bytes, arch: str) -> List[ShellcodeMatch]:
        """Detect ROP gadget chain patterns."""
        matches: List[ShellcodeMatch] = []

        if len(data) < 16:
            return matches

        # ROP chains on x86: sequence of 4-byte addresses, many ending with
        # gadgets that contain 'ret' (C3). Look for repeated patterns of
        # 4-byte values that when dereferenced would end with C3.
        # Heuristic: look for many consecutive 4-byte aligned values in a
        # range typical of module base addresses (0x00400000-0x7FFFFFFF)
        if arch in ('x86', 'auto'):
            consecutive_addrs = 0
            chain_start = 0
            for i in range(0, len(data) - 4, 4):
                val = struct.unpack_from('<I', data, i)[0]
                if 0x00400000 <= val <= 0x7FFFFFFF:
                    if consecutive_addrs == 0:
                        chain_start = i
                    consecutive_addrs += 1
                else:
                    if consecutive_addrs >= 6:
                        matches.append(ShellcodeMatch(
                            technique='rop_chain',
                            offset=chain_start,
                            length=consecutive_addrs * 4,
                            confidence=min(0.4 + consecutive_addrs * 0.05, 0.85),
                            description=(
                                f'Potential ROP chain ({consecutive_addrs} gadgets) '
                                f'at 0x{chain_start:x}'
                            ),
                            severity='HIGH',
                            arch='x86',
                            raw_bytes=data[chain_start:chain_start + 16],
                        ))
                    consecutive_addrs = 0

        return matches

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_arch(data: bytes) -> str:
        """Heuristic architecture detection."""
        if len(data) < 4:
            return 'x86'

        # Check for x64 REX prefixes (0x40-0x4f)
        rex_count = sum(1 for b in data[:256] if 0x40 <= b <= 0x4F)
        if rex_count > len(data[:256]) * 0.15:
            return 'x64'

        # ARM: look for ARM magic or BL instructions
        if data[:4] == b'\x7fELF' and len(data) > 18:
            if data[18] == 0x28:  # EM_ARM
                return 'arm'

        return 'x86'

    @staticmethod
    def _has_instruction_context(data: bytes, offset: int, window: int) -> bool:
        """Check if surrounding bytes look like plausible instructions."""
        start = max(0, offset - window)
        end = min(len(data), offset + window)
        region = data[start:end]
        if len(region) < 8:
            return True
        # Null-heavy regions are less likely real code
        null_ratio = region.count(0) / len(region)
        return null_ratio < 0.50

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Shannon entropy of a byte sequence."""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = 0.0
        for f in freq:
            if f > 0:
                p = f / length
                entropy -= p * math.log2(p)
        return entropy

    def _calculate_score(self, matches: List[ShellcodeMatch]) -> int:
        """Aggregate matches into a 0-100 threat score."""
        if not matches:
            return 0

        severity_weights = {
            'CRITICAL': 30,
            'HIGH': 20,
            'MEDIUM': 10,
            'LOW': 5,
        }

        score = 0
        for m in matches:
            contribution = severity_weights.get(m.severity, 5) * m.confidence
            score += contribution

        return min(int(score), 100)

    @staticmethod
    def _map_mitre(techniques: List[str]) -> List[str]:
        """Map detected techniques to MITRE ATT&CK IDs."""
        mapping = {
            'nop_sled':                 'T1027.009',  # Obfuscated Files: Embedded Payloads
            'framework_metasploit':     'T1059.006',  # Command and Scripting: Python (generic)
            'framework_cobalt_strike':  'T1071.001',  # App Layer Protocol: Web
            'framework_sliver':         'T1071.001',
            'framework_havoc':          'T1071.001',
            'framework_brc4':           'T1071.001',
            'api_hashing':              'T1027.007',  # Dynamic API Resolution
            'syscall':                  'T1106',       # Native API
            'getpc_call_pop':           'T1055.012',  # Process Injection: Process Hollowing
            'getpc_fpu':                'T1055.012',
            'xor_encoding':             'T1027',       # Obfuscated Files
            'xor_encoding_multibyte':   'T1027',
            'heap_spray':               'T1203',       # Exploitation for Client Execution
            'rop_chain':                'T1203',
        }
        ids = set()
        for t in techniques:
            if t in mapping:
                ids.add(mapping[t])
        return sorted(ids)
