"""
Author: Ugur Ates
Packer / Crypter / Protector Detection Module.

Detection techniques:
- Byte-pattern signatures for known packers (UPX, Themida, VMProtect, ASPack, ...)
- Section name heuristics
- Import table anomaly detection (only LoadLibrary + GetProcAddress)
- Entropy profile analysis (packed sections have entropy > 7.0)
- Entry point pattern matching
- Overlay detection for appended packer data

Best Practice: Malware commonly uses packers to evade static analysis.
Detecting the packer helps the analyst decide whether to attempt unpacking.
"""

import logging
import math
import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Check pefile availability
PEFILE_AVAILABLE = False
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    logger.debug("[PACKER] pefile not available")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PackerMatch:
    """Single packer detection hit."""
    packer_name: str
    detection_method: str   # 'signature', 'section_name', 'import_anomaly', 'entropy', 'entry_point'
    confidence: float       # 0.0 - 1.0
    description: str
    offset: int = 0
    details: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'packer_name': self.packer_name,
            'detection_method': self.detection_method,
            'confidence': round(self.confidence, 2),
            'description': self.description,
            'offset': self.offset,
            'details': self.details,
        }


@dataclass
class PackerReport:
    """Aggregated packer detection report."""
    is_packed: bool = False
    packer_name: str = ''
    threat_score: int = 0
    matches: List[PackerMatch] = field(default_factory=list)
    summary: str = ''
    entropy_profile: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'is_packed': self.is_packed,
            'packer_name': self.packer_name,
            'threat_score': self.threat_score,
            'match_count': len(self.matches),
            'matches': [m.to_dict() for m in self.matches],
            'summary': self.summary,
            'entropy_profile': self.entropy_profile,
        }


# ---------------------------------------------------------------------------
# Packer signature database
# ---------------------------------------------------------------------------

# (byte_offset_from_EP, bytes, packer_name, description)
ENTRY_POINT_SIGNATURES: List[Tuple[int, bytes, str, str]] = [
    # UPX
    (0, b'\x60\xBE', 'UPX', 'UPX entry point (pushad + mov esi)'),
    (0, b'\x60\x89\xE5\x31', 'UPX', 'UPX variant entry point'),

    # ASPack
    (0, b'\x60\xE8\x00\x00\x00\x00', 'ASPack', 'ASPack entry (pushad + call $+5)'),
    (0, b'\x60\xE8\x03\x00\x00\x00', 'ASPack', 'ASPack 2.x entry'),

    # PECompact
    (0, b'\xB8\x00\x00\x00\x00\x50\x64', 'PECompact', 'PECompact entry point'),

    # Themida / WinLicense
    (0, b'\xB8\x00\x00\x00\x00\x60\x0B\xC0', 'Themida', 'Themida entry point'),
    (0, b'\xEB\x01\xE8', 'Themida', 'Themida anti-disassembly entry'),

    # VMProtect
    (0, b'\x68\x00\x00\x00\x00\xE8', 'VMProtect', 'VMProtect push + call entry'),

    # MPRESS
    (0, b'\x60\xE8\x00\x00\x00\x00\x58', 'MPRESS', 'MPRESS entry (pushad+call+pop)'),

    # Petite
    (0, b'\xB8\x00\x00\x00\x00\x66\x9C\x60\x50', 'Petite', 'Petite entry point'),

    # Obsidium
    (0, b'\xEB\x02\x00\x00\xE8', 'Obsidium', 'Obsidium entry point'),

    # Enigma
    (0, b'\x60\xE8\x00\x00\x00\x00\x5D', 'Enigma', 'Enigma Protector entry'),

    # NSPack
    (0, b'\x9C\x60\xE8\x00\x00\x00\x00', 'NSPack', 'NSPack entry (pushfd+pushad+call)'),

    # ConfuserEx (.NET)
    (0, b'\x46\x69\x6C\x65', 'ConfuserEx', 'ConfuserEx .NET protector marker'),
]

# Section name -> packer mapping
PACKER_SECTION_NAMES: Dict[str, str] = {
    'UPX0':      'UPX',
    'UPX1':      'UPX',
    'UPX2':      'UPX',
    '.UPX':      'UPX',
    '.aspack':   'ASPack',
    '.adata':    'ASPack',
    '.ASPack':   'ASPack',
    'PEC2':      'PECompact',
    'PECompact2':'PECompact',
    '.PEC':      'PECompact',
    '.themida':  'Themida',
    '.tmd':      'Themida',
    '.Themida':  'Themida',
    '.vmp0':     'VMProtect',
    '.vmp1':     'VMProtect',
    '.vmp2':     'VMProtect',
    '.VMP':      'VMProtect',
    '.enigma1':  'Enigma',
    '.enigma2':  'Enigma',
    '.MPRESS1':  'MPRESS',
    '.MPRESS2':  'MPRESS',
    '.petite':   'Petite',
    '.nsp0':     'NSPack',
    '.nsp1':     'NSPack',
    '.ndata':    'NSIS Installer',
    'CODE':      'Delphi/Borland',
    '.rsrc':     None,    # ignore - standard resource section
}

# Byte pattern signatures (searched anywhere in the file)
RAW_BYTE_SIGNATURES: List[Tuple[bytes, str, str]] = [
    (b'UPX!',                       'UPX',        'UPX magic marker'),
    (b'PEC2',                       'PECompact',  'PECompact magic'),
    (b'.themida',                   'Themida',    'Themida section marker'),
    (b'.vmp0',                      'VMProtect',  'VMProtect section marker'),
    (b'MPRESS1',                    'MPRESS',     'MPRESS section marker'),
    (b'Obsidium',                   'Obsidium',   'Obsidium marker string'),
    (b'The Enigma Protector',       'Enigma',     'Enigma Protector string'),
    (b'\x00\x00\x00\x00NullsoftInst', 'NSIS',    'NSIS installer marker'),
    (b'Inno Setup',                 'Inno Setup', 'Inno Setup installer'),
    (b'InstallShield',              'InstallShield', 'InstallShield marker'),
]


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

class PackerDetector:
    """
    Multi-technique packer / crypter / protector detection engine.

    Usage::

        detector = PackerDetector()
        report = detector.analyze_file("sample.exe")
        if report.is_packed:
            print(f"Packed with {report.packer_name}")
    """

    # Entropy thresholds
    HIGH_ENTROPY_THRESHOLD = 7.0
    VERY_HIGH_ENTROPY_THRESHOLD = 7.6

    def __init__(self):
        pass

    def analyze_file(self, file_path: str) -> PackerReport:
        """Full packer analysis of a PE file.

        Args:
            file_path: Path to PE executable.

        Returns:
            :class:`PackerReport` with detection results.
        """
        report = PackerReport()

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception as exc:
            report.summary = f'Error reading file: {exc}'
            return report

        return self.analyze_data(data, file_name=Path(file_path).name)

    def analyze_data(self, data: bytes, file_name: str = '') -> PackerReport:
        """Analyze raw PE data for packer indicators."""
        report = PackerReport()

        if len(data) < 64:
            report.summary = 'File too small for packer analysis'
            return report

        # 1. Raw byte signatures (works without pefile)
        report.matches.extend(self._check_raw_signatures(data))

        # 2. PE-level analysis (requires pefile)
        if PEFILE_AVAILABLE and data[:2] == b'MZ':
            try:
                pe = pefile.PE(data=data, fast_load=False)
                report.matches.extend(self._check_section_names(pe))
                report.matches.extend(self._check_entry_point_signatures(pe, data))
                report.matches.extend(self._check_import_anomalies(pe))
                report.entropy_profile = self._build_entropy_profile(pe)
                report.matches.extend(
                    self._check_entropy_anomalies(pe, report.entropy_profile)
                )
                pe.close()
            except Exception as exc:
                logger.debug(f"[PACKER] PE parse error: {exc}")

        # 3. Aggregate results
        if report.matches:
            report.is_packed = True
            # Pick highest confidence match as primary
            best = max(report.matches, key=lambda m: m.confidence)
            report.packer_name = best.packer_name
            report.threat_score = self._calculate_score(report.matches)
            names = sorted(set(m.packer_name for m in report.matches))
            report.summary = (
                f"Packer detected: {', '.join(names)} "
                f"({len(report.matches)} indicators)"
            )
        else:
            report.summary = 'No packer indicators detected'

        logger.info(f"[PACKER] {file_name}: {report.summary}")
        return report

    # ------------------------------------------------------------------
    # Detection methods
    # ------------------------------------------------------------------

    def _check_raw_signatures(self, data: bytes) -> List[PackerMatch]:
        matches = []
        for sig, name, desc in RAW_BYTE_SIGNATURES:
            offset = data.find(sig)
            if offset != -1:
                matches.append(PackerMatch(
                    packer_name=name,
                    detection_method='signature',
                    confidence=0.80,
                    description=desc,
                    offset=offset,
                ))
        return matches

    def _check_section_names(self, pe) -> List[PackerMatch]:
        matches = []
        for section in pe.sections:
            name = section.Name.decode('ascii', errors='ignore').rstrip('\x00').strip()
            if name in PACKER_SECTION_NAMES and PACKER_SECTION_NAMES[name]:
                packer = PACKER_SECTION_NAMES[name]
                matches.append(PackerMatch(
                    packer_name=packer,
                    detection_method='section_name',
                    confidence=0.85,
                    description=f'Packer section name: {name}',
                    details={'section_name': name},
                ))
        return matches

    def _check_entry_point_signatures(self, pe, data: bytes) -> List[PackerMatch]:
        matches = []
        ep_offset = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        try:
            ep_file_offset = pe.get_offset_from_rva(ep_offset)
        except Exception:
            return matches

        ep_bytes = data[ep_file_offset:ep_file_offset + 32]
        if len(ep_bytes) < 4:
            return matches

        for offset, sig, name, desc in ENTRY_POINT_SIGNATURES:
            if offset < len(ep_bytes):
                region = ep_bytes[offset:]
                # For patterns with null bytes (wildcards), only match non-null bytes
                if len(sig) <= len(region) and self._pattern_match(sig, region):
                    matches.append(PackerMatch(
                        packer_name=name,
                        detection_method='entry_point',
                        confidence=0.75,
                        description=f'{desc} at EP+{offset}',
                        offset=ep_file_offset + offset,
                        details={'ep_rva': ep_offset, 'first_bytes': ep_bytes[:16].hex()},
                    ))
        return matches

    def _check_import_anomalies(self, pe) -> List[PackerMatch]:
        """Detect suspiciously small import tables (typical of packed files)."""
        matches = []
        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
                ])

            imports = getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
            total_functions = 0
            dll_names = []
            has_loadlib = False
            has_getproc = False

            for entry in imports:
                dll_name = entry.dll.decode('ascii', errors='ignore').lower()
                dll_names.append(dll_name)
                for imp in entry.imports:
                    total_functions += 1
                    if imp.name:
                        fname = imp.name.decode('ascii', errors='ignore')
                        if 'LoadLibrary' in fname:
                            has_loadlib = True
                        if 'GetProcAddress' in fname:
                            has_getproc = True

            # Anomaly 1: Very few imports (packed files resolve dynamically)
            if 0 < total_functions <= 5:
                matches.append(PackerMatch(
                    packer_name='Unknown Packer',
                    detection_method='import_anomaly',
                    confidence=0.65,
                    description=(
                        f'Minimal import table ({total_functions} functions from '
                        f'{len(dll_names)} DLLs) - typical of packed executables'
                    ),
                    details={'total_imports': total_functions, 'dlls': dll_names},
                ))

            # Anomaly 2: Only LoadLibrary + GetProcAddress (dynamic resolution)
            if has_loadlib and has_getproc and total_functions <= 10:
                matches.append(PackerMatch(
                    packer_name='Dynamic Resolver',
                    detection_method='import_anomaly',
                    confidence=0.70,
                    description=(
                        'Import table contains only LoadLibrary + GetProcAddress '
                        '(runtime API resolution, common in packed/shellcode loaders)'
                    ),
                    details={'has_loadlib': True, 'has_getproc': True},
                ))

        except Exception as exc:
            logger.debug(f"[PACKER] Import check error: {exc}")

        return matches

    def _check_entropy_anomalies(self, pe, profile: Dict) -> List[PackerMatch]:
        """Detect packer-typical entropy patterns."""
        matches = []
        sections = profile.get('sections', [])

        high_entropy_count = 0
        rwx_high_entropy = False

        for sec_info in sections:
            ent = sec_info['entropy']
            name = sec_info['name']
            chars = sec_info.get('characteristics', 0)

            if ent >= self.HIGH_ENTROPY_THRESHOLD:
                high_entropy_count += 1

            # Writable + Executable + high entropy
            is_writable = bool(chars & 0x80000000)   # IMAGE_SCN_MEM_WRITE
            is_executable = bool(chars & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
            if is_writable and is_executable and ent >= self.HIGH_ENTROPY_THRESHOLD:
                rwx_high_entropy = True
                matches.append(PackerMatch(
                    packer_name='Unknown Packer',
                    detection_method='entropy',
                    confidence=0.75,
                    description=(
                        f'Section "{name}" is writable+executable with high entropy '
                        f'({ent:.2f}) - strong packing indicator'
                    ),
                    details={'section': name, 'entropy': round(ent, 2), 'rwx': True},
                ))

        # Overall high entropy
        overall = profile.get('overall_entropy', 0)
        if overall >= self.VERY_HIGH_ENTROPY_THRESHOLD:
            matches.append(PackerMatch(
                packer_name='Unknown Packer',
                detection_method='entropy',
                confidence=0.60,
                description=(
                    f'Very high overall entropy ({overall:.2f}) suggests '
                    f'encryption or heavy packing'
                ),
                details={'overall_entropy': round(overall, 2)},
            ))

        # Most sections have high entropy
        total = len(sections)
        if total >= 2 and high_entropy_count >= total * 0.75:
            matches.append(PackerMatch(
                packer_name='Unknown Packer',
                detection_method='entropy',
                confidence=0.65,
                description=(
                    f'{high_entropy_count}/{total} sections have high entropy '
                    f'(≥{self.HIGH_ENTROPY_THRESHOLD})'
                ),
                details={'high_entropy_sections': high_entropy_count, 'total_sections': total},
            ))

        return matches

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_entropy_profile(pe) -> Dict:
        """Build entropy profile for all PE sections."""
        sections = []
        all_data = b''
        for section in pe.sections:
            name = section.Name.decode('ascii', errors='ignore').rstrip('\x00').strip()
            data = section.get_data()
            ent = PackerDetector._entropy(data) if data else 0.0
            sections.append({
                'name': name,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': round(ent, 4),
                'characteristics': section.Characteristics,
            })
            all_data += data

        overall = PackerDetector._entropy(all_data) if all_data else 0.0
        return {
            'sections': sections,
            'overall_entropy': round(overall, 4),
            'section_count': len(sections),
        }

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        ent = 0.0
        for f in freq:
            if f > 0:
                p = f / length
                ent -= p * math.log2(p)
        return ent

    @staticmethod
    def _pattern_match(pattern: bytes, data: bytes) -> bool:
        """Match pattern against data, treating 0x00 in pattern as wildcard."""
        for i, p in enumerate(pattern):
            if i >= len(data):
                return False
            if p != 0x00 and p != data[i]:
                return False
        return True

    @staticmethod
    def _calculate_score(matches: List[PackerMatch]) -> int:
        if not matches:
            return 0
        # Base: 30 for any packing, +10 per additional indicator, up to 80
        score = 30
        for m in matches[1:]:
            score += int(10 * m.confidence)
        # Known protectors bump score higher
        protectors = {'Themida', 'VMProtect', 'Enigma', 'Obsidium'}
        for m in matches:
            if m.packer_name in protectors:
                score = max(score, 60)
                break
        return min(score, 80)
