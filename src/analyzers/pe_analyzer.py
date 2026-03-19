"""
PE Analyzer - Profesyonel Windows Executable Analizi.

Entegre Araclar:
- pefile: PE header parsing
- capa: Capability detection (Mandiant)
- FLOSS: Obfuscated string extraction (Mandiant)
- DIE: Packer/compiler detection
- YARA: Malware family detection

v2.0.0 - Enhanced Analysis Suite with Deep Inspection
"""

import os
import re
import math
import struct
import time
import logging
import datetime
from typing import Dict, List, Optional, Tuple
from collections import Counter
from pathlib import Path

from .ransomware_analyzer import RansomwareAnalyzer

logger = logging.getLogger(__name__)

# pefile availability
PEFILE_AVAILABLE = False
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    logger.warning("[PE] pefile not available - install with: pip install pefile")


class PEAnalyzer:
    """
    Profesyonel PE file analizi with external tool integration.

    Features:
    - PE header parsing (pefile)
    - Capability detection (capa)
    - Obfuscated string extraction (FLOSS)
    - Packer/compiler detection (DIE)
    - Section entropy analysis
    - Import/Export analysis
    - Suspicious indicator detection
    - TLS callback detection
    - PDB path extraction & analysis
    - Rich header analysis
    - Resource analysis (embedded PEs, scripts, language anomalies)
    - Import count anomaly detection
    - Ordinal-only import detection
    - Compilation timestamp analysis
    - PE checksum validation
    - Manifest analysis (UAC bypass, privilege escalation)
    - Entry point anomaly detection
    - DOS stub analysis
    - Section permission analysis (W+X)
    """

    # Known packer sections
    PACKER_SECTIONS = {
        'UPX': ['UPX0', 'UPX1', 'UPX2', '.UPX'],
        'ASPack': ['.aspack', '.adata', '.ASPack'],
        'PECompact': ['PEC2', 'PECompact2', '.PEC'],
        'Themida': ['.themida', '.tmd', '.Themida'],
        'VMProtect': ['.vmp0', '.vmp1', '.vmp2', '.VMP'],
        'Enigma': ['.enigma1', '.enigma2'],
        'MPRESS': ['.MPRESS1', '.MPRESS2'],
        'Petite': ['.petite'],
    }

    # Suspicious imports by category
    SUSPICIOUS_IMPORTS = {
        'process_injection': [
            'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
            'CreateRemoteThread', 'CreateRemoteThreadEx', 'WriteProcessMemory',
            'ReadProcessMemory', 'NtCreateThreadEx', 'RtlCreateUserThread',
            'NtAllocateVirtualMemory', 'NtProtectVirtualMemory',
            'QueueUserAPC', 'NtQueueApcThread', 'SetThreadContext',
        ],
        'process_hollowing': [
            'NtUnmapViewOfSection', 'ZwUnmapViewOfSection',
            'NtResumeThread', 'ZwResumeThread',
        ],
        'code_loading': [
            'LoadLibrary', 'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryEx',
            'GetProcAddress', 'GetModuleHandle', 'LdrLoadDll',
        ],
        'process_creation': [
            'CreateProcess', 'CreateProcessA', 'CreateProcessW',
            'ShellExecute', 'ShellExecuteA', 'ShellExecuteW',
            'WinExec', 'system',
        ],
        'network': [
            'URLDownloadToFile', 'InternetOpen', 'InternetOpenUrl',
            'InternetReadFile', 'HttpSendRequest', 'HttpOpenRequest',
            'WSAStartup', 'socket', 'connect', 'send', 'recv',
        ],
        'registry': [
            'RegSetValue', 'RegSetValueEx', 'RegCreateKey', 'RegCreateKeyEx',
            'RegOpenKey', 'RegOpenKeyEx', 'RegDeleteKey',
        ],
        'crypto': [
            'CryptAcquireContext', 'CryptEncrypt', 'CryptDecrypt',
            'CryptGenKey', 'CryptDeriveKey', 'BCryptEncrypt',
        ],
        'keylogger': [
            'SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyState',
            'GetKeyboardState', 'RegisterHotKey',
        ],
        'anti_debug': [
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
            'NtQueryInformationProcess', 'OutputDebugString',
        ],
    }

    # Suspicious PDB path patterns
    _SUSPICIOUS_PDB_PATTERNS = [
        (re.compile(r'(?i)\\(hack|exploit|rat|trojan|virus|malware|payload|shell|inject|keylog|ransom|crypter|fud|stealer|botnet|ddos|rootkit)'), 'high'),
        (re.compile(r'(?i)\\(test|debug|release)\\', re.IGNORECASE), 'info'),
        (re.compile(r'[\u0400-\u04ff]'), 'medium'),  # Cyrillic characters
        (re.compile(r'[\u4e00-\u9fff]'), 'medium'),  # Chinese characters
        (re.compile(r'[\u0600-\u06ff]'), 'medium'),  # Arabic characters
        (re.compile(r'(?i)C:\\Users\\[^\\]+\\Desktop\\'), 'low'),
        (re.compile(r'(?i)C:\\Users\\[^\\]+\\Downloads\\'), 'low'),
        (re.compile(r'(?i)\\(temp|tmp)\\', re.IGNORECASE), 'low'),
    ]

    # Known Delphi epoch timestamp: 1992-06-19 22:22:17 UTC
    DELPHI_TIMESTAMP = 708992537

    # Standard DOS stub message
    _STANDARD_DOS_STUB = b'This program cannot be run in DOS mode'

    def __init__(self):
        """Initialize PE analyzer with tool integration."""
        self._init_tools()
        self.ransomware_analyzer = RansomwareAnalyzer()

    def _init_tools(self):
        """Initialize external tools."""
        try:
            from ..tools.external_tool_runner import get_tool_runner
            self.tool_runner = get_tool_runner()
        except Exception:
            self.tool_runner = None

        try:
            from .capability_analyzer import CapabilityAnalyzer
            self.capa_analyzer = CapabilityAnalyzer()
        except Exception:
            self.capa_analyzer = None

        try:
            from .obfuscated_string_analyzer import ObfuscatedStringAnalyzer
            self.floss_analyzer = ObfuscatedStringAnalyzer()
        except Exception:
            self.floss_analyzer = None

    def analyze(self, file_path: str) -> Dict:
        """
        Kapsamli PE analizi with all integrated tools.

        Pipeline:
        1. PE header analysis (pefile)
        2. Deep inspection checks (TLS, PDB, Rich header, resources, etc.)
        3. Capability detection (capa)
        4. Obfuscated string extraction (FLOSS)
        5. Packer/compiler detection (DIE)
        6. Combined threat scoring
        """
        logger.info(f"[PE] Analyzing: {Path(file_path).name}")

        result = {
            'file_path': file_path,
            'file_type': 'PE',
            'analysis_tools': [],
            'is_pe': False,

            # PE analysis
            'pe_analysis': {
                'headers': {},
                'sections': [],
                'imports': [],
                'exports': [],
                'resources': [],
                'entropy': {},
                'packer_detected': None,
                'suspicious_imports': [],
                'anomalies': [],
                'threat_score': 0,
            },

            # Deep inspection results
            'deep_inspection': {
                'tls_callbacks': {},
                'pdb_info': {},
                'rich_header': {},
                'resource_analysis': {},
                'import_anomalies': {},
                'ordinal_imports': {},
                'timestamp_analysis': {},
                'checksum_validation': {},
                'manifest_analysis': {},
                'entry_point_analysis': {},
                'dos_stub_analysis': {},
                'section_permissions': {},
            },

            # External tools
            'capabilities': {},
            'strings': {},
            'packer_detection': {},
            'embedded_files': {},

            # Combined
            'threat_indicators': [],
            'threat_score': 0,
            'verdict': 'UNKNOWN',
            'raw_outputs': {},
        }

        # 1. PE Header Analysis (pefile)
        if PEFILE_AVAILABLE:
            pe_result = self._analyze_pe_headers(file_path)
            result['pe_analysis'] = pe_result
            result['is_pe'] = pe_result.get('is_pe', False)
            result['analysis_tools'].append('pefile')

            if pe_result.get('suspicious_imports'):
                for imp in pe_result['suspicious_imports'][:5]:
                    result['threat_indicators'].append(f"Suspicious import: {imp}")

            # 1b. Deep Inspection Checks (only if PE parsed successfully)
            if result['is_pe']:
                deep = self._run_deep_inspection(file_path)
                result['deep_inspection'] = deep

                # Collect threat indicators from deep inspection
                self._collect_deep_inspection_indicators(deep, result['threat_indicators'])

        # 2. Capability Detection (capa)
        if self.capa_analyzer and self.tool_runner and self.tool_runner.is_available('capa'):
            capa_result = self.capa_analyzer.analyze(file_path)
            if capa_result.success:
                result['capabilities'] = {
                    'success': True,
                    'capabilities': [
                        {'name': c.name, 'namespace': c.namespace, 'attack_ids': c.attack_ids}
                        for c in capa_result.capabilities
                    ],
                    'attack_techniques': capa_result.attack_techniques,
                    'mbc_behaviors': capa_result.mbc_behaviors,
                    'threat_score': capa_result.threat_score,
                    'summary': capa_result.summary,
                }
                result['raw_outputs']['capa'] = capa_result.raw_output[:50000]
                result['analysis_tools'].append('capa')

                if capa_result.capabilities:
                    result['threat_indicators'].append(
                        f"capa: {len(capa_result.capabilities)} capabilities detected"
                    )

        # 3. Obfuscated String Extraction (FLOSS)
        if self.floss_analyzer and self.tool_runner and self.tool_runner.is_available('floss'):
            floss_result = self.floss_analyzer.analyze(file_path)
            if floss_result.success:
                result['strings'] = {
                    'success': True,
                    'static_count': len(floss_result.static_strings),
                    'decoded_count': len(floss_result.decoded_strings),
                    'stack_count': len(floss_result.stack_strings),
                    'tight_count': len(floss_result.tight_strings),
                    'urls': floss_result.urls[:30],
                    'ips': floss_result.ips[:30],
                    'domains': floss_result.domains[:30],
                    'registry_keys': floss_result.registry_keys[:30],
                    'suspicious_strings': floss_result.suspicious_strings[:50],
                    'threat_score': floss_result.threat_score,
                    'summary': floss_result.summary,
                }
                result['raw_outputs']['floss'] = floss_result.raw_output[:50000]
                result['analysis_tools'].append('floss')

                if floss_result.decoded_strings:
                    result['threat_indicators'].append(
                        f"FLOSS: {len(floss_result.decoded_strings)} decoded strings (obfuscation)"
                    )

        # 4. Packer/Compiler Detection (DIE)
        if self.tool_runner and self.tool_runner.is_available('diec'):
            die_result = self.tool_runner.run_diec(file_path)
            if die_result.success and die_result.parsed_output:
                result['packer_detection'] = self._parse_die_output(die_result.parsed_output)
                result['raw_outputs']['diec'] = die_result.stdout
                result['analysis_tools'].append('diec')

                if result['packer_detection'].get('packers'):
                    result['threat_indicators'].append(
                        f"DIE: Packed with {result['packer_detection']['packers'][0]}"
                    )
                if result['packer_detection'].get('protectors'):
                    result['threat_indicators'].append(
                        f"DIE: Protected with {result['packer_detection']['protectors'][0]}"
                    )

        # 5. Embedded Files (binwalk)
        if self.tool_runner and self.tool_runner.is_available('binwalk'):
            binwalk_result = self.tool_runner.run_binwalk_signature(file_path)
            if binwalk_result.success:
                result['embedded_files'] = self._parse_binwalk_output(binwalk_result.stdout)
                result['raw_outputs']['binwalk'] = binwalk_result.stdout
                result['analysis_tools'].append('binwalk')

        # 5b. Ransomware-specific analysis
        logger.info("[PE] Running ransomware-specific analysis...")
        ransomware_results = self.ransomware_analyzer.analyze_file(file_path)
        result['ransomware_analysis'] = ransomware_results
        result['analysis_tools'].append('ransomware_analyzer')

        if ransomware_results.get('is_ransomware'):
            result['threat_indicators'].append(
                f"RANSOMWARE: {ransomware_results.get('verdict')} "
                f"(score: {ransomware_results.get('ransomware_score')}, "
                f"family: {ransomware_results.get('family', 'Unknown')})"
            )
            # Add MITRE techniques from ransomware analysis
            for technique in ransomware_results.get('mitre_techniques', []):
                result['threat_indicators'].append(f"MITRE: {technique} (ransomware)")

        # 6. Calculate combined score
        result['threat_score'] = self._calculate_combined_score(result)
        result['verdict'] = self._determine_verdict(result['threat_score'])

        return result

    # Alias for compatibility
    def analyze_file(self, file_path: str) -> Dict:
        """Alias for analyze() for backward compatibility."""
        return self.analyze(file_path)

    # ------------------------------------------------------------------ #
    #  Deep Inspection Orchestrator                                       #
    # ------------------------------------------------------------------ #

    def _run_deep_inspection(self, file_path: str) -> Dict:
        """Run all deep inspection checks on a valid PE file."""
        deep = {
            'tls_callbacks': {},
            'pdb_info': {},
            'rich_header': {},
            'resource_analysis': {},
            'import_anomalies': {},
            'ordinal_imports': {},
            'timestamp_analysis': {},
            'checksum_validation': {},
            'manifest_analysis': {},
            'entry_point_analysis': {},
            'dos_stub_analysis': {},
            'section_permissions': {},
        }

        try:
            pe = pefile.PE(file_path)
        except Exception as e:
            logger.error(f"[PE] Deep inspection failed to open PE: {e}")
            return deep

        try:
            raw_data = None
            try:
                with open(file_path, 'rb') as f:
                    raw_data = f.read()
            except Exception:
                pass

            deep['tls_callbacks'] = self._check_tls_callbacks(pe)
            deep['pdb_info'] = self._check_pdb_path(pe)
            deep['rich_header'] = self._check_rich_header(pe, raw_data)
            deep['resource_analysis'] = self._check_resources(pe)
            deep['import_anomalies'] = self._check_import_count_anomalies(pe)
            deep['ordinal_imports'] = self._check_ordinal_imports(pe)
            deep['timestamp_analysis'] = self._check_timestamp(pe)
            deep['checksum_validation'] = self._check_checksum(pe)
            deep['manifest_analysis'] = self._check_manifest(pe)
            deep['entry_point_analysis'] = self._check_entry_point(pe)
            deep['dos_stub_analysis'] = self._check_dos_stub(pe, raw_data)
            deep['section_permissions'] = self._check_section_permissions(pe)
        except Exception as e:
            logger.error(f"[PE] Deep inspection error: {e}")
        finally:
            try:
                pe.close()
            except Exception:
                pass

        return deep

    def _collect_deep_inspection_indicators(self, deep: Dict, indicators: List[str]):
        """Extract high-severity findings from deep inspection into threat_indicators."""
        severity_threshold = {'critical', 'high'}

        for check_name, check_result in deep.items():
            findings = check_result.get('findings', [])
            for finding in findings:
                sev = finding.get('severity', 'info')
                if sev in severity_threshold:
                    desc = finding.get('description', check_name)
                    mitre = finding.get('mitre_attack', '')
                    tag = f" [{mitre}]" if mitre else ''
                    indicators.append(f"[{sev.upper()}] {desc}{tag}")

    # ------------------------------------------------------------------ #
    #  1. TLS Callback Detection                                         #
    # ------------------------------------------------------------------ #

    def _check_tls_callbacks(self, pe) -> Dict:
        """
        Check for TLS (Thread Local Storage) callbacks.

        TLS callbacks execute before the entry point and are commonly abused by
        malware for anti-debugging, anti-analysis, and payload unpacking.
        """
        result = {
            'has_tls': False,
            'callback_count': 0,
            'callback_addresses': [],
            'findings': [],
        }

        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                return result

            tls = pe.DIRECTORY_ENTRY_TLS
            result['has_tls'] = True

            # Collect callback addresses
            if hasattr(tls.struct, 'AddressOfCallBacks') and tls.struct.AddressOfCallBacks:
                callbacks = []
                callback_rva = tls.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase

                try:
                    idx = 0
                    addr_size = 8 if pe.PE_TYPE == 0x20b else 4  # PE32+ vs PE32
                    fmt = '<Q' if addr_size == 8 else '<I'
                    while True:
                        cb_data = pe.get_data(callback_rva + idx * addr_size, addr_size)
                        cb_addr = struct.unpack(fmt, cb_data)[0]
                        if cb_addr == 0:
                            break
                        callbacks.append(hex(cb_addr))
                        idx += 1
                        if idx > 64:  # safety limit
                            break
                except Exception:
                    pass

                result['callback_addresses'] = callbacks
                result['callback_count'] = len(callbacks)

            if result['callback_count'] > 0:
                result['findings'].append({
                    'description': f"PE contains {result['callback_count']} TLS callback(s) that execute before entry point",
                    'detail': f"Callback addresses: {', '.join(result['callback_addresses'][:10])}",
                    'severity': 'high',
                    'reason': 'TLS callbacks execute before the main entry point and are used by '
                              'malware for anti-debug checks, environment detection, and payload unpacking',
                    'mitre_attack': 'T1055.012',
                })
            elif result['has_tls']:
                result['findings'].append({
                    'description': 'TLS directory present but no callbacks registered',
                    'severity': 'low',
                    'reason': 'TLS directory without callbacks is unusual but not necessarily malicious',
                    'mitre_attack': '',
                })

        except Exception as e:
            logger.debug(f"[PE] TLS callback check error: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  2. PDB Path Extraction & Analysis                                 #
    # ------------------------------------------------------------------ #

    def _check_pdb_path(self, pe) -> Dict:
        """
        Extract and analyze PDB debug path from the debug directory.

        PDB paths can reveal developer usernames, project names, and development
        environments. Suspicious paths may indicate malware toolkits.
        """
        result = {
            'has_debug_info': False,
            'pdb_path': None,
            'debug_type': None,
            'findings': [],
        }

        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                return result

            for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
                # IMAGE_DEBUG_TYPE_CODEVIEW = 2
                if debug_entry.struct.Type == 2:
                    result['has_debug_info'] = True
                    result['debug_type'] = 'CodeView'

                    debug_data = pe.get_data(
                        debug_entry.struct.AddressOfRawData,
                        debug_entry.struct.SizeOfData,
                    )

                    # CodeView signature: RSDS (PDB 7.0) or NB10 (PDB 2.0)
                    if debug_data[:4] == b'RSDS':
                        # RSDS: 4 sig + 16 GUID + 4 age + pdb_path
                        pdb_path_bytes = debug_data[24:]
                        pdb_path = pdb_path_bytes.split(b'\x00')[0].decode('utf-8', errors='replace')
                        result['pdb_path'] = pdb_path
                    elif debug_data[:4] == b'NB10':
                        # NB10: 4 sig + 4 offset + 4 timestamp + 4 age + pdb_path
                        pdb_path_bytes = debug_data[16:]
                        pdb_path = pdb_path_bytes.split(b'\x00')[0].decode('utf-8', errors='replace')
                        result['pdb_path'] = pdb_path

                    if result['pdb_path']:
                        result['findings'].append({
                            'description': f"PDB path found: {result['pdb_path']}",
                            'severity': 'info',
                            'reason': 'Debug path reveals development environment information',
                            'mitre_attack': '',
                        })

                        # Check for suspicious patterns
                        for pattern, severity in self._SUSPICIOUS_PDB_PATTERNS:
                            match = pattern.search(result['pdb_path'])
                            if match:
                                matched_text = match.group(0)
                                result['findings'].append({
                                    'description': f"Suspicious PDB path pattern: '{matched_text}' in {result['pdb_path']}",
                                    'severity': severity,
                                    'reason': 'PDB path contains keywords or character sets commonly '
                                              'associated with malware development environments',
                                    'mitre_attack': 'T1027',
                                })
                    break  # Only process first CodeView entry

        except Exception as e:
            logger.debug(f"[PE] PDB path check error: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  3. Rich Header Analysis                                           #
    # ------------------------------------------------------------------ #

    def _check_rich_header(self, pe, raw_data: Optional[bytes] = None) -> Dict:
        """
        Analyze the Rich header (between DOS stub and PE header).

        The Rich header records the build tools (compiler, linker, assembler)
        used to create the PE. Its absence, corruption, or mismatch with the
        actual PE structure can indicate tampering or stolen headers.
        """
        result = {
            'has_rich_header': False,
            'entries': [],
            'checksum': None,
            'checksum_valid': None,
            'raw_hash': None,
            'findings': [],
        }

        try:
            if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER is not None:
                result['has_rich_header'] = True

                rich = pe.RICH_HEADER
                result['checksum'] = hex(rich.checksum) if hasattr(rich, 'checksum') else None

                # Known product IDs for common tools
                tool_names = {
                    1: 'Import0', 6: 'cvtomf', 7: 'Linker',
                    10: 'MASM', 14: 'Linker', 15: 'Import',
                    19: 'Linker', 20: 'Import', 21: 'Import',
                    40: 'Import', 45: 'Linker', 83: 'C',
                    84: 'C++', 93: 'MASM', 94: 'Linker',
                    95: 'Import', 105: 'C', 106: 'C++',
                    130: 'MASM', 131: 'Import', 132: 'Linker',
                    133: 'C', 134: 'C++', 147: 'Linker',
                    148: 'Import', 150: 'MASM', 151: 'C',
                    152: 'C++', 170: 'C', 171: 'C++',
                    172: 'Linker', 175: 'Import', 176: 'MASM',
                    199: 'Import', 200: 'C', 201: 'C++',
                    202: 'Linker', 203: 'MASM', 217: 'Linker',
                    218: 'C', 219: 'C++', 220: 'Import',
                    221: 'MASM', 255: 'C', 256: 'C++',
                    257: 'Linker', 258: 'Import', 259: 'MASM',
                    260: 'Resource', 261: 'AliasObj',
                }

                if hasattr(rich, 'values') and rich.values:
                    # Rich header values are pairs of (compid, count)
                    for i in range(0, len(rich.values), 2):
                        if i + 1 < len(rich.values):
                            comp_id = rich.values[i]
                            count = rich.values[i + 1]
                            prod_id = comp_id >> 16
                            build = comp_id & 0xFFFF
                            tool = tool_names.get(prod_id, f'Unknown({prod_id})')
                            result['entries'].append({
                                'tool': tool,
                                'product_id': prod_id,
                                'build': build,
                                'count': count,
                            })

                if not result['entries']:
                    result['findings'].append({
                        'description': 'Rich header present but could not parse entries',
                        'severity': 'low',
                        'reason': 'Unparseable Rich header may indicate corruption or tampering',
                        'mitre_attack': 'T1036',
                    })
                else:
                    result['findings'].append({
                        'description': f"Rich header contains {len(result['entries'])} build tool entries",
                        'severity': 'info',
                        'reason': 'Rich header records the toolchain used to build the PE',
                        'mitre_attack': '',
                    })

                # Check for Rich header checksum validation
                if raw_data and hasattr(rich, 'checksum'):
                    try:
                        validated = self._validate_rich_checksum(raw_data, rich.checksum)
                        result['checksum_valid'] = validated
                        if not validated:
                            result['findings'].append({
                                'description': 'Rich header checksum is invalid - header may be tampered',
                                'severity': 'high',
                                'reason': 'Invalid Rich header checksum indicates the header was copied '
                                          'from another binary or manually modified to mislead attribution',
                                'mitre_attack': 'T1036.005',
                            })
                    except Exception:
                        pass

            else:
                # No Rich header - could be non-MSVC compiler or stripped
                result['findings'].append({
                    'description': 'No Rich header found',
                    'severity': 'info',
                    'reason': 'Absence of Rich header may indicate non-MSVC compilation, '
                              'header stripping, or custom-built PE',
                    'mitre_attack': '',
                })

        except Exception as e:
            logger.debug(f"[PE] Rich header check error: {e}")

        return result

    def _validate_rich_checksum(self, raw_data: bytes, expected_checksum: int) -> bool:
        """Validate the Rich header XOR checksum against the DOS header."""
        try:
            # Find the "Rich" signature
            rich_offset = raw_data.find(b'Rich')
            if rich_offset < 0:
                return False

            # The checksum follows "Rich"
            # Compute: XOR of rotated DOS header bytes + DanS contributions
            e_lfanew = struct.unpack_from('<I', raw_data, 0x3C)[0]

            checksum = rich_offset
            # XOR with DOS header (first 0x80 bytes, skipping e_lfanew at 0x3C)
            for i in range(rich_offset):
                if 0x3C <= i < 0x40:
                    continue
                val = raw_data[i]
                checksum += ((val << (i % 32)) | (val >> (32 - (i % 32)))) & 0xFFFFFFFF
                checksum &= 0xFFFFFFFF

            return checksum == expected_checksum
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    #  4. PE Resource Analysis                                           #
    # ------------------------------------------------------------------ #

    def _check_resources(self, pe) -> Dict:
        """
        Enumerate and analyze PE resources.

        Checks for embedded PE files, scripts, high-entropy RCDATA,
        version info mismatches, and language anomalies.
        """
        result = {
            'total_resources': 0,
            'resource_types': [],
            'languages': [],
            'embedded_pe_count': 0,
            'embedded_scripts': [],
            'high_entropy_resources': [],
            'version_info': {},
            'findings': [],
        }

        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                return result

            languages_found = set()
            resource_types_found = []

            # Standard resource type names
            RT_NAMES = {
                1: 'RT_CURSOR', 2: 'RT_BITMAP', 3: 'RT_ICON', 4: 'RT_MENU',
                5: 'RT_DIALOG', 6: 'RT_STRING', 7: 'RT_FONTDIR', 8: 'RT_FONT',
                9: 'RT_ACCELERATOR', 10: 'RT_RCDATA', 11: 'RT_MESSAGETABLE',
                12: 'RT_GROUP_CURSOR', 14: 'RT_GROUP_ICON', 16: 'RT_VERSION',
                17: 'RT_DLGINCLUDE', 19: 'RT_PLUGPLAY', 20: 'RT_VXD',
                21: 'RT_ANICURSOR', 22: 'RT_ANIICON', 23: 'RT_HTML',
                24: 'RT_MANIFEST',
            }

            # Language ID to readable name (common ones)
            LANG_NAMES = {
                0x0409: 'English (US)', 0x0809: 'English (UK)',
                0x0419: 'Russian', 0x0804: 'Chinese (Simplified)',
                0x0404: 'Chinese (Traditional)', 0x0412: 'Korean',
                0x0411: 'Japanese', 0x0407: 'German',
                0x040C: 'French', 0x0C0A: 'Spanish',
                0x0416: 'Portuguese (Brazil)', 0x0816: 'Portuguese (Portugal)',
                0x041F: 'Turkish', 0x0401: 'Arabic',
                0x040D: 'Hebrew', 0x0415: 'Polish',
                0x0000: 'Neutral', 0x0400: 'Process Default',
            }

            # Non-Western language IDs that may be suspicious in certain contexts
            SUSPICIOUS_LANGS = {
                0x0419: 'Russian', 0x0804: 'Chinese (Simplified)',
                0x0404: 'Chinese (Traditional)', 0x0412: 'Korean',
                0x0401: 'Arabic', 0x040D: 'Hebrew',
            }

            def _walk_resources(entry, level=0, res_type=None):
                nonlocal languages_found
                if hasattr(entry, 'directory'):
                    for sub in entry.directory.entries:
                        current_type = res_type
                        if level == 0:
                            if hasattr(sub, 'id') and sub.id is not None:
                                type_name = RT_NAMES.get(sub.id, f'UNKNOWN({sub.id})')
                                current_type = (sub.id, type_name)
                                resource_types_found.append(type_name)
                            elif hasattr(sub, 'name') and sub.name:
                                current_type = (None, str(sub.name))
                                resource_types_found.append(str(sub.name))
                        _walk_resources(sub, level + 1, current_type)
                elif hasattr(entry, 'data'):
                    result['total_resources'] += 1
                    data_entry = entry.data
                    lang_id = data_entry.lang
                    sublang = data_entry.sublang
                    full_lang = (lang_id & 0xFF) | ((sublang & 0xFF) << 10)
                    # Use primary language for tracking
                    primary_lang_id = lang_id
                    if primary_lang_id:
                        languages_found.add(primary_lang_id)

                    # Get resource data for analysis
                    try:
                        res_data = pe.get_data(data_entry.struct.OffsetToData, data_entry.struct.Size)
                    except Exception:
                        res_data = None

                    if res_data and res_type:
                        type_id, type_name = res_type

                        # Check for embedded PE files (MZ header)
                        if res_data[:2] == b'MZ':
                            result['embedded_pe_count'] += 1
                            result['findings'].append({
                                'description': f"Embedded PE file found in {type_name} resource "
                                               f"(size: {len(res_data)} bytes)",
                                'severity': 'critical',
                                'reason': 'Embedded executables in resources are used by droppers '
                                          'and malware to carry secondary payloads',
                                'mitre_attack': 'T1027.009',
                            })

                        # Check for embedded scripts
                        script_sigs = [
                            (b'<script', 'JavaScript/VBScript'),
                            (b'powershell', 'PowerShell'),
                            (b'#!/', 'Shell script'),
                            (b'import ', 'Python script'),
                            (b'<?xml', 'XML'),
                            (b'WScript.', 'WScript'),
                            (b'CreateObject', 'VBScript/COM'),
                        ]
                        for sig, script_type in script_sigs:
                            if sig in res_data[:1024]:
                                result['embedded_scripts'].append({
                                    'type': script_type,
                                    'resource_type': type_name,
                                    'size': len(res_data),
                                })
                                result['findings'].append({
                                    'description': f"Embedded {script_type} detected in {type_name} resource",
                                    'severity': 'medium',
                                    'reason': 'Embedded scripts in PE resources may be extracted '
                                              'and executed at runtime',
                                    'mitre_attack': 'T1059',
                                })
                                break

                        # High entropy RCDATA check
                        if type_id == 10 and len(res_data) > 256:  # RT_RCDATA
                            entropy = self._calculate_entropy(res_data)
                            if entropy > 7.0:
                                result['high_entropy_resources'].append({
                                    'type': type_name,
                                    'size': len(res_data),
                                    'entropy': round(entropy, 2),
                                })
                                result['findings'].append({
                                    'description': f"High entropy RT_RCDATA resource "
                                                   f"(entropy: {entropy:.2f}, size: {len(res_data)} bytes)",
                                    'severity': 'high',
                                    'reason': 'RT_RCDATA with high entropy suggests encrypted or '
                                              'compressed payload data stored in resources',
                                    'mitre_attack': 'T1027.009',
                                })

            _walk_resources(pe.DIRECTORY_ENTRY_RESOURCE)

            result['resource_types'] = list(set(resource_types_found))

            # Resolve language names
            lang_names = []
            for lid in languages_found:
                # Build full LCID from primary language
                for lcid, name in LANG_NAMES.items():
                    if (lcid & 0x3FF) == lid:
                        lang_names.append(name)
                        break
                else:
                    lang_names.append(f"LangID(0x{lid:04x})")
            result['languages'] = lang_names

            # Check for suspicious resource languages
            for lid in languages_found:
                for sus_lcid, sus_name in SUSPICIOUS_LANGS.items():
                    if (sus_lcid & 0x3FF) == lid:
                        result['findings'].append({
                            'description': f"Resource language is {sus_name} (LangID: 0x{lid:04x})",
                            'severity': 'medium',
                            'reason': 'Non-Western resource language in software targeting Western '
                                      'audiences may reveal the true origin of the binary',
                            'mitre_attack': 'T1614',
                        })
                        break

            # Multiple different languages = suspicious
            if len(languages_found) > 2:
                result['findings'].append({
                    'description': f"Multiple resource languages detected: {', '.join(lang_names)}",
                    'severity': 'medium',
                    'reason': 'Multiple resource languages may indicate resource manipulation or '
                              'binary was patched with resources from different sources',
                    'mitre_attack': 'T1036',
                })

            # Extract version info
            try:
                if hasattr(pe, 'VS_VERSIONINFO') or hasattr(pe, 'FileInfo'):
                    for file_info_list in getattr(pe, 'FileInfo', []):
                        # FileInfo can be a list of lists depending on pefile version
                        entries = file_info_list if isinstance(file_info_list, list) else [file_info_list]
                        for fi in entries:
                            if hasattr(fi, 'StringTable'):
                                for st in fi.StringTable:
                                    for key, val in st.entries.items():
                                        k = key.decode('utf-8', errors='replace') if isinstance(key, bytes) else str(key)
                                        v = val.decode('utf-8', errors='replace') if isinstance(val, bytes) else str(val)
                                        result['version_info'][k] = v
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"[PE] Resource check error: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  5. Import Count Anomaly Detection                                 #
    # ------------------------------------------------------------------ #

    def _check_import_count_anomalies(self, pe) -> Dict:
        """
        Detect suspiciously low import counts.

        Legitimate binaries typically import many functions. A PE with very few
        imports (especially only LoadLibrary + GetProcAddress) strongly suggests
        packing, obfuscation, or runtime API resolution.
        """
        result = {
            'total_import_count': 0,
            'dll_count': 0,
            'has_only_loader_imports': False,
            'loader_functions_found': [],
            'findings': [],
        }

        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                result['findings'].append({
                    'description': 'No import directory found',
                    'severity': 'high',
                    'reason': 'A PE file with no imports at all is almost certainly packed or '
                              'manually crafted; legitimate compilers always produce imports',
                    'mitre_attack': 'T1027.002',
                })
                return result

            loader_funcs = {
                'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
                'GetProcAddress', 'LdrLoadDll', 'LdrGetProcedureAddress',
            }
            all_func_names = []
            loader_found = []

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                result['dll_count'] += 1
                for imp in entry.imports:
                    result['total_import_count'] += 1
                    if imp.name:
                        fname = imp.name.decode('utf-8', errors='ignore')
                        all_func_names.append(fname)
                        if fname in loader_funcs:
                            loader_found.append(fname)

            result['loader_functions_found'] = loader_found

            if result['total_import_count'] < 5:
                # Check if only loader functions
                non_loader = [f for f in all_func_names if f not in loader_funcs]
                result['has_only_loader_imports'] = len(non_loader) == 0 and len(loader_found) > 0

                severity = 'high' if result['has_only_loader_imports'] else 'medium'
                detail = (
                    "Only dynamic loader functions found (LoadLibrary/GetProcAddress) - "
                    "strong indicator of runtime API resolution"
                    if result['has_only_loader_imports']
                    else f"Only {result['total_import_count']} imports found"
                )

                result['findings'].append({
                    'description': f"Suspiciously low import count: {result['total_import_count']} "
                                   f"functions from {result['dll_count']} DLLs",
                    'detail': detail,
                    'severity': severity,
                    'reason': 'Very few imports suggest the binary is packed or uses runtime API '
                              'resolution to hide its true functionality',
                    'mitre_attack': 'T1027.002',
                })

        except Exception as e:
            logger.debug(f"[PE] Import count check error: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  6. Ordinal-Only Import Detection                                  #
    # ------------------------------------------------------------------ #

    def _check_ordinal_imports(self, pe) -> Dict:
        """
        Detect imports by ordinal number instead of name.

        Importing by ordinal hides the actual function being called, making
        static analysis harder. While some system DLLs legitimately use ordinals,
        heavy ordinal usage is suspicious.
        """
        result = {
            'ordinal_import_count': 0,
            'total_import_count': 0,
            'ordinal_imports': [],
            'ordinal_ratio': 0.0,
            'findings': [],
        }

        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                return result

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    result['total_import_count'] += 1
                    if imp.import_by_ordinal:
                        result['ordinal_import_count'] += 1
                        result['ordinal_imports'].append({
                            'dll': dll_name,
                            'ordinal': imp.ordinal,
                        })

            if result['total_import_count'] > 0:
                result['ordinal_ratio'] = round(
                    result['ordinal_import_count'] / result['total_import_count'], 2
                )

            if result['ordinal_import_count'] > 0:
                # ws2_32.dll and some COM DLLs commonly use ordinals
                non_system_ordinals = [
                    o for o in result['ordinal_imports']
                    if o['dll'].lower() not in ('ws2_32.dll', 'wsock32.dll', 'oleaut32.dll')
                ]

                if len(non_system_ordinals) > 3:
                    result['findings'].append({
                        'description': f"{len(non_system_ordinals)} non-system ordinal-only imports detected",
                        'severity': 'medium',
                        'reason': 'Importing functions by ordinal instead of name hides the actual '
                                  'API calls from static analysis, a technique used to evade detection',
                        'mitre_attack': 'T1027',
                    })
                elif result['ordinal_ratio'] > 0.5 and result['total_import_count'] > 5:
                    result['findings'].append({
                        'description': f"High ordinal import ratio: {result['ordinal_ratio']*100:.0f}% "
                                       f"({result['ordinal_import_count']}/{result['total_import_count']})",
                        'severity': 'medium',
                        'reason': 'More than half of imports are by ordinal, which obscures '
                                  'the binary\'s true API usage',
                        'mitre_attack': 'T1027',
                    })
                elif result['ordinal_import_count'] > 0:
                    result['findings'].append({
                        'description': f"{result['ordinal_import_count']} ordinal import(s) found",
                        'severity': 'info',
                        'reason': 'Some ordinal imports detected; may be normal for certain system DLLs',
                        'mitre_attack': '',
                    })

        except Exception as e:
            logger.debug(f"[PE] Ordinal import check error: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  7. Compilation Timestamp Analysis                                 #
    # ------------------------------------------------------------------ #

    def _check_timestamp(self, pe) -> Dict:
        """
        Analyze the PE compilation timestamp for anomalies.

        Checks for future dates, epoch zero, the Delphi fixed value, pre-2000
        timestamps on modern PEs, and cross-references with resource timestamps.
        """
        result = {
            'timestamp_raw': None,
            'timestamp_utc': None,
            'timestamp_anomalies': [],
            'resource_timestamps': [],
            'findings': [],
        }

        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            result['timestamp_raw'] = ts

            try:
                dt = datetime.datetime.utcfromtimestamp(ts)
                result['timestamp_utc'] = dt.isoformat() + 'Z'
            except (OSError, OverflowError, ValueError):
                result['timestamp_utc'] = 'INVALID'
                result['findings'].append({
                    'description': f"Invalid/unparseable timestamp value: {ts} (0x{ts:08x})",
                    'severity': 'high',
                    'reason': 'Timestamp that cannot be parsed as a valid date indicates '
                              'intentional manipulation',
                    'mitre_attack': 'T1070.006',
                })
                return result

            now = datetime.datetime.utcnow()

            # Check: epoch zero (1970-01-01)
            if ts == 0:
                result['timestamp_anomalies'].append('epoch_zero')
                result['findings'].append({
                    'description': 'Compilation timestamp is epoch zero (1970-01-01 00:00:00)',
                    'severity': 'medium',
                    'reason': 'Zeroed timestamp indicates the timestamp was intentionally wiped '
                              'to prevent build-time attribution',
                    'mitre_attack': 'T1070.006',
                })

            # Check: Delphi fixed value (1992-06-19 22:22:17)
            elif ts == self.DELPHI_TIMESTAMP:
                result['timestamp_anomalies'].append('delphi_fixed')
                result['findings'].append({
                    'description': 'Compilation timestamp matches Delphi fixed value '
                                   '(1992-06-19 22:22:17 UTC)',
                    'severity': 'info',
                    'reason': 'Borland Delphi/C++ Builder uses a fixed timestamp; this is '
                              'normal for Delphi-compiled binaries',
                    'mitre_attack': '',
                })

            # Check: future timestamp
            elif dt > now:
                result['timestamp_anomalies'].append('future')
                result['findings'].append({
                    'description': f"Compilation timestamp is in the future: {result['timestamp_utc']}",
                    'severity': 'high',
                    'reason': 'A future compilation date is impossible and indicates timestamp '
                              'manipulation to confuse timeline analysis',
                    'mitre_attack': 'T1070.006',
                })

            # Check: very old timestamp (before 2000 for non-legacy PE)
            elif dt.year < 2000:
                result['timestamp_anomalies'].append('pre_2000')
                result['findings'].append({
                    'description': f"Compilation timestamp is unusually old: {result['timestamp_utc']}",
                    'severity': 'medium',
                    'reason': 'Pre-2000 timestamp on a modern PE format is suspicious and may '
                              'indicate timestamp tampering',
                    'mitre_attack': 'T1070.006',
                })

            # Cross-reference with resource directory timestamps
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                try:
                    res_ts = pe.DIRECTORY_ENTRY_RESOURCE.struct.TimeDateStamp
                    if res_ts and res_ts != 0:
                        result['resource_timestamps'].append(res_ts)
                        try:
                            res_dt = datetime.datetime.utcfromtimestamp(res_ts)
                            time_diff = abs((dt - res_dt).total_seconds())
                            # If more than 1 year apart, flag it
                            if time_diff > 365 * 24 * 3600:
                                result['findings'].append({
                                    'description': (
                                        f"Resource timestamp ({res_dt.isoformat()}Z) differs "
                                        f"significantly from PE timestamp ({result['timestamp_utc']})"
                                    ),
                                    'severity': 'medium',
                                    'reason': 'Large discrepancy between PE header and resource '
                                              'directory timestamps suggests post-compilation '
                                              'modification or resource transplanting',
                                    'mitre_attack': 'T1070.006',
                                })
                        except (OSError, OverflowError, ValueError):
                            pass
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"[PE] Timestamp check error: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  8. PE Checksum Validation                                         #
    # ------------------------------------------------------------------ #

    def _check_checksum(self, pe) -> Dict:
        """
        Compare the stored PE checksum with the calculated checksum.

        A mismatch indicates the PE was modified after compilation (patched,
        injected, or tampered with). Note that many legitimate tools zero out
        the checksum, so a zero stored checksum is treated differently.
        """
        result = {
            'stored_checksum': None,
            'calculated_checksum': None,
            'checksum_matches': None,
            'findings': [],
        }

        try:
            if not hasattr(pe, 'OPTIONAL_HEADER'):
                return result

            stored = pe.OPTIONAL_HEADER.CheckSum
            result['stored_checksum'] = hex(stored)

            try:
                calculated = pe.generate_checksum()
                result['calculated_checksum'] = hex(calculated)
                result['checksum_matches'] = (stored == calculated)

                if stored == 0:
                    result['findings'].append({
                        'description': 'PE checksum is zero (not set)',
                        'severity': 'low',
                        'reason': 'Many compilers and packers do not set the PE checksum; '
                                  'however some malware deliberately zeros it after patching',
                        'mitre_attack': '',
                    })
                elif stored != calculated:
                    result['findings'].append({
                        'description': (
                            f"PE checksum mismatch: stored={hex(stored)}, "
                            f"calculated={hex(calculated)}"
                        ),
                        'severity': 'high',
                        'reason': 'Checksum mismatch proves the PE was modified after '
                                  'compilation (binary patching, code injection, or resource modification)',
                        'mitre_attack': 'T1027',
                    })
                else:
                    result['findings'].append({
                        'description': 'PE checksum is valid',
                        'severity': 'info',
                        'reason': 'Checksum matches, no post-compilation modification detected',
                        'mitre_attack': '',
                    })
            except Exception:
                result['findings'].append({
                    'description': 'Could not calculate PE checksum',
                    'severity': 'info',
                    'reason': 'Checksum calculation failed; file may be corrupted',
                    'mitre_attack': '',
                })

        except Exception as e:
            logger.debug(f"[PE] Checksum check error: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  9. Manifest Analysis                                              #
    # ------------------------------------------------------------------ #

    def _check_manifest(self, pe) -> Dict:
        """
        Extract and analyze the embedded application manifest.

        Checks for privilege escalation (requireAdministrator), UAC bypass
        (autoElevate), and other security-relevant settings.
        """
        result = {
            'has_manifest': False,
            'manifest_text': None,
            'requested_execution_level': None,
            'auto_elevate': False,
            'ui_access': False,
            'dpi_aware': None,
            'findings': [],
        }

        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                return result

            # RT_MANIFEST = 24
            manifest_data = self._extract_resource_by_type(pe, 24)
            if not manifest_data:
                return result

            result['has_manifest'] = True
            manifest_text = manifest_data.decode('utf-8', errors='replace')
            # Limit stored manifest size
            result['manifest_text'] = manifest_text[:4096]

            # Parse requestedExecutionLevel
            exec_level_match = re.search(
                r'requestedExecutionLevel\s+level\s*=\s*["\'](\w+)["\']',
                manifest_text,
            )
            if exec_level_match:
                level = exec_level_match.group(1)
                result['requested_execution_level'] = level

                if level == 'requireAdministrator':
                    result['findings'].append({
                        'description': 'Manifest requests administrator privileges (requireAdministrator)',
                        'severity': 'high',
                        'reason': 'Binary explicitly requests admin elevation via UAC, which '
                                  'is used by malware for privilege escalation',
                        'mitre_attack': 'T1548.002',
                    })
                elif level == 'highestAvailable':
                    result['findings'].append({
                        'description': 'Manifest requests highest available privileges',
                        'severity': 'medium',
                        'reason': 'Binary requests the highest privilege level available to the user',
                        'mitre_attack': 'T1548.002',
                    })
                elif level == 'asInvoker':
                    result['findings'].append({
                        'description': 'Manifest requests standard user privileges (asInvoker)',
                        'severity': 'info',
                        'reason': 'Normal execution level, runs with invoker\'s privileges',
                        'mitre_attack': '',
                    })

            # Check uiAccess
            ui_access_match = re.search(
                r'uiAccess\s*=\s*["\'](\w+)["\']',
                manifest_text,
            )
            if ui_access_match:
                result['ui_access'] = ui_access_match.group(1).lower() == 'true'
                if result['ui_access']:
                    result['findings'].append({
                        'description': 'Manifest has uiAccess=true (can interact with elevated UI)',
                        'severity': 'high',
                        'reason': 'uiAccess=true allows the process to drive input to higher '
                                  'privilege windows, which can be abused for UAC bypass',
                        'mitre_attack': 'T1548.002',
                    })

            # Check autoElevate
            if re.search(r'<autoElevate\s*>\s*true\s*</autoElevate>', manifest_text, re.IGNORECASE):
                result['auto_elevate'] = True
                result['findings'].append({
                    'description': 'Manifest contains autoElevate=true (automatic UAC elevation)',
                    'severity': 'critical',
                    'reason': 'autoElevate is used by Windows system binaries; its presence in '
                              'a non-system binary is a strong indicator of UAC bypass attempt',
                    'mitre_attack': 'T1548.002',
                })

            # Check DPI awareness
            dpi_match = re.search(
                r'<dpiAware\s*>(.*?)</dpiAware>',
                manifest_text,
                re.IGNORECASE,
            )
            if dpi_match:
                result['dpi_aware'] = dpi_match.group(1).strip()

        except Exception as e:
            logger.debug(f"[PE] Manifest check error: {e}")

        return result

    def _extract_resource_by_type(self, pe, resource_type_id: int) -> Optional[bytes]:
        """Extract the first resource matching the given type ID."""
        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                return None

            for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(res_type, 'id') and res_type.id == resource_type_id:
                    if hasattr(res_type, 'directory'):
                        for res_id in res_type.directory.entries:
                            if hasattr(res_id, 'directory'):
                                for res_lang in res_id.directory.entries:
                                    if hasattr(res_lang, 'data'):
                                        data_entry = res_lang.data
                                        return pe.get_data(
                                            data_entry.struct.OffsetToData,
                                            data_entry.struct.Size,
                                        )
            return None
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    #  10. Entry Point Anomaly Detection                                 #
    # ------------------------------------------------------------------ #

    def _check_entry_point(self, pe) -> Dict:
        """
        Analyze the entry point for anomalies.

        Checks if the entry point is in a writable section, outside any section,
        in a non-standard section, or at the very start of a section.
        """
        result = {
            'entry_point_rva': None,
            'entry_point_section': None,
            'is_in_writable_section': False,
            'is_outside_sections': False,
            'is_in_non_text_section': False,
            'is_at_section_start': False,
            'findings': [],
        }

        try:
            if not hasattr(pe, 'OPTIONAL_HEADER'):
                return result

            ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            result['entry_point_rva'] = hex(ep_rva)

            if ep_rva == 0:
                result['findings'].append({
                    'description': 'Entry point is at RVA 0x0 (likely a DLL or resource-only PE)',
                    'severity': 'info',
                    'reason': 'Zero entry point is normal for DLLs but unusual for executables',
                    'mitre_attack': '',
                })
                return result

            # Find which section contains the entry point
            ep_section = None
            for section in pe.sections:
                sec_start = section.VirtualAddress
                sec_end = sec_start + max(section.Misc_VirtualSize, section.SizeOfRawData)
                if sec_start <= ep_rva < sec_end:
                    ep_section = section
                    break

            if ep_section is None:
                result['is_outside_sections'] = True
                result['findings'].append({
                    'description': f"Entry point (0x{ep_rva:x}) is outside all defined sections",
                    'severity': 'critical',
                    'reason': 'Entry point outside any section indicates overlay execution, '
                              'header-based code execution, or a corrupted/crafted PE',
                    'mitre_attack': 'T1027',
                })
                return result

            section_name = ep_section.Name.decode('utf-8', errors='ignore').strip('\x00')
            result['entry_point_section'] = section_name

            # Check: entry point in writable section
            is_writable = bool(ep_section.Characteristics & 0x80000000)
            is_executable = bool(ep_section.Characteristics & 0x20000000)

            if is_writable:
                result['is_in_writable_section'] = True
                result['findings'].append({
                    'description': f"Entry point is in writable section '{section_name}'",
                    'severity': 'high',
                    'reason': 'Entry point in a writable section enables self-modifying code '
                              'and is a hallmark of packed or polymorphic malware',
                    'mitre_attack': 'T1027.002',
                })

            # Check: entry point in non-.text section
            standard_code_sections = {'.text', '.code', 'CODE', '.itext'}
            if section_name not in standard_code_sections and not section_name.startswith('.text'):
                result['is_in_non_text_section'] = True
                # Check if it is a known packer section
                is_packer_section = any(
                    section_name in sigs for sigs in self.PACKER_SECTIONS.values()
                )
                severity = 'high' if is_packer_section else 'medium'
                reason = (
                    'Entry point in a known packer section confirms the binary is packed'
                    if is_packer_section
                    else 'Entry point in a non-standard code section may indicate packing, '
                         'obfuscation, or unusual build configuration'
                )
                result['findings'].append({
                    'description': f"Entry point is in non-standard section '{section_name}'",
                    'severity': severity,
                    'reason': reason,
                    'mitre_attack': 'T1027.002',
                })

            # Check: entry point at exact start of section
            if ep_rva == ep_section.VirtualAddress:
                result['is_at_section_start'] = True
                result['findings'].append({
                    'description': f"Entry point is at the very start of section '{section_name}'",
                    'severity': 'low',
                    'reason': 'Entry point at the exact start of a section is common in packed '
                              'binaries but can also occur in some linker configurations',
                    'mitre_attack': '',
                })

        except Exception as e:
            logger.debug(f"[PE] Entry point check error: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  11. DOS Stub Analysis                                             #
    # ------------------------------------------------------------------ #

    def _check_dos_stub(self, pe, raw_data: Optional[bytes] = None) -> Dict:
        """
        Analyze the DOS stub for non-standard content.

        The DOS stub is the code between the DOS header and the PE header.
        Non-standard stubs may contain shellcode or other malicious payloads.
        """
        result = {
            'has_dos_stub': False,
            'is_standard_stub': None,
            'stub_size': 0,
            'stub_entropy': None,
            'findings': [],
        }

        try:
            if raw_data is None:
                return result

            # DOS stub starts after the DOS header (typically at offset 0x40)
            # and ends at e_lfanew (offset to PE header)
            e_lfanew = pe.DOS_HEADER.e_lfanew
            dos_stub_start = 0x40  # Typical start after DOS header
            if e_lfanew <= dos_stub_start:
                return result

            dos_stub = raw_data[dos_stub_start:e_lfanew]
            result['has_dos_stub'] = len(dos_stub) > 0
            result['stub_size'] = len(dos_stub)

            if not dos_stub:
                return result

            # Check if standard DOS stub
            result['is_standard_stub'] = self._STANDARD_DOS_STUB in dos_stub

            # Calculate entropy of the stub
            if len(dos_stub) > 16:
                stub_entropy = self._calculate_entropy(dos_stub)
                result['stub_entropy'] = round(stub_entropy, 2)

                if not result['is_standard_stub']:
                    if stub_entropy > 6.5:
                        result['findings'].append({
                            'description': (
                                f"Non-standard DOS stub with high entropy "
                                f"({stub_entropy:.2f}, size: {len(dos_stub)} bytes)"
                            ),
                            'severity': 'high',
                            'reason': 'High-entropy non-standard DOS stub may contain encrypted '
                                      'shellcode or packed payload that executes in DOS mode or '
                                      'is extracted by the PE loader',
                            'mitre_attack': 'T1027.009',
                        })
                    elif len(dos_stub) > 256:
                        result['findings'].append({
                            'description': (
                                f"Non-standard DOS stub is unusually large "
                                f"({len(dos_stub)} bytes, entropy: {stub_entropy:.2f})"
                            ),
                            'severity': 'medium',
                            'reason': 'Oversized DOS stub may contain hidden code or data; '
                                      'standard stubs are typically ~100 bytes',
                            'mitre_attack': 'T1027',
                        })
                    else:
                        result['findings'].append({
                            'description': 'Non-standard DOS stub detected (custom stub message)',
                            'severity': 'low',
                            'reason': 'Custom DOS stub may be from a non-standard compiler or '
                                      'intentional modification',
                            'mitre_attack': '',
                        })

                    # Check for common shellcode patterns in stub
                    shellcode_indicators = [
                        b'\xfc\xe8',      # CLD; CALL (common shellcode start)
                        b'\xeb\xfe',      # JMP short $-2 (infinite loop)
                        b'\x64\xa1\x30',  # MOV EAX, FS:[0x30] (PEB access)
                        b'\x31\xc0\x50',  # XOR EAX,EAX; PUSH EAX
                    ]
                    for pattern in shellcode_indicators:
                        if pattern in dos_stub:
                            result['findings'].append({
                                'description': 'DOS stub contains shellcode-like byte patterns',
                                'severity': 'critical',
                                'reason': 'Shellcode patterns in the DOS stub strongly indicate '
                                          'the stub has been replaced with malicious code',
                                'mitre_attack': 'T1059.004',
                            })
                            break

        except Exception as e:
            logger.debug(f"[PE] DOS stub check error: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  12. Section Permission Analysis (W+X)                             #
    # ------------------------------------------------------------------ #

    def _check_section_permissions(self, pe) -> Dict:
        """
        Analyze section permissions for write+execute (W+X) combinations.

        Sections that are both writable and executable enable self-modifying code
        and are a strong indicator of packing or runtime code generation.
        """
        result = {
            'wx_sections': [],
            'total_sections': 0,
            'findings': [],
        }

        try:
            for section in pe.sections:
                result['total_sections'] += 1
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                is_writable = bool(section.Characteristics & 0x80000000)
                is_executable = bool(section.Characteristics & 0x20000000)
                is_readable = bool(section.Characteristics & 0x40000000)

                if is_writable and is_executable:
                    perms = ''
                    if is_readable:
                        perms += 'R'
                    perms += 'W+X'

                    result['wx_sections'].append({
                        'name': section_name,
                        'permissions': perms,
                        'virtual_size': section.Misc_VirtualSize,
                        'raw_size': section.SizeOfRawData,
                        'entropy': round(section.get_entropy(), 2),
                    })

            if result['wx_sections']:
                wx_names = [s['name'] for s in result['wx_sections']]
                result['findings'].append({
                    'description': (
                        f"{len(result['wx_sections'])} section(s) with Write+Execute "
                        f"permissions: {', '.join(wx_names)}"
                    ),
                    'severity': 'high',
                    'reason': 'Write+Execute (W+X) sections enable self-modifying code and are '
                              'a strong indicator of packed, encrypted, or polymorphic malware. '
                              'Legitimate compilers rarely produce W+X sections.',
                    'mitre_attack': 'T1027.002',
                })

        except Exception as e:
            logger.debug(f"[PE] Section permission check error: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  Existing methods (unchanged)                                      #
    # ------------------------------------------------------------------ #

    def _analyze_pe_headers(self, file_path: str) -> Dict:
        """Analyze PE headers using pefile."""
        result = {
            'is_pe': False,
            'headers': {},
            'sections': [],
            'imports': [],
            'exports': [],
            'resources': [],
            'entropy': {},
            'packer_detected': None,
            'suspicious_imports': [],
            'anomalies': [],
            'threat_score': 0,
        }

        try:
            pe = pefile.PE(file_path)
            result['is_pe'] = True

            # Headers
            result['headers'] = {
                'machine': hex(pe.FILE_HEADER.Machine),
                'timestamp': pe.FILE_HEADER.TimeDateStamp,
                'characteristics': hex(pe.FILE_HEADER.Characteristics),
                'subsystem': pe.OPTIONAL_HEADER.Subsystem if hasattr(pe, 'OPTIONAL_HEADER') else None,
                'dll_characteristics': hex(pe.OPTIONAL_HEADER.DllCharacteristics) if hasattr(pe, 'OPTIONAL_HEADER') else None,
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint) if hasattr(pe, 'OPTIONAL_HEADER') else None,
            }

            # Security features
            if hasattr(pe, 'OPTIONAL_HEADER'):
                dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
                result['headers']['aslr'] = bool(dll_char & 0x0040)
                result['headers']['dep'] = bool(dll_char & 0x0100)
                result['headers']['seh'] = not bool(dll_char & 0x0400)
                result['headers']['cfg'] = bool(dll_char & 0x4000)

            # Sections
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                entropy = section.get_entropy()

                section_info = {
                    'name': section_name,
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': round(entropy, 2),
                    'characteristics': hex(section.Characteristics),
                    'is_executable': bool(section.Characteristics & 0x20000000),
                    'is_writable': bool(section.Characteristics & 0x80000000),
                }
                result['sections'].append(section_info)

                # High entropy detection
                if entropy > 7.0:
                    result['anomalies'].append(f"High entropy section: {section_name} ({entropy:.2f})")

                # Packer detection by section name
                for packer, signatures in self.PACKER_SECTIONS.items():
                    if section_name in signatures:
                        result['packer_detected'] = packer
                        result['anomalies'].append(f"Packer detected: {packer}")

            # Overall entropy
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                result['entropy']['overall'] = round(self._calculate_entropy(data), 2)
            except Exception:
                pass

            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            result['imports'].append({
                                'dll': dll_name,
                                'function': func_name,
                            })

                            # Check for suspicious imports
                            for category, funcs in self.SUSPICIOUS_IMPORTS.items():
                                if func_name in funcs:
                                    result['suspicious_imports'].append(f"[{category}] {func_name}")

            # Exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        result['exports'].append(exp.name.decode('utf-8', errors='ignore'))

            # Calculate PE-specific threat score
            result['threat_score'] = self._calculate_pe_score(result)

            pe.close()

        except pefile.PEFormatError:
            result['anomalies'].append("Invalid PE format")
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"[PE] Analysis error: {e}")

        return result

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0

        byte_counts = Counter(data)
        length = len(data)

        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)

        return entropy

    def _parse_die_output(self, data: Dict) -> Dict:
        """Parse DIE JSON output."""
        result = {
            'file_type': data.get('filetype', 'Unknown'),
            'packers': [],
            'protectors': [],
            'compilers': [],
            'linkers': [],
            'libraries': [],
        }

        for item in data.get('detects', []):
            item_type = item.get('type', '').lower()
            name = item.get('name', '')
            version = item.get('version', '')
            entry = f"{name} {version}".strip()

            if item_type == 'packer':
                result['packers'].append(entry)
            elif item_type == 'protector':
                result['protectors'].append(entry)
            elif item_type == 'compiler':
                result['compilers'].append(entry)
            elif item_type == 'linker':
                result['linkers'].append(entry)
            elif item_type == 'library':
                result['libraries'].append(entry)

        return result

    def _parse_binwalk_output(self, output: str) -> Dict:
        """Parse binwalk output."""
        result = {
            'embedded_files': [],
            'high_entropy_regions': [],
        }

        for line in output.split('\n'):
            if line.strip() and not line.startswith('DECIMAL'):
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    try:
                        result['embedded_files'].append({
                            'offset': int(parts[0]),
                            'description': parts[2][:100]
                        })
                    except Exception:
                        pass

        return result

    def _calculate_pe_score(self, pe_result: Dict) -> int:
        """Calculate PE-specific threat score."""
        score = 0

        # Suspicious imports
        score += min(len(pe_result.get('suspicious_imports', [])) * 3, 30)

        # Packer detection
        if pe_result.get('packer_detected'):
            score += 20

        # Anomalies
        score += len(pe_result.get('anomalies', [])) * 5

        # High overall entropy
        if pe_result.get('entropy', {}).get('overall', 0) > 7.0:
            score += 15

        # Missing security features
        headers = pe_result.get('headers', {})
        if not headers.get('aslr'):
            score += 5
        if not headers.get('dep'):
            score += 5

        return min(score, 100)

    def _calculate_combined_score(self, result: Dict) -> int:
        """Calculate combined threat score from all tools."""
        scores = {}

        # PE analysis score
        scores['pe'] = result.get('pe_analysis', {}).get('threat_score', 0)

        # capa score
        scores['capa'] = result.get('capabilities', {}).get('threat_score', 0)

        # FLOSS score
        scores['floss'] = result.get('strings', {}).get('threat_score', 0)

        # Packer detection bonus
        if result.get('packer_detection', {}).get('packers'):
            scores['packer'] = 30
        elif result.get('packer_detection', {}).get('protectors'):
            scores['packer'] = 50
        else:
            scores['packer'] = 0

        # Deep inspection score
        scores['deep'] = self._calculate_deep_inspection_score(
            result.get('deep_inspection', {})
        )

        # Ransomware score
        ransomware_data = result.get('ransomware_analysis', {})
        ransomware_score = ransomware_data.get('ransomware_score', 0)
        if ransomware_score > 0:
            scores['ransomware'] = ransomware_score

        # Weighted average (adjusted for deep inspection and ransomware)
        weights = {'pe': 0.20, 'capa': 0.30, 'floss': 0.15, 'packer': 0.15, 'deep': 0.20, 'ransomware': 0.25}

        total_weight = sum(weights.get(k, 0) for k in scores.keys())
        weighted_sum = sum(scores[k] * weights.get(k, 0.1) for k in scores.keys())

        if total_weight > 0:
            combined = min(int(weighted_sum / total_weight), 100)
        else:
            combined = 0

        # If ransomware is strongly detected, enforce a minimum score
        if ransomware_score >= 70:
            combined = max(combined, 80)
        elif ransomware_score >= 40:
            combined = max(combined, 55)

        return combined

    def _calculate_deep_inspection_score(self, deep: Dict) -> int:
        """Calculate threat score contribution from deep inspection findings."""
        severity_scores = {
            'critical': 25,
            'high': 15,
            'medium': 8,
            'low': 3,
            'info': 0,
        }

        total = 0
        for check_name, check_result in deep.items():
            if not isinstance(check_result, dict):
                continue
            for finding in check_result.get('findings', []):
                sev = finding.get('severity', 'info')
                total += severity_scores.get(sev, 0)

        return min(total, 100)

    def _determine_verdict(self, score: int) -> str:
        """Determine verdict from score."""
        if score >= 70:
            return 'MALICIOUS'
        elif score >= 40:
            return 'SUSPICIOUS'
        else:
            return 'CLEAN'
