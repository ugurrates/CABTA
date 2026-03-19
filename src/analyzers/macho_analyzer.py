"""
Author: Ugur Ates
Mach-O Analyzer - macOS Executable Analizi.

Entegre Araçlar:
- otool: Mach-O header/load commands
- strings: String extraction
- codesign: Signature verification
"""

import logging
import re
from typing import Dict, List
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)
@dataclass
class MachOAnalysisResult:
    """Mach-O analiz sonucu."""
    success: bool = False
    file_path: str = ""
    cpu_type: str = ""
    file_type: str = ""
    load_commands: List[Dict] = field(default_factory=list)
    segments: List[Dict] = field(default_factory=list)
    imported_libraries: List[str] = field(default_factory=list)
    imported_symbols: List[str] = field(default_factory=list)
    exported_symbols: List[str] = field(default_factory=list)
    entitlements: List[str] = field(default_factory=list)
    code_signed: bool = False
    hardened_runtime: bool = False
    suspicious_imports: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)
    threat_indicators: List[str] = field(default_factory=list)
    threat_score: int = 0
    raw_outputs: Dict[str, str] = field(default_factory=dict)
class MachOAnalyzer:
    """macOS Mach-O executable analizi."""
    
    SUSPICIOUS_IMPORTS = {
        'injection': ['task_for_pid', 'mach_vm_allocate', 'mach_vm_write', 'thread_create'],
        'keylogger': ['CGEventTapCreate', 'CGEventPost', 'IOHIDManagerCreate'],
        'network': ['CFSocketCreate', 'CFStreamCreatePairWithSocketToHost'],
        'persistence': ['LSSharedFileListInsertItemURL', 'SMJobSubmit'],
        'execution': ['NSTask', 'posix_spawn', 'execve', 'system'],
        'anti_debug': ['ptrace', 'sysctl', 'proc_pidinfo'],
    }
    
    def __init__(self):
        from ..tools.external_tool_runner import get_tool_runner
        self.tool_runner = get_tool_runner()
    
    def analyze(self, file_path: str) -> MachOAnalysisResult:
        """Kapsamlı Mach-O analizi."""
        logger.info(f"[MACHO] Analyzing: {Path(file_path).name}")
        result = MachOAnalysisResult(file_path=file_path)
        
        if self.tool_runner.is_available('otool'):
            # Header
            header_out = self.tool_runner.run_otool(file_path, '-h')
            if header_out.success:
                self._parse_header(header_out.stdout, result)
                result.raw_outputs['header'] = header_out.stdout
            
            # Load commands
            load_out = self.tool_runner.run_otool(file_path, '-l')
            if load_out.success:
                self._parse_load_commands(load_out.stdout, result)
                result.raw_outputs['load_commands'] = load_out.stdout
            
            # Libraries
            lib_out = self.tool_runner.run_otool(file_path, '-L')
            if lib_out.success:
                self._parse_libraries(lib_out.stdout, result)
                result.raw_outputs['libraries'] = lib_out.stdout
            
            result.success = True
        
        # Strings
        if self.tool_runner.is_available('strings'):
            strings_out = self.tool_runner.run_strings(file_path, min_length=6)
            if strings_out.success:
                self._analyze_strings(strings_out.stdout, result)
        
        self._detect_suspicious(result)
        result.threat_score = self._calculate_score(result)
        return result
    
    def _parse_header(self, output: str, result: MachOAnalysisResult):
        if 'X86_64' in output or 'x86_64' in output:
            result.cpu_type = 'x86_64'
        elif 'ARM64' in output or 'arm64' in output:
            result.cpu_type = 'arm64'
        
        if 'EXECUTE' in output:
            result.file_type = 'EXECUTE'
        elif 'DYLIB' in output:
            result.file_type = 'DYLIB'
        elif 'BUNDLE' in output:
            result.file_type = 'BUNDLE'
    
    def _parse_load_commands(self, output: str, result: MachOAnalysisResult):
        current_segment = None
        for line in output.split('\n'):
            line = line.strip()
            if 'cmd LC_SEGMENT' in line:
                current_segment = {'type': 'LC_SEGMENT'}
            elif 'segname' in line and current_segment:
                current_segment['name'] = line.split()[-1]
                result.segments.append(current_segment)
                current_segment = None
            elif 'LC_CODE_SIGNATURE' in line:
                result.code_signed = True
    
    def _parse_libraries(self, output: str, result: MachOAnalysisResult):
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('/') or line.startswith('@'):
                lib = line.split('(')[0].strip()
                if lib:
                    result.imported_libraries.append(lib)
    
    def _analyze_strings(self, output: str, result: MachOAnalysisResult):
        patterns = [
            (r'osascript', 'AppleScript exec'),
            (r'launchctl', 'LaunchAgent'),
            (r'/Library/LaunchAgents', 'Persistence'),
            (r'/Library/LaunchDaemons', 'Persistence'),
            (r'com\.apple\.security', 'Security framework'),
            (r'keychain', 'Keychain access'),
            (r'CGEventTap', 'Event monitoring'),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, output, re.I):
                result.suspicious_strings.append(desc)
    
    def _detect_suspicious(self, result: MachOAnalysisResult):
        for cat, funcs in self.SUSPICIOUS_IMPORTS.items():
            for f in funcs:
                for lib in result.imported_libraries:
                    if f.lower() in lib.lower():
                        result.suspicious_imports.append(f"[{cat}] {f}")
    
    def _calculate_score(self, result: MachOAnalysisResult) -> int:
        score = 0
        score += min(len(result.suspicious_imports) * 5, 40)
        score += min(len(result.suspicious_strings) * 5, 30)
        if not result.code_signed: score += 15
        return min(score, 100)
