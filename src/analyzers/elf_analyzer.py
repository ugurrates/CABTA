"""
Author: Ugur Ates
ELF Analyzer - Linux Executable Analizi.

Entegre Araçlar:
- readelf: ELF header/section analysis
- objdump: Disassembly ve symbol analysis
- strings: String extraction
- capa: Capability detection (ELF support)
"""

import logging
import re
from typing import Dict, List
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)
@dataclass
class ELFAnalysisResult:
    """ELF analiz sonucu."""
    success: bool = False
    file_path: str = ""
    elf_class: str = ""
    data_encoding: str = ""
    os_abi: str = ""
    elf_type: str = ""
    machine: str = ""
    entry_point: int = 0
    sections: List[Dict] = field(default_factory=list)
    symbols: List[Dict] = field(default_factory=list)
    imported_functions: List[str] = field(default_factory=list)
    exported_functions: List[str] = field(default_factory=list)
    shared_libraries: List[str] = field(default_factory=list)
    pie_enabled: bool = False
    nx_enabled: bool = True
    relro: str = "Unknown"
    stack_canary: bool = False
    suspicious_imports: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)
    threat_indicators: List[str] = field(default_factory=list)
    threat_score: int = 0
    raw_outputs: Dict[str, str] = field(default_factory=dict)
class ELFAnalyzer:
    """Linux ELF executable analizi."""
    
    SUSPICIOUS_IMPORTS = {
        'process': ['ptrace', 'process_vm_readv', 'mmap', 'mprotect', 'memfd_create'],
        'network': ['socket', 'connect', 'bind', 'send', 'recv', 'getaddrinfo'],
        'execution': ['execve', 'system', 'popen', 'fork', 'clone'],
        'anti_debug': ['ptrace', 'prctl', 'getppid'],
        'crypto': ['EVP_EncryptInit', 'AES_encrypt', 'RSA_public_encrypt'],
    }
    
    def __init__(self):
        from ..tools.external_tool_runner import get_tool_runner
        self.tool_runner = get_tool_runner()
    
    def analyze(self, file_path: str) -> ELFAnalysisResult:
        """Kapsamlı ELF analizi."""
        logger.info(f"[ELF] Analyzing: {Path(file_path).name}")
        result = ELFAnalysisResult(file_path=file_path)
        
        if self.tool_runner.is_available('readelf'):
            # Header
            header_out = self.tool_runner.run_readelf(file_path, '-h')
            if header_out.success:
                self._parse_header(header_out.stdout, result)
                result.raw_outputs['header'] = header_out.stdout
            
            # Sections
            section_out = self.tool_runner.run_readelf(file_path, '-S')
            if section_out.success:
                self._parse_sections(section_out.stdout, result)
                result.raw_outputs['sections'] = section_out.stdout
            
            # Symbols
            symbol_out = self.tool_runner.run_readelf(file_path, '-s')
            if symbol_out.success:
                self._parse_symbols(symbol_out.stdout, result)
                result.raw_outputs['symbols'] = symbol_out.stdout
            
            # Dynamic
            dynamic_out = self.tool_runner.run_readelf(file_path, '-d')
            if dynamic_out.success:
                self._parse_dynamic(dynamic_out.stdout, result)
                result.raw_outputs['dynamic'] = dynamic_out.stdout
            
            result.success = True
        
        # Strings
        if self.tool_runner.is_available('strings'):
            strings_out = self.tool_runner.run_strings(file_path, min_length=6)
            if strings_out.success:
                self._analyze_strings(strings_out.stdout, result)
        
        self._detect_suspicious(result)
        result.threat_score = self._calculate_score(result)
        return result
    
    def _parse_header(self, output: str, result: ELFAnalysisResult):
        for line in output.split('\n'):
            if 'Class:' in line:
                result.elf_class = 'ELF64' if 'ELF64' in line else 'ELF32'
            elif 'Data:' in line:
                result.data_encoding = 'LE' if 'little' in line.lower() else 'BE'
            elif 'OS/ABI:' in line:
                result.os_abi = line.split(':')[-1].strip()
            elif 'Type:' in line:
                if 'DYN' in line:
                    result.elf_type = 'DYN'
                    result.pie_enabled = True
                elif 'EXEC' in line:
                    result.elf_type = 'EXEC'
            elif 'Machine:' in line:
                result.machine = line.split(':')[-1].strip()
            elif 'Entry point' in line:
                try:
                    result.entry_point = int(line.split(':')[-1].strip(), 16)
                except: pass
    
    def _parse_sections(self, output: str, result: ELFAnalysisResult):
        pattern = re.compile(r'\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)')
        for m in pattern.finditer(output):
            result.sections.append({
                'name': m.group(1), 'type': m.group(2),
                'addr': int(m.group(3), 16), 'offset': int(m.group(4), 16),
                'size': int(m.group(5), 16)
            })
    
    def _parse_symbols(self, output: str, result: ELFAnalysisResult):
        pattern = re.compile(r'\s+\d+:\s+[0-9a-fA-F]+\s+\d+\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)\s+(.*)')
        for m in pattern.finditer(output):
            name = m.group(4).strip()
            if not name: continue
            section = m.group(3)
            if m.group(2) == 'GLOBAL':
                if section == 'UND':
                    result.imported_functions.append(name)
                else:
                    result.exported_functions.append(name)
    
    def _parse_dynamic(self, output: str, result: ELFAnalysisResult):
        for line in output.split('\n'):
            if 'NEEDED' in line:
                match = re.search(r'\[(.+)\]', line)
                if match:
                    result.shared_libraries.append(match.group(1))
            elif 'BIND_NOW' in line:
                result.relro = 'Full'
    
    def _analyze_strings(self, output: str, result: ELFAnalysisResult):
        patterns = [
            (r'/bin/sh', 'Shell'), (r'/bin/bash', 'Bash'),
            (r'wget\s+http', 'Download'), (r'curl\s+http', 'Download'),
            (r'/etc/passwd', 'Passwd access'), (r'/etc/shadow', 'Shadow access'),
            (r'authorized_keys', 'SSH keys'), (r'LD_PRELOAD', 'Preload'),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, output, re.I):
                result.suspicious_strings.append(desc)
    
    def _detect_suspicious(self, result: ELFAnalysisResult):
        for cat, funcs in self.SUSPICIOUS_IMPORTS.items():
            for f in funcs:
                for imp in result.imported_functions:
                    if f.lower() in imp.lower():
                        result.suspicious_imports.append(f"[{cat}] {imp}")
        
        for sym in result.imported_functions:
            if '__stack_chk' in sym:
                result.stack_canary = True
                break
    
    def _calculate_score(self, result: ELFAnalysisResult) -> int:
        score = 0
        score += min(len(result.suspicious_imports) * 5, 40)
        score += min(len(result.suspicious_strings) * 5, 30)
        score += len(result.threat_indicators) * 10
        if not result.stack_canary: score += 5
        if not result.pie_enabled and result.elf_type == 'EXEC': score += 5
        return min(score, 100)
