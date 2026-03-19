"""
Author: Ugur Ates
External Tool Runner - Profesyonel malware analiz araçlarını çalıştırır.

Desteklenen Araçlar:
- capa: Capability detection (Mandiant)
- floss: Obfuscated string extraction (Mandiant)
- diec: Detect It Easy CLI (packer/compiler detection)
- binwalk: Firmware/embedded file analysis
- olevba: Office VBA macro extraction
- mraptor: Malicious macro detection
- pdfid: PDF suspicious keyword detection
- pdf-parser: PDF object extraction
- strings: Basic string extraction
- file: File type detection
"""

import subprocess
import json
import shutil
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)
class ToolAvailability(Enum):
    AVAILABLE = "available"
    NOT_INSTALLED = "not_installed"
    ERROR = "error"
@dataclass
class ToolResult:
    """Harici araç çalıştırma sonucu."""
    tool_name: str
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    parsed_output: Optional[Dict] = None
    execution_time_ms: float = 0
    error_message: str = ""
class ExternalToolRunner:
    """Harici malware analiz araçlarını çalıştırır."""
    
    # Araç binary isimleri ve alternatif isimleri
    TOOL_BINARIES = {
        'capa': ['capa', 'capa.exe'],
        'floss': ['floss', 'floss.exe'],
        'diec': ['diec', 'diec.exe', 'die'],
        'binwalk': ['binwalk'],
        'olevba': ['olevba', 'olevba3'],
        'mraptor': ['mraptor', 'mraptor3'],
        'oleobj': ['oleobj'],
        'oleid': ['oleid'],
        'pdfid': ['pdfid.py', 'pdfid'],
        'pdf-parser': ['pdf-parser.py', 'pdf-parser'],
        'strings': ['strings'],
        'file': ['file'],
        'sha256sum': ['sha256sum', 'shasum'],
        'readelf': ['readelf'],
        'objdump': ['objdump'],
        'otool': ['otool'],
        'apktool': ['apktool'],
        'aapt': ['aapt', 'aapt2'],
        'unzip': ['unzip', '7z'],
        'exiftool': ['exiftool'],
    }
    
    def __init__(self):
        self.tool_paths: Dict[str, str] = {}
        self._discover_tools()
    
    def _discover_tools(self):
        """Sistemde mevcut araçları keşfet."""
        for tool_name, binaries in self.TOOL_BINARIES.items():
            for binary in binaries:
                path = shutil.which(binary)
                if path:
                    self.tool_paths[tool_name] = path
                    logger.info(f"[TOOLS] Found {tool_name}: {path}")
                    break
            if tool_name not in self.tool_paths:
                logger.debug(f"[TOOLS] {tool_name} not found in PATH")
    
    def is_available(self, tool_name: str) -> bool:
        """Araç mevcut mu kontrol et."""
        return tool_name in self.tool_paths
    
    def get_available_tools(self) -> List[str]:
        """Mevcut araçların listesini döndür."""
        return list(self.tool_paths.keys())
    
    def get_tool_status(self) -> Dict[str, str]:
        """Tüm araçların durumunu döndür."""
        status = {}
        for tool_name in self.TOOL_BINARIES.keys():
            if tool_name in self.tool_paths:
                status[tool_name] = f"✓ {self.tool_paths[tool_name]}"
            else:
                status[tool_name] = "✗ Not installed"
        return status
    
    def run_tool(self, tool_name: str, args: List[str], 
                 timeout: int = 300, input_data: bytes = None) -> ToolResult:
        """Harici aracı çalıştır."""
        start_time = time.time()
        
        if tool_name not in self.tool_paths:
            return ToolResult(
                tool_name=tool_name,
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                error_message=f"Tool not found: {tool_name}"
            )
        
        cmd = [self.tool_paths[tool_name]] + args
        logger.info(f"[TOOLS] Running: {tool_name} {' '.join(args[:3])}...")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                input=input_data
            )
            
            execution_time = (time.time() - start_time) * 1000
            
            return ToolResult(
                tool_name=tool_name,
                success=result.returncode == 0,
                exit_code=result.returncode,
                stdout=result.stdout.decode('utf-8', errors='replace'),
                stderr=result.stderr.decode('utf-8', errors='replace'),
                execution_time_ms=execution_time
            )
        
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=tool_name,
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                error_message=f"Timeout after {timeout}s"
            )
        except Exception as e:
            logger.error(f"[TOOLS] {tool_name} error: {e}")
            return ToolResult(
                tool_name=tool_name,
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                error_message=str(e)
            )
    
    # ==================== CAPA ====================
    def run_capa(self, file_path: str, output_format: str = 'json') -> ToolResult:
        """
        Mandiant capa ile capability detection.
        
        Capabilities:
        - ATT&CK technique mapping
        - Malware behavior identification
        - Anti-analysis detection
        - Network/file/process capabilities
        """
        args = [file_path, '-f', output_format]
        if output_format == 'json':
            args.append('-j')
        
        result = self.run_tool('capa', args, timeout=600)
        
        if result.success and output_format == 'json':
            try:
                result.parsed_output = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        
        return result
    
    # ==================== FLOSS ====================
    def run_floss(self, file_path: str, output_format: str = 'json') -> ToolResult:
        """
        Mandiant FLOSS ile obfuscated string extraction.
        
        String Types:
        - Static ASCII/Unicode strings
        - Decoded/decrypted strings
        - Stack strings
        - Tight strings
        """
        args = [file_path]
        if output_format == 'json':
            args.append('--json')
        
        result = self.run_tool('floss', args, timeout=900)  # FLOSS can be slow
        
        if result.success and output_format == 'json':
            try:
                result.parsed_output = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        
        return result
    
    # ==================== DETECT IT EASY ====================
    def run_diec(self, file_path: str) -> ToolResult:
        """
        Detect It Easy CLI ile packer/compiler/linker detection.
        
        Detects:
        - Compilers (MSVC, GCC, Clang, Delphi, Go, Rust, etc.)
        - Packers (UPX, ASPack, Themida, VMProtect, etc.)
        - Protectors (.NET Reactor, Confuser, etc.)
        - Linkers and build tools
        """
        args = ['-j', file_path]  # JSON output
        result = self.run_tool('diec', args)
        
        if result.success:
            try:
                result.parsed_output = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        
        return result
    
    # ==================== BINWALK ====================
    def run_binwalk(self, file_path: str, extract: bool = False, 
                    entropy: bool = True, signature: bool = True) -> ToolResult:
        """
        Binwalk ile embedded file ve firmware analizi.
        
        Features:
        - Signature scanning
        - Entropy analysis
        - Embedded file extraction
        - Filesystem detection
        """
        args = []
        
        if signature:
            args.append('-B')  # Signature scan
        
        if entropy:
            args.extend(['-E', '--nplot'])  # Entropy without plot
        
        if extract:
            args.extend(['-e', '-M', '--depth=3'])  # Extract with recursion
        
        args.append(file_path)
        
        return self.run_tool('binwalk', args)
    
    def run_binwalk_entropy(self, file_path: str) -> ToolResult:
        """Binwalk entropy analysis only."""
        args = ['-E', '--nplot', file_path]
        return self.run_tool('binwalk', args)
    
    def run_binwalk_signature(self, file_path: str) -> ToolResult:
        """Binwalk signature scan only."""
        args = ['-B', file_path]
        return self.run_tool('binwalk', args)
    
    # ==================== OLETOOLS ====================
    def run_olevba(self, file_path: str, decode: bool = True) -> ToolResult:
        """
        olevba ile Office VBA macro extraction.
        
        Features:
        - VBA macro extraction
        - Obfuscation detection
        - IOC extraction (URLs, IPs, etc.)
        - AutoExec detection
        - Suspicious keyword detection
        """
        args = ['-a', file_path]  # Analyze mode
        if decode:
            args.insert(1, '--decode')
        
        result = self.run_tool('olevba', args)
        return result
    
    def run_olevba_json(self, file_path: str) -> ToolResult:
        """olevba with JSON output."""
        args = ['-a', '--json', file_path]
        result = self.run_tool('olevba', args)
        
        if result.success:
            try:
                result.parsed_output = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        
        return result
    
    def run_mraptor(self, file_path: str) -> ToolResult:
        """
        mraptor ile malicious macro detection.
        
        Detects macros that:
        - A: Auto-execute
        - W: Write to filesystem
        - X: Execute commands
        """
        args = [file_path]
        return self.run_tool('mraptor', args)
    
    def run_oleobj(self, file_path: str) -> ToolResult:
        """oleobj ile embedded OLE object extraction."""
        args = [file_path]
        return self.run_tool('oleobj', args)
    
    def run_oleid(self, file_path: str) -> ToolResult:
        """oleid ile OLE file indicator detection."""
        args = [file_path]
        return self.run_tool('oleid', args)
    
    # ==================== PDF TOOLS ====================
    def run_pdfid(self, file_path: str) -> ToolResult:
        """
        pdfid ile PDF suspicious keyword detection.
        
        Detects:
        - /JavaScript, /JS
        - /OpenAction, /AA (Auto-Action)
        - /Launch
        - /EmbeddedFile
        - /AcroForm
        - /JBIG2Decode (CVE-2009-0658)
        """
        args = [file_path]
        return self.run_tool('pdfid', args)
    
    def run_pdf_parser(self, file_path: str, search: str = None, 
                       object_id: int = None, raw: bool = True) -> ToolResult:
        """
        pdf-parser ile PDF object extraction.
        
        Features:
        - Object enumeration
        - Stream decompression
        - JavaScript extraction
        - URI extraction
        """
        args = [file_path]
        
        if search:
            args.extend(['--search', search])
        if object_id:
            args.extend(['--object', str(object_id)])
        if raw:
            args.append('--raw')
        
        return self.run_tool('pdf-parser', args)
    
    # ==================== ELF TOOLS ====================
    def run_readelf(self, file_path: str, option: str = '-a') -> ToolResult:
        """readelf ile ELF header/section analizi."""
        args = [option, file_path]
        return self.run_tool('readelf', args)
    
    def run_objdump(self, file_path: str, headers: bool = True, 
                    disassemble: bool = False) -> ToolResult:
        """objdump ile disassembly ve header analizi."""
        args = []
        if headers:
            args.append('-x')
        if disassemble:
            args.append('-d')
        args.append(file_path)
        return self.run_tool('objdump', args)
    
    # ==================== MACH-O TOOLS ====================
    def run_otool(self, file_path: str, option: str = '-L') -> ToolResult:
        """otool ile Mach-O analizi (macOS)."""
        args = [option, file_path]
        return self.run_tool('otool', args)
    
    # ==================== APK TOOLS ====================
    def run_apktool(self, file_path: str, output_dir: str) -> ToolResult:
        """apktool ile APK decompilation."""
        args = ['d', file_path, '-o', output_dir, '-f']
        return self.run_tool('apktool', args)
    
    def run_aapt(self, file_path: str) -> ToolResult:
        """aapt ile APK metadata extraction."""
        args = ['dump', 'badging', file_path]
        return self.run_tool('aapt', args)
    
    # ==================== BASIC TOOLS ====================
    def run_strings(self, file_path: str, min_length: int = 4, 
                    encoding: str = 'all') -> ToolResult:
        """strings ile string extraction."""
        args = ['-n', str(min_length)]
        
        if encoding == 'unicode':
            args.extend(['-e', 'l'])  # Little-endian 16-bit
        elif encoding == 'all':
            args.append('-a')
        
        args.append(file_path)
        return self.run_tool('strings', args)
    
    def run_file(self, file_path: str) -> ToolResult:
        """file komutu ile file type detection."""
        args = ['-b', file_path]  # Brief output
        return self.run_tool('file', args)
    
    def run_sha256sum(self, file_path: str) -> ToolResult:
        """sha256sum ile hash calculation."""
        args = [file_path]
        return self.run_tool('sha256sum', args)
    
    def run_exiftool(self, file_path: str) -> ToolResult:
        """exiftool ile metadata extraction."""
        args = ['-j', file_path]  # JSON output
        result = self.run_tool('exiftool', args)
        
        if result.success:
            try:
                result.parsed_output = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        
        return result
# Singleton instance
_tool_runner: Optional[ExternalToolRunner] = None
def get_tool_runner() -> ExternalToolRunner:
    """Get or create singleton tool runner instance."""
    global _tool_runner
    if _tool_runner is None:
        _tool_runner = ExternalToolRunner()
    return _tool_runner
