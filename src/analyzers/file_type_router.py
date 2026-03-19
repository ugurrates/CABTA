"""
Author: Ugur Ates
File Type Router - Dosya tipine göre uygun analyzer'a yönlendirir.

Supported Types:
- PE: Windows executables (.exe, .dll, .sys, .scr)
- ELF: Linux executables
- Mach-O: macOS executables
- Office: .doc, .docx, .xls, .xlsx, .ppt, .pptx
- PDF: .pdf
- Script: .ps1, .vbs, .js, .bat, .sh, .py
- APK: Android packages
- Archive: .zip, .rar, .7z, .tar, .gz
- Firmware: Binary blobs with embedded content
"""

import logging
from pathlib import Path
from typing import Dict, Tuple, Optional, Type
from enum import Enum

logger = logging.getLogger(__name__)

# Magic library availability
MAGIC_AVAILABLE = False
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    logger.warning("[ROUTER] python-magic not available, using fallback detection")
class FileType(Enum):
    """Desteklenen dosya tipleri."""
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    OFFICE = "office"
    PDF = "pdf"
    SCRIPT = "script"
    APK = "apk"
    ARCHIVE = "archive"
    FIRMWARE = "firmware"
    MEMORY = "memory"
    TEXT = "text"
    UNKNOWN = "unknown"
class FileTypeRouter:
    """Dosya tipini tespit et ve uygun analyzer'a yönlendir."""
    
    # Extension -> FileType mapping
    EXTENSION_MAP = {
        # PE (Windows Executables)
        '.exe': FileType.PE, '.dll': FileType.PE, '.sys': FileType.PE,
        '.scr': FileType.PE, '.ocx': FileType.PE, '.cpl': FileType.PE,
        '.drv': FileType.PE, '.efi': FileType.PE,
        
        # ELF (Linux Executables)
        '.so': FileType.ELF, '.ko': FileType.ELF, '.o': FileType.ELF,
        
        # Mach-O (macOS Executables)
        '.dylib': FileType.MACHO, '.bundle': FileType.MACHO,
        '.kext': FileType.MACHO,
        
        # Office Documents
        '.doc': FileType.OFFICE, '.docx': FileType.OFFICE,
        '.docm': FileType.OFFICE, '.dotm': FileType.OFFICE,
        '.xls': FileType.OFFICE, '.xlsx': FileType.OFFICE,
        '.xlsm': FileType.OFFICE, '.xlsb': FileType.OFFICE,
        '.xltm': FileType.OFFICE, '.xlam': FileType.OFFICE,
        '.ppt': FileType.OFFICE, '.pptx': FileType.OFFICE,
        '.pptm': FileType.OFFICE, '.potm': FileType.OFFICE,
        '.rtf': FileType.OFFICE, '.odt': FileType.OFFICE,
        '.ods': FileType.OFFICE, '.odp': FileType.OFFICE,
        
        # PDF
        '.pdf': FileType.PDF,
        
        # Scripts
        '.ps1': FileType.SCRIPT, '.psm1': FileType.SCRIPT, '.psd1': FileType.SCRIPT,
        '.vbs': FileType.SCRIPT, '.vbe': FileType.SCRIPT,
        '.js': FileType.SCRIPT, '.jse': FileType.SCRIPT,
        '.bat': FileType.SCRIPT, '.cmd': FileType.SCRIPT,
        '.sh': FileType.SCRIPT, '.bash': FileType.SCRIPT,
        '.py': FileType.SCRIPT, '.pyw': FileType.SCRIPT,
        '.rb': FileType.SCRIPT, '.pl': FileType.SCRIPT,
        '.php': FileType.SCRIPT, '.asp': FileType.SCRIPT,
        '.hta': FileType.SCRIPT, '.wsf': FileType.SCRIPT,
        '.wsh': FileType.SCRIPT, '.scf': FileType.SCRIPT,
        
        # APK (Android)
        '.apk': FileType.APK, '.aab': FileType.APK,
        '.xapk': FileType.APK,
        
        # Archives
        '.zip': FileType.ARCHIVE, '.rar': FileType.ARCHIVE,
        '.7z': FileType.ARCHIVE, '.tar': FileType.ARCHIVE,
        '.gz': FileType.ARCHIVE, '.bz2': FileType.ARCHIVE,
        '.xz': FileType.ARCHIVE, '.cab': FileType.ARCHIVE,
        '.iso': FileType.ARCHIVE, '.img': FileType.ARCHIVE,
        '.dmg': FileType.ARCHIVE, '.pkg': FileType.ARCHIVE,
        '.deb': FileType.ARCHIVE, '.rpm': FileType.ARCHIVE,
        '.msi': FileType.ARCHIVE, '.msix': FileType.ARCHIVE,
        
        # Firmware
        '.bin': FileType.FIRMWARE, '.fw': FileType.FIRMWARE,
        '.rom': FileType.FIRMWARE, '.uf2': FileType.FIRMWARE,
        '.hex': FileType.FIRMWARE, '.srec': FileType.FIRMWARE,

        # Memory dumps
        '.dmp': FileType.MEMORY, '.raw': FileType.MEMORY,
        '.vmem': FileType.MEMORY, '.mem': FileType.MEMORY,

        # Text / Config / Log files
        '.txt': FileType.TEXT, '.log': FileType.TEXT,
        '.csv': FileType.TEXT, '.tsv': FileType.TEXT,
        '.conf': FileType.TEXT, '.cfg': FileType.TEXT,
        '.ini': FileType.TEXT, '.properties': FileType.TEXT,
        '.json': FileType.TEXT, '.xml': FileType.TEXT,
        '.yaml': FileType.TEXT, '.yml': FileType.TEXT,
        '.md': FileType.TEXT, '.rst': FileType.TEXT,
        '.html': FileType.TEXT, '.htm': FileType.TEXT,
        '.eml': FileType.TEXT, '.msg': FileType.TEXT,
        '.ioc': FileType.TEXT, '.rules': FileType.TEXT,
        '.yar': FileType.TEXT, '.yara': FileType.TEXT,
    }
    
    # MIME type patterns -> FileType
    MIME_PATTERNS = {
        'application/x-dosexec': FileType.PE,
        'application/x-msdownload': FileType.PE,
        'application/x-executable': FileType.ELF,
        'application/x-sharedlib': FileType.ELF,
        'application/x-object': FileType.ELF,
        'application/x-mach-binary': FileType.MACHO,
        'application/msword': FileType.OFFICE,
        'application/vnd.openxmlformats-officedocument': FileType.OFFICE,
        'application/vnd.ms-excel': FileType.OFFICE,
        'application/vnd.ms-powerpoint': FileType.OFFICE,
        'application/vnd.oasis.opendocument': FileType.OFFICE,
        'application/pdf': FileType.PDF,
        'text/x-python': FileType.SCRIPT,
        'text/x-shellscript': FileType.SCRIPT,
        'application/javascript': FileType.SCRIPT,
        'text/javascript': FileType.SCRIPT,
        'application/x-powershell': FileType.SCRIPT,
        'application/vnd.android.package-archive': FileType.APK,
        'application/zip': FileType.ARCHIVE,
        'application/x-rar': FileType.ARCHIVE,
        'application/x-7z-compressed': FileType.ARCHIVE,
        'application/gzip': FileType.ARCHIVE,
        'application/x-tar': FileType.ARCHIVE,
        'application/x-iso9660-image': FileType.ARCHIVE,
        'text/plain': FileType.TEXT,
        'text/html': FileType.TEXT,
        'text/xml': FileType.TEXT,
        'text/csv': FileType.TEXT,
        'application/json': FileType.TEXT,
        'application/xml': FileType.TEXT,
        'text/yaml': FileType.TEXT,
        'text/x-log': FileType.TEXT,
        'message/rfc822': FileType.TEXT,
    }
    
    # Magic bytes signatures
    MAGIC_SIGNATURES = {
        b'MZ': FileType.PE,
        b'\x7fELF': FileType.ELF,
        b'\xfe\xed\xfa\xce': FileType.MACHO,  # MH_MAGIC
        b'\xce\xfa\xed\xfe': FileType.MACHO,  # MH_CIGAM
        b'\xfe\xed\xfa\xcf': FileType.MACHO,  # MH_MAGIC_64
        b'\xcf\xfa\xed\xfe': FileType.MACHO,  # MH_CIGAM_64
        b'%PDF': FileType.PDF,
        b'PK\x03\x04': FileType.ARCHIVE,  # ZIP/APK
        b'PK\x05\x06': FileType.ARCHIVE,  # Empty ZIP
        b'Rar!\x1a\x07': FileType.ARCHIVE,  # RAR
        b'7z\xbc\xaf\x27\x1c': FileType.ARCHIVE,  # 7z
        b'\x1f\x8b': FileType.ARCHIVE,  # GZIP
        b'\xd0\xcf\x11\xe0': FileType.OFFICE,  # OLE (old Office)
    }
    
    @staticmethod
    def detect_file_type(file_path: str) -> Tuple[FileType, Dict]:
        """
        Dosya tipini tespit et.
        
        Returns:
            (FileType, metadata dict)
        """
        path = Path(file_path)
        
        if not path.exists():
            return (FileType.UNKNOWN, {'error': 'File not found'})
        
        metadata = {
            'filename': path.name,
            'extension': path.suffix.lower(),
            'size': path.stat().st_size,
            'detection_method': 'unknown'
        }
        
        # 1. Magic bytes check (most reliable)
        try:
            with open(file_path, 'rb') as f:
                header = f.read(32)
            
            for magic_bytes, file_type in FileTypeRouter.MAGIC_SIGNATURES.items():
                if header.startswith(magic_bytes):
                    metadata['detection_method'] = 'magic_bytes'
                    metadata['magic_signature'] = magic_bytes.hex()
                    
                    # Special handling for ZIP-based formats
                    if magic_bytes == b'PK\x03\x04':
                        ext = metadata['extension']
                        if ext == '.apk':
                            return (FileType.APK, metadata)
                        elif ext in ['.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm']:
                            return (FileType.OFFICE, metadata)
                        # Fall through to ARCHIVE
                    
                    logger.info(f"[ROUTER] Detected {file_type.value} by magic bytes")
                    return (file_type, metadata)
            
            # PE detailed check (MZ header + PE signature)
            if header[:2] == b'MZ':
                # Check for PE signature at offset in DOS header
                if len(header) >= 64:
                    pe_offset_bytes = header[60:64]
                    pe_offset = int.from_bytes(pe_offset_bytes, 'little')
                    
                    with open(file_path, 'rb') as f:
                        f.seek(pe_offset)
                        pe_sig = f.read(4)
                    
                    if pe_sig == b'PE\x00\x00':
                        metadata['detection_method'] = 'pe_signature'
                        metadata['pe_offset'] = pe_offset
                        return (FileType.PE, metadata)
                
                # Could be DOS executable or broken PE
                metadata['detection_method'] = 'mz_header'
                return (FileType.PE, metadata)
            
            # ELF detailed check
            if header[:4] == b'\x7fELF':
                metadata['detection_method'] = 'elf_magic'
                metadata['elf_class'] = 'ELF64' if header[4] == 2 else 'ELF32'
                metadata['elf_endian'] = 'LE' if header[5] == 1 else 'BE'
                return (FileType.ELF, metadata)
        
        except Exception as e:
            logger.warning(f"[ROUTER] Magic byte detection failed: {e}")
        
        # 2. Magic library check
        if MAGIC_AVAILABLE:
            try:
                mime = magic.from_file(file_path, mime=True)
                file_magic = magic.from_file(file_path)
                metadata['mime_type'] = mime
                metadata['magic_description'] = file_magic
                
                # Check MIME patterns
                for pattern, file_type in FileTypeRouter.MIME_PATTERNS.items():
                    if pattern in mime:
                        metadata['detection_method'] = 'libmagic_mime'
                        logger.info(f"[ROUTER] Detected {file_type.value} by MIME: {mime}")
                        return (file_type, metadata)
                
                # Additional magic description checks
                if 'PE32' in file_magic or 'PE32+' in file_magic:
                    metadata['detection_method'] = 'libmagic_desc'
                    metadata['pe_type'] = 'PE32+' if 'PE32+' in file_magic else 'PE32'
                    return (FileType.PE, metadata)
                
                if 'ELF' in file_magic:
                    metadata['detection_method'] = 'libmagic_desc'
                    return (FileType.ELF, metadata)
                
                if 'Mach-O' in file_magic:
                    metadata['detection_method'] = 'libmagic_desc'
                    return (FileType.MACHO, metadata)
                
            except Exception as e:
                logger.warning(f"[ROUTER] libmagic detection failed: {e}")
        
        # 3. Extension-based fallback
        if metadata['extension'] in FileTypeRouter.EXTENSION_MAP:
            metadata['detection_method'] = 'extension'
            file_type = FileTypeRouter.EXTENSION_MAP[metadata['extension']]
            logger.info(f"[ROUTER] Detected {file_type.value} by extension: {metadata['extension']}")
            return (file_type, metadata)
        
        # 4. Script detection by content
        try:
            with open(file_path, 'rb') as f:
                start = f.read(512)
            
            # Shebang check
            if start.startswith(b'#!'):
                metadata['detection_method'] = 'shebang'
                shebang = start.split(b'\n')[0].decode('utf-8', errors='ignore')
                metadata['shebang'] = shebang
                return (FileType.SCRIPT, metadata)
            
            # PowerShell detection
            if b'param(' in start.lower() or b'function ' in start.lower():
                if b'$' in start:  # PowerShell variable
                    metadata['detection_method'] = 'content_heuristic'
                    return (FileType.SCRIPT, metadata)
            
            # VBScript detection
            if b'dim ' in start.lower() or b'sub ' in start.lower():
                metadata['detection_method'] = 'content_heuristic'
                return (FileType.SCRIPT, metadata)
            
            # Batch file detection
            if b'@echo off' in start.lower() or b'rem ' in start.lower():
                metadata['detection_method'] = 'content_heuristic'
                return (FileType.SCRIPT, metadata)
        
        except Exception as e:
            logger.warning(f"[ROUTER] Content detection failed: {e}")
        
        # 5. Check if it's a text/readable file before declaring unknown
        try:
            with open(file_path, 'rb') as f:
                sample = f.read(4096)
            # If most bytes are printable ASCII, treat as text
            printable_count = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
            if len(sample) > 0 and (printable_count / len(sample)) > 0.75:
                metadata['detection_method'] = 'content_heuristic_text'
                logger.info("[ROUTER] Detected text file by content heuristic (>75% printable)")
                return (FileType.TEXT, metadata)
        except Exception:
            pass

        # 6. Unknown - but check if potentially firmware (high entropy binary)
        metadata['detection_method'] = 'unknown'
        return (FileType.UNKNOWN, metadata)
    
    @staticmethod
    def get_analyzer_class(file_type: FileType) -> Optional[Type]:
        """
        FileType için uygun analyzer class'ını döndür.
        
        Returns:
            Analyzer class or None
        """
        # Lazy import to avoid circular dependencies
        analyzer_map = {}
        
        try:
            from .pe_analyzer import PEAnalyzer
            analyzer_map[FileType.PE] = PEAnalyzer
        except ImportError:
            pass
        
        try:
            from .elf_analyzer import ELFAnalyzer
            analyzer_map[FileType.ELF] = ELFAnalyzer
        except ImportError:
            pass
        
        try:
            from .macho_analyzer import MachOAnalyzer
            analyzer_map[FileType.MACHO] = MachOAnalyzer
        except ImportError:
            pass
        
        try:
            from .office_analyzer import OfficeAnalyzer
            analyzer_map[FileType.OFFICE] = OfficeAnalyzer
        except ImportError:
            pass
        
        try:
            from .pdf_analyzer import PDFAnalyzer
            analyzer_map[FileType.PDF] = PDFAnalyzer
        except ImportError:
            pass
        
        try:
            from .script_analyzer import ScriptAnalyzer
            analyzer_map[FileType.SCRIPT] = ScriptAnalyzer
        except ImportError:
            pass
        
        try:
            from .apk_analyzer import APKAnalyzer
            analyzer_map[FileType.APK] = APKAnalyzer
        except ImportError:
            pass
        
        try:
            from .archive_analyzer import ArchiveAnalyzer
            analyzer_map[FileType.ARCHIVE] = ArchiveAnalyzer
        except ImportError:
            pass
        
        try:
            from .firmware_analyzer import FirmwareAnalyzer
            analyzer_map[FileType.FIRMWARE] = FirmwareAnalyzer
        except ImportError:
            pass

        try:
            from .memory_analyzer import MemoryAnalyzer
            analyzer_map[FileType.MEMORY] = MemoryAnalyzer
        except ImportError:
            pass

        try:
            from .text_analyzer import TextFileAnalyzer
            analyzer_map[FileType.TEXT] = TextFileAnalyzer
        except ImportError:
            pass

        return analyzer_map.get(file_type)
    
    @staticmethod
    def get_supported_extensions() -> Dict[str, str]:
        """Return all supported extensions with their file types."""
        return {ext: ft.value for ext, ft in FileTypeRouter.EXTENSION_MAP.items()}
    
    @staticmethod
    def is_potentially_dangerous(file_type: FileType, extension: str) -> bool:
        """Check if file type is potentially dangerous."""
        dangerous_types = {FileType.PE, FileType.OFFICE, FileType.SCRIPT, FileType.APK}
        dangerous_extensions = {
            '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js',
            '.hta', '.wsf', '.docm', '.xlsm', '.pptm', '.jar', '.apk'
        }
        
        return file_type in dangerous_types or extension.lower() in dangerous_extensions
