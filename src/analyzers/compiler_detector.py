"""
Author: Ugur AtesCompiler and build toolchain detection for PE files."""

import logging
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    logger.warning("[COMPILER] pefile not available")
class CompilerDetector:
    """
    Detect compiler and build toolchain from PE files.
    
    Features:
    - Rich header analysis
    - Compiler string detection
    - PDB path extraction
    - Linker version detection
    - Debug info analysis
    """
    
    # Known compiler signatures
    COMPILER_SIGNATURES = {
        'Microsoft Visual C++': [
            b'Microsoft (R) Optimizing Compiler',
            b'Microsoft C/C++ MSF',
            b'MSVC'
        ],
        'GCC': [
            b'GCC: ',
            b'GNU C++',
            b'GNU C'
        ],
        'Clang': [
            b'clang version',
            b'LLVM'
        ],
        'MinGW': [
            b'mingw',
            b'MinGW'
        ],
        'Borland': [
            b'Borland',
            b'Embarcadero'
        ],
        'Intel C++': [
            b'Intel C++',
            b'Intel(R) C++'
        ],
        'Delphi': [
            b'Delphi',
            b'Pascal'
        ],
        'Go': [
            b'Go build',
            b'runtime.main'
        ],
        'Rust': [
            b'rustc',
            b'Rust'
        ]
    }
    
    @staticmethod
    def detect_compiler(file_path: str) -> Dict:
        """
        Detect compiler used to build PE file.
        
        Args:
            file_path: Path to PE file
        
        Returns:
            Compiler detection results
        """
        if not PEFILE_AVAILABLE:
            return {'error': 'pefile library not available'}
        
        result = {
            'compiler': None,
            'version': None,
            'rich_header': None,
            'pdb_path': None,
            'linker_version': None,
            'compiler_strings': [],
            'confidence': 'unknown'
        }
        
        try:
            pe = pefile.PE(file_path)
            
            # 1. Rich Header Analysis
            rich_info = CompilerDetector._analyze_rich_header(pe)
            if rich_info:
                result['rich_header'] = rich_info
                result['compiler'] = rich_info.get('compiler')
                result['version'] = rich_info.get('version')
                result['confidence'] = 'high'
            
            # 2. PDB Path Extraction
            pdb_path = CompilerDetector._extract_pdb_path(pe)
            if pdb_path:
                result['pdb_path'] = pdb_path
                
                # Extract compiler hints from PDB path
                compiler_hint = CompilerDetector._compiler_from_pdb(pdb_path)
                if compiler_hint and not result['compiler']:
                    result['compiler'] = compiler_hint
                    result['confidence'] = 'medium'
            
            # 3. Linker Version
            linker = CompilerDetector._get_linker_version(pe)
            if linker:
                result['linker_version'] = linker
            
            # 4. String-based Detection
            with open(file_path, 'rb') as f:
                data = f.read()
                
                for compiler, signatures in CompilerDetector.COMPILER_SIGNATURES.items():
                    for sig in signatures:
                        if sig in data:
                            result['compiler_strings'].append({
                                'compiler': compiler,
                                'string': sig.decode('utf-8', errors='ignore')
                            })
                            
                            # Set compiler if not already detected
                            if not result['compiler']:
                                result['compiler'] = compiler
                                result['confidence'] = 'low'
            
            pe.close()
            
        except Exception as e:
            logger.error(f"[COMPILER] Detection failed: {e}")
            result['error'] = str(e)
        
        return result
    
    @staticmethod
    def _analyze_rich_header(pe: 'pefile.PE') -> Optional[Dict]:
        """
        Analyze Rich header for compiler information.
        
        Rich header contains:
        - Compiler product IDs
        - Build numbers
        - Use counts
        """
        try:
            if not hasattr(pe, 'RICH_HEADER'):
                return None
            
            rich = pe.RICH_HEADER
            if not rich:
                return None
            
            # Parse Rich header values
            values = getattr(rich, 'values', [])
            if not values:
                return None
            
            # Map product IDs to compilers (Microsoft specific)
            PRODUCT_IDS = {
                0x5349: 'Visual C++ 5.0',
                0x5F5E: 'Visual C++ 6.0',
                0x7809: 'Visual C++ 7.0 (2002)',
                0x8309: 'Visual C++ 7.1 (2003)',
                0x8C09: 'Visual C++ 8.0 (2005)',
                0x9209: 'Visual C++ 9.0 (2008)',
                0x9819: 'Visual C++ 10.0 (2010)',
                0xA019: 'Visual C++ 11.0 (2012)',
                0xA419: 'Visual C++ 12.0 (2013)',
                0xAA1F: 'Visual C++ 14.0 (2015)',
                0xB01F: 'Visual C++ 14.1 (2017)',
                0xB830: 'Visual C++ 14.2 (2019)',
            }
            
            # Get most common product ID
            if values:
                first_value = values[0]
                prod_id = first_value.get('product_id', 0)
                build = first_value.get('build_number', 0)
                
                compiler = PRODUCT_IDS.get(prod_id, f'Unknown (0x{prod_id:04x})')
                
                return {
                    'compiler': compiler,
                    'version': f'Build {build}',
                    'product_id': f'0x{prod_id:04x}',
                    'build_number': build,
                    'source': 'rich_header'
                }
        
        except Exception as e:
            logger.debug(f"[COMPILER] Rich header parsing failed: {e}")
        
        return None
    
    @staticmethod
    def _extract_pdb_path(pe: 'pefile.PE') -> Optional[str]:
        """Extract PDB (debug symbols) path from PE."""
        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                return None
            
            for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
                if hasattr(debug_entry.entry, 'PdbFileName'):
                    pdb_path = debug_entry.entry.PdbFileName.decode('utf-8', errors='ignore')
                    return pdb_path.rstrip('\x00')
        
        except Exception as e:
            logger.debug(f"[COMPILER] PDB extraction failed: {e}")
        
        return None
    
    @staticmethod
    def _compiler_from_pdb(pdb_path: str) -> Optional[str]:
        """Infer compiler from PDB path."""
        pdb_lower = pdb_path.lower()
        
        if 'visual studio' in pdb_lower or 'vc' in pdb_lower:
            return 'Microsoft Visual C++'
        elif 'mingw' in pdb_lower:
            return 'MinGW'
        elif 'gcc' in pdb_lower:
            return 'GCC'
        elif 'clang' in pdb_lower:
            return 'Clang'
        
        return None
    
    @staticmethod
    def _get_linker_version(pe: 'pefile.PE') -> Optional[str]:
        """Get linker version from PE header."""
        try:
            major = pe.OPTIONAL_HEADER.MajorLinkerVersion
            minor = pe.OPTIONAL_HEADER.MinorLinkerVersion
            
            return f"{major}.{minor}"
        
        except Exception:
            return None
    
    @staticmethod
    def detect_build_environment(file_path: str) -> Dict:
        """
        Detect build environment details.
        
        Args:
            file_path: Path to PE file
        
        Returns:
            Build environment information
        """
        compiler_info = CompilerDetector.detect_compiler(file_path)
        
        result = {
            'compiler': compiler_info,
            'build_characteristics': {},
            'debug_info': False,
            'optimizations': 'unknown'
        }
        
        if not PEFILE_AVAILABLE:
            return result
        
        try:
            pe = pefile.PE(file_path)
            
            # Check for debug info
            result['debug_info'] = hasattr(pe, 'DIRECTORY_ENTRY_DEBUG')
            
            # Check characteristics
            chars = pe.FILE_HEADER.Characteristics
            result['build_characteristics'] = {
                'executable': bool(chars & 0x0002),
                'dll': bool(chars & 0x2000),
                'debug_stripped': bool(chars & 0x0200),
                'system': bool(chars & 0x1000)
            }
            
            # Infer optimizations (rough heuristic)
            if result['debug_info'] and not result['build_characteristics']['debug_stripped']:
                result['optimizations'] = 'debug'
            elif result['build_characteristics']['debug_stripped']:
                result['optimizations'] = 'release'
            
            pe.close()
            
        except Exception as e:
            logger.error(f"[COMPILER] Build env detection failed: {e}")
        
        return result
def analyze_compiler(file_path: str) -> Dict:
    """
    Main entry point for compiler analysis.
    
    Args:
        file_path: Path to PE file
    
    Returns:
        Complete compiler analysis
    """
    result = {
        'compiler_analysis': {}
    }
    
    # Detect compiler
    compiler_info = CompilerDetector.detect_compiler(file_path)
    result['compiler_analysis']['detection'] = compiler_info
    
    # Detect build environment
    build_env = CompilerDetector.detect_build_environment(file_path)
    result['compiler_analysis']['build_environment'] = build_env
    
    # Risk assessment
    risk_score = 0
    
    # No compiler detected = suspicious
    if not compiler_info.get('compiler'):
        risk_score += 20
    
    # No PDB path = potential obfuscation
    if not compiler_info.get('pdb_path'):
        risk_score += 10
    
    # Debug info present in release = unusual
    if build_env.get('debug_info') and build_env.get('optimizations') == 'release':
        risk_score += 15
    
    result['compiler_analysis']['risk_score'] = risk_score
    
    return result
