"""
Author: Ugur AtesOverlay detection and analysis for PE files."""

import logging
import math
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    logger.warning("[OVERLAY] pefile not available")
class OverlayDetector:
    """
    Detect and analyze overlay data in PE files.
    
    Overlay = data appended after the PE structure
    Often used for:
    - Resource storage
    - Installers
    - Malware payloads
    - Embedded files
    """
    
    @staticmethod
    def detect_overlay(file_path: str) -> Dict:
        """
        Detect overlay in PE file.
        
        Args:
            file_path: Path to PE file
        
        Returns:
            Overlay detection results
        """
        if not PEFILE_AVAILABLE:
            return {'has_overlay': False, 'error': 'pefile not available'}
        
        result = {
            'has_overlay': False,
            'overlay_size': 0,
            'overlay_offset': 0,
            'overlay_percentage': 0.0,
            'characteristics': {},
            'suspicious': False,
            'risk_score': 0
        }
        
        try:
            file_size = Path(file_path).stat().st_size
            pe = pefile.PE(file_path)
            
            # Calculate where PE structure ends
            pe_end = pe.get_overlay_data_start_offset()
            
            if pe_end and pe_end < file_size:
                overlay_size = file_size - pe_end
                
                result['has_overlay'] = True
                result['overlay_size'] = overlay_size
                result['overlay_offset'] = pe_end
                result['overlay_percentage'] = (overlay_size / file_size) * 100
                
                # Extract and analyze overlay data
                with open(file_path, 'rb') as f:
                    f.seek(pe_end)
                    overlay_data = f.read(min(overlay_size, 8192))  # First 8KB
                
                # Analyze characteristics
                chars = OverlayDetector._analyze_overlay_data(overlay_data)
                result['characteristics'] = chars
                
                # Calculate risk score
                result['risk_score'] = OverlayDetector._calculate_overlay_risk(
                    overlay_size, overlay_data, chars
                )
                
                result['suspicious'] = result['risk_score'] > 50
            
            pe.close()
            
        except Exception as e:
            logger.error(f"[OVERLAY] Detection failed: {e}")
            result['error'] = str(e)
        
        return result
    
    @staticmethod
    def _analyze_overlay_data(data: bytes) -> Dict:
        """
        Analyze overlay data characteristics.
        
        Returns characteristics dict
        """
        chars = {
            'entropy': 0.0,
            'printable_ratio': 0.0,
            'null_ratio': 0.0,
            'has_pe_header': False,
            'has_zip_header': False,
            'has_executable_code': False,
            'file_signatures': []
        }
        
        if not data:
            return chars
        
        # Calculate entropy
        chars['entropy'] = OverlayDetector._calculate_entropy(data)
        
        # Calculate ratios
        printable_count = sum(1 for b in data if 32 <= b <= 126)
        null_count = data.count(0)
        
        chars['printable_ratio'] = printable_count / len(data)
        chars['null_ratio'] = null_count / len(data)
        
        # Check for file signatures
        if data.startswith(b'MZ'):
            chars['has_pe_header'] = True
            chars['file_signatures'].append('PE/DOS executable')
        
        if data.startswith(b'PK'):
            chars['has_zip_header'] = True
            chars['file_signatures'].append('ZIP archive')
        
        if data.startswith(b'\x1f\x8b'):
            chars['file_signatures'].append('GZIP compressed')
        
        if data.startswith(b'Rar!'):
            chars['file_signatures'].append('RAR archive')
        
        if data.startswith(b'%PDF'):
            chars['file_signatures'].append('PDF document')
        
        # Check for executable code patterns
        # x86 instruction patterns (simplified)
        executable_patterns = [
            b'\x55\x8B\xEC',  # push ebp; mov ebp, esp
            b'\x56\x57',      # push esi; push edi
            b'\xE8',          # call
            b'\xC3',          # ret
        ]
        
        for pattern in executable_patterns:
            if pattern in data[:1024]:
                chars['has_executable_code'] = True
                break
        
        return chars
    
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        
        High entropy (> 7.0) = compressed or encrypted
        Low entropy (< 3.0) = repetitive or structured
        """
        if not data:
            return 0.0
        
        # Count byte frequencies
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in frequencies.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def _calculate_overlay_risk(size: int, data: bytes, chars: Dict) -> int:
        """
        Calculate risk score for overlay.
        
        Returns risk score 0-100
        """
        risk = 0
        
        # Size-based risk
        if size > 10 * 1024 * 1024:  # > 10MB
            risk += 20
        elif size > 1 * 1024 * 1024:  # > 1MB
            risk += 10
        
        # Entropy-based risk (high entropy = encrypted/packed)
        entropy = chars.get('entropy', 0)
        if entropy > 7.5:
            risk += 30
        elif entropy > 7.0:
            risk += 15
        
        # Embedded PE = very suspicious
        if chars.get('has_pe_header'):
            risk += 40
        
        # Executable code in overlay = suspicious
        if chars.get('has_executable_code'):
            risk += 25
        
        # Low printable ratio = binary/obfuscated
        if chars.get('printable_ratio', 0) < 0.1:
            risk += 10
        
        # High null ratio = padding/junk
        if chars.get('null_ratio', 0) > 0.5:
            risk += 5
        
        return min(risk, 100)
    
    @staticmethod
    def extract_overlay(file_path: str, output_path: Optional[str] = None) -> bool:
        """
        Extract overlay data to separate file.
        
        Args:
            file_path: Path to PE file
            output_path: Output path for overlay (default: filename.overlay)
        
        Returns:
            True if extraction successful
        """
        if not PEFILE_AVAILABLE:
            return False
        
        try:
            pe = pefile.PE(file_path)
            overlay_offset = pe.get_overlay_data_start_offset()
            
            if not overlay_offset:
                logger.info("[OVERLAY] No overlay to extract")
                return False
            
            # Read overlay
            with open(file_path, 'rb') as f:
                f.seek(overlay_offset)
                overlay_data = f.read()
            
            # Determine output path
            if not output_path:
                output_path = f"{file_path}.overlay"
            
            # Write overlay
            with open(output_path, 'wb') as f:
                f.write(overlay_data)
            
            logger.info(f"[OVERLAY] Extracted {len(overlay_data)} bytes to {output_path}")
            pe.close()
            return True
            
        except Exception as e:
            logger.error(f"[OVERLAY] Extraction failed: {e}")
            return False
def analyze_overlay(file_path: str) -> Dict:
    """
    Main entry point for overlay analysis.
    
    Args:
        file_path: Path to PE file
    
    Returns:
        Complete overlay analysis
    """
    result = {
        'overlay_analysis': {}
    }
    
    # Detect overlay
    detection = OverlayDetector.detect_overlay(file_path)
    result['overlay_analysis'] = detection
    
    # Add interpretation
    if detection.get('has_overlay'):
        risk = detection.get('risk_score', 0)
        
        if risk > 70:
            interpretation = 'High risk - likely malicious payload'
        elif risk > 40:
            interpretation = 'Medium risk - investigate further'
        elif risk > 20:
            interpretation = 'Low risk - possibly legitimate'
        else:
            interpretation = 'Minimal risk - likely benign'
        
        result['overlay_analysis']['interpretation'] = interpretation
    
    return result
