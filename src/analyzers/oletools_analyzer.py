"""
Author: Ugur Ates
OleTools Integration for Deep Office Document Analysis
Blue Team Tool Integration - 
"""

import logging
import subprocess
import json
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

OLETOOLS_AVAILABLE = False
try:
    import oletools
    from oletools import olevba
    from oletools import mraptor
    from oletools import msodde
    from oletools import oleobj
    from oletools import rtfobj
    OLETOOLS_AVAILABLE = True
except ImportError:
    logger.warning("[OLETOOLS] oletools not available - install with: pip install oletools")
class OleToolsAnalyzer:
    """
    Deep Office document analysis using OleTools suite.
    
    Integrated Blue Team Tools:
    - olevba: VBA Macro extraction & analysis
    - MacroRaptor: Malicious macro detection
    - msodde: DDE link detection
    - oleobj: OLE object extraction
    - rtfobj: RTF object extraction
    """
    
    @staticmethod
    def analyze_office_document(file_path: str) -> Dict:
        """
        Comprehensive Office document analysis.
        
        Args:
            file_path: Path to Office document
        
        Returns:
            Complete analysis results
        """
        if not OLETOOLS_AVAILABLE:
            return {
                'error': 'oletools not available',
                'install_command': 'pip install oletools'
            }
        
        result = {
            'oletools_analysis': {},
            'vba_macros': {},
            'macro_indicators': {},
            'dde_links': {},
            'ole_objects': {},
            'risk_score': 0
        }
        
        try:
            # 1. VBA Macro Analysis
            logger.info("[OLETOOLS] Analyzing VBA macros...")
            vba_result = OleToolsAnalyzer._analyze_vba_macros(file_path)
            result['vba_macros'] = vba_result
            
            # 2. MacroRaptor Analysis
            logger.info("[OLETOOLS] Running MacroRaptor...")
            raptor_result = OleToolsAnalyzer._run_macro_raptor(file_path)
            result['macro_indicators'] = raptor_result
            
            # 3. DDE Link Detection
            logger.info("[OLETOOLS] Checking for DDE links...")
            dde_result = OleToolsAnalyzer._detect_dde_links(file_path)
            result['dde_links'] = dde_result
            
            # 4. OLE Object Extraction
            logger.info("[OLETOOLS] Extracting OLE objects...")
            ole_result = OleToolsAnalyzer._extract_ole_objects(file_path)
            result['ole_objects'] = ole_result
            
            # Calculate aggregate risk score
            result['risk_score'] = OleToolsAnalyzer._calculate_oletools_risk(result)
            
        except Exception as e:
            logger.error(f"[OLETOOLS] Analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    @staticmethod
    def _analyze_vba_macros(file_path: str) -> Dict:
        """Extract and analyze VBA macros."""
        try:
            vbaparser = olevba.VBA_Parser(file_path)
            
            if not vbaparser.detect_vba_macros():
                return {
                    'has_macros': False,
                    'macro_count': 0
                }
            
            macros = []
            indicators = []
            
            # Extract macros
            for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                macros.append({
                    'filename': vba_filename,
                    'stream': stream_path,
                    'code_length': len(vba_code)
                })
            
            # Analyze indicators
            results = vbaparser.analyze_macros()
            if results:
                for kw_type, keyword, description in results:
                    indicators.append({
                        'type': kw_type,
                        'keyword': keyword,
                        'description': description
                    })
            
            vbaparser.close()
            
            return {
                'has_macros': True,
                'macro_count': len(macros),
                'macros': macros,
                'indicators': indicators,
                'suspicious': len(indicators) > 0
            }
            
        except Exception as e:
            logger.error(f"[OLETOOLS] VBA analysis failed: {e}")
            return {'error': str(e)}
    
    @staticmethod
    def _run_macro_raptor(file_path: str) -> Dict:
        """Run MacroRaptor for malicious macro detection."""
        try:
            # MacroRaptor analysis
            m = mraptor.MacroRaptor(file_path)
            m.scan()
            
            return {
                'suspicious': m.suspicious,
                'score': getattr(m, 'score', 0),
                'flags': m.flags if hasattr(m, 'flags') else []
            }
            
        except Exception as e:
            logger.error(f"[OLETOOLS] MacroRaptor failed: {e}")
            return {'error': str(e)}
    
    @staticmethod
    def _detect_dde_links(file_path: str) -> Dict:
        """Detect DDE/DDEAUTO links."""
        try:
            # Use msodde to detect DDE links
            result = subprocess.run(
                ['msodde', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if 'DDE' in result.stdout or 'DDEAUTO' in result.stdout:
                return {
                    'has_dde': True,
                    'dde_content': result.stdout
                }
            
            return {'has_dde': False}
            
        except subprocess.TimeoutExpired:
            return {'error': 'DDE detection timeout'}
        except Exception as e:
            logger.error(f"[OLETOOLS] DDE detection failed: {e}")
            return {'error': str(e)}
    
    @staticmethod
    def _extract_ole_objects(file_path: str) -> Dict:
        """Extract OLE objects from document."""
        try:
            # Use oleobj to extract objects
            result = subprocess.run(
                ['oleobj', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            objects = []
            if 'Found' in result.stdout:
                # Parse output for objects
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Object' in line or 'Embedded' in line:
                        objects.append(line.strip())
            
            return {
                'object_count': len(objects),
                'objects': objects,
                'has_objects': len(objects) > 0
            }
            
        except subprocess.TimeoutExpired:
            return {'error': 'Object extraction timeout'}
        except Exception as e:
            logger.error(f"[OLETOOLS] Object extraction failed: {e}")
            return {'error': str(e)}
    
    @staticmethod
    def _calculate_oletools_risk(analysis: Dict) -> int:
        """Calculate risk score from OleTools analysis."""
        risk = 0
        
        # VBA Macros
        vba = analysis.get('vba_macros', {})
        if vba.get('has_macros'):
            risk += 20
            if vba.get('suspicious'):
                risk += 30
            risk += min(len(vba.get('indicators', [])) * 5, 25)
        
        # MacroRaptor
        raptor = analysis.get('macro_indicators', {})
        if raptor.get('suspicious'):
            risk += 40
        
        # DDE Links
        dde = analysis.get('dde_links', {})
        if dde.get('has_dde'):
            risk += 50  # DDE is very suspicious
        
        # OLE Objects
        ole = analysis.get('ole_objects', {})
        if ole.get('has_objects'):
            risk += 15
        
        return min(risk, 100)
def analyze_with_oletools(file_path: str) -> Dict:
    """
    Main entry point for OleTools analysis.
    
    Args:
        file_path: Path to Office document
    
    Returns:
        Complete OleTools analysis
    """
    return OleToolsAnalyzer.analyze_office_document(file_path)
