"""
Author: Ugur Ates
PDF Analyzer - Profesyonel PDF Analizi.

Entegre Araçlar:
- pdfid: Suspicious keyword detection
- pdf-parser: Object extraction & analysis
- YARA scanning
- String extraction

v1.0.0 - Professional Analysis Suite
"""

import re
import logging
from typing import Dict, List
from pathlib import Path

logger = logging.getLogger(__name__)
class PDFAnalyzer:
    """
    Profesyonel PDF analizi with external tool integration.
    
    Features:
    - JavaScript detection & extraction
    - OpenAction/AA (Auto-Action) detection
    - Launch action detection
    - Embedded file detection
    - URI extraction
    - Obfuscation detection
    """
    
    # Suspicious PDF keywords
    SUSPICIOUS_KEYWORDS = {
        'javascript': ['/JavaScript', '/JS'],
        'auto_action': ['/OpenAction', '/AA'],
        'launch': ['/Launch'],
        'embedded': ['/EmbeddedFile', '/EmbeddedFiles'],
        'form': ['/AcroForm', '/XFA'],
        'uri': ['/URI'],
        'vulnerability': ['/JBIG2Decode', '/RichMedia', '/Flash'],
        'encryption': ['/Encrypt'],
        'object_streams': ['/ObjStm'],
    }
    
    # High-risk keyword combinations
    HIGH_RISK_COMBINATIONS = [
        ('/JavaScript', '/OpenAction'),
        ('/JS', '/AA'),
        ('/Launch', '/OpenAction'),
        ('/EmbeddedFile', '/JavaScript'),
    ]
    
    def __init__(self):
        """Initialize with tool runner."""
        try:
            from ..tools.external_tool_runner import get_tool_runner
            self.tool_runner = get_tool_runner()
        except:
            self.tool_runner = None
    
    def analyze(self, file_path: str) -> Dict:
        """
        Kapsamlı PDF analizi.
        
        Pipeline:
        1. pdfid - Keyword detection
        2. pdf-parser - Object extraction
        3. JavaScript extraction
        4. URI extraction
        5. Basic content analysis
        """
        logger.info(f"[PDF] Analyzing: {Path(file_path).name}")
        
        result = {
            'file_path': file_path,
            'file_type': 'PDF',
            'analysis_tools': [],
            
            'pdf_structure': {},
            'javascript': [],
            'uris': [],
            'embedded_files': [],
            'suspicious_objects': [],
            
            'threat_indicators': [],
            'threat_score': 0,
            'verdict': 'UNKNOWN',
            'raw_outputs': {},
        }
        
        # 1. PDFiD Analysis
        if self.tool_runner and self.tool_runner.is_available('pdfid'):
            pdfid_out = self.tool_runner.run_pdfid(file_path)
            if pdfid_out.success:
                result['pdf_structure'] = self._parse_pdfid(pdfid_out.stdout)
                result['raw_outputs']['pdfid'] = pdfid_out.stdout
                result['analysis_tools'].append('pdfid')
                
                struct = result['pdf_structure']
                if struct.get('javascript', 0) > 0:
                    result['threat_indicators'].append(
                        f"JavaScript: {struct['javascript']} occurrences"
                    )
                if struct.get('openaction', 0) > 0 or struct.get('aa', 0) > 0:
                    result['threat_indicators'].append("Auto-action detected")
                if struct.get('launch', 0) > 0:
                    result['threat_indicators'].append("Launch action (code execution)")
                if struct.get('embeddedfile', 0) > 0:
                    result['threat_indicators'].append(
                        f"Embedded files: {struct['embeddedfile']}"
                    )
        
        # 2. PDF-Parser Analysis
        if self.tool_runner and self.tool_runner.is_available('pdf-parser'):
            # JavaScript extraction
            js_out = self.tool_runner.run_pdf_parser(file_path, search='javascript')
            if js_out.success:
                result['javascript'] = self._extract_javascript(js_out.stdout)
                result['raw_outputs']['pdf-parser-js'] = js_out.stdout
            
            # URI extraction
            uri_out = self.tool_runner.run_pdf_parser(file_path, search='URI')
            if uri_out.success:
                result['uris'] = self._extract_uris(uri_out.stdout)
                result['raw_outputs']['pdf-parser-uri'] = uri_out.stdout
                
                if result['uris']:
                    result['threat_indicators'].append(f"URIs found: {len(result['uris'])}")
            
            result['analysis_tools'].append('pdf-parser')
        
        # 3. Basic analysis fallback
        if not result['analysis_tools']:
            basic = self._basic_analysis(file_path)
            result['pdf_structure'] = basic
            result['analysis_tools'].append('basic')
        
        # 4. Calculate threat score
        result['threat_score'] = self._calculate_score(result)
        result['verdict'] = self._determine_verdict(result['threat_score'])
        
        return result
    
    def _parse_pdfid(self, output: str) -> Dict:
        """Parse pdfid output."""
        structure = {
            'header': '',
            'objects': 0,
            'streams': 0,
            'pages': 0,
            'javascript': 0,
            'js': 0,
            'openaction': 0,
            'aa': 0,
            'launch': 0,
            'embeddedfile': 0,
            'acroform': 0,
            'xfa': 0,
            'uri': 0,
            'jbig2decode': 0,
            'richmedia': 0,
            'objstm': 0,
            'encrypt': 0,
            'obfuscated': 0,
        }
        
        for line in output.split('\n'):
            line_lower = line.strip().lower()
            
            if 'pdf header' in line_lower:
                structure['header'] = line.split(':')[-1].strip()
            
            # Parse each keyword
            for keyword in structure.keys():
                if keyword == 'header':
                    continue
                
                # Match format like "/JavaScript     3"
                pattern = rf'/{keyword}\s+(\d+)'
                match = re.search(pattern, line_lower)
                if match:
                    structure[keyword] = int(match.group(1))
                
                # Also check without slash
                pattern2 = rf'\b{keyword}\s+(\d+)'
                match2 = re.search(pattern2, line_lower)
                if match2:
                    structure[keyword] = int(match2.group(1))
            
            # Obfuscation detection (parentheses in output)
            if '(' in line and ')' in line:
                obf_match = re.search(r'\((\d+)\)', line)
                if obf_match:
                    structure['obfuscated'] += int(obf_match.group(1))
        
        return structure
    
    def _extract_javascript(self, output: str) -> List[Dict]:
        """Extract JavaScript code from pdf-parser output."""
        scripts = []
        
        current_obj = None
        js_content = []
        
        for line in output.split('\n'):
            if line.startswith('obj ') or line.startswith('Object '):
                if current_obj and js_content:
                    scripts.append({
                        'object': current_obj,
                        'code': '\n'.join(js_content)[:1000]
                    })
                parts = line.split()
                current_obj = parts[1] if len(parts) > 1 else 'unknown'
                js_content = []
            elif current_obj:
                js_content.append(line)
        
        if current_obj and js_content:
            scripts.append({
                'object': current_obj,
                'code': '\n'.join(js_content)[:1000]
            })
        
        return scripts
    
    def _extract_uris(self, output: str) -> List[str]:
        """Extract URIs from pdf-parser output."""
        uris = set()
        
        # Standard URL pattern
        url_pattern = re.compile(r'https?://[^\s<>"\')\]]+')
        for url in url_pattern.findall(output):
            uris.add(url)
        
        # /URI entries
        uri_entry = re.compile(r'/URI\s*\((.*?)\)')
        for uri in uri_entry.findall(output):
            uris.add(uri)
        
        return list(uris)[:50]
    
    def _basic_analysis(self, file_path: str) -> Dict:
        """Basic PDF analysis without external tools."""
        structure = {
            'header': '',
            'javascript': 0,
            'openaction': 0,
            'launch': 0,
            'embeddedfile': 0,
            'uri': 0,
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(100000).decode('latin-1', errors='ignore')
            
            # Check header
            if content.startswith('%PDF'):
                match = re.search(r'%PDF-(\d\.\d)', content)
                if match:
                    structure['header'] = f'PDF-{match.group(1)}'
            
            # Count keywords
            structure['javascript'] = content.lower().count('/javascript')
            structure['openaction'] = content.lower().count('/openaction')
            structure['launch'] = content.lower().count('/launch')
            structure['embeddedfile'] = content.lower().count('/embeddedfile')
            structure['uri'] = content.lower().count('/uri')
            
        except Exception as e:
            logger.warning(f"[PDF] Basic analysis failed: {e}")
        
        return structure
    
    def _calculate_score(self, result: Dict) -> int:
        """Calculate threat score."""
        score = 0
        struct = result.get('pdf_structure', {})
        
        # JavaScript
        js_count = struct.get('javascript', 0) + struct.get('js', 0)
        if js_count > 0:
            score += 25 + min(js_count * 5, 15)
        
        # Auto-actions
        if struct.get('openaction', 0) > 0 or struct.get('aa', 0) > 0:
            score += 15
        
        # Launch (code execution) - HIGH RISK
        if struct.get('launch', 0) > 0:
            score += 35
        
        # Embedded files
        if struct.get('embeddedfile', 0) > 0:
            score += 15
        
        # XFA forms
        if struct.get('xfa', 0) > 0:
            score += 10
        
        # Known vulnerabilities
        if struct.get('jbig2decode', 0) > 0:
            score += 30  # CVE-2009-0658
        if struct.get('richmedia', 0) > 0:
            score += 15
        
        # Obfuscation
        if struct.get('obfuscated', 0) > 0:
            score += 20
        
        # Actual JavaScript content
        if result.get('javascript'):
            score += len(result['javascript']) * 10
        
        # Dangerous combinations
        for combo in self.HIGH_RISK_COMBINATIONS:
            kw1 = combo[0].replace('/', '').lower()
            kw2 = combo[1].replace('/', '').lower()
            if struct.get(kw1, 0) > 0 and struct.get(kw2, 0) > 0:
                score += 15
        
        return min(score, 100)
    
    def _determine_verdict(self, score: int) -> str:
        if score >= 70:
            return 'MALICIOUS'
        elif score >= 40:
            return 'SUSPICIOUS'
        else:
            return 'CLEAN'
