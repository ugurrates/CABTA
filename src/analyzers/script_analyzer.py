"""
Author: Ugur Ates
Script Analyzer - Professional Script Analysis with Tool Integration.

v1.0.0 Features:
- PowerShell obfuscation detection
- VBScript Chr() encoding detection
- JavaScript eval/unescape detection
- Base64 encoded command detection
- IOC extraction
- Suspicious API detection
- Threat scoring

Supported Scripts:
- PowerShell (.ps1, .psm1, .psd1)
- VBScript (.vbs, .vbe)
- JavaScript (.js, .jse)
- Batch (.bat, .cmd)
- Shell (.sh, .bash)
- Python (.py)
- HTA (.hta)
- WSF (.wsf)
"""

import re
import os
import base64
from typing import Dict, List, Optional
from pathlib import Path
import logging

from .deobfuscators import (
    PowerShellDeobfuscator,
    VBScriptDeobfuscator,
    JavaScriptDeobfuscator,
    BatchDeobfuscator,
)

logger = logging.getLogger(__name__)


class ScriptAnalyzer:
    """Professional script file analysis with obfuscation detection."""
    
    # PowerShell suspicious patterns
    POWERSHELL_SUSPICIOUS = {
        'download': [
            r'(Invoke-WebRequest|IWR|wget|curl)',
            r'(New-Object\s+System\.Net\.WebClient)',
            r'(DownloadString|DownloadFile|DownloadData)',
            r'(Start-BitsTransfer)',
            r'(Invoke-RestMethod|IRM)',
        ],
        'execution': [
            r'(Invoke-Expression|IEX)',
            r'(Invoke-Command|ICM)',
            r'(\.\s*\(|&\s*\()',
            r'(Start-Process|saps)',
            r'(Invoke-Item|ii)',
        ],
        'encoding': [
            r'(-EncodedCommand|-enc|-e\s)',
            r'(\[System\.Convert\]::FromBase64String)',
            r'(\[System\.Text\.Encoding\])',
            r'(-bxor|-band|-bor)',
        ],
        'evasion': [
            r'(Set-ExecutionPolicy|Bypass)',
            r'(-WindowStyle\s+Hidden)',
            r'(Out-Null)',
            r'(\$env:ComSpec)',
            r'(AmsiUtils|amsiInitFailed)',
            r'(Disable-WindowsDefender)',
        ],
        'persistence': [
            r'(New-ItemProperty.*Run)',
            r'(schtasks|Register-ScheduledTask)',
            r'(New-Service|sc\.exe)',
            r'(HKLM:|HKCU:)',
        ],
        'credential': [
            r'(Get-Credential|ConvertTo-SecureString)',
            r'(mimikatz|sekurlsa)',
            r'(lsass|SAM|SECURITY)',
            r'(Invoke-Mimikatz|Get-GPPPassword)',
        ],
        'recon': [
            r'(Get-WmiObject|gwmi)',
            r'(Get-Process|gps)',
            r'(Get-Service|gsv)',
            r'(Get-ADUser|Get-ADComputer)',
            r'(Test-NetConnection|tnc)',
        ],
    }
    
    # VBScript suspicious patterns
    VBSCRIPT_SUSPICIOUS = {
        'execution': [
            r'(CreateObject.*Shell)',
            r'(WScript\.Shell)',
            r'(Shell\.Application)',
            r'(\.Run\s*\()',
            r'(\.Exec\s*\()',
        ],
        'download': [
            r'(MSXML2\.XMLHTTP|WinHttp)',
            r'(\.Open.*GET|\.Open.*POST)',
            r'(\.responseBody|\.responseText)',
            r'(ADODB\.Stream)',
        ],
        'encoding': [
            r'(Chr\s*\(\s*\d+\s*\))',
            r'(Execute\s*\()',
            r'(Eval\s*\()',
            r'(StrReverse)',
        ],
        'file_ops': [
            r'(Scripting\.FileSystemObject)',
            r'(\.CreateTextFile|\.OpenTextFile)',
            r'(\.CopyFile|\.MoveFile)',
            r'(\.Write|\.WriteLine)',
        ],
    }
    
    # JavaScript suspicious patterns
    JAVASCRIPT_SUSPICIOUS = {
        'execution': [
            r'(eval\s*\()',
            r'(Function\s*\()',
            r'(setTimeout|setInterval).*eval',
            r'(new\s+ActiveXObject)',
        ],
        'encoding': [
            r'(String\.fromCharCode)',
            r'(unescape\s*\()',
            r'(atob|btoa)',
            r'(\\x[0-9a-fA-F]{2}){5,}',
            r'(\\u[0-9a-fA-F]{4}){5,}',
        ],
        'dom': [
            r'(document\.write)',
            r'(innerHTML\s*=)',
            r'(createElement.*script)',
        ],
    }
    
    # Map extensions to their deobfuscator classes
    _DEOBFUSCATORS = {
        '.ps1': PowerShellDeobfuscator,
        '.psm1': PowerShellDeobfuscator,
        '.psd1': PowerShellDeobfuscator,
        '.vbs': VBScriptDeobfuscator,
        '.vbe': VBScriptDeobfuscator,
        '.js': JavaScriptDeobfuscator,
        '.jse': JavaScriptDeobfuscator,
        '.bat': BatchDeobfuscator,
        '.cmd': BatchDeobfuscator,
        '.hta': JavaScriptDeobfuscator,  # HTA often contains JS/VBS
        '.wsf': JavaScriptDeobfuscator,  # WSF can contain JS
    }

    def __init__(self):
        """Initialize script analyzer with deobfuscation engines."""
        self._deob_cache: Dict = {}  # Cache deobfuscator instances
    
    def analyze(self, file_path: str) -> Dict:
        """
        Analyze script file for malicious indicators.
        
        Args:
            file_path: Path to script file
            
        Returns:
            Comprehensive analysis results with threat scoring
        """
        logger.info(f"[SCRIPT] Analyzing: {Path(file_path).name}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            ext = Path(file_path).suffix.lower()
            script_type = self._get_script_type(ext)
            
            # Run deobfuscation engine for supported script types
            deob_result = self._run_deobfuscation(content, ext)
            # Use deobfuscated content for deeper analysis when available
            analysis_content = deob_result.get('deobfuscated', content) if deob_result else content

            result = {
                'file_path': file_path,
                'file_type': 'Script',
                'script_type': script_type,
                'analysis_tools': ['pattern_analyzer', 'deobfuscator'] if deob_result else ['pattern_analyzer'],
                'size': os.path.getsize(file_path),
                'lines': len(content.split('\n')),

                # Analysis results (use deobfuscated content for pattern matching)
                'obfuscation': self._detect_obfuscation(content, ext),
                'deobfuscation': deob_result,
                'suspicious_patterns': self._detect_suspicious_patterns(analysis_content, ext),
                'encoded_content': self._extract_encoded_content(content),
                'iocs': self._extract_iocs(analysis_content),
                'network_indicators': self._detect_network_activity(analysis_content),
                'file_indicators': self._detect_file_operations(analysis_content),
                'registry_indicators': self._detect_registry_operations(analysis_content),

                'threat_score': 0,
                'threat_indicators': [],
                'verdict': 'UNKNOWN',
            }
            
            # Calculate threat score
            result['threat_score'] = self._calculate_threat_score(result)
            result['threat_indicators'] = self._get_threat_indicators(result)
            result['verdict'] = self._determine_verdict(result['threat_score'])
            
            return result
            
        except Exception as e:
            logger.error(f"[SCRIPT] Analysis failed: {e}")
            return {'error': str(e), 'file_type': 'Script'}
    
    def _get_script_type(self, ext: str) -> str:
        """Determine script type from extension."""
        type_map = {
            '.ps1': 'PowerShell', '.psm1': 'PowerShell', '.psd1': 'PowerShell',
            '.vbs': 'VBScript', '.vbe': 'VBScript',
            '.js': 'JavaScript', '.jse': 'JavaScript',
            '.bat': 'Batch', '.cmd': 'Batch',
            '.sh': 'Shell', '.bash': 'Shell',
            '.py': 'Python',
            '.hta': 'HTA',
            '.wsf': 'WSF',
        }
        return type_map.get(ext, 'Unknown')
    
    def _detect_obfuscation(self, content: str, ext: str) -> Dict:
        """Detect obfuscation techniques."""
        result = {
            'likely_obfuscated': False,
            'confidence': 0,
            'techniques': [],
            'indicators': [],
        }
        
        if ext in ['.ps1', '.psm1']:
            # Base64 encoded commands
            if re.search(r'-[Ee]nc(odedCommand)?\s+[A-Za-z0-9+/=]{50,}', content):
                result['techniques'].append('Base64 Encoded Command')
                result['indicators'].append('PowerShell -EncodedCommand detected')
                result['confidence'] += 40
            
            # String concatenation
            concat_count = len(re.findall(r'\+\s*["\'][^"\']+["\']\s*\+', content))
            if concat_count > 10:
                result['techniques'].append('String Concatenation')
                result['confidence'] += 20
            
            # Backtick obfuscation
            tick_count = content.count('`')
            if tick_count > 20:
                result['techniques'].append('Backtick Obfuscation')
                result['confidence'] += 25
            
            # Variable substitution
            if re.search(r'\$\{[^}]+\}', content):
                result['techniques'].append('Variable Substitution')
                result['confidence'] += 15
            
            # Character replacement
            if re.search(r'-replace\s*["\']', content, re.I):
                replace_count = len(re.findall(r'-replace', content, re.I))
                if replace_count > 5:
                    result['techniques'].append('Character Replacement')
                    result['confidence'] += 20
            
            # Format operator obfuscation
            if re.search(r'["\'][^"\']*\{\d+\}[^"\']*["\']\s*-f', content):
                result['techniques'].append('Format Operator Obfuscation')
                result['confidence'] += 25
        
        elif ext == '.vbs':
            # Chr() encoding
            chr_count = len(re.findall(r'Chr\s*\(\s*\d+\s*\)', content, re.I))
            if chr_count > 10:
                result['techniques'].append('Chr() Encoding')
                result['confidence'] += 30
            
            # String reversal
            if 'StrReverse' in content:
                result['techniques'].append('String Reversal')
                result['confidence'] += 20
            
            # Replace obfuscation
            if 'Replace(' in content:
                replace_count = content.count('Replace(')
                if replace_count > 5:
                    result['techniques'].append('Replace Obfuscation')
                    result['confidence'] += 15
        
        elif ext == '.js':
            # Hex encoding
            hex_count = len(re.findall(r'\\x[0-9a-fA-F]{2}', content))
            if hex_count > 20:
                result['techniques'].append('Hex Encoding')
                result['confidence'] += 25
            
            # Unicode encoding
            unicode_count = len(re.findall(r'\\u[0-9a-fA-F]{4}', content))
            if unicode_count > 10:
                result['techniques'].append('Unicode Encoding')
                result['confidence'] += 25
            
            # eval usage
            if re.search(r'eval\s*\(', content):
                result['techniques'].append('Dynamic Evaluation')
                result['confidence'] += 20
            
            # String.fromCharCode
            if 'fromCharCode' in content:
                result['techniques'].append('fromCharCode Encoding')
                result['confidence'] += 20
        
        # Common obfuscation detection
        # Long lines (common in obfuscated scripts)
        lines = content.split('\n')
        long_lines = sum(1 for line in lines if len(line) > 500)
        if long_lines > 3:
            result['techniques'].append('Long Lines (possible packed code)')
            result['confidence'] += 15
        
        # High ratio of special characters
        special_chars = sum(1 for c in content if not c.isalnum() and c not in ' \n\t')
        if len(content) > 0 and special_chars / len(content) > 0.3:
            result['techniques'].append('High Special Character Ratio')
            result['confidence'] += 10
        
        result['likely_obfuscated'] = result['confidence'] >= 40
        result['confidence'] = min(result['confidence'], 100)
        
        return result
    
    def _detect_suspicious_patterns(self, content: str, ext: str) -> Dict:
        """Detect suspicious patterns based on script type."""
        result = {
            'categories': {},
            'total_matches': 0,
        }
        
        patterns = {}
        if ext in ['.ps1', '.psm1']:
            patterns = self.POWERSHELL_SUSPICIOUS
        elif ext == '.vbs':
            patterns = self.VBSCRIPT_SUSPICIOUS
        elif ext == '.js':
            patterns = self.JAVASCRIPT_SUSPICIOUS
        
        for category, pattern_list in patterns.items():
            matches = []
            for pattern in pattern_list:
                found = re.findall(pattern, content, re.I | re.M)
                if found:
                    matches.extend(found if isinstance(found[0], str) else [m[0] if isinstance(m, tuple) else m for m in found])
            
            if matches:
                unique_matches = list(set(matches))
                result['categories'][category] = {
                    'count': len(matches),
                    'samples': unique_matches[:5]
                }
                result['total_matches'] += len(matches)
        
        return result
    
    def _extract_encoded_content(self, content: str) -> List[Dict]:
        """Extract and decode encoded content."""
        encoded_items = []
        
        # Base64 patterns
        b64_patterns = [
            r'-[Ee]nc(?:odedCommand)?\s+([A-Za-z0-9+/=]{50,})',
            r'FromBase64String\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']',
            r'atob\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']',
        ]
        
        for pattern in b64_patterns:
            matches = re.findall(pattern, content)
            for match in matches[:5]:  # Limit to first 5
                try:
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    if len(decoded) > 10:
                        encoded_items.append({
                            'type': 'base64',
                            'encoded': match[:50] + '...' if len(match) > 50 else match,
                            'decoded_preview': decoded[:200]
                        })
                except:
                    pass
        
        return encoded_items[:10]
    
    def _extract_iocs(self, content: str) -> Dict:
        """
        Extract IOCs from script using global IOCExtractor.
        
        v1.0.0: Global IOCExtractor kullanılıyor - tüm false positive filtering dahil
        """
        from ..utils.ioc_extractor import IOCExtractor
        
        # Global IOCExtractor kullan - tüm filtering dahil
        all_iocs = IOCExtractor.extract_all(content)
        
        # File paths ayrıca extract et (script-specific)
        file_paths = []
        path_pattern = re.compile(r'[A-Za-z]:\\[^\s<>"\'*?|]+')
        for path in path_pattern.findall(content):
            if path not in file_paths:
                file_paths.append(path[:100])
        
        return {
            'urls': all_iocs.get('urls', [])[:30],
            'ipv4': all_iocs.get('ipv4', [])[:30],
            'domains': all_iocs.get('domains', [])[:30],
            'emails': all_iocs.get('emails', [])[:30],
            'file_paths': file_paths[:30],
        }
    
    def _detect_network_activity(self, content: str) -> List[str]:
        """Detect network-related activities."""
        activities = []
        
        patterns = {
            'HTTP Request': r'(Invoke-WebRequest|WebClient|XMLHTTP|fetch\(|XMLHttpRequest)',
            'Download': r'(DownloadFile|DownloadString|curl|wget)',
            'Socket': r'(TcpClient|UdpClient|Socket|\.Connect\()',
            'DNS': r'(Resolve-DnsName|nslookup|dig\s)',
            'FTP': r'(FtpWebRequest|ftp://)',
            'SMTP': r'(SmtpClient|Send-MailMessage)',
        }
        
        for activity, pattern in patterns.items():
            if re.search(pattern, content, re.I):
                activities.append(activity)
        
        return activities
    
    def _detect_file_operations(self, content: str) -> List[str]:
        """Detect file operations."""
        operations = []
        
        patterns = {
            'Write File': r'(Out-File|Set-Content|WriteAllText|>|>>|\.Write)',
            'Read File': r'(Get-Content|ReadAllText|type\s|\.Read)',
            'Delete File': r'(Remove-Item|del\s|rm\s|Delete)',
            'Execute': r'(Start-Process|Invoke-Item|\.Run\(|\.Exec\()',
            'Copy/Move': r'(Copy-Item|Move-Item|\.CopyFile|\.MoveFile)',
        }
        
        for operation, pattern in patterns.items():
            if re.search(pattern, content, re.I):
                operations.append(operation)
        
        return operations
    
    def _detect_registry_operations(self, content: str) -> List[str]:
        """Detect registry operations."""
        operations = []
        
        patterns = {
            'Registry Read': r'(Get-ItemProperty|RegRead|HKLM:|HKCU:)',
            'Registry Write': r'(Set-ItemProperty|New-ItemProperty|RegWrite)',
            'Registry Delete': r'(Remove-ItemProperty|RegDelete)',
            'Run Key': r'(CurrentVersion\\Run|CurrentVersion\\RunOnce)',
            'Services': r'(CurrentControlSet\\Services)',
        }
        
        for operation, pattern in patterns.items():
            if re.search(pattern, content, re.I):
                operations.append(operation)
        
        return operations
    
    def _calculate_threat_score(self, result: Dict) -> int:
        """
        Calculate threat score based on findings.
        
        v1.0.0: Ağırlıklar artırıldı - yüksek riskli pattern'ler için daha yüksek skor
        """
        score = 0
        
        # Obfuscation (0-50 points)
        if result['obfuscation']['likely_obfuscated']:
            score += result['obfuscation']['confidence'] // 2

        # Deobfuscation findings add to threat score (0-20 points)
        deob = result.get('deobfuscation')
        if deob and deob.get('techniques_found'):
            score += min(len(deob['techniques_found']) * 5, 20)
        
        # Suspicious patterns - base (0-30 points)
        patterns = result['suspicious_patterns']
        score += min(patterns['total_matches'] * 3, 30)
        
      
        high_risk_weights = {
            'execution': 10,      # Invoke-Expression, Start-Process
            'download': 10,       # WebClient, DownloadFile
            'credential': 15,     # Mimikatz, credential dump
            'evasion': 12,        # AMSI bypass, disable logging
            'persistence': 10,    # Registry run keys, scheduled tasks
            'privilege': 12,      # UAC bypass, admin check
        }
        
        for category, weight in high_risk_weights.items():
            if category in patterns.get('categories', {}):
                cat_count = patterns['categories'][category].get('count', 0)
                score += min(cat_count * weight, 50)
        
        # Encoded content (0-40 points)
        encoded = result.get('encoded_content', {})
        if isinstance(encoded, dict):
            b64_count = len(encoded.get('base64_strings', []))
            score += min(b64_count * 15, 40)
        elif isinstance(encoded, list):
            score += min(len(encoded) * 10, 40)
        
        # IOCs (0-30 points)
        iocs = result['iocs']
        score += min(len(iocs.get('urls', [])) * 5, 15)
        score += min(len(iocs.get('ipv4', [])) * 5, 15)
        
        # Network indicators (0-25 points)
        score += min(len(result['network_indicators']) * 8, 25)
        
        # File operations (0-15 points)
        score += min(len(result['file_indicators']) * 3, 15)
        
        # Registry operations - high risk (0-25 points)
        score += min(len(result['registry_indicators']) * 8, 25)
        
        return min(score, 100)
    
    def _get_threat_indicators(self, result: Dict) -> List[str]:
        """Generate threat indicator list."""
        indicators = []

        # Deobfuscation findings
        deob = result.get('deobfuscation')
        if deob and deob.get('techniques_found'):
            indicators.append(
                f"Deobfuscated ({len(deob['techniques_found'])} layers): "
                f"{', '.join(deob['techniques_found'][:4])}"
            )

        if result['obfuscation']['likely_obfuscated']:
            indicators.append(f"Obfuscated: {', '.join(result['obfuscation']['techniques'][:3])}")
        
        patterns = result['suspicious_patterns']
        for category, data in patterns.get('categories', {}).items():
            indicators.append(f"{category.title()}: {data['count']} patterns")
        
        if result['encoded_content']:
            indicators.append(f"Encoded content: {len(result['encoded_content'])} blocks")
        
        if result['network_indicators']:
            indicators.append(f"Network: {', '.join(result['network_indicators'][:3])}")
        
        if result['registry_indicators']:
            indicators.append(f"Registry: {', '.join(result['registry_indicators'][:3])}")
        
        return indicators[:10]
    
    def _determine_verdict(self, score: int) -> str:
        """Determine verdict from score."""
        if score >= 70:
            return 'MALICIOUS'
        elif score >= 40:
            return 'SUSPICIOUS'
        else:
            return 'CLEAN'

    # ------------------------------------------------------------------
    # Deobfuscation integration
    # ------------------------------------------------------------------

    def _run_deobfuscation(self, content: str, ext: str) -> Optional[Dict]:
        """Run the appropriate deobfuscation engine for the script type.

        Args:
            content: Raw script content
            ext: File extension (e.g. '.ps1')

        Returns:
            Deobfuscation result dict or None if no deobfuscator available.
        """
        deob_cls = self._DEOBFUSCATORS.get(ext)
        if deob_cls is None:
            return None

        # Cache deobfuscator instances for reuse
        cls_name = deob_cls.__name__
        if cls_name not in self._deob_cache:
            self._deob_cache[cls_name] = deob_cls()

        deob = self._deob_cache[cls_name]

        try:
            result = deob.deobfuscate(content)
            # Only include deobfuscation if something actually changed
            if result.get('deobfuscated', content) != content:
                logger.info(
                    f"[SCRIPT] Deobfuscation applied: {len(result.get('techniques_found', []))} "
                    f"techniques ({', '.join(result.get('techniques_found', []))})"
                )
                return result
            return None
        except Exception as exc:
            logger.debug(f"[SCRIPT] Deobfuscation error: {exc}")
            return None
