"""
Author: Ugur Ates
String Extraction & Deobfuscation Tool
Best Practices: Extract IOCs, deobfuscate scripts, identify patterns
"""

import re
import base64
import binascii
import logging
from typing import Dict, List, Set

logger = logging.getLogger(__name__)
class StringExtractor:
    """
    Extract and analyze strings from files.
    
    Capabilities:
    - ASCII/Unicode string extraction
    - IOC pattern detection (IPs, URLs, emails)
    - Base64 encoded string detection
    - Hex encoded string detection
    - PowerShell/VBScript deobfuscation
    - Suspicious API identification
    """
    
    # Suspicious Windows API calls
    SUSPICIOUS_APIS = [
        'VirtualAlloc', 'VirtualAllocEx', 'CreateRemoteThread', 
        'WriteProcessMemory', 'OpenProcess', 'QueueUserAPC',
        'CreateProcess', 'WinExec', 'ShellExecute', 'URLDownloadToFile',
        'InternetOpen', 'InternetOpenUrl', 'HttpSendRequest',
        'RegSetValueEx', 'RegCreateKeyEx', 'CryptAcquireContext',
        'GetProcAddress', 'LoadLibrary', 'NtAllocateVirtualMemory'
    ]
    
    # Suspicious strings/patterns
    SUSPICIOUS_PATTERNS = [
        r'cmd\.exe', r'powershell', r'wscript', r'cscript',
        r'eval\(', r'exec\(', r'invoke-expression',
        r'frombase64string', r'downloadstring', r'downloadfile',
        r'bypass', r'hidden', r'-enc', r'-encodedcommand',
        r'shellcode', r'payload', r'exploit'
    ]
    
    @staticmethod
    def extract_strings(file_path: str, min_length: int = 4) -> Dict:
        """
        Extract all printable strings from a file.
        
        Args:
            file_path: Path to file
            min_length: Minimum string length
        
        Returns:
            Dict with extracted strings and analysis
        """
        result = {
            'ascii_strings': [],
            'unicode_strings': [],
            'suspicious_apis': [],
            'suspicious_patterns': [],
            'iocs': {
                'ips': [],
                'urls': [],
                'emails': [],
                'domains': []
            },
            'encoded_strings': {
                'base64': [],
                'hex': []
            }
        }
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Extract ASCII strings
            ascii_pattern = b'[\x20-\x7E]{' + str(min_length).encode() + b',}'
            ascii_strings = re.findall(ascii_pattern, data)
            result['ascii_strings'] = [s.decode('ascii', errors='ignore') for s in ascii_strings[:1000]]  # Limit
            
            # Extract Unicode strings
            unicode_pattern = b'(?:[\x20-\x7E][\x00]){' + str(min_length).encode() + b',}'
            unicode_strings = re.findall(unicode_pattern, data)
            result['unicode_strings'] = [s.decode('utf-16-le', errors='ignore') for s in unicode_strings[:1000]]
            
            # Analyze strings
            all_strings = result['ascii_strings'] + result['unicode_strings']
            
            # Find suspicious APIs
            for string in all_strings:
                for api in StringExtractor.SUSPICIOUS_APIS:
                    if api.lower() in string.lower():
                        if api not in result['suspicious_apis']:
                            result['suspicious_apis'].append(api)
            
            # Find suspicious patterns
            for string in all_strings:
                for pattern in StringExtractor.SUSPICIOUS_PATTERNS:
                    if re.search(pattern, string, re.IGNORECASE):
                        result['suspicious_patterns'].append(string[:100])  # Truncate
            
            # Extract IOCs
            result['iocs'] = StringExtractor._extract_iocs(all_strings)
            
            # Detect encoded strings
            result['encoded_strings'] = StringExtractor._detect_encoded(all_strings)
            
            logger.info(f"[STRING-EXTRACT] Extracted {len(all_strings)} strings")
            
        except Exception as e:
            logger.error(f"[STRING-EXTRACT] Extraction failed: {e}")
            result['error'] = str(e)
        
        return result
    
    @staticmethod
    def _extract_iocs(strings: List[str]) -> Dict:
        """Extract IOCs from strings."""
        iocs = {
            'ips': set(),
            'urls': set(),
            'emails': set(),
            'domains': set()
        }
        
        # IP pattern
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        # URL pattern
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        
        # Email pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        # Domain pattern
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        
        for string in strings:
            # IPs
            ips = re.findall(ip_pattern, string)
            iocs['ips'].update(ips)
            
            # URLs
            urls = re.findall(url_pattern, string)
            iocs['urls'].update(urls)
            
            # Emails
            emails = re.findall(email_pattern, string)
            iocs['emails'].update(emails)
            
            # Domains
            domains = re.findall(domain_pattern, string.lower())
            iocs['domains'].update(domains)
        
        # Convert sets to lists
        return {k: list(v)[:100] for k, v in iocs.items()}  # Limit to 100 each
    
    @staticmethod
    def _detect_encoded(strings: List[str]) -> Dict:
        """Detect encoded strings (base64, hex)."""
        encoded = {
            'base64': [],
            'hex': []
        }
        
        # Base64 pattern (at least 20 chars)
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        
        # Hex pattern (at least 20 chars)
        hex_pattern = r'[0-9a-fA-F]{20,}'
        
        for string in strings:
            # Base64
            b64_matches = re.findall(base64_pattern, string)
            for match in b64_matches:
                try:
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    if len(decoded) > 3:
                        encoded['base64'].append({
                            'encoded': match[:50],
                            'decoded': decoded[:100]
                        })
                except:
                    pass
            
            # Hex
            hex_matches = re.findall(hex_pattern, string)
            for match in hex_matches:
                try:
                    decoded = binascii.unhexlify(match).decode('utf-8', errors='ignore')
                    if len(decoded) > 3:
                        encoded['hex'].append({
                            'encoded': match[:50],
                            'decoded': decoded[:100]
                        })
                except:
                    pass
        
        # Limit results
        return {k: v[:20] for k, v in encoded.items()}
class ScriptDeobfuscator:
    """
    Deobfuscate common script obfuscation techniques.
    
    Supports:
    - PowerShell Base64 encoding
    - VBScript encoding
    - JavaScript obfuscation
    - Hex encoding
    """
    
    @staticmethod
    def deobfuscate_powershell(script: str) -> Dict:
        """
        Deobfuscate PowerShell scripts.
        
        Args:
            script: Obfuscated PowerShell code
        
        Returns:
            Deobfuscated code and analysis
        """
        result = {
            'original': script[:500],
            'deobfuscated': '',
            'techniques_found': []
        }
        
        deobfuscated = script
        
        try:
            # Base64 encoded commands
            if '-encodedcommand' in script.lower() or '-enc' in script.lower():
                result['techniques_found'].append('Base64 Encoding')
                
                # Extract base64 content
                b64_pattern = r'-(?:enc(?:odedcommand)?)\s+([A-Za-z0-9+/=]+)'
                matches = re.findall(b64_pattern, script, re.IGNORECASE)
                
                for match in matches:
                    try:
                        decoded = base64.b64decode(match).decode('utf-16-le', errors='ignore')
                        deobfuscated = deobfuscated.replace(match, decoded)
                    except:
                        pass
            
            # String concatenation
            if '+' in script or '-join' in script.lower():
                result['techniques_found'].append('String Concatenation')
            
            # Character replacement
            if '-replace' in script.lower():
                result['techniques_found'].append('Character Replacement')
            
            # Invoke-Expression
            if 'iex' in script.lower() or 'invoke-expression' in script.lower():
                result['techniques_found'].append('Invoke-Expression (Dynamic Execution)')
            
            # DownloadString
            if 'downloadstring' in script.lower():
                result['techniques_found'].append('Remote Download')
            
            result['deobfuscated'] = deobfuscated[:1000]  # Limit
            
        except Exception as e:
            logger.error(f"[DEOBFUSCATE] PowerShell failed: {e}")
            result['error'] = str(e)
        
        return result
    
    @staticmethod
    def deobfuscate_javascript(script: str) -> Dict:
        """Deobfuscate JavaScript."""
        result = {
            'original': script[:500],
            'deobfuscated': '',
            'techniques_found': []
        }
        
        deobfuscated = script
        
        try:
            # eval() usage
            if 'eval(' in script:
                result['techniques_found'].append('eval() Dynamic Execution')
            
            # Hex encoding
            hex_pattern = r'\\x[0-9a-fA-F]{2}'
            if re.search(hex_pattern, script):
                result['techniques_found'].append('Hex Encoding')
                
                # Decode hex
                def decode_hex(match):
                    try:
                        return chr(int(match.group()[2:], 16))
                    except:
                        return match.group()
                
                deobfuscated = re.sub(hex_pattern, decode_hex, script)
            
            # Unicode escaping
            if '\\u' in script:
                result['techniques_found'].append('Unicode Escaping')
            
            result['deobfuscated'] = deobfuscated[:1000]
            
        except Exception as e:
            logger.error(f"[DEOBFUSCATE] JavaScript failed: {e}")
            result['error'] = str(e)
        
        return result
def extract_strings_from_file(file_path: str) -> Dict:
    """
    Main entry point for string extraction.
    
    Args:
        file_path: File to analyze
    
    Returns:
        Complete string analysis
    """
    return StringExtractor.extract_strings(file_path)
def deobfuscate_script(script: str, script_type: str = 'powershell') -> Dict:
    """
    Main entry point for script deobfuscation.
    
    Args:
        script: Script content
        script_type: 'powershell', 'javascript', 'vbscript'
    
    Returns:
        Deobfuscation results
    """
    if script_type.lower() == 'powershell':
        return ScriptDeobfuscator.deobfuscate_powershell(script)
    elif script_type.lower() == 'javascript':
        return ScriptDeobfuscator.deobfuscate_javascript(script)
    else:
        return {'error': 'Unsupported script type'}
