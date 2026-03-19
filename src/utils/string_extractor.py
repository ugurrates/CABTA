"""
Author: Ugur AtesString extraction utility for malware analysis."""

import re
import logging
from typing import List, Dict, Set

logger = logging.getLogger(__name__)
class StringExtractor:
    """
    Extract and categorize strings from binary files.
    
    Features:
    - ASCII & Unicode string extraction
    - Suspicious pattern detection
    - URL/IP/Email extraction
    - Registry key extraction
    - Mutex/semaphore detection
    - User agent detection
    """
    
    # Suspicious string patterns
    SUSPICIOUS_PATTERNS = {
        'crypto': [
            r'AES', r'RSA', r'DES', r'RC4', r'SHA', r'MD5',
            r'encrypt', r'decrypt', r'cipher', r'CryptAcquireContext'
        ],
        'persistence': [
            r'HKEY_', r'CurrentVersion\\Run', r'Software\\Microsoft\\Windows\\CurrentVersion',
            r'\\Start Menu\\Programs\\Startup', r'schtasks', r'at.exe'
        ],
        'process': [
            r'CreateProcess', r'ShellExecute', r'WinExec', r'CreateRemoteThread',
            r'VirtualAllocEx', r'WriteProcessMemory', r'ReflectiveLoader'
        ],
        'network': [
            r'InternetOpen', r'InternetConnect', r'HttpOpenRequest', r'HttpSendRequest',
            r'URLDownloadToFile', r'WinHttpOpen', r'socket', r'connect', r'send', r'recv'
        ],
        'anti_analysis': [
            r'IsDebuggerPresent', r'CheckRemoteDebuggerPresent', r'OutputDebugString',
            r'VirtualBox', r'VMware', r'QEMU', r'Sandboxie', r'wine_get'
        ],
        'keylogging': [
            r'GetAsyncKeyState', r'SetWindowsHookEx', r'GetForegroundWindow',
            r'GetKeyState', r'MapVirtualKey'
        ],
        'injection': [
            r'LoadLibrary', r'GetProcAddress', r'CreateRemoteThread',
            r'NtUnmapViewOfSection', r'ZwUnmapViewOfSection'
        ]
    }
    
    @staticmethod
    def extract_strings(file_path: str, min_length: int = 4) -> Dict[str, List[str]]:
        """
        Extract ASCII and Unicode strings from file.
        
        Args:
            file_path: Path to file
            min_length: Minimum string length
        
        Returns:
            Dict with 'ascii' and 'unicode' string lists
        """
        strings_data = {
            'ascii': [],
            'unicode': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Extract ASCII strings
            ascii_pattern = b'[\x20-\x7e]{' + str(min_length).encode() + b',}'
            ascii_strings = re.findall(ascii_pattern, data)
            strings_data['ascii'] = [s.decode('ascii') for s in ascii_strings]
            
            # Extract Unicode strings (UTF-16 LE)
            unicode_pattern = b'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + b',}'
            unicode_strings = re.findall(unicode_pattern, data)
            strings_data['unicode'] = [s.decode('utf-16-le', errors='ignore').strip('\x00') for s in unicode_strings]
            
            logger.info(f"[STRING] Extracted {len(strings_data['ascii'])} ASCII, {len(strings_data['unicode'])} Unicode strings")
            
        except Exception as e:
            logger.error(f"[STRING] Extraction failed: {e}")
        
        return strings_data
    
    @staticmethod
    def categorize_suspicious_strings(strings: List[str]) -> Dict[str, List[str]]:
        """
        Categorize strings by suspicious patterns.
        
        Args:
            strings: List of extracted strings
        
        Returns:
            Dict of categorized suspicious strings
        """
        categorized = {}
        all_strings = ' '.join(strings).lower()
        
        for category, patterns in StringExtractor.SUSPICIOUS_PATTERNS.items():
            category_matches = []
            for pattern in patterns:
                for string in strings:
                    if re.search(pattern, string, re.IGNORECASE):
                        category_matches.append(string)
            
            if category_matches:
                categorized[category] = list(set(category_matches))  # Unique
        
        return categorized
    
    @staticmethod
    def extract_iocs_from_strings(strings: List[str]) -> Dict:
        """
        Extract IOCs from string list.
        
        Args:
            strings: List of strings
        
        Returns:
            Dict with IOCs
        """
        from .ioc_extractor import IOCExtractor
        
        combined = '\n'.join(strings)
        return IOCExtractor.extract_all(combined)
    
    @staticmethod
    def extract_registry_keys(strings: List[str]) -> List[str]:
        """Extract registry keys from strings."""
        registry_keys = []
        
        reg_pattern = r'(HKEY_[A-Z_]+\\[^\s\x00]+|SOFTWARE\\[^\s\x00]+|SYSTEM\\[^\s\x00]+)'
        
        for string in strings:
            matches = re.findall(reg_pattern, string, re.IGNORECASE)
            registry_keys.extend(matches)
        
        return list(set(registry_keys))
    
    @staticmethod
    def extract_mutexes(strings: List[str]) -> List[str]:
        """Extract mutex/semaphore names."""
        mutexes = []
        
        # Common mutex patterns
        mutex_patterns = [
            r'Global\\[A-Za-z0-9_\-]+',
            r'Local\\[A-Za-z0-9_\-]+',
            r'[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}',  # GUID format
        ]
        
        for string in strings:
            for pattern in mutex_patterns:
                matches = re.findall(pattern, string)
                mutexes.extend(matches)
        
        return list(set(mutexes))
    
    @staticmethod
    def extract_user_agents(strings: List[str]) -> List[str]:
        """Extract User-Agent strings."""
        user_agents = []
        
        ua_pattern = r'Mozilla/[0-9.]+.*'
        
        for string in strings:
            if re.match(ua_pattern, string):
                user_agents.append(string)
        
        return list(set(user_agents))
    
    @staticmethod
    def extract_file_paths(strings: List[str]) -> Dict[str, List[str]]:
        """Extract file paths (Windows & Linux)."""
        paths = {
            'windows': [],
            'linux': []
        }
        
        for string in strings:
            # Windows paths
            if re.match(r'[A-Z]:\\', string) or '\\' in string:
                paths['windows'].append(string)
            # Linux paths
            elif string.startswith('/'):
                paths['linux'].append(string)
        
        return paths
    
    @staticmethod
    def get_interesting_strings(strings: List[str], limit: int = 50) -> List[str]:
        """
        Get most interesting strings for quick triage.
        
        Prioritizes:
        - Long strings (potential C2 URLs)
        - Strings with special characters
        - Base64-like strings
        - Strings with IOC patterns
        """
        interesting = []
        
        for string in strings:
            score = 0
            
            # Length score
            if len(string) > 50:
                score += 2
            elif len(string) > 20:
                score += 1
            
            # Has URL/IP
            if re.search(r'https?://', string) or re.search(r'\d+\.\d+\.\d+\.\d+', string):
                score += 5
            
            # Has suspicious keywords
            suspicious_keywords = ['password', 'admin', 'root', 'cmd', 'shell', 'backdoor', 'malware']
            if any(kw in string.lower() for kw in suspicious_keywords):
                score += 3
            
            # Base64-like
            if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', string):
                score += 2
            
            # Has registry key
            if 'HKEY_' in string or 'SOFTWARE\\' in string:
                score += 2
            
            if score > 0:
                interesting.append((score, string))
        
        # Sort by score and return top N
        interesting.sort(reverse=True)
        return [s[1] for s in interesting[:limit]]
