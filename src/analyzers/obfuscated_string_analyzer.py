"""
Author: Ugur Ates
Obfuscated String Analyzer - Mandiant FLOSS entegrasyonu.

FLOSS (FLARE Obfuscated String Solver) obfuscate edilmiş stringleri otomatik çıkarır:
- Static strings (ASCII/Unicode)
- Decoded/decrypted strings
- Stack strings
- Tight strings (modified stack strings)

https://github.com/mandiant/flare-floss
"""

import json
import re
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)
@dataclass
class ExtractedString:
    """Çıkarılan string."""
    value: str
    string_type: str  # static, decoded, stack, tight
    encoding: str = "ascii"  # ascii, utf-16le, utf-16be
    offset: Optional[int] = None
    function_address: Optional[str] = None
@dataclass
class FlossAnalysisResult:
    """FLOSS analiz sonucu."""
    success: bool = False
    
    # String kategorileri
    static_strings: List[ExtractedString] = field(default_factory=list)
    decoded_strings: List[ExtractedString] = field(default_factory=list)
    stack_strings: List[ExtractedString] = field(default_factory=list)
    tight_strings: List[ExtractedString] = field(default_factory=list)
    
    # Kategorize edilmiş IOC'lar
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    file_paths: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    
    # Suspicious pattern matches
    crypto_constants: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)
    api_names: List[str] = field(default_factory=list)
    
    threat_score: int = 0
    summary: str = ""
    raw_output: str = ""
    error_message: str = ""
class ObfuscatedStringAnalyzer:
    """Mandiant FLOSS ile obfuscated string extraction."""
    
    # IOC extraction patterns
    IOC_PATTERNS = {
        'url': re.compile(
            r'https?://[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?:[/?#][^\s<>"\']*)?',
            re.IGNORECASE
        ),
        'ip': re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        'domain': re.compile(
            r'\b[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,}\b'
        ),
        'email': re.compile(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        ),
        'file_path_win': re.compile(
            r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'
        ),
        'file_path_unix': re.compile(
            r'(?:/[a-zA-Z0-9._-]+)+/?'
        ),
        'registry': re.compile(
            r'(?:HKEY_[A-Z_]+|HK[A-Z]{2})\\[^\s"\'<>]+',
            re.IGNORECASE
        ),
    }
    
    # Suspicious string patterns by category
    SUSPICIOUS_PATTERNS = {
        'crypto': [
            r'\bAES\b', r'\bRSA\b', r'\bDES\b', r'\bRC4\b', r'\bBlowfish\b',
            r'\bRijndael\b', r'\bCryptoAPI\b', r'\bBCrypt\b', r'\bNCrypt\b',
            r'crypt32\.dll', r'advapi32\.dll', r'\bCryptAcquire',
            r'\bCryptEncrypt', r'\bCryptDecrypt', r'\bCryptGenKey',
        ],
        'persistence': [
            r'CurrentVersion\\Run', r'CurrentVersion\\RunOnce',
            r'HKLM\\SOFTWARE', r'HKCU\\SOFTWARE', r'HKEY_LOCAL_MACHINE',
            r'\bschtasks\b', r'at\.exe', r'sc\.exe', r'reg\.exe',
            r'StartupFolder', r'\\Startup\\', r'\\Start Menu\\',
            r'WMI', r'Win32_Process', r'__EventFilter',
        ],
        'network': [
            r'\bWinHTTP\b', r'\bWinINet\b', r'\bURLDownload',
            r'\bHttpSendRequest', r'\bInternetOpen', r'\bInternetConnect',
            r'\bsocket\b', r'\bconnect\b', r'\bsend\b', r'\brecv\b',
            r'\bWSAStartup', r'\bgetaddrinfo', r'\bgethostbyname',
            r'\bHttpOpenRequest', r'\bInternetReadFile',
        ],
        'injection': [
            r'\bVirtualAlloc', r'\bVirtualProtect', r'\bWriteProcessMemory',
            r'\bCreateRemoteThread', r'\bNtCreateThreadEx',
            r'\bRtlCreateUserThread', r'\bQueueUserAPC',
            r'\bSetWindowsHookEx', r'\bLoadLibrary', r'\bGetProcAddress',
            r'\bNtAllocateVirtualMemory', r'\bNtProtectVirtualMemory',
        ],
        'evasion': [
            r'\bIsDebuggerPresent', r'\bCheckRemoteDebugger',
            r'\bNtQueryInformationProcess', r'\bGetTickCount',
            r'\bQueryPerformanceCounter', r'\brdtsc\b',
            r'\bVMware\b', r'\bVirtualBox\b', r'\bSandbox\b',
            r'\bWine\b', r'\bQEMU\b', r'\bHyper-V\b', r'\bVBox\b',
            r'\bSbieDll', r'\bcuckoomon', r'\bdbghelp',
        ],
        'credential': [
            r'\bmimikatz\b', r'\bsekurlsa\b', r'\bwdigest\b',
            r'\blsass\b', r'\bSAM\b', r'\bSECURITY\b',
            r'CredentialManager', r'\bVault\b', r'credentials\.xml',
            r'\bpassword\b', r'\bpasswd\b', r'\bcredential\b',
            r'Login Data', r'cookies\.sqlite', r'key3\.db',
        ],
        'command_execution': [
            r'\bcmd\.exe\b', r'\bpowershell\b', r'\bcscript\b', r'\bwscript\b',
            r'\bmshta\b', r'\brundll32\b', r'\bregsvr32\b', r'\bcertutil\b',
            r'\bbitsadmin\b', r'\bwmic\b', r'\bShell\b', r'\bWScript\.Shell\b',
            r'-enc ', r'-EncodedCommand', r'FromBase64',
        ],
        'file_operations': [
            r'\bDeleteFile\b', r'\bMoveFile\b', r'\bCopyFile\b',
            r'\bCreateFile\b', r'\bWriteFile\b', r'\bReadFile\b',
            r'Open.*For Output', r'Open.*For Binary',
            r'\bShred\b', r'\bWipe\b', r'\bsecure delete\b',
        ],
    }
    
    # Windows API names that are suspicious in certain contexts
    SUSPICIOUS_APIS = [
        'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
        'CreateRemoteThread', 'CreateRemoteThreadEx', 'WriteProcessMemory',
        'ReadProcessMemory', 'NtCreateThreadEx', 'RtlCreateUserThread',
        'SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyState',
        'CreateProcess', 'ShellExecute', 'WinExec', 'system',
        'RegSetValue', 'RegCreateKey', 'RegOpenKey',
        'InternetOpen', 'URLDownloadToFile', 'HttpSendRequest',
        'CryptAcquireContext', 'CryptEncrypt', 'CryptDecrypt',
        'OpenProcess', 'TerminateProcess', 'SuspendThread',
        'LoadLibrary', 'GetProcAddress', 'GetModuleHandle',
    ]
    
    def __init__(self):
        from ..tools.external_tool_runner import get_tool_runner
        self.tool_runner = get_tool_runner()
    
    def analyze(self, file_path: str) -> FlossAnalysisResult:
        """
        FLOSS ile dosyayı analiz et.
        
        Args:
            file_path: Analiz edilecek dosya
            
        Returns:
            FlossAnalysisResult
        """
        logger.info(f"[FLOSS] Analyzing: {file_path}")
        
        if not self.tool_runner.is_available('floss'):
            logger.warning("[FLOSS] FLOSS not installed")
            return FlossAnalysisResult(
                success=False,
                error_message="FLOSS not available - install from https://github.com/mandiant/flare-floss/releases"
            )
        
        # Run FLOSS with JSON output
        result = self.tool_runner.run_floss(file_path, output_format='json')
        
        if not result.success:
            # FLOSS might return non-zero but still have useful output
            if result.stdout and len(result.stdout) > 100:
                logger.warning(f"[FLOSS] Non-zero exit but has output, attempting parse")
            else:
                return FlossAnalysisResult(
                    success=False,
                    error_message=result.error_message or result.stderr[:500],
                    raw_output=result.stderr
                )
        
        return self._parse_floss_output(result.stdout, result.parsed_output)
    
    def _parse_floss_output(self, raw_output: str, parsed: Optional[Dict]) -> FlossAnalysisResult:
        """FLOSS JSON çıktısını parse et."""
        static_strings = []
        decoded_strings = []
        stack_strings = []
        tight_strings = []
        
        all_string_values: Set[str] = set()
        
        try:
            data = parsed or json.loads(raw_output)
            
            strings_data = data.get('strings', {})
            
            # Static strings
            for s in strings_data.get('static_strings', []):
                value = s if isinstance(s, str) else s.get('string', '')
                if value and len(value) >= 4:
                    es = ExtractedString(
                        value=value,
                        string_type='static',
                        encoding=s.get('encoding', 'ascii') if isinstance(s, dict) else 'ascii',
                        offset=s.get('offset') if isinstance(s, dict) else None
                    )
                    static_strings.append(es)
                    all_string_values.add(value)
            
            # Decoded strings (most interesting - these were obfuscated)
            for s in strings_data.get('decoded_strings', []):
                value = s if isinstance(s, str) else s.get('string', '')
                if value and len(value) >= 4:
                    es = ExtractedString(
                        value=value,
                        string_type='decoded',
                        encoding=s.get('encoding', 'ascii') if isinstance(s, dict) else 'ascii',
                        function_address=s.get('address', s.get('function')) if isinstance(s, dict) else None
                    )
                    decoded_strings.append(es)
                    all_string_values.add(value)
            
            # Stack strings
            for s in strings_data.get('stack_strings', []):
                value = s if isinstance(s, str) else s.get('string', '')
                if value and len(value) >= 4:
                    es = ExtractedString(
                        value=value,
                        string_type='stack',
                        encoding='ascii',
                        function_address=s.get('function') if isinstance(s, dict) else None
                    )
                    stack_strings.append(es)
                    all_string_values.add(value)
            
            # Tight strings
            for s in strings_data.get('tight_strings', []):
                value = s if isinstance(s, str) else s.get('string', '')
                if value and len(value) >= 4:
                    es = ExtractedString(
                        value=value,
                        string_type='tight',
                        encoding='ascii',
                        function_address=s.get('function') if isinstance(s, dict) else None
                    )
                    tight_strings.append(es)
                    all_string_values.add(value)
            
            # Extract IOCs and suspicious strings
            all_strings_list = list(all_string_values)
            urls, ips, domains, emails, file_paths, registry_keys = self._extract_iocs(all_strings_list)
            crypto_constants, suspicious_strings, api_names = self._find_suspicious(all_strings_list)
            
            # Calculate threat score
            threat_score = self._calculate_threat_score(
                decoded_strings, stack_strings, tight_strings,
                urls, ips, suspicious_strings, api_names
            )
            
            # Generate summary
            summary = self._generate_summary(
                len(static_strings), len(decoded_strings),
                len(stack_strings), len(tight_strings),
                len(urls), len(suspicious_strings)
            )
            
            return FlossAnalysisResult(
                success=True,
                static_strings=static_strings[:1000],  # Limit
                decoded_strings=decoded_strings[:500],
                stack_strings=stack_strings[:500],
                tight_strings=tight_strings[:200],
                urls=urls[:100],
                ips=ips[:100],
                domains=domains[:100],
                emails=emails[:50],
                file_paths=file_paths[:100],
                registry_keys=registry_keys[:100],
                crypto_constants=crypto_constants[:50],
                suspicious_strings=suspicious_strings[:200],
                api_names=api_names[:100],
                threat_score=threat_score,
                summary=summary,
                raw_output=raw_output[:50000]
            )
            
        except json.JSONDecodeError as e:
            logger.error(f"[FLOSS] JSON parse error: {e}")
            return FlossAnalysisResult(
                success=False,
                error_message=f"JSON parse error: {e}",
                raw_output=raw_output[:5000]
            )
        except Exception as e:
            logger.error(f"[FLOSS] Parse error: {e}", exc_info=True)
            return FlossAnalysisResult(
                success=False,
                error_message=f"Parse error: {e}",
                raw_output=raw_output[:5000]
            )
    
    def _extract_iocs(self, strings: List[str]) -> tuple:
        """Stringlerden IOC'ları çıkar."""
        urls: Set[str] = set()
        ips: Set[str] = set()
        domains: Set[str] = set()
        emails: Set[str] = set()
        file_paths: Set[str] = set()
        registry_keys: Set[str] = set()
        
        # Common false positive domains to filter
        fp_domains = {
            'microsoft.com', 'windows.com', 'google.com', 'mozilla.org',
            'example.com', 'localhost', 'schema.org', 'w3.org',
        }
        
        # Common false positive IPs
        fp_ips = {'0.0.0.0', '127.0.0.1', '255.255.255.255', '224.0.0.0'}
        
        for s in strings:
            if not s or len(s) < 4:
                continue
            
            # URLs
            for url in self.IOC_PATTERNS['url'].findall(s):
                urls.add(url)
            
            # IPs
            for ip in self.IOC_PATTERNS['ip'].findall(s):
                if ip not in fp_ips and not ip.startswith('0.'):
                    ips.add(ip)
            
            # Domains
            for domain in self.IOC_PATTERNS['domain'].findall(s):
                domain_lower = domain.lower()
                if (len(domain) > 4 and 
                    domain_lower not in fp_domains and
                    not domain_lower.endswith('.dll') and
                    not domain_lower.endswith('.exe')):
                    domains.add(domain)
            
            # Emails
            for email in self.IOC_PATTERNS['email'].findall(s):
                emails.add(email)
            
            # File paths (Windows)
            for path in self.IOC_PATTERNS['file_path_win'].findall(s):
                if len(path) > 5:
                    file_paths.add(path)
            
            # Registry keys
            for reg in self.IOC_PATTERNS['registry'].findall(s):
                registry_keys.add(reg)
        
        return (
            list(urls), list(ips), list(domains),
            list(emails), list(file_paths), list(registry_keys)
        )
    
    def _find_suspicious(self, strings: List[str]) -> tuple:
        """Suspicious string'leri bul."""
        crypto: Set[str] = set()
        suspicious: Set[str] = set()
        api_names: Set[str] = set()
        
        for s in strings:
            if not s or len(s) < 3:
                continue
            
            s_check = s
            
            # Check crypto patterns
            for pattern in self.SUSPICIOUS_PATTERNS['crypto']:
                if re.search(pattern, s_check, re.IGNORECASE):
                    crypto.add(s[:100])
                    break
            
            # Check all suspicious patterns
            for category, patterns in self.SUSPICIOUS_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, s_check, re.IGNORECASE):
                        suspicious.add(s[:100])
                        break
            
            # Check for API names
            for api in self.SUSPICIOUS_APIS:
                if api.lower() in s_check.lower():
                    api_names.add(api)
        
        return list(crypto), list(suspicious), list(api_names)
    
    def _calculate_threat_score(self, decoded, stack, tight,
                                urls, ips, suspicious, api_names) -> int:
        """Threat score hesapla."""
        score = 0
        
        # Obfuscated strings are significant indicators
        score += min(len(decoded) * 5, 30)  # Up to 30 points
        score += min(len(stack) * 3, 15)    # Up to 15 points
        score += min(len(tight) * 3, 10)    # Up to 10 points
        
        # Network IOCs
        score += min(len(urls) * 3, 15)
        score += min(len(ips) * 3, 15)
        
        # Suspicious strings
        score += min(len(suspicious) * 2, 20)
        
        # Suspicious API names
        score += min(len(api_names) * 2, 15)
        
        return min(score, 100)
    
    def _generate_summary(self, static, decoded, stack, tight, urls, suspicious) -> str:
        """Summary oluştur."""
        lines = ["FLOSS String Analysis:"]
        lines.append(f"  Static strings: {static}")
        lines.append(f"  Decoded strings: {decoded}")
        lines.append(f"  Stack strings: {stack}")
        lines.append(f"  Tight strings: {tight}")
        
        if decoded > 0:
            lines.append("\n⚠️ DECODED STRINGS DETECTED")
            lines.append("  → Malware actively decrypting/decoding strings at runtime")
        
        if stack > 0:
            lines.append("\n⚠️ STACK STRINGS DETECTED")
            lines.append("  → Strings built on stack to evade static analysis")
        
        if urls > 0:
            lines.append(f"\n🔗 URLs found: {urls}")
        
        if suspicious > 0:
            lines.append(f"\n⚠️ Suspicious patterns: {suspicious}")
        
        return '\n'.join(lines)
