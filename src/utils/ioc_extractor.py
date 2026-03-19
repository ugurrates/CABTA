"""
Author: Ugur AtesIOC extraction utilities for Blue Team Assistant."""

import re
import hashlib
from typing import List, Dict, Set
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)
class IOCExtractor:
    """Extract Indicators of Compromise from text and files."""
    
    # Regex patterns
    IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    URL_PATTERN = r'https?://(?:[-\w.])+(?::\d+)?(?:/[^\s<>"\']*)?'
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
    SHA1_PATTERN = r'\b[a-fA-F0-9]{40}\b'
    SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
    
  
    URL_WHITELIST_PATTERNS = [
        r'https?://(www\.)?w3\.org/',           # W3C standards
        r'https?://(www\.)?schema\.org/',       # Schema.org
        r'https?://schemas\.microsoft\.com/',   # Microsoft schemas
        r'https?://xmlns\.',                    # XML namespaces
        r'https?://.*\.dtd$',                   # DTD files
        r'https?://.*\.xsd$',                   # XSD files
    ]
    
    # Private IP ranges to exclude
    PRIVATE_IP_RANGES = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        r'^192\.168\.',
        r'^127\.',
        r'^169\.254\.',
        r'^0\.',
        r'^255\.255\.255\.255$'
    ]
    
    # Version string IPs to exclude (common in PE files)
    VERSION_STRING_IPS = {
        '1.0.0.0', '1.0.0.1', '2.0.0.0', '3.0.0.0', '4.0.0.0',
        '5.0.0.0', '6.0.0.0', '7.0.0.0', '8.0.0.0', '9.0.0.0',
        '1.1.0.0', '1.2.0.0', '1.3.0.0', '1.4.0.0', '1.5.0.0',
        '2.1.0.0', '2.2.0.0', '3.1.0.0', '4.1.0.0', '5.1.0.0',
    }
    
    # Common non-malicious domains to exclude
    WHITELIST_DOMAINS = {
        'microsoft.com', 'windows.com', 'office.com', 'live.com',
        'google.com', 'googleapis.com', 'gstatic.com',
        'apple.com', 'icloud.com',
        'mozilla.org', 'firefox.com',
        'adobe.com', 'adobedc.net',
        'localhost', 'example.com', 'example.org',
        'w3.org', 'schema.org',
        # Certificate Authorities - NEVER flag as malicious
        'digicert.com', 'verisign.com', 'letsencrypt.org', 'comodo.com',
        'godaddy.com', 'globalsign.com', 'entrust.com', 'thawte.com',
        'geotrust.com', 'rapidssl.com', 'sectigo.com', 'comodoca.com',
        'usertrust.com', 'trustwave.com', 'symantec.com',
        # CDN and infrastructure
        'akamai.net', 'akamaiedge.net', 'cloudflare.com', 'fastly.net',
        'amazonaws.com', 'azure.com', 'azureedge.net',
    }
    
    # Namespace/Assembly patterns to exclude (NOT domains)
    NAMESPACE_PATTERNS = {
        'exehead', 'common', 'controls', 'interop', 'runtime',
        'configuration', 'componentmodel', 'collections', 'generics',
        'threading', 'reflection', 'security', 'permissions',
        'resources', 'globalization', 'serialization', 'codedom',
    }
    
    # File extensions to exclude from domain detection (NOT domains!)
    FILE_EXTENSIONS = {
        # Images
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp', '.tiff',
        # Documents
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf', '.odt',
        # Archives
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
        # Executables
        '.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.sh',
        # Scripts
        '.js', '.vbs', '.py', '.rb', '.pl', '.php',
        # Others
        '.xml', '.json', '.csv', '.log', '.ini', '.cfg', '.conf', '.dtd', '.xsd'
    }
    
    # False positive keywords (PowerShell, Windows, etc.)
  
    FALSE_POSITIVE_KEYWORDS = {
        # PowerShell automatic variables and properties
        'myinvocation', 'pscmdlet', 'psscriptroot', 'pshome', 'psversiontable',
        'executioncontext', 'host', 'error', 'stacktrace', 'errorrecord',
        'powershell', 'pwsh', 'mycommand', 'scriptblock', 'invocationname',
        
        # Common PowerShell properties
        'starttype', 'status', 'displayname', 'servicename', 'path', 'fullname',
        'name', 'extension', 'basename', 'directory', 'directoryname',
        'length', 'count', 'value', 'type', 'mode',
        
        # Windows services and system components
        'wuauserv', 'bits', 'mpssvc', 'wscsvc', 'windefend', 'wuau',
        'services', 'registry', 'filesystem', 'eventlog', 'process',
        'sppsvc', 'wmi', 'dcom', 'rpc', 'netlogon', 'dnscache',
        'dhcp', 'lanmanserver', 'lanmanworkstation', 'browser',
        
        # Tool names (false positives from scripts)
        'advancedrun', 'nirsoft', 'sysinternals', 'psexec', 'procdump',
        'autoruns', 'procmon', 'tcpview', 'regmon', 'filemon',
        
        # HTML/XML/Web
        'xhtml1', 'transitional', 'strict', 'frameset', 'xmlns',
        'doctype', 'html', 'head', 'body', 'script', 'style',
        
        # General false positives
        'system', 'current', 'local', 'temp', 'user', 'public',
        'localhost', 'hostname', 'computername', 'username', 'domain',
        'default', 'null', 'void', 'string', 'object', 'array',
        
        # Common programming terms
        'function', 'class', 'method', 'property', 'variable',
        'param', 'return', 'import', 'export', 'module',
    }
    
    @staticmethod
    def extract_ipv4(text: str, exclude_private: bool = True) -> List[str]:
        """
        Extract IPv4 addresses from text.
        
        Args:
            text: Input text
            exclude_private: Exclude private IP ranges
        
        Returns:
            List of unique IPv4 addresses
        """
        ips = re.findall(IOCExtractor.IPV4_PATTERN, text)
        ips = list(set(ips))  # Unique
        
        filtered_ips = []
        for ip in ips:
            # Skip version string IPs
            if ip in IOCExtractor.VERSION_STRING_IPS:
                continue
            
            # Skip IPs that look like version numbers (X.X.X.X where first octet < 10)
            octets = ip.split('.')
            if int(octets[0]) < 10 and int(octets[3]) == 0:
                continue  # Likely version string like 6.0.0.0
            
            if exclude_private:
                is_private = any(re.match(pattern, ip) for pattern in IOCExtractor.PRIVATE_IP_RANGES)
                if is_private:
                    continue
            
            filtered_ips.append(ip)
        
        return filtered_ips
    
    @staticmethod
    def extract_domains(text: str, exclude_whitelist: bool = True) -> List[str]:
        """
        Extract domain names from text.
        
        v1.0.0: İyileştirildi - trailing dots, tek kelime domain'ler, kısa TLD'ler filtreli
        
        Args:
            text: Input text
            exclude_whitelist: Exclude common legitimate domains
        
        Returns:
            List of unique domains
        """
        domains = re.findall(IOCExtractor.DOMAIN_PATTERN, text)
        domains = [d.lower() for d in set(domains)]  # Unique, lowercase
        
        # Filter out file extensions and false positives
        filtered_domains = []
        for domain in domains:
          
            if domain.endswith('.'):
                continue
            
          
            parts = domain.split('.')
            if len(parts) < 2:
                continue
            
          
            tld = parts[-1].lower()
            if len(tld) < 2:
                continue
            
          
            if tld.isdigit():
                continue
            
          
            known_tlds = {
                'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'us', 'uk', 'de', 'fr',
                'ru', 'cn', 'jp', 'au', 'ca', 'br', 'in', 'mx', 'es', 'it', 'nl', 'be', 'ch', 'at',
                'pl', 'se', 'no', 'dk', 'fi', 'cz', 'hu', 'ro', 'bg', 'gr', 'pt', 'ie', 'nz', 'za',
                'sg', 'hk', 'tw', 'kr', 'th', 'vn', 'ph', 'id', 'my', 'pk', 'bd', 'ua', 'kz', 'tr',
                'il', 'ae', 'sa', 'eg', 'ng', 'ke', 'ar', 'cl', 'pe', 'co', 've', 'ec', 'uy', 'py',
                'info', 'biz', 'name', 'pro', 'coop', 'aero', 'museum', 'jobs', 'travel', 'mobi',
                'cat', 'asia', 'tel', 'xxx', 'post', 'app', 'dev', 'page', 'blog', 'shop', 'store',
                'online', 'site', 'website', 'web', 'tech', 'cloud', 'host', 'digital', 'media',
                'news', 'live', 'tv', 'video', 'download', 'email', 'link', 'click', 'space',
                'one', 'top', 'xyz', 'club', 'vip', 'win', 'bid', 'loan', 'work', 'review', 'date',
                'party', 'science', 'racing', 'stream', 'trade', 'webcam', 'gdn', 'men', 'mom', 'xin',
                'wang', 'ltd', 'group', 'game', 'games', 'city', 'world', 'center', 'today', 'life',
                'network', 'company', 'systems', 'agency', 'solutions', 'services', 'global', 'zone',
                'consulting', 'marketing', 'technology', 'international', 'enterprises', 'industries',
                'az', 'by', 'kz', 'uz', 'tm', 'tj', 'kg', 'am', 'ge', 'md', 'lv', 'lt', 'ee',
            }
            
            # ALL TLDs must be in known list - strict validation
            if tld not in known_tlds:
                continue
            
            # Check for namespace patterns (NOT real domains)
            namespace_keywords = {
                'exehead', 'common', 'controls', 'interop', 'runtime', 'configuration',
                'componentmodel', 'collections', 'generics', 'threading', 'reflection',
                'security', 'permissions', 'resources', 'globalization', 'serialization',
                'codedom', 'nullsoft', 'nsis', 'microsoft', 'windows', 'system',
            }
            is_namespace = False
            for part in parts:
                if part.lower() in namespace_keywords and len(parts) > 2:
                    # Looks like a namespace: microsoft.windows.common
                    is_namespace = True
                    break
            if is_namespace:
                continue
            
          
            domain_part = parts[0] if len(parts) == 2 else '.'.join(parts[:-1])
            if len(domain_part) <= 2 and len(tld) <= 3:
                continue  # e.g., "fl.rm", "o.nv" - too short to be real
            
            # Check if it's actually a file extension
            is_file = any(domain.endswith(ext) for ext in IOCExtractor.FILE_EXTENSIONS)
            
            # Also check if it looks like a filename
            if not is_file and len(parts) == 2:
                extension = '.' + parts[-1]
                if extension in IOCExtractor.FILE_EXTENSIONS:
                    is_file = True
            
            # Check for PowerShell/Windows false positives
            is_false_positive = False
            for part in parts:
                if part in IOCExtractor.FALSE_POSITIVE_KEYWORDS:
                    is_false_positive = True
                    break
            
          
            if len(domain) < 4:  # e.g., "a.b" is not a real domain
                continue
            
            if not is_file and not is_false_positive:
                filtered_domains.append(domain)
        
        domains = filtered_domains
        
        if exclude_whitelist:
            filtered_domains = []
            for domain in domains:
                # Check if domain or parent domain is whitelisted
                is_whitelisted = False
                for wl_domain in IOCExtractor.WHITELIST_DOMAINS:
                    if domain == wl_domain or domain.endswith('.' + wl_domain):
                        is_whitelisted = True
                        break
                
                if not is_whitelisted:
                    filtered_domains.append(domain)
            
            return filtered_domains
        
        return domains
    
    @staticmethod
    def extract_urls(text: str, filter_whitelist: bool = True) -> List[str]:
        """
        Extract URLs from text.
        
        v1.0.0: URL temizleme eklendi - trailing quotes ve noktalama
        v1.0.0: URL whitelist filtering, HTML tag temizleme
        
        Args:
            text: Input text
            filter_whitelist: Exclude standard/namespace URLs (w3.org, schema.org, etc.)
        
        Returns:
            List of unique URLs
        """
        urls = re.findall(IOCExtractor.URL_PATTERN, text)
        
        cleaned_urls = []
        for url in urls:
          
            if '"><' in url:
                url = url.split('"><')[0]
            if '">' in url:
                url = url.split('">')[0]
            if "'>" in url:
                url = url.split("'>")[0]
            if '<' in url:
                url = url.split('<')[0]
            
            # Sondaki tırnak, parantez, noktalama işaretlerini temizle
            url = url.rstrip('"\'><)]};,.')
            
            # Başındaki tırnak işaretlerini temizle
            url = url.lstrip('"\'<([{')
            
            # Geçerli URL kontrolü
            if not url or len(url) <= 10 or '://' not in url:
                continue
            
          
            if filter_whitelist:
                is_whitelisted = False
                for pattern in IOCExtractor.URL_WHITELIST_PATTERNS:
                    if re.match(pattern, url, re.I):
                        is_whitelisted = True
                        break
                if is_whitelisted:
                    continue
            
            cleaned_urls.append(url)
        
        return list(set(cleaned_urls))
    
    @staticmethod
    def extract_emails(text: str) -> List[str]:
        """
        Extract email addresses from text.
        
        Args:
            text: Input text
        
        Returns:
            List of unique email addresses
        """
        emails = re.findall(IOCExtractor.EMAIL_PATTERN, text)
        return list(set([e.lower() for e in emails]))
    
    @staticmethod
    def extract_hashes(text: str) -> Dict[str, List[str]]:
        """
        Extract file hashes from text.
        
        Args:
            text: Input text
        
        Returns:
            Dict with 'md5', 'sha1', 'sha256' lists
        """
        return {
            'md5': list(set(re.findall(IOCExtractor.MD5_PATTERN, text))),
            'sha1': list(set(re.findall(IOCExtractor.SHA1_PATTERN, text))),
            'sha256': list(set(re.findall(IOCExtractor.SHA256_PATTERN, text)))
        }
    
    @staticmethod
    def extract_all(text: str) -> Dict[str, List[str]]:
        """
        Extract all IOC types from text.
        
        Args:
            text: Input text
        
        Returns:
            Dict containing all extracted IOCs
        
        Example:
            >>> iocs = IOCExtractor.extract_all("Visit http://evil.com at 203.0.113.45")
            >>> print(iocs['urls'])
            ['http://evil.com']
        """
        return {
            'ipv4': IOCExtractor.extract_ipv4(text),
            'domains': IOCExtractor.extract_domains(text),
            'urls': IOCExtractor.extract_urls(text),
            'emails': IOCExtractor.extract_emails(text),
            'hashes': IOCExtractor.extract_hashes(text)
        }
    
    @staticmethod
    def defang_ioc(ioc: str) -> str:
        """
        Defang IOC for safe display.
        
        Args:
            ioc: IOC to defang
        
        Returns:
            Defanged IOC
        
        Example:
            >>> IOCExtractor.defang_ioc("http://evil.com")
            'hxxp://evil[.]com'
        """
        defanged = ioc.replace('http://', 'hxxp://')
        defanged = defanged.replace('https://', 'hxxps://')
        defanged = defanged.replace('.', '[.]')
        defanged = defanged.replace('@', '[@]')
        return defanged
    
    @staticmethod
    def refang_ioc(ioc: str) -> str:
        """
        Refang IOC for analysis.
        
        Args:
            ioc: Defanged IOC
        
        Returns:
            Refanged IOC
        """
        refanged = ioc.replace('hxxp://', 'http://')
        refanged = refanged.replace('hxxps://', 'https://')
        refanged = refanged.replace('[.]', '.')
        refanged = refanged.replace('[@]', '@')
        return refanged
    
    @staticmethod
    def categorize_ioc(ioc: str) -> str:
        """
        Detect IOC type.
        
        Args:
            ioc: IOC string
        
        Returns:
            IOC type: 'ipv4', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email', 'unknown'
        """
        ioc = ioc.strip()
        
        # Check hashes
        if re.match(f'^{IOCExtractor.SHA256_PATTERN}$', ioc):
            return 'sha256'
        if re.match(f'^{IOCExtractor.SHA1_PATTERN}$', ioc):
            return 'sha1'
        if re.match(f'^{IOCExtractor.MD5_PATTERN}$', ioc):
            return 'md5'
        
        # Check URL
        if re.match(IOCExtractor.URL_PATTERN, ioc):
            return 'url'
        
        # Check email
        if re.match(IOCExtractor.EMAIL_PATTERN, ioc):
            return 'email'
        
        # Check IPv4
        if re.match(f'^{IOCExtractor.IPV4_PATTERN}$', ioc):
            return 'ipv4'
        
        # Check domain
        if re.match(f'^{IOCExtractor.DOMAIN_PATTERN}$', ioc):
            return 'domain'
        
        return 'unknown'
    
    @staticmethod
    def calculate_domain_entropy(domain: str) -> float:
        """
        Calculate domain entropy (DGA detection).
        
        Args:
            domain: Domain name
        
        Returns:
            Entropy value (higher = more random)
        
        Example:
            >>> entropy = IOCExtractor.calculate_domain_entropy("google.com")
            >>> print(entropy < 4.0)  # Legitimate domain
            True
        """
        domain = domain.split('.')[0]  # Get subdomain/hostname only
        
        if not domain:
            return 0.0
        
        entropy = 0.0
        for char in set(domain):
            freq = domain.count(char) / len(domain)
            entropy -= freq * (freq and (freq * 1.442695))  # log2(freq)
        
        return entropy
