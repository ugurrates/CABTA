"""
Author: Ugur AtesThreat intelligence API integrations (20+ sources)."""

import aiohttp
import asyncio
from typing import Dict, Optional, List
from datetime import datetime
import logging
import json
from ..utils.api_key_validator import get_valid_key

logger = logging.getLogger(__name__)
class ThreatIntelligence:
    """
    Multi-source threat intelligence aggregator.
    
    Supports 20+ threat intelligence sources including:
    - VirusTotal, AbuseIPDB, Shodan, AlienVault OTX
    - URLhaus, FeodoTracker, ThreatFox, MalwareBazaar
    - USOM, C2 Trackers, Tor Exit Nodes, SSL Blacklist
    - GreyNoise, Censys, Talos Intelligence, IBM X-Force
    - Pulsedive, Threatcrowd, Criminal IP, IPQualityScore
    - Spamhaus, CIRCL, PhishTank, Google Safe Browsing
    """
    
    def __init__(self, config: Dict):
        """
        Initialize threat intelligence client.
        
        Args:
            config: Configuration dict with API keys
        """
        self.config = config
        self.api_keys = config.get('api_keys', {})
        self.timeout = aiohttp.ClientTimeout(total=config.get('timeouts', {}).get('api_timeout', 30))
        
        # Cache for C2 feeds (refresh hourly)
        self._c2_cache = None
        self._c2_cache_time = None
        
        # Initialize extended sources
        from .threat_intel_extended import ThreatIntelExtended
        self.extended = ThreatIntelExtended(config)

        # Initialize threat feed checker (USOM, etc.)
        from .threat_feeds import ThreatFeeds
        self.threat_feeds = ThreatFeeds(config)
    
    async def check_virustotal(self, ioc: str, ioc_type: str) -> Dict:
        """
        Check IOC against VirusTotal.
        
        Args:
            ioc: Indicator to check
            ioc_type: Type (ipv4, domain, url, hash)
        
        Returns:
            VirusTotal analysis result
        """
        api_key = get_valid_key(self.api_keys, 'virustotal')
        if not api_key:
            return {'status': '⚠', 'error': 'No valid API key configured'}
        
        try:
            headers = {'x-apikey': api_key}
            
            # Determine endpoint
            if ioc_type == 'hash':
                url = f'https://www.virustotal.com/api/v3/files/{ioc}'
            elif ioc_type == 'ipv4':
                url = f'https://www.virustotal.com/api/v3/ip_addresses/{ioc}'
            elif ioc_type == 'domain':
                url = f'https://www.virustotal.com/api/v3/domains/{ioc}'
            elif ioc_type == 'url':
                import base64
                url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip('=')
                url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
            else:
                return {'status': '⚠', 'error': 'Unsupported type'}
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 404:
                        return {'status': '✗', 'detections': '0/0', 'message': 'Not found in VT'}
                    
                    if response.status == 200:
                        data = await response.json()
                        attributes = data.get('data', {}).get('attributes', {})
                        
                        # Get stats
                        last_analysis_stats = attributes.get('last_analysis_stats', {})
                        malicious = last_analysis_stats.get('malicious', 0)
                        total = sum(last_analysis_stats.values())
                        
                        last_analysis = attributes.get('last_analysis_date')
                        last_date = datetime.fromtimestamp(last_analysis).strftime('%Y-%m-%d') if last_analysis else 'N/A'
                        
                        return {
                            'status': '✓' if malicious > 0 else '✗',
                            'detections': f'{malicious}/{total}',
                            'last_analysis': last_date,
                            'score': min(100, malicious * 5) if malicious > 0 else 0
                        }
                    else:
                        return {'status': '⚠', 'error': f'HTTP {response.status}'}
        
        except asyncio.TimeoutError:
            logger.warning("[VT] Timeout")
            return {'status': '⚠', 'error': 'Timeout'}
        except Exception as e:
            logger.error(f"[VT] Error: {e}")
            return {'status': '⚠', 'error': str(e)}
    
    async def check_abuseipdb(self, ip: str) -> Dict:
        """
        Check IP against AbuseIPDB.
        
        Args:
            ip: IP address
        
        Returns:
            AbuseIPDB analysis result
        """
        api_key = get_valid_key(self.api_keys, 'abuseipdb')
        if not api_key:
            return {'status': '⚠', 'error': 'No valid API key configured'}
        
        try:
            headers = {'Key': api_key, 'Accept': 'application/json'}
            params = {'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': ''}
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers,
                    params=params
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        ip_data = data.get('data', {})
                        
                        confidence = ip_data.get('abuseConfidenceScore', 0)
                        reports = ip_data.get('totalReports', 0)
                        
                        return {
                            'status': '✓' if confidence > 50 else '✗',
                            'confidence': confidence,
                            'reports': reports,
                            'score': confidence
                        }
                    else:
                        return {'status': '⚠', 'error': f'HTTP {response.status}'}
        
        except asyncio.TimeoutError:
            return {'status': '⚠', 'error': 'Timeout'}
        except Exception as e:
            logger.error(f"[AbuseIPDB] Error: {e}")
            return {'status': '⚠', 'error': str(e)}
    
    async def check_shodan(self, ip: str) -> Dict:
        """
        Check IP against Shodan with C2 framework detection.
        
        Detects: Cobalt Strike, Metasploit, Empire, Covenant, PoshC2,
                 Sliver, Havoc, Brute Ratel, Mythic, Nighthawk
        
        Args:
            ip: IP address
        
        Returns:
            Shodan analysis with C2 framework detection
        """
        api_key = get_valid_key(self.api_keys, 'shodan')
        if not api_key:
            return {'status': '⚠', 'error': 'No valid API key configured'}
        
        # Known C2 framework signatures in Shodan data
        C2_SIGNATURES = {
            'cobalt_strike': [
                'MSSE-', '%c%c%c%c%c%c%c%c%cMSSE', 
                'StartBrowser', 'runasadmin', 'postex',
                'beacon', 'X-Malware-Hash', 'sleeptime',
            ],
            'metasploit': [
                'metsrv', 'METERPRETER', 'meterpreter',
                'Metasploit', 'msf', 'reverse_tcp',
                'ext_server', 'stdapi',
            ],
            'empire': [
                'Empire', 'PowerShell Empire',
                '/admin/get.php', '/login/process.php',
                'STAGE0', 'STAGE1', 'STAGE2',
            ],
            'covenant': [
                'Covenant', 'GruntHTTP', 'GruntSMB',
                'YOURDOMAINBACK', 'Elite', 'grunt',
            ],
            'poshc2': [
                'PoshC2', 'poshc2', '/images/',
                'dropper_cs', 'Implant',
            ],
            'sliver': [
                'sliver', 'SLIVER', 'bishopfox',
                'sliverpb', 'implant',
            ],
            'havoc': [
                'havoc', 'Havoc', 'demon', 'Demon',
                'teamserver', 'HavocFramework',
            ],
            'brute_ratel': [
                'BRc4', 'Brute Ratel', 'badger',
                'brc4', 'ParanoidNinja',
            ],
            'mythic': [
                'Mythic', 'mythic', 'Apollo', 'Apfell',
                'Athena', 'poseidon',
            ],
            'nighthawk': [
                'nighthawk', 'Nighthawk', 'MDSec',
            ],
        }
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(f'https://api.shodan.io/shodan/host/{ip}?key={api_key}') as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        ports = data.get('ports', [])
                        vulns = data.get('vulns', [])
                        tags = data.get('tags', [])
                        hostnames = data.get('hostnames', [])
                        
                        # Get raw data for C2 detection
                        raw_data = json.dumps(data).lower()
                        
                        # C2 Framework Detection
                        detected_c2 = []
                        c2_indicators = []
                        
                        for framework, signatures in C2_SIGNATURES.items():
                            for sig in signatures:
                                if sig.lower() in raw_data:
                                    if framework not in detected_c2:
                                        detected_c2.append(framework)
                                        c2_indicators.append(f"{framework}: '{sig}' found")
                        
                        # Check banner data for each service
                        for service in data.get('data', []):
                            banner = service.get('data', '')
                            http = service.get('http', {})
                            html = http.get('html', '') or ''
                            
                            content = f"{banner} {html}".lower()
                            for framework, signatures in C2_SIGNATURES.items():
                                for sig in signatures:
                                    if sig.lower() in content and framework not in detected_c2:
                                        detected_c2.append(framework)
                                        c2_indicators.append(f"{framework}: banner match '{sig[:20]}'")
                        
                        # Calculate score
                        score = 0
                        is_c2 = False
                        
                        if detected_c2:
                            score = 90
                            is_c2 = True
                        elif any(tag in ['malware', 'botnet', 'tor'] for tag in tags):
                            score = 60
                        elif len(vulns) > 10:
                            score = 40
                        elif len(vulns) > 5:
                            score = 30
                        
                        # Suspicious port combinations (common for C2)
                        c2_ports = {443, 8443, 8080, 8888, 4444, 5555, 9999, 1337, 31337, 50050}
                        if set(ports) & c2_ports and len(ports) < 5:
                            score += 10
                        
                        return {
                            'status': '✓' if score > 0 or detected_c2 else '✗',
                            'ports': ports[:10],
                            'vulns': len(vulns),
                            'tags': tags,
                            'hostnames': hostnames[:5],
                            'is_c2': is_c2,
                            'c2_frameworks': detected_c2,
                            'c2_indicators': c2_indicators[:10],
                            'score': min(100, score)
                        }
                    elif response.status == 404:
                        return {'status': '✗', 'found': False, 'score': 0}
                    else:
                        return {'status': '⚠', 'error': f'HTTP {response.status}'}
        
        except asyncio.TimeoutError:
            return {'status': '⚠', 'error': 'Timeout'}
        except Exception as e:
            logger.error(f"[Shodan] Error: {e}")
            return {'status': '⚠', 'error': str(e)}
    
    async def check_alienvault(self, ioc: str, ioc_type: str) -> Dict:
        """
        Check IOC against AlienVault OTX.
        
        Args:
            ioc: Indicator
            ioc_type: Type (ipv4, domain, url, hash)
        
        Returns:
            AlienVault analysis result
        """
        api_key = get_valid_key(self.api_keys, 'alienvault')
        if not api_key:
            return {'status': '⚠', 'error': 'No valid API key configured'}
        
        try:
            headers = {'X-OTX-API-KEY': api_key}
            
            # Determine endpoint
            if ioc_type == 'ipv4':
                endpoint = f'IPv4/{ioc}/general'
            elif ioc_type == 'domain':
                endpoint = f'domain/{ioc}/general'
            elif ioc_type == 'hash':
                endpoint = f'file/{ioc}/general'
            elif ioc_type == 'url':
                endpoint = f'url/{ioc}/general'
            else:
                return {'status': '⚠', 'error': 'Unsupported type'}
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    f'https://otx.alienvault.com/api/v1/indicators/{endpoint}',
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        pulse_count = data.get('pulse_info', {}).get('count', 0)
                        
                        return {
                            'status': '✓' if pulse_count > 0 else '✗',
                            'pulses': pulse_count,
                            'score': min(100, pulse_count * 10)
                        }
                    else:
                        return {'status': '⚠', 'error': f'HTTP {response.status}'}
        
        except asyncio.TimeoutError:
            return {'status': '⚠', 'error': 'Timeout'}
        except Exception as e:
            logger.error(f"[AlienVault] Error: {e}")
            return {'status': '⚠', 'error': str(e)}
    
    async def check_urlhaus(self, url: str) -> Dict:
        """
        Check URL against URLhaus (Abuse.ch).
        
        Args:
            url: URL to check
        
        Returns:
            URLhaus analysis result
        """
        try:
            data = {'url': url}
            
            # Disable SSL verification due to cert issues
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(timeout=self.timeout, connector=connector) as session:
                async with session.post('https://urlhaus-api.abuse.ch/v1/url/', data=data) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        if result.get('query_status') == 'ok':
                            threat = result.get('threat', 'unknown')
                            tags = result.get('tags', [])
                            
                            return {
                                'status': '✓',
                                'threat': threat,
                                'tags': tags,
                                'score': 90
                            }
                        else:
                            return {'status': '✗', 'message': 'Not found'}
                    else:
                        return {'status': '⚠', 'error': f'HTTP {response.status}'}
        
        except Exception as e:
            logger.error(f"[URLhaus] Error: {e}")
            return {'status': '⚠', 'error': str(e)}
    
    async def check_feodotracker(self, ip: str) -> Dict:
        """
        Check IP against FeodoTracker (Abuse.ch).
        
        Args:
            ip: IP address
        
        Returns:
            FeodoTracker analysis result
        """
        try:
            # Download latest feed
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get('https://feodotracker.abuse.ch/downloads/ipblocklist.json') as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Search for IP
                        for entry in data:
                            if entry.get('ip_address') == ip:
                                return {
                                    'status': '✓',
                                    'botnet': entry.get('malware', 'Unknown'),
                                    'first_seen': entry.get('first_seen', 'N/A'),
                                    'last_seen': entry.get('last_online', 'N/A'),
                                    'score': 95
                                }
                        
                        return {'status': '✗', 'message': 'Not found'}
                    else:
                        return {'status': '⚠', 'error': f'HTTP {response.status}'}
        
        except Exception as e:
            logger.error(f"[FeodoTracker] Error: {e}")
            return {'status': '⚠', 'error': str(e)}
    
    async def check_threatfox(self, ioc: str) -> Dict:
        """
        Check IOC against ThreatFox (Abuse.ch).
        
        v1.0.0: İyileştirildi - hata yönetimi, no-auth API
        
        Args:
            ioc: IOC to check
        
        Returns:
            ThreatFox analysis result
        """
        try:
            # ThreatFox API - may require API key for authenticated access
            api_key = get_valid_key(self.api_keys, 'threatfox') or get_valid_key(self.api_keys, 'abusech')
            data = {'query': 'search_ioc', 'search_term': ioc}
            headers = {'Content-Type': 'application/json'}
            if api_key:
                headers['Auth-Key'] = api_key

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    'https://threatfox-api.abuse.ch/api/v1/',
                    json=data,
                    headers=headers
                ) as response:
                    if response.status == 200:
                        result = await response.json()

                        if result.get('query_status') == 'ok':
                            ioc_data = result.get('data', [])
                            if ioc_data:
                                first = ioc_data[0]
                                return {
                                    'status': '✓',
                                    'found': True,
                                    'malware': first.get('malware_printable', 'Unknown'),
                                    'malware_family': first.get('malware', ''),
                                    'threat_type': first.get('threat_type', ''),
                                    'confidence': first.get('confidence_level', 0),
                                    'first_seen': first.get('first_seen', ''),
                                    'score': 90
                                }
                            return {'status': '✗', 'found': False, 'message': 'Not found in ThreatFox', 'score': 0}
                        elif result.get('query_status') == 'no_result':
                            return {'status': '✗', 'found': False, 'message': 'Not listed', 'score': 0}

                        return {'status': '✗', 'found': False, 'score': 0}
                    elif response.status == 401:
                        return {'status': '⚠', 'found': False, 'message': 'API key required (abuse.ch now requires auth)', 'error': 'HTTP 401', 'score': 0}
                    else:
                        return {'status': '⚠', 'error': f'HTTP {response.status}'}
        
        except asyncio.TimeoutError:
            return {'status': '⚠', 'error': 'Timeout', 'score': 0}
        except Exception as e:
            logger.error(f"[ThreatFox] Error: {e}")
            return {'status': '⚠', 'error': str(e)}
    
    async def check_malwarebazaar(self, hash_value: str) -> Dict:
        """
        Check hash against MalwareBazaar (Abuse.ch).
        
        Args:
            hash_value: File hash
        
        Returns:
            MalwareBazaar analysis result
        """
        try:
            data = {'query': 'get_info', 'hash': hash_value}
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post('https://mb-api.abuse.ch/api/v1/', data=data) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        if result.get('query_status') == 'ok':
                            sample_data = result.get('data', [])
                            if sample_data:
                                first = sample_data[0]
                                return {
                                    'status': '✓',
                                    'signature': first.get('signature', 'Unknown'),
                                    'file_type': first.get('file_type', 'Unknown'),
                                    'score': 95
                                }
                        
                        return {'status': '✗', 'message': 'Not found'}
                    else:
                        return {'status': '⚠', 'error': f'HTTP {response.status}'}
        
        except Exception as e:
            logger.error(f"[MalwareBazaar] Error: {e}")
            return {'status': '⚠', 'error': str(e)}
    
    async def check_tor_exit_nodes(self, ip: str) -> Dict:
        """
        Check if IP is Tor exit node.
        
        Args:
            ip: IP address
        
        Returns:
            Tor check result
        """
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get('https://check.torproject.org/torbulkexitlist') as response:
                    if response.status == 200:
                        text = await response.text()
                        is_tor = ip in text
                        
                        return {
                            'status': '✓' if is_tor else '✗',
                            'is_tor': is_tor,
                            'score': 30 if is_tor else 0
                        }
                    else:
                        return {'status': '⚠', 'error': f'HTTP {response.status}'}
        
        except Exception as e:
            logger.error(f"[Tor] Error: {e}")
            return {'status': '⚠', 'error': str(e)}
    
    async def check_c2_trackers(self, ioc: str) -> Dict:
        """
        Check IOC against comprehensive C2 tracker sources (10+ sources).
        
        Sources:
        - montysecurity/C2-Tracker (Main + per-framework)
        - drb-ra/C2IntelFeeds
        - jmousqueton/C2-Tracker
        - stamparm/maltrail
        
        Args:
            ioc: IOC to check (IP, domain, or hash)
        
        Returns:
            Comprehensive C2 tracker results
        """
        try:
            # Expanded C2 tracker sources (10+ feeds)
            trackers = {
                'montysecurity_combined': {
                    'url': 'https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/combined.csv',
                    'format': 'csv',
                },
                'drb_ra_30day': {
                    'url': 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv',
                    'format': 'csv',
                },
                'jmousqueton': {
                    'url': 'https://raw.githubusercontent.com/jmousqueton/C2-Tracker/main/c2-tracker.csv',
                    'format': 'csv',
                },
                'stamparm_maltrail': {
                    'url': 'https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/c2.txt',
                    'format': 'txt',
                },
                'c2_all_ips': {
                    'url': 'https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/ips/all.txt',
                    'format': 'txt',
                },
                'c2_cobalt_strike': {
                    'url': 'https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Cobalt%20Strike.csv',
                    'format': 'csv',
                    'framework': 'cobalt_strike',
                },
                'c2_metasploit': {
                    'url': 'https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Metasploit.csv',
                    'format': 'csv',
                    'framework': 'metasploit',
                },
                'c2_sliver': {
                    'url': 'https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Sliver.csv',
                    'format': 'csv',
                    'framework': 'sliver',
                },
                'c2_brute_ratel': {
                    'url': 'https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Brute%20Ratel%20C4.csv',
                    'format': 'csv',
                    'framework': 'brute_ratel',
                },
                'c2_havoc': {
                    'url': 'https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Havoc.csv',
                    'format': 'csv',
                    'framework': 'havoc',
                },
            }
            
            results = {
                'found': False,
                'sources_checked': 0,
                'sources_found': [],
                'malware_families': [],
                'c2_frameworks': [],
                'first_seen': None,
                'last_seen': None,
                'score': 0
            }
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                for source_name, source_info in trackers.items():
                    try:
                        async with session.get(source_info['url']) as response:
                            results['sources_checked'] += 1
                            
                            if response.status == 200:
                                text = await response.text()
                                
                                if ioc.lower() in text.lower():
                                    results['found'] = True
                                    results['sources_found'].append(source_name)
                                    
                                    # Direct framework detection from source name
                                    if 'framework' in source_info:
                                        fw = source_info['framework']
                                        if fw not in results['c2_frameworks']:
                                            results['c2_frameworks'].append(fw)
                                    
                                    # Extract malware family from CSV
                                    if source_info['format'] == 'csv':
                                        for line in text.split('\n'):
                                            if ioc.lower() in line.lower():
                                                parts = line.split(',')
                                                if len(parts) >= 2:
                                                    family = parts[1].strip().lower()
                                                    if family and family not in results['malware_families'] and family != 'malware_family':
                                                        results['malware_families'].append(family)
                                                
                                                # Try to get dates
                                                if len(parts) >= 4:
                                                    try:
                                                        if not results['first_seen']:
                                                            results['first_seen'] = parts[2].strip()
                                                        results['last_seen'] = parts[3].strip() if len(parts) > 3 else None
                                                    except:
                                                        pass
                                                
                                                # Detect framework from family name
                                                framework_keywords = {
                                                    'cobalt': 'cobalt_strike',
                                                    'cobaltstrike': 'cobalt_strike',
                                                    'metasploit': 'metasploit',
                                                    'meterpreter': 'metasploit',
                                                    'empire': 'empire',
                                                    'covenant': 'covenant',
                                                    'sliver': 'sliver',
                                                    'havoc': 'havoc',
                                                    'brute': 'brute_ratel',
                                                    'mythic': 'mythic',
                                                    'poshc2': 'poshc2',
                                                }
                                                for kw, fw in framework_keywords.items():
                                                    if kw in family.lower():
                                                        if fw not in results['c2_frameworks']:
                                                            results['c2_frameworks'].append(fw)
                                                break
                                
                    except asyncio.TimeoutError:
                        continue
                    except Exception:
                        continue
            
            # Calculate score
            if results['found']:
                results['score'] = 85
                if results['c2_frameworks']:
                    results['score'] = 95  # Known C2 framework
                if len(results['sources_found']) > 2:
                    results['score'] = min(100, results['score'] + 5)
            
            return {
                'status': '✓' if results['found'] else '✗',
                'found': results['found'],
                'is_c2': results['found'],
                'sources_checked': results['sources_checked'],
                'sources_found': results['sources_found'],
                'malware_families': results['malware_families'],
                'c2_frameworks': results['c2_frameworks'],
                'first_seen': results['first_seen'],
                'last_seen': results['last_seen'],
                'score': results['score']
            }
        
        except Exception as e:
            logger.error(f"[C2Tracker] Error: {e}")
            return {'status': '⚠', 'error': str(e), 'found': False}
    
    async def investigate_ioc_comprehensive(self, ioc: str, ioc_type: str) -> Dict:
        """
        Comprehensive IOC investigation across all 22 sources.
        
        Args:
            ioc: Indicator to investigate
            ioc_type: Type (ipv4, domain, url, hash)
        
        Returns:
            Aggregated results from all sources with proper error handling
        """
        logger.info(f"[INTEL] Investigating {ioc_type}: {ioc}")
        
      
        # ➖ = Not applicable for this IOC type
        # ⏳ = Pending/Will be checked
        source_defaults = {
            'virustotal': {'status': '⏳', 'message': 'Pending'},
            'abuseipdb': {'status': '➖', 'message': 'IP only'},
            'shodan': {'status': '➖', 'message': 'IP only'},
            'alienvault': {'status': '⏳', 'message': 'Pending'},
            'urlhaus': {'status': '➖', 'message': 'URL only'},
            'feodotracker': {'status': '➖', 'message': 'IP only'},
            'threatfox': {'status': '⏳', 'message': 'Pending'},
            'malwarebazaar': {'status': '➖', 'message': 'Hash only'},
            'c2_trackers': {'status': '⏳', 'message': 'Pending'},
            'tor_exit_nodes': {'status': '➖', 'message': 'IP only'},
            'ssl_blacklist': {'status': '➖', 'message': 'Hash only'},
            'usom': {'status': '➖', 'message': 'Domain/IP only'},
            'greynoise': {'status': '➖', 'message': 'IP only'},
            'censys': {'status': '➖', 'message': 'IP only'},
            'talos': {'status': '➖', 'message': 'IP only'},
            'pulsedive': {'status': '➖', 'message': 'URL/Domain'},
            'threatcrowd': {'status': '➖', 'message': 'Domain/IP'},
            'criminalip': {'status': '➖', 'message': 'IP only'},
            'ipqualityscore': {'status': '➖', 'message': 'IP only'},
            'spamhaus': {'status': '➖', 'message': 'IP only'},
            'phishtank': {'status': '➖', 'message': 'URL only'},
            'circl': {'status': '➖', 'message': 'Domain only'},
            'ip2proxy': {'status': '➖', 'message': 'IP only'},
            'triage': {'status': '➖', 'message': 'Hash only'},
            'threatzone': {'status': '➖', 'message': 'Hash only'},
        }
        
        results = dict(source_defaults)
        
        # Create task list based on IOC type
        tasks = []
        
        # VirusTotal (all types)
        tasks.append(('virustotal', self.check_virustotal(ioc, ioc_type)))
        
        # ThreatFox (all types)
        tasks.append(('threatfox', self.check_threatfox(ioc)))
        
        # IP-specific sources
        if ioc_type == 'ipv4':
            # Core IP sources
            tasks.append(('abuseipdb', self.check_abuseipdb(ioc)))
            tasks.append(('shodan', self.check_shodan(ioc)))
            tasks.append(('feodotracker', self.check_feodotracker(ioc)))
            tasks.append(('tor_exit_nodes', self.check_tor_exit_nodes(ioc)))
            tasks.append(('c2_trackers', self.check_c2_trackers(ioc)))
            
            # Extended IP sources
            tasks.append(('greynoise', self.extended.check_greynoise(ioc)))
            tasks.append(('censys', self.extended.check_censys(ioc, ioc_type)))
            tasks.append(('talos', self.extended.check_talos(ioc)))
            tasks.append(('criminalip', self.extended.check_criminalip(ioc)))
            tasks.append(('ipqualityscore', self.extended.check_ipqualityscore(ioc)))
            tasks.append(('spamhaus', self.extended.check_spamhaus(ioc)))
            
          
            tasks.append(('ip2proxy', self.extended.check_ip2proxy(ioc)))

            # USOM threat feed (supports IP)
            tasks.append(('usom', self.threat_feeds.check_usom(ioc)))

            # ThreatCrowd (supports IP)
            tasks.append(('threatcrowd', self.extended.check_threatcrowd(ioc, ioc_type)))

            # Also check AlienVault for IPs
            tasks.append(('alienvault', self.check_alienvault(ioc, ioc_type)))
        
        # Domain sources
        if ioc_type == 'domain':
            tasks.append(('alienvault', self.check_alienvault(ioc, ioc_type)))
            tasks.append(('c2_trackers', self.check_c2_trackers(ioc)))
            
            # Extended domain sources
            tasks.append(('pulsedive', self.extended.check_pulsedive(ioc)))
            tasks.append(('threatcrowd', self.extended.check_threatcrowd(ioc, ioc_type)))
            tasks.append(('circl', self.extended.check_circl(ioc)))
        
        # URL sources
        if ioc_type == 'url':
            tasks.append(('urlhaus', self.check_urlhaus(ioc)))
            tasks.append(('alienvault', self.check_alienvault(ioc, ioc_type)))
            tasks.append(('c2_trackers', self.check_c2_trackers(ioc)))
            
            # Extended URL sources
            tasks.append(('phishtank', self.extended.check_phishtank(ioc)))
            tasks.append(('pulsedive', self.extended.check_pulsedive(ioc)))
            tasks.append(('threatcrowd', self.extended.check_threatcrowd(ioc, 'domain')))
        
        # Hash sources
        if ioc_type in ['md5', 'sha1', 'sha256', 'hash']:
            tasks.append(('malwarebazaar', self.check_malwarebazaar(ioc)))
            tasks.append(('alienvault', self.check_alienvault(ioc, 'hash')))
            
          
            tasks.append(('triage', self.extended.check_triage(ioc)))
            tasks.append(('threatzone', self.extended.check_threatzone(ioc)))
        
        # Execute all checks with timeout
        import asyncio
        
        async def safe_execute(name: str, coro) -> tuple:
            """Execute with timeout and error handling."""
            try:
                result = await asyncio.wait_for(coro, timeout=15.0)
                return name, result
            except asyncio.TimeoutError:
                logger.warning(f"[INTEL] {name}: Timeout after 15s")
                return name, {'status': '⚠', 'error': 'Timeout'}
            except Exception as e:
                logger.error(f"[INTEL] {name} failed: {e}")
                return name, {'status': '⚠', 'error': str(e)}
        
        # Run all tasks concurrently
        safe_tasks = [safe_execute(name, coro) for name, coro in tasks]
        completed = await asyncio.gather(*safe_tasks, return_exceptions=True)
        
        # Process results
        for item in completed:
            if isinstance(item, tuple):
                name, result = item
                results[name] = result
                if result.get('status') == '✓':
                    logger.info(f"[INTEL] {name}: FLAGGED")
                else:
                    logger.debug(f"[INTEL] {name}: {result.get('status', 'Unknown')}")
        
        # Calculate aggregate threat score
        total_score = 0
        score_count = 0
        sources_flagged = 0
        
        for source, data in results.items():
            if isinstance(data, dict):
                # Count flagged sources
                if data.get('status') == '✓':
                    sources_flagged += 1
                
                # Aggregate scores
                if 'score' in data and isinstance(data['score'], (int, float)):
                    total_score += data['score']
                    score_count += 1
        
        avg_score = int(total_score / score_count) if score_count > 0 else 0
        
        # Count actually checked sources (not "Not applicable")
        sources_checked = sum(1 for r in results.values() 
                             if isinstance(r, dict) and r.get('error') != 'Not applicable')
        
        return {
            'ioc': ioc,
            'ioc_type': ioc_type,
            'sources': results,
            'threat_score': avg_score,
            'sources_checked': sources_checked,
            'sources_flagged': sources_flagged
        }
