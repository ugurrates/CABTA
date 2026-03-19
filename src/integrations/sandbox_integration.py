"""
Author: Ugur AtesSandbox integration for automated malware detonation and analysis."""

import aiohttp
import asyncio
import hashlib
from typing import Dict, Optional, List
import logging

logger = logging.getLogger(__name__)
class SandboxIntegration:
    """
    Integrate with multiple malware sandboxes for automated detonation.
    
    Supported Sandboxes:
    - Hybrid Analysis (Public API)
    - VirusTotal Sandbox
    - ANY.RUN (View-only)
    - Joe Sandbox (Public submissions)
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.api_keys = config.get('api_keys', {})
        self.timeout = aiohttp.ClientTimeout(total=30)
        
        # Sandbox endpoints
        self.endpoints = {
            'hybrid_analysis': 'https://www.hybrid-analysis.com/api/v2',
            'virustotal': 'https://www.virustotal.com/api/v3',
            'anyrun': 'https://api.any.run/v1',
            'joesandbox': 'https://jbxcloud.joesecurity.org/api'
        }
    
    async def check_file_sandboxes(self, file_hash: str) -> Dict:
        """
        Check if file has been analyzed in sandboxes.
        
        Args:
            file_hash: SHA256 hash of file
        
        Returns:
            Sandbox analysis results from all sources
        """
        results = {
            'hybrid_analysis': {},
            'virustotal_behavior': {},
            'anyrun': {},
            'joe_sandbox': {},
            'summary': {
                'total_sandboxes': 4,
                'available_reports': 0,
                'verdict': 'UNKNOWN',
                'behaviors': [],
                'network_activity': [],
                'mitre_techniques': []
            }
        }
        
        tasks = [
            self._check_hybrid_analysis(file_hash),
            self._check_virustotal_behavior(file_hash),
            self._check_anyrun(file_hash),
            self._check_joe_sandbox(file_hash)
        ]
        
        sandbox_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Hybrid Analysis
        if not isinstance(sandbox_results[0], Exception) and sandbox_results[0]:
            results['hybrid_analysis'] = sandbox_results[0]
            if sandbox_results[0].get('found'):
                results['summary']['available_reports'] += 1
        
        # VirusTotal Behavior
        if not isinstance(sandbox_results[1], Exception) and sandbox_results[1]:
            results['virustotal_behavior'] = sandbox_results[1]
            if sandbox_results[1].get('found'):
                results['summary']['available_reports'] += 1
        
        # ANY.RUN
        if not isinstance(sandbox_results[2], Exception) and sandbox_results[2]:
            results['anyrun'] = sandbox_results[2]
            if sandbox_results[2].get('found'):
                results['summary']['available_reports'] += 1
        
        # Joe Sandbox
        if not isinstance(sandbox_results[3], Exception) and sandbox_results[3]:
            results['joe_sandbox'] = sandbox_results[3]
            if sandbox_results[3].get('found'):
                results['summary']['available_reports'] += 1
        
        # Aggregate behaviors
        results['summary'] = self._aggregate_sandbox_results(results)
        
        return results
    
    async def _check_hybrid_analysis(self, file_hash: str) -> Dict:
        """Check Hybrid Analysis for existing reports."""
        api_key = self.api_keys.get('hybrid_analysis', '')
        if not api_key:
            return {'error': 'API key not configured'}
        
        try:
            url = f"{self.endpoints['hybrid_analysis']}/search/hash"
            headers = {
                'api-key': api_key,
                'User-Agent': 'Blue Team Assistant',
                'accept': 'application/json'
            }
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(url, headers=headers, data={'hash': file_hash}) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data and len(data) > 0:
                            report = data[0]  # Latest report
                            
                            return {
                                'found': True,
                                'report_url': f"https://www.hybrid-analysis.com/sample/{file_hash}",
                                'verdict': report.get('verdict', 'unknown'),
                                'threat_score': report.get('threat_score', 0),
                                'malware_family': report.get('av_detect', 'Unknown'),
                                'analysis_date': report.get('analysis_start_time', 'Unknown'),
                                'behaviors': report.get('tags', []),
                                'network_activity': {
                                    'domains': report.get('domains', []),
                                    'ips': report.get('hosts', []),
                                    'urls': report.get('extracted_files', [])
                                },
                                'mitre_attck': report.get('mitre_attcks', [])
                            }
                        else:
                            return {'found': False}
                    else:
                        return {'error': f'HTTP {response.status}'}
        
        except Exception as e:
            logger.error(f"[SANDBOX] Hybrid Analysis error: {e}")
            return {'error': str(e)}
    
    async def _check_virustotal_behavior(self, file_hash: str) -> Dict:
        """Check VirusTotal for behavior analysis."""
        api_key = self.api_keys.get('virustotal', '')
        if not api_key:
            return {'error': 'API key not configured'}
        
        try:
            url = f"{self.endpoints['virustotal']}/files/{file_hash}/behaviour_summary"
            headers = {
                'x-apikey': api_key
            }
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        behavior_data = data.get('data', {})
                        
                        if behavior_data:
                            return {
                                'found': True,
                                'report_url': f"https://www.virustotal.com/gui/file/{file_hash}/behavior",
                                'behaviors': behavior_data.get('tags', []),
                                'network_activity': {
                                    'dns_lookups': behavior_data.get('dns_lookups', []),
                                    'ip_traffic': behavior_data.get('ip_traffic', []),
                                    'http_conversations': behavior_data.get('http_conversations', [])
                                },
                                'files_written': behavior_data.get('files_written', []),
                                'files_deleted': behavior_data.get('files_deleted', []),
                                'registry_keys': behavior_data.get('registry_keys_set', []),
                                'processes_created': behavior_data.get('processes_created', []),
                                'mitre_attck': behavior_data.get('mitre_attack_techniques', [])
                            }
                        else:
                            return {'found': False}
                    elif response.status == 404:
                        return {'found': False}
                    else:
                        return {'error': f'HTTP {response.status}'}
        
        except Exception as e:
            logger.error(f"[SANDBOX] VirusTotal Behavior error: {e}")
            return {'error': str(e)}
    
    async def _check_anyrun(self, file_hash: str) -> Dict:
        """Check ANY.RUN for public submissions."""
        # ANY.RUN public search doesn't require API key
        try:
            # Search public submissions
            url = f"https://any.run/malware-trends/search/?iocs={file_hash}"
            
            return {
                'found': True,  # Assume found for now
                'report_url': url,
                'note': 'Check ANY.RUN manually for detailed analysis'
            }
        
        except Exception as e:
            logger.error(f"[SANDBOX] ANY.RUN error: {e}")
            return {'error': str(e)}
    
    async def _check_joe_sandbox(self, file_hash: str) -> Dict:
        """Check Joe Sandbox for public submissions."""
        api_key = self.api_keys.get('joe_sandbox', '')
        if not api_key:
            return {'error': 'API key not configured'}
        
        try:
            url = f"{self.endpoints['joesandbox']}/search"
            params = {
                'apikey': api_key,
                'q': file_hash
            }
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data and len(data) > 0:
                            report = data[0]
                            
                            return {
                                'found': True,
                                'report_url': report.get('webid', ''),
                                'verdict': report.get('detection', 'unknown'),
                                'analysis_date': report.get('time', 'Unknown')
                            }
                        else:
                            return {'found': False}
                    else:
                        return {'error': f'HTTP {response.status}'}
        
        except Exception as e:
            logger.error(f"[SANDBOX] Joe Sandbox error: {e}")
            return {'error': str(e)}
    
    def _aggregate_sandbox_results(self, results: Dict) -> Dict:
        """Aggregate results from all sandboxes."""
        summary = {
            'total_sandboxes': 4,
            'available_reports': 0,
            'verdict': 'UNKNOWN',
            'behaviors': set(),
            'network_activity': {
                'domains': set(),
                'ips': set(),
                'urls': set()
            },
            'mitre_techniques': set(),
            'report_urls': []
        }
        
        # Hybrid Analysis
        ha = results.get('hybrid_analysis', {})
        if ha.get('found'):
            summary['available_reports'] += 1
            summary['report_urls'].append(ha.get('report_url'))
            
            if ha.get('verdict') in ['malicious', 'suspicious']:
                summary['verdict'] = 'MALICIOUS'
            
            summary['behaviors'].update(ha.get('behaviors', []))
            
            network = ha.get('network_activity', {})
            summary['network_activity']['domains'].update(network.get('domains', []))
            summary['network_activity']['ips'].update(network.get('ips', []))
            
            summary['mitre_techniques'].update(ha.get('mitre_attck', []))
        
        # VirusTotal Behavior
        vt = results.get('virustotal_behavior', {})
        if vt.get('found'):
            summary['available_reports'] += 1
            summary['report_urls'].append(vt.get('report_url'))
            
            summary['behaviors'].update(vt.get('behaviors', []))
            
            network = vt.get('network_activity', {})
            summary['network_activity']['domains'].update([d.get('hostname') for d in network.get('dns_lookups', [])])
            summary['network_activity']['ips'].update([ip.get('destination_ip') for ip in network.get('ip_traffic', [])])
            
            summary['mitre_techniques'].update([t.get('id') for t in vt.get('mitre_attck', [])])
        
        # Convert sets to lists
        summary['behaviors'] = list(summary['behaviors'])
        summary['network_activity']['domains'] = list(summary['network_activity']['domains'])
        summary['network_activity']['ips'] = list(summary['network_activity']['ips'])
        summary['network_activity']['urls'] = list(summary['network_activity']['urls'])
        summary['mitre_techniques'] = list(summary['mitre_techniques'])
        
        return summary
    
    # ==================== AUTO-SUBMIT FUNCTIONALITY () ====================
    
    async def submit_file_to_sandbox(self, file_path: str, 
                                     sandbox: str = 'auto') -> Dict:
        """
        Submit file to sandbox for automated analysis.
        
        Args:
            file_path: Path to file to submit
            sandbox: 'virustotal', 'hybrid_analysis', 'joe_sandbox', or 'auto'
        
        Returns:
            Submission result with tracking info
        """
        result = {
            'submitted': False,
            'sandbox': sandbox,
            'submissions': [],
            'errors': []
        }
        
        # Read file
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            import hashlib
            file_hash = hashlib.sha256(file_data).hexdigest()
            file_name = file_path.split('/')[-1].split('\\')[-1]
            
        except Exception as e:
            result['errors'].append(f"File read error: {e}")
            return result
        
        # Determine which sandboxes to use
        if sandbox == 'auto':
            sandboxes = ['virustotal', 'hybrid_analysis']
        else:
            sandboxes = [sandbox]
        
        # Submit to each sandbox
        for sb in sandboxes:
            try:
                if sb == 'virustotal':
                    sub_result = await self._submit_to_virustotal(file_data, file_name)
                elif sb == 'hybrid_analysis':
                    sub_result = await self._submit_to_hybrid_analysis(file_data, file_name)
                elif sb == 'joe_sandbox':
                    sub_result = await self._submit_to_joe_sandbox(file_data, file_name)
                else:
                    sub_result = {'error': f'Unknown sandbox: {sb}'}
                
                if sub_result.get('success'):
                    result['submitted'] = True
                    result['submissions'].append({
                        'sandbox': sb,
                        'analysis_id': sub_result.get('analysis_id'),
                        'report_url': sub_result.get('report_url'),
                        'status': 'SUBMITTED'
                    })
                else:
                    result['errors'].append(f"{sb}: {sub_result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                result['errors'].append(f"{sb}: {str(e)}")
        
        logger.info(f"[SANDBOX] Submit result: {len(result['submissions'])} successful, {len(result['errors'])} errors")
        
        return result
    
    async def _submit_to_virustotal(self, file_data: bytes, file_name: str) -> Dict:
        """Submit file to VirusTotal for scanning."""
        api_key = self.api_keys.get('virustotal', '')
        if not api_key:
            return {'error': 'VirusTotal API key not configured'}
        
        try:
            url = f"{self.endpoints['virustotal']}/files"
            headers = {'x-apikey': api_key}
            
            import aiohttp
            form = aiohttp.FormData()
            form.add_field('file', file_data, filename=file_name)
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as session:
                async with session.post(url, headers=headers, data=form) as response:
                    if response.status == 200:
                        data = await response.json()
                        analysis_id = data.get('data', {}).get('id', '')
                        sha256 = data.get('data', {}).get('attributes', {}).get('sha256', '')
                        
                        return {
                            'success': True,
                            'analysis_id': analysis_id,
                            'sha256': sha256,
                            'report_url': f"https://www.virustotal.com/gui/file/{sha256}"
                        }
                    else:
                        return {'error': f'HTTP {response.status}: {await response.text()}'}
        
        except Exception as e:
            logger.error(f"[SANDBOX] VirusTotal submit error: {e}")
            return {'error': str(e)}
    
    async def _submit_to_hybrid_analysis(self, file_data: bytes, file_name: str) -> Dict:
        """Submit file to Hybrid Analysis."""
        api_key = self.api_keys.get('hybrid_analysis', '')
        if not api_key:
            return {'error': 'Hybrid Analysis API key not configured'}
        
        try:
            url = f"{self.endpoints['hybrid_analysis']}/submit/file"
            headers = {
                'api-key': api_key,
                'User-Agent': 'Blue Team Assistant/6.2'
            }
            
            import aiohttp
            form = aiohttp.FormData()
            form.add_field('file', file_data, filename=file_name)
            form.add_field('environment_id', '160')  # Windows 10 64-bit
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as session:
                async with session.post(url, headers=headers, data=form) as response:
                    if response.status in [200, 201]:
                        data = await response.json()
                        job_id = data.get('job_id', '')
                        sha256 = data.get('sha256', '')
                        
                        return {
                            'success': True,
                            'analysis_id': job_id,
                            'sha256': sha256,
                            'report_url': f"https://www.hybrid-analysis.com/sample/{sha256}"
                        }
                    else:
                        return {'error': f'HTTP {response.status}: {await response.text()}'}
        
        except Exception as e:
            logger.error(f"[SANDBOX] Hybrid Analysis submit error: {e}")
            return {'error': str(e)}
    
    async def _submit_to_joe_sandbox(self, file_data: bytes, file_name: str) -> Dict:
        """Submit file to Joe Sandbox (Cloud)."""
        api_key = self.api_keys.get('joe_sandbox', '')
        if not api_key:
            return {'error': 'Joe Sandbox API key not configured'}
        
        try:
            url = f"{self.endpoints['joesandbox']}/v2/submission/new"
            
            import aiohttp
            form = aiohttp.FormData()
            form.add_field('apikey', api_key)
            form.add_field('sample', file_data, filename=file_name)
            form.add_field('systems', 'w10x64')
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as session:
                async with session.post(url, data=form) as response:
                    if response.status == 200:
                        data = await response.json()
                        submission_id = data.get('data', {}).get('submission_id', '')
                        
                        return {
                            'success': True,
                            'analysis_id': submission_id,
                            'report_url': f"https://www.joesandbox.com/analysis/{submission_id}"
                        }
                    else:
                        return {'error': f'HTTP {response.status}'}
        
        except Exception as e:
            logger.error(f"[SANDBOX] Joe Sandbox submit error: {e}")
            return {'error': str(e)}
    
    async def check_analysis_status(self, sandbox: str, analysis_id: str) -> Dict:
        """
        Check status of a submitted analysis.
        
        Args:
            sandbox: Sandbox name
            analysis_id: Analysis/job ID from submission
        
        Returns:
            Status info
        """
        if sandbox == 'virustotal':
            return await self._check_vt_analysis_status(analysis_id)
        elif sandbox == 'hybrid_analysis':
            return await self._check_ha_analysis_status(analysis_id)
        else:
            return {'error': f'Status check not implemented for {sandbox}'}
    
    async def _check_vt_analysis_status(self, analysis_id: str) -> Dict:
        """Check VirusTotal analysis status."""
        api_key = self.api_keys.get('virustotal', '')
        if not api_key:
            return {'error': 'API key not configured'}
        
        try:
            url = f"{self.endpoints['virustotal']}/analyses/{analysis_id}"
            headers = {'x-apikey': api_key}
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        attrs = data.get('data', {}).get('attributes', {})
                        
                        return {
                            'status': attrs.get('status', 'unknown'),
                            'stats': attrs.get('stats', {}),
                            'completed': attrs.get('status') == 'completed'
                        }
                    else:
                        return {'error': f'HTTP {response.status}'}
        
        except Exception as e:
            return {'error': str(e)}
    
    async def _check_ha_analysis_status(self, job_id: str) -> Dict:
        """Check Hybrid Analysis job status."""
        api_key = self.api_keys.get('hybrid_analysis', '')
        if not api_key:
            return {'error': 'API key not configured'}
        
        try:
            url = f"{self.endpoints['hybrid_analysis']}/report/{job_id}/state"
            headers = {'api-key': api_key}
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        return {
                            'status': data.get('state', 'unknown'),
                            'completed': data.get('state') == 'SUCCESS'
                        }
                    else:
                        return {'error': f'HTTP {response.status}'}
        
        except Exception as e:
            return {'error': str(e)}
