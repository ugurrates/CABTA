"""
Author: Ugur AtesSandbox integration for malware analysis."""

import aiohttp
import asyncio
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)
class SandboxAnalyzer:
    """
    Integration with sandbox services.
    
    Supports:
    - Hybrid Analysis
    - ANY.RUN
    - Tria.ge
    - Threat.Zone
    """
    
    def __init__(self, config: Dict):
        """
        Initialize sandbox analyzer.
        
        Args:
            config: Configuration dict with API keys
        """
        self.config = config
        self.api_keys = config.get('api_keys', {})
        self.timeout = aiohttp.ClientTimeout(total=config.get('timeouts', {}).get('sandbox_timeout', 300))
    
    async def check_hybrid_analysis(self, hash_value: str) -> Dict:
        """
        Check hash against Hybrid Analysis.
        
        Args:
            hash_value: File hash
        
        Returns:
            Hybrid Analysis result
        """
        api_key = self.api_keys.get('hybridanalysis')
        if not api_key:
            return {'status': '⚠', 'error': 'No API key'}
        
        try:
            headers = {'api-key': api_key, 'user-agent': 'Falcon Sandbox'}
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    'https://www.hybrid-analysis.com/api/v2/search/hash',
                    headers=headers,
                    data={'hash': hash_value}
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data:
                            first = data[0]
                            verdict = first.get('verdict', 'unknown')
                            threat_score = first.get('threat_score', 0)
                            
                            return {
                                'status': '✓' if threat_score > 50 else '✗',
                                'verdict': verdict,
                                'threat_score': threat_score,
                                'vx_family': first.get('vx_family', 'Unknown'),
                                'score': threat_score
                            }
                        else:
                            return {'status': '✗', 'message': 'Not found'}
                    else:
                        return {'status': '⚠', 'error': f'HTTP {response.status}'}
        
        except Exception as e:
            logger.error(f"[HybridAnalysis] Error: {e}")
            return {'status': '⚠', 'error': str(e)}
    
    async def check_anyrun(self, hash_value: str) -> Dict:
        """
        Check hash against ANY.RUN.
        
        Args:
            hash_value: File hash
        
        Returns:
            ANY.RUN result
        """
        api_key = self.api_keys.get('anyrun')
        if not api_key:
            return {'status': '⚠', 'error': 'No API key'}
        
        # Note: ANY.RUN API requires specific implementation
        return {'status': '⚠', 'message': 'Not implemented'}
    
    async def check_triage(self, hash_value: str) -> Dict:
        """
        Check hash against Tria.ge.
        
        Args:
            hash_value: File hash
        
        Returns:
            Tria.ge result
        """
        api_key = self.api_keys.get('triage')
        if not api_key:
            return {'status': '⚠', 'error': 'No API key'}
        
        try:
            headers = {'Authorization': f'Bearer {api_key}'}
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    f'https://api.tria.ge/v0/search?query=sha256:{hash_value}',
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('data'):
                            first = data['data'][0]
                            score = first.get('score', 0)
                            
                            return {
                                'status': '✓' if score > 5 else '✗',
                                'score': score * 10,
                                'family': first.get('family', 'Unknown')
                            }
                        else:
                            return {'status': '✗', 'message': 'Not found'}
                    else:
                        return {'status': '⚠', 'error': f'HTTP {response.status}'}
        
        except Exception as e:
            logger.error(f"[Triage] Error: {e}")
            return {'status': '⚠', 'error': str(e)}
    
    async def analyze_hash_all_sandboxes(self, hash_value: str) -> Dict:
        """
        Check hash across all available sandboxes.
        
        Args:
            hash_value: File hash
        
        Returns:
            Aggregated sandbox results
        """
        logger.info(f"[SANDBOX] Checking hash: {hash_value}")
        
        tasks = []
        
        if self.api_keys.get('hybridanalysis'):
            tasks.append(('hybrid_analysis', self.check_hybrid_analysis(hash_value)))
        
        if self.api_keys.get('triage'):
            tasks.append(('triage', self.check_triage(hash_value)))
        
        results = {}
        for name, task in tasks:
            try:
                result = await task
                results[name] = result
            except Exception as e:
                logger.error(f"[SANDBOX] {name} failed: {e}")
                results[name] = {'status': '⚠', 'error': str(e)}
        
        return results
