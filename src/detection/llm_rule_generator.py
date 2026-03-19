"""
Author: Ugur Ates
LLM-Powered Detection Rule Generator v1.0.0
Generates intelligent, context-aware detection rules using local LLM (Ollama).
"""

import json
from datetime import datetime
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)
class LLMRuleGenerator:
    """
    Generate detection rules using LLM for contextual, intelligent rule creation.
    
    Supports:
    - KQL (Microsoft Defender/Sentinel)
    - SPL (Splunk)
    - SIGMA (Universal)
    - YARA (File signatures)
    
    Uses Ollama for local, private rule generation.
    """
    
    def __init__(self, llm_analyzer):
        """
        Initialize with LLM analyzer.
        
        Args:
            llm_analyzer: LLMAnalyzer instance
        """
        self.llm = llm_analyzer
    
    async def generate_rules_for_ioc(self, ioc: str, ioc_type: str, analysis_result: Dict) -> Dict[str, str]:
        """
        Generate detection rules for IOC using LLM.
        
        Args:
            ioc: Indicator of Compromise
            ioc_type: Type (ipv4, domain, url, hash)
            analysis_result: Full investigation results
        
        Returns:
            Dict with rules for each platform
        """
        # Prepare context
        context = {
            'ioc': ioc,
            'type': ioc_type,
            'threat_score': analysis_result.get('threat_score', 0),
            'verdict': analysis_result.get('verdict', 'UNKNOWN'),
            'sources_flagged': analysis_result.get('sources_flagged', 0),
            'malware_family': analysis_result.get('malware_family', 'Unknown'),
            'campaign': analysis_result.get('campaign', 'Unknown')
        }
        
        # Extract key findings
        sources = analysis_result.get('sources', {})
        key_findings = []
        for source_name, source_data in sources.items():
            if source_data.get('status') == '✓':
                if source_data.get('botnet'):
                    key_findings.append(f"{source_name}: Botnet {source_data.get('botnet')}")
                if source_data.get('threat'):
                    key_findings.append(f"{source_name}: {source_data.get('threat')}")
                if source_data.get('malware'):
                    key_findings.append(f"{source_name}: {source_data.get('malware')}")
        
        context['key_findings'] = key_findings[:5]
        
        prompt = f"""You are a detection engineer. Generate detection rules for this IOC.

IOC: {ioc}
Type: {ioc_type}
Threat Score: {context['threat_score']}/100
Verdict: {context['verdict']}
Key Findings: {json.dumps(context['key_findings'])}

Generate rules in this exact JSON format:
{{
    "kql": "// KQL rule here - include proper syntax for Microsoft Defender/Sentinel",
    "sigma": "title: Rule Title\\nid: unique-id\\nstatus: experimental\\ndescription: Description\\nauthor: Ugur Ates\\nlogsource:\\n  category: network_connection\\ndetection:\\n  selection:\\n    dst_ip: '{ioc}'\\n  condition: selection\\nlevel: high"
}}

Rules should:
1. Be syntactically correct
2. Include comments explaining what they detect
3. Be optimized for the IOC type ({ioc_type})
4. Include relevant MITRE ATT&CK references if applicable

Return ONLY the JSON object, no other text."""

        try:
            response = await self.llm._call_ollama_api(prompt)
            
            if response:
                # Parse LLM response
                if isinstance(response, dict):
                    return {
                        'kql': response.get('kql', self._fallback_kql(ioc, ioc_type)),
                        'sigma': response.get('sigma', self._fallback_sigma(ioc, ioc_type))
                    }
                elif isinstance(response, str):
                    # Try to extract JSON from response
                    try:
                        start = response.find('{')
                        end = response.rfind('}') + 1
                        if start >= 0 and end > start:
                            parsed = json.loads(response[start:end])
                            return {
                                'kql': parsed.get('kql', self._fallback_kql(ioc, ioc_type)),
                                'sigma': parsed.get('sigma', self._fallback_sigma(ioc, ioc_type))
                            }
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            logger.error(f"[LLM-RULES] Failed to generate rules: {e}")
        
        # Fallback to template-based rules
        return {
            'kql': self._fallback_kql(ioc, ioc_type),
            'sigma': self._fallback_sigma(ioc, ioc_type)
        }
    
    async def generate_rules_for_file(self, file_analysis: Dict) -> Dict[str, str]:
        """
        Generate detection rules for malicious file.
        
        Args:
            file_analysis: Complete file analysis results
        
        Returns:
            Dict with rules for each platform
        """
        # Extract key indicators
        hashes = file_analysis.get('hashes', {})
        static = file_analysis.get('static_analysis', {})
        yara = file_analysis.get('yara_analysis', {})
        strings = file_analysis.get('string_analysis', {})
        
        context = {
            'filename': file_analysis.get('file_info', {}).get('name', 'Unknown'),
            'sha256': hashes.get('sha256', ''),
            'sha1': hashes.get('sha1', ''),
            'md5': hashes.get('md5', ''),
            'file_type': static.get('pe_type', static.get('file_type', 'Unknown')),
            'verdict': file_analysis.get('verdict', 'UNKNOWN'),
            'composite_score': file_analysis.get('composite_score', 0),
            'packer': static.get('packer_detection', {}).get('packer', ''),
            'malware_families': yara.get('interpretation', {}).get('malware_families', []),
            'suspicious_apis': [],
            'registry_keys': strings.get('registry_keys', [])[:3],
            'mutexes': strings.get('mutexes', [])[:3],
            'interesting_strings': strings.get('interesting_strings', [])[:5]
        }
        
        # Extract suspicious APIs
        imports = static.get('imports', [])
        for imp in imports:
            if imp.get('suspicious_apis'):
                context['suspicious_apis'].extend(imp.get('suspicious_apis', []))
        context['suspicious_apis'] = context['suspicious_apis'][:10]
        
        prompt = f"""You are a detection engineer. Generate detection rules for this malicious file.

File: {context['filename']}
Type: {context['file_type']}
SHA256: {context['sha256']}
Verdict: {context['verdict']} (Score: {context['composite_score']}/100)
Malware Families: {', '.join(context['malware_families']) if context['malware_families'] else 'Unknown'}
Packer: {context['packer'] if context['packer'] else 'None detected'}
Suspicious APIs: {', '.join(context['suspicious_apis'][:5])}
Registry Keys: {', '.join(context['registry_keys'])}
Mutexes: {', '.join(context['mutexes'])}

Generate rules in this exact JSON format:
{{
    "kql": "// KQL hunt rule for this file/behavior",
    "yara": "rule MalwareDetection {{ meta: description = \\"Description\\" strings: $hash = \\"{context['sha256']}\\" condition: any of them }}"
}}

Rules should:
1. Use hashes for exact matching
2. Include behavioral indicators where available
3. Be syntactically correct
4. Include MITRE ATT&CK references

Return ONLY the JSON object."""

        try:
            response = await self.llm._call_ollama_api(prompt)
            
            if response:
                if isinstance(response, dict):
                    return {
                        'kql': response.get('kql', self._fallback_file_kql(context)),
                        'yara': response.get('yara', self._fallback_yara(context))
                    }
                elif isinstance(response, str):
                    try:
                        start = response.find('{')
                        end = response.rfind('}') + 1
                        if start >= 0 and end > start:
                            parsed = json.loads(response[start:end])
                            return {
                                'kql': parsed.get('kql', self._fallback_file_kql(context)),
                                'yara': parsed.get('yara', self._fallback_yara(context))
                            }
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            logger.error(f"[LLM-RULES] Failed to generate file rules: {e}")
        
        return {
            'kql': self._fallback_file_kql(context),
            'yara': self._fallback_yara(context)
        }
    
    async def generate_rules_for_email(self, email_analysis: Dict) -> Dict[str, str]:
        """
        Generate detection rules for phishing email.
        
        Args:
            email_analysis: Complete email analysis results
        
        Returns:
            Dict with rules for each platform
        """
        email_data = email_analysis.get('email_data', {})
        advanced = email_analysis.get('advanced_analysis', {})
        ioc_analysis = email_analysis.get('ioc_analysis', {})
        
        context = {
            'subject': email_data.get('subject', ''),
            'from_domain': email_data.get('from_domain', ''),
            'verdict': email_analysis.get('verdict', 'UNKNOWN'),
            'score': email_analysis.get('composite_score', 0),
            'malicious_urls': [],
            'malicious_domains': [],
            'lookalike_domains': [d.get('domain') for d in advanced.get('lookalike_domains', [])]
        }
        
        # Extract malicious IOCs
        ioc_results = ioc_analysis.get('ioc_results', {})
        for url in ioc_results.get('urls', []):
            if url.get('verdict') == 'MALICIOUS':
                context['malicious_urls'].append(url.get('ioc'))
        for domain in ioc_results.get('domains', []):
            if domain.get('verdict') == 'MALICIOUS':
                context['malicious_domains'].append(domain.get('ioc'))
        
        prompt = f"""You are a detection engineer. Generate detection rules for this phishing email campaign.

Subject: {context['subject'][:50]}
From Domain: {context['from_domain']}
Verdict: {context['verdict']} (Score: {context['score']}/100)
Malicious URLs: {', '.join(context['malicious_urls'][:3])}
Malicious Domains: {', '.join(context['malicious_domains'][:3])}
Lookalike Domains: {', '.join(context['lookalike_domains'][:3])}

Generate rules in this exact JSON format:
{{
    "kql": "// KQL rule for Microsoft Defender for Office 365",
    "sigma": "title: Phishing Campaign Detection\\n..."
}}

Rules should:
1. Block sender domain and malicious URLs
2. Detect similar phishing attempts
3. Be syntactically correct

Return ONLY the JSON object."""

        try:
            response = await self.llm._call_ollama_api(prompt)
            
            if response:
                if isinstance(response, dict):
                    return {
                        'kql': response.get('kql', self._fallback_email_kql(context)),
                        'sigma': response.get('sigma', self._fallback_sigma(context['from_domain'], 'domain'))
                    }
        except Exception as e:
            logger.error(f"[LLM-RULES] Failed to generate email rules: {e}")
        
        return {
            'kql': self._fallback_email_kql(context),
            'sigma': self._fallback_sigma(context['from_domain'], 'domain')
        }
    
    def _fallback_kql(self, ioc: str, ioc_type: str) -> str:
        """Fallback KQL rule."""
        if ioc_type == 'ipv4':
            return f"""// KQL - Hunt for IP: {ioc}
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "{ioc}"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| summarize count() by DeviceName, RemoteIP"""
        
        elif ioc_type == 'domain':
            return f"""// KQL - Hunt for Domain: {ioc}
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "{ioc}"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName
| summarize count() by DeviceName, RemoteUrl"""
        
        elif ioc_type == 'url':
            return f"""// KQL - Hunt for URL: {ioc}
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "{ioc}"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName"""
        
        elif ioc_type in ['sha256', 'sha1', 'md5']:
            return f"""// KQL - Hunt for File Hash
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "{ioc}" or SHA1 == "{ioc}" or MD5 == "{ioc}"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256"""
        
        return f"// No KQL rule template for type: {ioc_type}"
    
    def _fallback_sigma(self, ioc: str, ioc_type: str) -> str:
        """Fallback SIGMA rule."""
        return f"""title: IOC Detection - {ioc_type.upper()}
id: mcp-soc-auto-{hash(ioc) % 10000:04d}
status: experimental
description: Detects {ioc_type} IOC - {ioc[:30]}
author: Ugur Ates
date: {datetime.now().strftime('%Y/%m/%d')}
logsource:
    category: network_connection
detection:
    selection:
        {'dst_ip' if ioc_type == 'ipv4' else 'query' if ioc_type == 'domain' else 'url'}: '{ioc}'
    condition: selection
falsepositives:
    - Unknown
level: high"""
    
    def _fallback_file_kql(self, context: Dict) -> str:
        """Fallback KQL for file detection."""
        sha256 = context.get('sha256', '')
        filename = context.get('filename', 'Unknown')
        
        return f"""// KQL - Hunt for Malicious File: {filename}
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "{sha256}"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| summarize count() by DeviceName, FileName"""
    
    def _fallback_yara(self, context: Dict) -> str:
        """Fallback YARA rule."""
        sha256 = context.get('sha256', 'unknown')
        families = context.get('malware_families', [])
        family_name = families[0] if families else 'Unknown'
        
        return f"""rule BTA_Detection_{hash(sha256) % 10000:04d} {{
    meta:
        description = "Detects {family_name} malware"
        author = "Blue Team Assistant"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        hash = "{sha256}"
    
    strings:
        $hash = "{sha256}" ascii nocase
    
    condition:
        uint16(0) == 0x5A4D and $hash
}}"""
    
    def _fallback_email_kql(self, context: Dict) -> str:
        """Fallback KQL for email detection."""
        domain = context.get('from_domain', 'unknown')
        urls = context.get('malicious_urls', [])
        
        url_filter = ' or '.join([f'Urls has "{url}"' for url in urls[:3]]) if urls else 'false'
        
        return f"""// KQL - Hunt for Phishing Campaign
EmailEvents
| where Timestamp > ago(30d)
| where SenderFromDomain == "{domain}" or {url_filter}
| project Timestamp, SenderFromAddress, Subject, RecipientEmailAddress, Urls
| summarize count() by SenderFromDomain"""
