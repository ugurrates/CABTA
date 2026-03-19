"""
Author: Ugur AtesLLM-powered intelligent analysis using Local (Ollama) or Cloud (Anthropic) models."""

import aiohttp
import json
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)
class LLMAnalyzer:
    """
    LLM-powered threat analysis using LOCAL (Ollama) or CLOUD (Anthropic) models.
    
    **LOCAL-FIRST APPROACH** (Recommended for Aviation/Critical Infrastructure):
    - Uses Ollama for local, private analysis
    - No data leaves your infrastructure
    - Free, unlimited usage
    - Supports: Llama 3.1, Mistral, Qwen, DeepSeek, etc.
    
    **CLOUD OPTION** (Optional):
    - Uses Anthropic Claude API
    - Requires API key and costs money
    - Only use for non-sensitive data
    
    Provides:
    - Intelligent threat scoring
    - Context-aware analysis
    - Natural language summaries
    - Actionable recommendations
    """
    
    def __init__(self, config: Dict):
        """
        Initialize LLM analyzer.
        
        Args:
            config: Configuration dict
        """
        self.config = config
        
        # Determine LLM provider (local/cloud)
        llm_config = config.get('llm', {})
        self.provider = llm_config.get('provider', 'ollama')  # Default: local
        
        # Ollama settings
        self.ollama_endpoint = llm_config.get('ollama_endpoint', 'http://localhost:11434')
        self.ollama_model = llm_config.get('ollama_model', 'llama3.1:8b')
        
        # Anthropic settings (fallback)
        self.anthropic_key = config.get('api_keys', {}).get('anthropic', '')
        self.anthropic_model = 'claude-sonnet-4-20250514'
        
        self.timeout = aiohttp.ClientTimeout(total=120)  # Longer timeout for local LLM
        
        logger.info(f"[LLM] Provider: {self.provider} | Model: {self.ollama_model if self.provider == 'ollama' else self.anthropic_model}")
    
    async def analyze_ioc_results(self, ioc: str, ioc_type: str, results: Dict) -> Dict:
        """
        Analyze IOC investigation results using LLM.
        
        Args:
            ioc: The IOC investigated
            ioc_type: IOC type
            results: Investigation results from all sources
        
        Returns:
            LLM analysis with verdict and recommendations
        """
        try:
            # Prepare context for LLM
            context = self._prepare_ioc_context(ioc, ioc_type, results)
            
            # Build prompt
            sources_checked = results.get('sources_checked', 0)
            sources_flagged = results.get('sources_flagged', 0)
            
            # Build explicit findings summary
            if sources_flagged == 0:
                findings_summary = f"✅ **CLEAN**: This IOC was NOT flagged by any of the {sources_checked} sources checked. No malicious activity detected."
            elif sources_flagged == 1:
                findings_summary = f"⚠️ **SUSPICIOUS**: 1 out of {sources_checked} sources flagged this IOC."
            else:
                findings_summary = f"🚨 **MALICIOUS**: {sources_flagged} out of {sources_checked} sources flagged this IOC."
            
            prompt = f"""You are a senior SOC analyst at TAV Technologies specializing in aviation cybersecurity. 

Analyze this IOC investigation and provide a professional, actionable analysis:

IOC: {ioc}
Type: {ioc_type}
Threat Score: {results.get('threat_score', 0)}/100

**Investigation Summary:**
{findings_summary}
Sources Checked: {sources_checked}
Sources Flagged: {sources_flagged}

**Key Findings:**
{json.dumps(context.get('key_findings', []), indent=2)}

**IMPORTANT RULES:**
1. Your verdict MUST match the investigation findings
2. If sources_flagged = 0, verdict MUST be "CLEAN"
3. If sources_flagged = 1-2, verdict can be "SUSPICIOUS"  
4. If sources_flagged >= 3, verdict can be "MALICIOUS"
5. Do NOT hallucinate findings that don't exist
6. Base your analysis ONLY on the data provided above

Provide your analysis in a clear, professional format. Include:

1. **Threat Assessment** (2-3 sentences)
   - Summarize the investigation results accurately
   - State verdict (MUST match sources_flagged count)
   - Mention any specific findings from sources

2. **Recommendations** (3-5 actionable items)
   - If CLEAN: Monitoring/documentation actions
   - If SUSPICIOUS/MALICIOUS: Immediate actions for SOC team

Respond in JSON format:
{{
    "verdict": "MALICIOUS/SUSPICIOUS/CLEAN",
    "analysis": "Your professional analysis here (2-3 sentences). MUST be consistent with sources_flagged count.",
    "recommendations": ["rec1", "rec2", "rec3"]
}}

Keep it concise and factual."""
            
            # Call appropriate LLM provider
            if self.provider == 'ollama':
                response_data = await self._call_ollama_api(prompt)
            else:
                response_data = await self._call_anthropic_api(prompt)
            
            if response_data:
                return response_data
            else:
                return {'error': 'Failed to get LLM response', 'provider': self.provider}
        
        except Exception as e:
            logger.error(f"[LLM] Analysis failed: {e}")
            return {'error': str(e)}
    
    async def analyze_email(self, email_data: Dict) -> Dict:
        """
        Analyze email using LLM.
        
        Args:
            email_data: Parsed email data
        
        Returns:
            LLM analysis of email
        """
        try:
            # Prepare comprehensive context for LLM
            context = {
                'subject': email_data.get('subject', 'N/A'),
                'from': email_data.get('from', 'N/A'),
                'to': email_data.get('to', 'N/A'),
                'authentication': {
                    'spf': email_data.get('spf', 'N/A'),
                    'dkim': email_data.get('dkim', 'N/A'),
                    'dmarc': email_data.get('dmarc', 'N/A')
                },
                'header_anomalies': self._ensure_list(email_data.get('header_anomalies', [])),
                'link_mismatches': self._ensure_list(email_data.get('link_mismatches', [])),
                'lookalike_domains': self._ensure_list(email_data.get('lookalike_domains', [])),
                'html_obfuscation_score': email_data.get('html_obfuscation_score', 0),
                'qr_codes': self._ensure_list(email_data.get('qr_codes', [])),
                'brand_impersonation': self._ensure_list(email_data.get('brand_impersonation', [])),
                'ioc_summary': {
                    'total': email_data.get('ioc_count', 0),
                    'malicious': email_data.get('malicious_iocs', 0),
                    'malicious_urls': [u.get('ioc') for u in email_data.get('malicious_urls', [])[:3]],
                    'malicious_domains': [d.get('ioc') for d in email_data.get('malicious_domains', [])[:3]]
                },
                'attachment_summary': {
                    'total': email_data.get('attachment_count', 0),
                    'malicious': email_data.get('malicious_attachments', 0),
                    'malicious_files': [a.get('filename') for a in email_data.get('malicious_attachment_details', [])[:3]]
                },
                'base_score': email_data.get('base_score', 0),
                'composite_score': email_data.get('composite_score', 0)
            }
            
            prompt = f"""You are a SOC analyst at TAV Technologies specializing in email security and phishing detection.

Analyze this email investigation:

Subject: {context['subject']}
From: {context['from']}
To: {context['to']}

Authentication:
- SPF: {context['authentication']['spf']}
- DKIM: {context['authentication']['dkim']}
- DMARC: {context['authentication']['dmarc']}

Advanced Analysis Results:
- Header Anomalies: {len(context['header_anomalies'])}
- Link-Text Mismatches: {len(context['link_mismatches'])}
- Lookalike Domains: {len(context['lookalike_domains'])}
- HTML Obfuscation Score: {context['html_obfuscation_score']}/100
- QR Codes Detected: {len(context['qr_codes'])}
- Brand Impersonation: {len(context['brand_impersonation'])}

IOC Analysis:
- Total IOCs: {context['ioc_summary']['total']}
- Malicious: {context['ioc_summary']['malicious']}
{f"- Malicious URLs: {', '.join(context['ioc_summary']['malicious_urls'])}" if context['ioc_summary']['malicious_urls'] else ""}
{f"- Malicious Domains: {', '.join(context['ioc_summary']['malicious_domains'])}" if context['ioc_summary']['malicious_domains'] else ""}

Attachments:
- Total: {context['attachment_summary']['total']}
- Malicious: {context['attachment_summary']['malicious']}
{f"- Malicious Files: {', '.join(context['attachment_summary']['malicious_files'])}" if context['attachment_summary']['malicious_files'] else ""}

Scoring:
- Base Phishing Score: {context['base_score']}/100
- Composite Score: {context['composite_score']}/100

Based on the above tool analysis, provide your professional assessment in JSON format:
{{
    "verdict": "PHISHING/SPAM/SUSPICIOUS/CLEAN",
    "analysis": "Your concise analysis (2-3 sentences) explaining WHY this is phishing/spam/clean based on the tool findings. Reference specific detections (e.g., 'lookalike domain paypa1.com', 'malicious attachment detected', 'links to known C2 infrastructure').",
    "recommendations": [
        "Block sender domain immediately",
        "Hunt for similar emails in mail gateway",
        "Add IOCs to threat intel platform"
    ]
}}

Be specific and reference the tool findings in your analysis."""
            
            if self.provider == 'ollama':
                response_data = await self._call_ollama_api(prompt)
            else:
                response_data = await self._call_anthropic_api(prompt)
            
            return response_data if response_data else {'error': 'Failed to analyze'}
        
        except Exception as e:
            logger.error(f"[LLM] Email analysis failed: {e}")
            return {'error': str(e)}
    
    async def analyze_file(self, file_data: Dict) -> Dict:
        """
        Analyze file using LLM.
        
        Args:
            file_data: File analysis data
        
        Returns:
            LLM analysis of file
        """
        try:
            # Prepare comprehensive context for LLM
            context = {
                'filename': file_data.get('filename', 'N/A'),
                'file_type': file_data.get('file_type', 'N/A'),
                'size_bytes': file_data.get('size_bytes', 0),
                'sha256': file_data.get('sha256', 'N/A')[:64],
                'hash_score': file_data.get('hash_score', 0),
                'architecture': file_data.get('architecture', 'N/A'),
                'signed': file_data.get('signature', {}).get('signed', False),
                'packer': file_data.get('packer_detection', {}).get('packer', 'None'),
                'packer_confidence': file_data.get('packer_detection', {}).get('confidence', 'N/A'),
                'entropy': file_data.get('entropy', 0),
                'entropy_category': file_data.get('entropy_category', 'unknown'),
                'suspicious_sections': [
                    f"{s.get('name', 'Unknown')} (entropy: {s.get('entropy', 0):.2f})" 
                    for s in file_data.get('suspicious_sections', [])[:3]
                ],
                'suspicious_imports': [
                    f"{imp.get('dll', 'Unknown')}: {', '.join(imp.get('suspicious_apis', [])[:3])}"
                    for imp in file_data.get('suspicious_imports', [])[:3]
                ],
                'anti_analysis': file_data.get('anti_analysis', []),
                'string_categories': self._process_string_categories(file_data.get('string_categories', {})),
                'registry_keys': file_data.get('registry_keys', [])[:3],
                'mutexes': file_data.get('mutexes', [])[:3],
                'yara_matches': [
                    {
                        'rule': m.get('rule', 'Unknown'),
                        'severity': m.get('meta', {}).get('severity', 'UNKNOWN')
                    }
                    for m in (file_data.get('yara_matches', []) if isinstance(file_data.get('yara_matches'), list) else [])
                ],
                'yara_match_count': file_data.get('yara_matches') if isinstance(file_data.get('yara_matches'), int) else len(file_data.get('yara_matches', [])),
                'malware_families': file_data.get('yara_malware_families', []),
                'ioc_count': file_data.get('ioc_count', 0),
                'malicious_iocs': file_data.get('malicious_iocs', 0),
                'malicious_ips': [ip.get('ioc') for ip in (file_data.get('malicious_ips') or [])[:3] if isinstance(ip, dict)],
                'malicious_domains': [d.get('ioc') for d in (file_data.get('malicious_domains') or [])[:3] if isinstance(d, dict)],
                'composite_score': file_data.get('composite_score', 0)
            }
            
            # Check if this is a text file with C2/IOC data
            is_text_file = file_data.get('file_type') == 'text'

            if is_text_file and file_data.get('c2_patterns'):
                prompt = self._build_text_file_prompt(file_data, context)
            else:
                prompt = self._build_standard_file_prompt(file_data, context)

            if self.provider == 'ollama':
                response_data = await self._call_ollama_api(prompt)
            else:
                response_data = await self._call_anthropic_api(prompt)

            return response_data if response_data else {'error': 'Failed to analyze'}

        except Exception as e:
            logger.error(f"[LLM] File analysis failed: {e}")
            return {'error': str(e)}

    def _build_text_file_prompt(self, file_data: Dict, context: Dict) -> str:
        """Build LLM prompt for text files with C2/IOC indicators."""
        c2_patterns = file_data.get('c2_patterns', [])
        ip_addresses = file_data.get('ip_addresses', [])
        urls = file_data.get('urls', [])
        encoded = file_data.get('encoded_content', [])
        creds = file_data.get('credential_indicators', [])
        ioc_results = file_data.get('ioc_results', [])

        c2_section = ""
        if c2_patterns:
            c2_lines = []
            for p in c2_patterns[:10]:
                c2_lines.append(f"  - [{p.get('severity', 'unknown').upper()}] {p.get('description', '')} "
                               f"(MITRE: {p.get('mitre', 'N/A')}, matches: {p.get('match_count', 0)})")
            c2_section = "C2 Communication Patterns Found:\n" + chr(10).join(c2_lines)

        ip_section = ""
        suspicious_ips = [ip for ip in ip_addresses if ip.get('suspicious') and not ip.get('is_private')]
        external_ips = [ip for ip in ip_addresses if not ip.get('is_private')]
        if suspicious_ips:
            ip_lines = [f"  - {ip['ip']}" + (f":{ip['port']}" if ip.get('port') else '') +
                       f" ({', '.join(ip.get('reasons', []))})" for ip in suspicious_ips[:10]]
            ip_section = f"Suspicious External IPs ({len(suspicious_ips)}):\n" + chr(10).join(ip_lines)
        elif external_ips:
            ip_lines = [f"  - {ip['ip']}" + (f":{ip['port']}" if ip.get('port') else '') for ip in external_ips[:10]]
            ip_section = f"External IPs Found ({len(external_ips)}):\n" + chr(10).join(ip_lines)

        url_section = ""
        suspicious_urls = [u for u in urls if u.get('suspicious')]
        if suspicious_urls:
            url_lines = [f"  - {u['url'][:100]} ({', '.join(u.get('reasons', []))})" for u in suspicious_urls[:10]]
            url_section = f"Suspicious URLs ({len(suspicious_urls)}):\n" + chr(10).join(url_lines)

        ioc_section = ""
        if ioc_results:
            malicious = [r for r in ioc_results if r.get('verdict') == 'MALICIOUS']
            suspicious = [r for r in ioc_results if r.get('verdict') == 'SUSPICIOUS']
            ioc_section = f"IOC Investigation Results:\n  - Total investigated: {len(ioc_results)}\n"
            if malicious:
                ioc_section += f"  - MALICIOUS: {len(malicious)} IOCs\n"
                for r in malicious[:5]:
                    ioc_section += f"    - {r.get('ioc', 'N/A')} (score: {r.get('threat_score', 0)})\n"
            if suspicious:
                ioc_section += f"  - SUSPICIOUS: {len(suspicious)} IOCs\n"

        return f"""You are a SOC analyst performing threat intelligence analysis on a text file.
This file contains potential indicators of compromise (IOCs), C2 configuration data, or threat intelligence information.

File Information:
- Filename: {context['filename']}
- Type: Text File
- Size: {context['size_bytes']:,} bytes

{c2_section}

{ip_section}

{url_section}

{f"Encoded Content: {len(encoded)} encoded blocks detected" if encoded else ""}
{f"Credential Indicators: {len(creds)} potential credential leaks" if creds else ""}

{ioc_section}

Composite Score: {context['composite_score']}/100

Based on the above analysis, provide your professional threat assessment in JSON format:
{{
    "verdict": "MALICIOUS/SUSPICIOUS/CLEAN",
    "analysis": "Your concise analysis (2-3 sentences). Is this a C2 configuration file? A threat intelligence report? A malware sample output? A data exfiltration log? Explain what the IOCs indicate - are they known malicious infrastructure? What threat actor or campaign might be involved?",
    "recommendations": [
        "Block identified C2 IPs at firewall",
        "Hunt for connections to identified infrastructure in SIEM",
        "Check for lateral movement from affected systems",
        "Update threat intelligence feeds with extracted IOCs"
    ]
}}

Be specific and reference the actual IOC findings in your analysis."""

    def _build_standard_file_prompt(self, file_data: Dict, context: Dict) -> str:
        """Build standard LLM prompt for binary/script files."""
        return f"""You are a malware analyst at TAV Technologies. Analyze this file investigation:

File Information:
- Filename: {context['filename']}
- Type: {context['file_type']}
- Size: {context['size_bytes']:,} bytes
- SHA256: {context['sha256']}

Threat Intelligence:
- Hash Score: {context['hash_score']}/100

PE Analysis (if applicable):
- Architecture: {context['architecture']}
- Signed: {context['signed']}
- Packer: {context['packer']} ({context['packer_confidence']} confidence)
- Entropy: {context['entropy']:.2f} ({context['entropy_category']})
{f"- Suspicious Sections: {', '.join(context['suspicious_sections'])}" if context['suspicious_sections'] else ""}
{f"- Suspicious Imports: {chr(10).join(['  - ' + imp for imp in context['suspicious_imports']])}" if context['suspicious_imports'] else ""}
{f"- Anti-Analysis Techniques: {', '.join(context['anti_analysis'][:3])}" if context['anti_analysis'] else ""}

String Analysis:
{chr(10).join([f"- {cat}: {count} strings" for cat, count in context['string_categories'].items()]) if context['string_categories'] else "- No suspicious strings"}
{f"- Registry Keys: {', '.join(context['registry_keys'])}" if context['registry_keys'] else ""}
{f"- Mutexes: {', '.join(context['mutexes'])}" if context['mutexes'] else ""}

YARA Analysis:
- Matches: {len(context['yara_matches'])} rules
{chr(10).join([f"  - {m['rule']} ({m['severity']})" for m in context['yara_matches']]) if context['yara_matches'] else ""}
{f"- Identified Families: {', '.join(context['malware_families'])}" if context['malware_families'] else ""}

Embedded IOC Analysis:
- Total IOCs: {context['ioc_count']}
- Malicious: {context['malicious_iocs']}
{f"- Malicious IPs: {', '.join(context['malicious_ips'])}" if context['malicious_ips'] else ""}
{f"- Malicious Domains: {', '.join(context['malicious_domains'])}" if context['malicious_domains'] else ""}

Composite Score: {context['composite_score']}/100

Based on the above tool analysis, provide your professional assessment in JSON format:
{{
    "verdict": "MALICIOUS/SUSPICIOUS/CLEAN",
    "analysis": "Your concise analysis (2-3 sentences) explaining the malware behavior, family, and threat. Reference specific tool findings (e.g., 'QakBot detected via YARA', 'UPX packer with entropy 7.8', 'C2 communication to known infrastructure').",
    "recommendations": [
        "Isolate infected systems immediately",
        "Block C2 IPs/domains at firewall",
        "Hunt for mutex across network",
        "Check for registry key modifications"
    ]
}}

Be specific and reference the tool findings in your analysis."""
    
    async def _call_ollama_api(self, prompt: str) -> Optional[Dict]:
        """
        Call Ollama local LLM API.
        
        Args:
            prompt: Analysis prompt
        
        Returns:
            Parsed JSON response or None
        """
        try:
            logger.info(f"[LLM] Calling Ollama ({self.ollama_model})...")
            
            payload = {
                'model': self.ollama_model,
                'prompt': prompt,
                'stream': False,
                'format': 'json'  # Request JSON output
            }
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f'{self.ollama_endpoint}/api/generate',
                    json=payload
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        response_text = data.get('response', '')
                        
                        # Parse JSON from response
                        try:
                            return json.loads(response_text)
                        except json.JSONDecodeError:
                            # Try to extract JSON from markdown code blocks
                            import re
                            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response_text, re.DOTALL)
                            if json_match:
                                return json.loads(json_match.group(1))
                            
                            # Try to find JSON object in text
                            start = response_text.find('{')
                            end = response_text.rfind('}') + 1
                            if start >= 0 and end > start:
                                return json.loads(response_text[start:end])
                            
                            logger.warning(f"[LLM] Could not parse JSON from Ollama response")
                            return {'raw_response': response_text}
                    else:
                        body = await response.text()
                        logger.error(f"[LLM] Ollama API error {response.status}: {body[:200]}")
                        return None

        except aiohttp.ClientConnectorError:
            logger.error(
                f"[LLM] Cannot connect to Ollama at {self.ollama_endpoint}. "
                "Is Ollama running? Start it with: ollama serve"
            )
            return None
        except Exception as e:
            logger.error(f"[LLM] Ollama API call failed: {e}")
            return None
    
    async def _call_anthropic_api(self, prompt: str) -> Optional[Dict]:
        """
        Call Anthropic Claude API.
        
        Args:
            prompt: Analysis prompt
        
        Returns:
            Parsed JSON response or None
        """
        if not self.anthropic_key:
            logger.warning("[LLM] No Anthropic API key configured")
            return {'error': 'No Anthropic API key configured'}
        
        try:
            logger.info(f"[LLM] Calling Anthropic ({self.anthropic_model})...")
            
            headers = {
                'anthropic-version': '2023-06-01',
                'content-type': 'application/json',
                'x-api-key': self.anthropic_key
            }
            
            payload = {
                'model': self.anthropic_model,
                'max_tokens': 2000,
                'messages': [
                    {'role': 'user', 'content': prompt}
                ]
            }
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    'https://api.anthropic.com/v1/messages',
                    headers=headers,
                    json=payload
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        content = data.get('content', [])
                        
                        if content and content[0].get('type') == 'text':
                            text = content[0].get('text', '')
                            
                            # Extract JSON from response
                            try:
                                # Try to find JSON in response
                                start = text.find('{')
                                end = text.rfind('}') + 1
                                if start >= 0 and end > start:
                                    json_str = text[start:end]
                                    return json.loads(json_str)
                            except:
                                pass
                            
                            return {'raw_response': text}
                    else:
                        logger.error(f"[LLM] Anthropic API error: {response.status}")
                        return None
        
        except Exception as e:
            logger.error(f"[LLM] Anthropic API call failed: {e}")
            return None
    
    def _ensure_list(self, value) -> list:
        """
        Ensure value is a list.
        
        Args:
            value: Can be list, int, or anything
        
        Returns:
            List representation
        """
        if isinstance(value, list):
            return value
        elif isinstance(value, int):
            return []  # Empty list if it's a count
        elif value is None:
            return []
        else:
            return [value]
    
    def _process_string_categories(self, string_categories) -> Dict:
        """
        Process string_categories - handle both dict and list formats.
        
        Args:
            string_categories: Can be dict or list
        
        Returns:
            Dict with category counts
        """
        if isinstance(string_categories, dict):
            # Already dict, process normally
            return {
                cat: len(strings) if isinstance(strings, list) else strings
                for cat, strings in string_categories.items()
            }
        elif isinstance(string_categories, list):
            # List format, count categories
            from collections import Counter
            category_counts = Counter()
            for item in string_categories:
                if isinstance(item, dict) and 'category' in item:
                    category_counts[item['category']] += 1
            return dict(category_counts)
        else:
            return {}
    
    def _prepare_ioc_context(self, ioc: str, ioc_type: str, results: Dict) -> Dict:
        """Prepare investigation results for LLM context."""
        # Extract key findings
        context = {
            'ioc': ioc,
            'type': ioc_type,
            'threat_score': results.get('threat_score', 0),
            'sources_flagged': results.get('sources_flagged', 0),
            'key_findings': []
        }
        
        # Extract important findings from each source
        sources = results.get('sources', {})
        for source_name, source_data in sources.items():
            if source_data.get('status') == '✓':
                finding = {'source': source_name}
                
                # Add relevant data
                if 'botnet' in source_data:
                    finding['botnet'] = source_data['botnet']
                if 'malware' in source_data:
                    finding['malware'] = source_data['malware']
                if 'threat' in source_data:
                    finding['threat'] = source_data['threat']
                if 'detections' in source_data:
                    finding['detections'] = source_data['detections']
                
                context['key_findings'].append(finding)
        
        return context
    
    async def generate_detection_rules(self, analysis_result: Dict, rule_type: str = 'all') -> Dict:
        """
        Generate detection rules using LLM based on analysis results.
        
        Args:
            analysis_result: File or IOC analysis results
            rule_type: 'kql', 'sigma', 'yara', 'spl', or 'all'
        
        Returns:
            Dict with generated rules for each platform
        """
        try:
            # Extract relevant info
            ioc = analysis_result.get('ioc', '')
            ioc_type = analysis_result.get('ioc_type', '')
            filename = analysis_result.get('filename', '')
            sha256 = analysis_result.get('sha256', '')
            
            # Build context
            malware_families = analysis_result.get('malware_families', [])
            threat_score = analysis_result.get('threat_score', 0)
            suspicious_strings = analysis_result.get('suspicious_strings', [])
            registry_keys = analysis_result.get('registry_keys', [])
            
            # Construct prompt
            prompt = f"""You are a detection engineer at TAV Technologies. Generate detection rules based on this analysis.

Analysis Context:
- IOC: {ioc or filename or sha256}
- Type: {ioc_type or 'file'}
- Threat Score: {threat_score}/100
- Malware Families: {', '.join(malware_families) if malware_families else 'Unknown'}
- Suspicious Strings: {', '.join(suspicious_strings[:5]) if suspicious_strings else 'None'}
- Registry Keys: {', '.join(registry_keys[:3]) if registry_keys else 'None'}

Generate detection rules in JSON format:
{{
    "kql": "Full KQL query for Microsoft Defender/Sentinel",
    "sigma": "YAML SIGMA rule",
    "yara": "YARA rule with strings and conditions",
    "spl": "Splunk SPL query"
}}

Make rules specific to the threat indicators found. Include:
- Proper escaping
- Meaningful rule names
- Detection logic based on actual findings
- Comments explaining the detection"""

            # Call LLM
            if self.provider == 'ollama':
                response_data = await self._call_ollama_api(prompt)
            else:
                response_data = await self._call_anthropic_api(prompt)
            
            if response_data:
                return response_data
            else:
                # Fallback to basic rules
                return self._generate_basic_rules(analysis_result)
        
        except Exception as e:
            logger.error(f"[LLM] Rule generation failed: {e}")
            return self._generate_basic_rules(analysis_result)
    
    def _generate_basic_rules(self, analysis_result: Dict) -> Dict:
        """Generate basic rules as fallback."""
        ioc = analysis_result.get('ioc', '')
        ioc_type = analysis_result.get('ioc_type', 'unknown')
        
        rules = {
            'kql': f'DeviceNetworkEvents | where RemoteIP == "{ioc}" or RemoteUrl has "{ioc}"',
            'sigma': f"""title: IOC Detection - {ioc}
detection:
  selection:
    DestinationIp|contains: '{ioc}'
  condition: selection""",
            'yara': f'''rule IOC_Detection {{
    strings:
        $ioc = "{ioc}"
    condition:
        $ioc
}}''',
            'spl': f'index=* ("{ioc}")'
        }
        
        return rules
