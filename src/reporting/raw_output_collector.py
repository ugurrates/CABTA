"""
Author: Ugur Ates
Raw Output Collector for Blue Team Assistant
Captures ALL analysis outputs in raw format for comprehensive reporting.
"""

from typing import Dict, List, Any
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)
class RawOutputCollector:
    """
    Collects ALL analysis outputs in RAW format.
    This data is used to populate comprehensive HTML reports.
    """
    
    def __init__(self):
        self.raw_data = {
            'analysis_start': datetime.now().isoformat(),
            'analysis_end': None,
            'file_analysis': {},
            'email_analysis': {},
            'ioc_analysis': {},
            'api_responses': {},
            'detection_rules': {},
            'scoring_details': {},
            'pipeline_steps': [],
            'errors': []
        }
        logger.info("[RAW] RawOutputCollector initialized")
    
    # ==================== FILE ANALYSIS CAPTURES ====================
    
    def capture_hash_output(self, hashes: Dict):
        """Capture hash calculation raw output."""
        self.raw_data['file_analysis']['hashes'] = {
            'md5': hashes.get('md5', ''),
            'sha1': hashes.get('sha1', ''),
            'sha256': hashes.get('sha256', ''),
            'ssdeep': hashes.get('ssdeep', ''),
            'imphash': hashes.get('imphash', ''),
            'timestamp': datetime.now().isoformat()
        }
    
    def capture_file_info(self, file_info: Dict):
        """Capture file metadata."""
        self.raw_data['file_analysis']['file_info'] = {
            'name': file_info.get('name', ''),
            'size': file_info.get('size', 0),
            'size_mb': file_info.get('size_mb', 0),
            'extension': file_info.get('extension', ''),
            'mime_type': file_info.get('mime_type', ''),
        }
    
    def capture_pe_analysis(self, pe_info: Dict):
        """Capture PE header analysis raw output."""
        self.raw_data['file_analysis']['pe_header'] = {
            'machine': pe_info.get('machine', pe_info.get('architecture', '')),
            'compilation_timestamp': pe_info.get('timestamp', pe_info.get('compile_time', '')),
            'subsystem': pe_info.get('subsystem', ''),
            'entry_point': pe_info.get('entry_point', ''),
            'image_base': pe_info.get('image_base', ''),
            'pe_type': pe_info.get('pe_type', ''),
            'sections': pe_info.get('sections', []),
            'imports': pe_info.get('imports', []),
            'exports': pe_info.get('exports', []),
            'signature': pe_info.get('signature', {}),
        }
    
    def capture_strings_output(self, strings: Dict):
        """Capture string extraction raw output."""
        self.raw_data['file_analysis']['strings'] = {
            'total_count': strings.get('total_strings', len(strings.get('all', []))),
            'ascii_count': strings.get('ascii_strings', len(strings.get('ascii', []))),
            'unicode_count': strings.get('unicode_strings', len(strings.get('unicode', []))),
            'urls': strings.get('urls', []),
            'ips': strings.get('ips', []),
            'emails': strings.get('emails', []),
            'registry': strings.get('registry_keys', strings.get('registry', [])),
            'paths': strings.get('file_paths', strings.get('paths', [])),
            'mutexes': strings.get('mutexes', []),
            'suspicious': strings.get('suspicious_strings', strings.get('suspicious', [])),
            'interesting': strings.get('interesting_strings', []),
            'categories': strings.get('suspicious_categories', {}),
        }
    
    def capture_yara_output(self, yara_results: Dict):
        """Capture YARA scanning raw output."""
        self.raw_data['file_analysis']['yara'] = {
            'total_matches': len(yara_results.get('matches', [])),
            'matched_rules': yara_results.get('matches', []),
            'malware_families': yara_results.get('interpretation', {}).get('malware_families', []),
            'tags': yara_results.get('interpretation', {}).get('tags', []),
        }
    
    def capture_entropy_analysis(self, entropy: Dict):
        """Capture entropy analysis raw output."""
      
        # Structure 1: {'file_entropy': {'overall_entropy': X}}
        # Structure 2: {'overall_entropy': X}
        if 'file_entropy' in entropy:
            overall = entropy['file_entropy'].get('overall_entropy', 0)
            category = entropy['file_entropy'].get('interpretation', {}).get('category', 'unknown')
        else:
            overall = entropy.get('overall_entropy', entropy.get('overall', 0))
            category = entropy.get('interpretation', {}).get('category', 'unknown')
        
        self.raw_data['file_analysis']['entropy'] = {
            'overall': overall,
            'is_packed': overall > 7.0,
            'category': category,
            'sections': entropy.get('sections', entropy.get('chunk_analysis', {})),
        }
    
    def capture_static_analysis(self, static: Dict):
        """Capture full static analysis output."""
        self.raw_data['file_analysis']['static_analysis'] = static
    
    def capture_tool_output(self, tool_name: str, output: Dict):
        """
        Generic capture method for tool outputs.
        
        v1.0.0: Added to support multiple tool integrations.
        
        Args:
            tool_name: Name of the tool (e.g., 'capa', 'floss', 'diec', 'binwalk', 'entropy')
            output: Tool output dictionary
        """
        if 'tool_outputs' not in self.raw_data['file_analysis']:
            self.raw_data['file_analysis']['tool_outputs'] = {}
        
        self.raw_data['file_analysis']['tool_outputs'][tool_name] = output
        
        # Also update specific sections if applicable
        if tool_name == 'entropy':
            self.capture_entropy_analysis(output)
    
    # ==================== EMAIL ANALYSIS CAPTURES ====================
    
    def capture_email_headers(self, headers: Dict):
        """Capture email header raw output."""
        to_val = headers.get('to', '')
        self.raw_data['email_analysis']['headers'] = {
            'from': headers.get('from', ''),
            'to': to_val if isinstance(to_val, list) else [to_val] if to_val else [],
            'cc': headers.get('cc', []),
            'bcc': headers.get('bcc', []),
            'subject': headers.get('subject', ''),
            'date': headers.get('date', ''),
            'message_id': headers.get('message_id', ''),
            'reply_to': headers.get('reply_to', ''),
            'return_path': headers.get('return_path', ''),
            'received_chain': headers.get('received', headers.get('received_chain', [])),
            'x_headers': headers.get('x_headers', {}),
        }
    
    def capture_authentication_results(self, auth: Dict):
        """Capture SPF/DKIM/DMARC raw output."""
        spf = auth.get('spf', auth.get('spf_result', 'none'))
        dkim = auth.get('dkim', auth.get('dkim_result', 'none'))
        dmarc = auth.get('dmarc', auth.get('dmarc_result', 'none'))
        
        self.raw_data['email_analysis']['authentication'] = {
            'spf': {'result': spf, 'record': auth.get('spf_record', ''), 'ip': auth.get('spf_ip', '')},
            'dkim': {'result': dkim, 'selector': auth.get('dkim_selector', ''), 'domain': auth.get('dkim_domain', '')},
            'dmarc': {'result': dmarc, 'policy': auth.get('dmarc_policy', ''), 'record': auth.get('dmarc_record', '')},
            'overall_pass': str(spf).lower() == 'pass' and str(dkim).lower() == 'pass' and str(dmarc).lower() == 'pass'
        }
    
    def capture_email_content(self, content: Dict):
        """Capture email body content raw output."""
        self.raw_data['email_analysis']['content'] = {
            'body_text': (content.get('body_text', content.get('text', '')) or '')[:2000],
            'has_html': bool(content.get('body_html', content.get('html', ''))),
            'urls': content.get('urls', []),
            'suspicious_keywords': content.get('suspicious_keywords', []),
            'urgency_indicators': content.get('urgency', content.get('urgency_indicators', [])),
        }
    
    def capture_email_attachments(self, attachments: List[Dict]):
        """Capture email attachment raw output."""
        self.raw_data['email_analysis']['attachments'] = {
            'count': len(attachments),
            'details': attachments,
            'suspicious': [a for a in attachments if a.get('suspicious', False)],
        }
    
    def capture_advanced_analysis(self, advanced: Dict):
        """Capture advanced email analysis output."""
        self.raw_data['email_analysis']['advanced'] = advanced
    
    def capture_forensics(self, forensics: Dict):
        """Capture forensics analysis output."""
        self.raw_data['email_analysis']['forensics'] = forensics
    
    # Alias for compatibility
    def capture_forensics_results(self, forensics: Dict):
        """Alias for capture_forensics."""
        self.capture_forensics(forensics)
    
    # ==================== IOC ANALYSIS CAPTURES ====================
    
    def capture_ioc_results(self, iocs: List[Dict]):
        """Capture IOC analysis results raw output."""
        by_type = {}
        by_verdict = {}
        
        for ioc in iocs:
            ioc_type = ioc.get('type', ioc.get('ioc_type', 'unknown'))
            verdict = ioc.get('verdict', 'UNKNOWN')
            
            if ioc_type not in by_type:
                by_type[ioc_type] = []
            by_type[ioc_type].append(ioc)
            
            if verdict not in by_verdict:
                by_verdict[verdict] = []
            by_verdict[verdict].append(ioc)
        
        self.raw_data['ioc_analysis'] = {
            'total_iocs': len(iocs),
            'malicious_iocs': len(by_verdict.get('MALICIOUS', [])),
            'suspicious_iocs': len(by_verdict.get('SUSPICIOUS', [])),
            'clean_iocs': len(by_verdict.get('CLEAN', [])),
            'by_type': by_type,
            'by_verdict': by_verdict,
            'results': iocs,
        }
    
    # ==================== API RESPONSE CAPTURES ====================
    
    def capture_api_response(self, source: str, response: Dict):
        """Capture API response raw output."""
        self.raw_data['api_responses'][source] = {
            'timestamp': datetime.now().isoformat(),
            'response': response,
            'status': 'success' if response else 'empty'
        }
    
    # ==================== SCORING & RULES CAPTURES ====================
    
    def capture_scoring_details(self, scoring: Dict):
        """Capture scoring breakdown raw output."""
        self.raw_data['scoring_details'] = {
            'composite_score': scoring.get('composite_score', 0),
            'verdict': scoring.get('verdict', 'UNKNOWN'),
            'confidence': scoring.get('confidence', 85),
            'breakdown': scoring.get('breakdown', {}),
        }
    
    def capture_detection_rules(self, rules: Dict):
        """Capture detection rules raw output."""
        self.raw_data['detection_rules'] = rules
    
    # ==================== PIPELINE CAPTURES ====================
    
    def add_pipeline_step(self, phase: str, step: str, status: str, duration_ms: float = 0, output: Any = None):
        """Add a pipeline step record."""
        self.raw_data['pipeline_steps'].append({
            'phase': phase,
            'step': step,
            'status': status,
            'duration_ms': duration_ms,
            'output_preview': str(output)[:200] if output else None,
        })
    
    def add_error(self, step: str, error: str):
        """Add an error record."""
        self.raw_data['errors'].append({
            'step': step,
            'error': str(error),
            'timestamp': datetime.now().isoformat()
        })
    
    # Alias for compatibility
    def record_pipeline_step(self, phase: str, step: str, status: str, duration_ms: float = 0, output: Any = None):
        """Alias for add_pipeline_step (compatibility)."""
        self.add_pipeline_step(phase, step, status, duration_ms, output)
    
    def capture_sandbox_results(self, sandbox: Dict):
        """Capture sandbox analysis results."""
        self.raw_data['file_analysis']['sandbox'] = sandbox
    
    def finalize(self):
        """Finalize the raw data collection."""
        self.raw_data['analysis_end'] = datetime.now().isoformat()
    
    # ==================== OUTPUT METHODS ====================
    
    def get_all_raw_data(self) -> Dict:
        """Get all raw data."""
        self.raw_data['analysis_end'] = datetime.now().isoformat()
        return self.raw_data
    
    def to_json(self) -> str:
        """Export as JSON string."""
        return json.dumps(self.get_all_raw_data(), indent=2, default=str)
