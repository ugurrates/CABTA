"""
Author: Ugur Ates
Comprehensive HTML Report Generator for Blue Team Assistant
Blue Team Assistant v1.0.0

Generates:
- File Analysis Reports: 14 Sections
- Email Analysis Reports: 12 Sections  
- IOC Investigation Reports: Full source analysis
"""

from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import json
import html as html_lib
import logging

logger = logging.getLogger(__name__)
class HTMLReportGenerator:
    """Generate comprehensive HTML reports with ALL analysis data."""
    
    @staticmethod
    def _escape(text: Any) -> str:
        """Safely escape HTML."""
        if text is None:
            return 'N/A'
        return html_lib.escape(str(text))
    
    @staticmethod
    def _get_css() -> str:
        """Return comprehensive CSS styles."""
        return """
:root {
    --bg-primary: #ffffff;
    --bg-secondary: #f8f9fa;
    --bg-tertiary: #e9ecef;
    --text-primary: #212529;
    --text-secondary: #6c757d;
    --border-color: #dee2e6;
}
[data-theme="dark"] {
    --bg-primary: #1a1d23;
    --bg-secondary: #242831;
    --bg-tertiary: #2d323e;
    --text-primary: #e9ecef;
    --text-secondary: #adb5bd;
    --border-color: #495057;
}
* { transition: background-color 0.3s, color 0.3s; }
body {
    background-color: var(--bg-primary);
    color: var(--text-primary);
    font-family: 'Segoe UI', Tahoma, sans-serif;
    margin: 0;
    padding: 0;
}
.container { max-width: 1400px; margin: 0 auto; padding: 20px; }
.card {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    margin-bottom: 20px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}
.card-header {
    background: var(--bg-tertiary);
    padding: 15px 20px;
    border-bottom: 1px solid var(--border-color);
    border-radius: 8px 8px 0 0;
}
.card-header h4 { margin: 0; }
.card-body { padding: 20px; }
.table {
    width: 100%;
    border-collapse: collapse;
    color: var(--text-primary);
}
.table th, .table td {
    padding: 10px;
    border: 1px solid var(--border-color);
    text-align: left;
}
.table th { background: var(--bg-tertiary); }
.table-striped tbody tr:nth-child(odd) { background: var(--bg-tertiary); }
.badge {
    display: inline-block;
    padding: 5px 12px;
    border-radius: 4px;
    font-weight: bold;
    color: white;
}
.badge-danger, .bg-danger { background: #dc3545; }
.badge-warning, .bg-warning { background: #ffc107; color: #212529; }
.badge-success, .bg-success { background: #28a745; }
.badge-secondary, .bg-secondary { background: #6c757d; }
.badge-primary, .bg-primary { background: #007bff; }
.badge-info, .bg-info { background: #17a2b8; }
.text-danger { color: #dc3545; }
.text-warning { color: #ffc107; }
.text-success { color: #28a745; }
.text-muted { color: var(--text-secondary); }
.alert {
    padding: 15px;
    border-radius: 4px;
    margin-bottom: 15px;
}
.alert-danger { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
.alert-warning { background: #fff3cd; border: 1px solid #ffeeba; color: #856404; }
.alert-success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
.alert-info { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }
pre, code {
    background: var(--bg-tertiary);
    padding: 2px 6px;
    border-radius: 4px;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 13px;
    word-break: break-all;
}
pre {
    padding: 15px;
    overflow-x: auto;
    max-height: 400px;
    border: 1px solid var(--border-color);
}
.report-header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 30px;
    text-align: center;
    margin-bottom: 30px;
}
.report-header.file-header { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
.report-header.email-header { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
.report-header.ioc-header { background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }
.report-header h1 { margin: 0 0 10px 0; font-size: 2em; }
.report-header h3 { margin: 0; font-weight: normal; opacity: 0.9; }
.score-box {
    display: inline-block;
    padding: 20px 30px;
    border-radius: 10px;
    text-align: center;
    margin: 10px;
}
.score-box h2 { margin: 0; font-size: 2.5em; }
.score-box p { margin: 5px 0 0 0; opacity: 0.8; }
.score-critical { background: #dc3545; color: white; }
.score-high { background: #fd7e14; color: white; }
.score-medium { background: #ffc107; color: #212529; }
.score-low { background: #28a745; color: white; }
.progress {
    height: 25px;
    background: var(--bg-tertiary);
    border-radius: 4px;
    overflow: hidden;
}
.progress-bar {
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-weight: bold;
}
.row { display: flex; flex-wrap: wrap; margin: -10px; }
.col { flex: 1; padding: 10px; min-width: 250px; }
.col-4 { flex: 0 0 33.333%; }
.col-6 { flex: 0 0 50%; }
.col-12 { flex: 0 0 100%; }
.text-center { text-align: center; }
.mb-3 { margin-bottom: 15px; }
.mt-3 { margin-top: 15px; }
.me-2 { margin-right: 10px; }
.accordion-item { border: 1px solid var(--border-color); margin-bottom: -1px; }
.accordion-header { margin: 0; }
.accordion-button {
    width: 100%;
    padding: 15px;
    background: var(--bg-tertiary);
    border: none;
    text-align: left;
    cursor: pointer;
    font-size: 16px;
    color: var(--text-primary);
}
.accordion-button:hover { background: var(--border-color); }
.accordion-body { padding: 15px; display: none; }
.accordion-body.show { display: block; }
.btn {
    display: inline-block;
    padding: 8px 16px;
    border-radius: 4px;
    border: none;
    cursor: pointer;
    font-size: 14px;
    text-decoration: none;
}
.btn-primary { background: #007bff; color: white; }
.btn-secondary { background: #6c757d; color: white; }
.btn-outline-primary { background: transparent; border: 1px solid #007bff; color: #007bff; }
.btn-outline-secondary { background: transparent; border: 1px solid #6c757d; color: #6c757d; }
.btn:hover { opacity: 0.8; }
.theme-toggle {
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 1000;
    width: 50px;
    height: 50px;
    border-radius: 50%;
    background: var(--bg-secondary);
    border: 2px solid var(--border-color);
    font-size: 24px;
    cursor: pointer;
}
.sandbox-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; }
.sandbox-link {
    display: block;
    padding: 15px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    text-align: center;
    text-decoration: none;
    color: var(--text-primary);
}
.sandbox-link:hover { background: var(--border-color); }
@media print {
    .theme-toggle, .btn, .no-print { display: none !important; }
    .card { break-inside: avoid; }
}
"""
    
    @staticmethod
    def _get_js(raw_data: Dict = None) -> str:
        """Return JavaScript for interactivity."""
        raw_json = json.dumps(raw_data or {}, default=str).replace('</script>', '<\\/script>')
        return f"""
const rawData = {raw_json};

function toggleTheme() {{
    const body = document.body;
    const theme = body.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    body.setAttribute('data-theme', theme);
    document.querySelector('.theme-toggle').textContent = theme === 'dark' ? '☀️' : '🌙';
    localStorage.setItem('theme', theme);
}}

// Load saved theme
document.addEventListener('DOMContentLoaded', function() {{
    const saved = localStorage.getItem('theme') || 'light';
    document.body.setAttribute('data-theme', saved);
    const toggle = document.querySelector('.theme-toggle');
    if (toggle) toggle.textContent = saved === 'dark' ? '☀️' : '🌙';
}});

function toggleAccordion(id) {{
    const body = document.getElementById(id);
    if (body) {{
        body.classList.toggle('show');
    }}
}}

function copyToClipboard(elementId) {{
    const el = document.getElementById(elementId);
    if (el) {{
        const pre = el.querySelector('pre');
        if (pre) {{
            navigator.clipboard.writeText(pre.textContent);
            alert('Copied to clipboard!');
        }}
    }}
}}

function downloadJSON() {{
    const blob = new Blob([JSON.stringify(rawData, null, 2)], {{type: 'application/json'}});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'analysis_data.json';
    a.click();
    URL.revokeObjectURL(url);
}}
"""

    # ==================== FILE REPORT - 14 SECTIONS ====================
    
    def generate_file_report(self, result: Dict, filename: str, output_path: str) -> str:
        """Generate comprehensive file analysis HTML report with 14 sections."""
        try:
            e = self._escape
            
            # Extract all data
            verdict = result.get('verdict', 'UNKNOWN')
            composite_score = result.get('composite_score', 0)
            hash_score = result.get('hash_score', 0)
            hashes = result.get('hashes', {})
            file_info = result.get('file_info', {})
            static_analysis = result.get('static_analysis', {})
            string_analysis = result.get('string_analysis', {})
            yara_analysis = result.get('yara_analysis', {})
            ioc_analysis = result.get('ioc_analysis', {})
            detection_rules = result.get('detection_rules', {})
            llm_analysis = result.get('llm_analysis', {})
            raw_output = result.get('raw_output', {})
            mitre_mapping = result.get('mitre_mapping', [])
            
          
            if not mitre_mapping:
                sandbox = result.get('sandbox_analysis', {})
                sandbox_summary = sandbox.get('summary', {})
                sandbox_mitre = sandbox_summary.get('mitre_techniques', [])
                if sandbox_mitre:
                    mitre_mapping = [{'technique_id': t, 'source': 'sandbox', 'confidence': 'high'} for t in sandbox_mitre]
            
            # Score styling
            score_class = 'score-critical' if composite_score >= 80 else 'score-high' if composite_score >= 60 else 'score-medium' if composite_score >= 30 else 'score-low'
            verdict_class = 'danger' if verdict == 'MALICIOUS' else 'warning' if verdict == 'SUSPICIOUS' else 'success'
            
            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Analysis Report - {e(filename)}</title>
    <style>{self._get_css()}</style>
</head>
<body>
    <button class="theme-toggle" onclick="toggleTheme()">🌙</button>
    
    <div class="report-header file-header">
        <h1>🔬 MALWARE ANALYSIS REPORT</h1>
        <h3>{e(filename)}</h3>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Blue Team Assistant.0</p>
    </div>
    
    <div class="container">
        <!-- SECTION 1: EXECUTIVE SUMMARY -->
        <div class="card">
            <div class="card-header bg-{verdict_class}"><h4>📊 SECTION 1: EXECUTIVE SUMMARY</h4></div>
            <div class="card-body">
                <div class="row text-center">
                    <div class="col">
                        <div class="score-box {score_class}">
                            <h2>{composite_score}/100</h2>
                            <p>Composite Score</p>
                        </div>
                    </div>
                    <div class="col">
                        <div class="score-box bg-{verdict_class}" style="color:white;">
                            <h2>{verdict}</h2>
                            <p>Verdict</p>
                        </div>
                    </div>
                    <div class="col">
                        <div class="score-box {'score-high' if hash_score > 50 else 'score-low'}">
                            <h2>{hash_score}/100</h2>
                            <p>Hash Score</p>
                        </div>
                    </div>
                </div>
                {self._render_malware_families(yara_analysis)}
            </div>
        </div>
        
        <!-- SECTION 2: FILE METADATA -->
        <div class="card">
            <div class="card-header"><h4>📁 SECTION 2: FILE METADATA</h4></div>
            <div class="card-body">
                <div class="row">
                    <div class="col-6">
                        <table class="table">
                            <tr><th>File Name</th><td>{e(file_info.get('name', filename))}</td></tr>
                            <tr><th>File Size</th><td>{file_info.get('size', 0):,} bytes ({file_info.get('size_mb', 0):.2f} MB)</td></tr>
                            <tr><th>File Type</th><td>{e(file_info.get('extension', 'Unknown'))}</td></tr>
                            <tr><th>MIME Type</th><td>{e(file_info.get('mime_type', 'Unknown'))}</td></tr>
                        </table>
                    </div>
                    <div class="col-6">
                        <h5>Hash Values</h5>
                        <table class="table">
                            <tr><th>MD5</th><td><code>{e(hashes.get('md5', 'N/A'))}</code></td></tr>
                            <tr><th>SHA1</th><td><code>{e(hashes.get('sha1', 'N/A'))}</code></td></tr>
                            <tr><th>SHA256</th><td><code style="font-size:11px;">{e(hashes.get('sha256', 'N/A'))}</code></td></tr>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- SECTION 3: STATIC ANALYSIS (PE or Script) -->
        {self._render_script_section(static_analysis)}
        {self._render_pe_section(static_analysis)}
        
        <!-- SECTION 4: STRING ANALYSIS -->
        {self._render_strings_section(string_analysis, raw_output)}
        
        <!-- SECTION 5: YARA ANALYSIS -->
        {self._render_yara_section(yara_analysis)}
        
        <!-- SECTION 6: ENTROPY ANALYSIS -->
        {self._render_entropy_section(result)}
        
        <!-- SECTION 7: IOC ANALYSIS -->
        {self._render_ioc_section(ioc_analysis, 'SECTION 7')}
        
        <!-- SECTION 8: MITRE ATT&CK MAPPING -->
        {self._render_mitre_section(mitre_mapping)}
        
        <!-- SECTION 9: DETECTION RULES -->
        {self._render_detection_rules_section(detection_rules, 'SECTION 9')}
        
        <!-- SECTION 10: AI ANALYSIS -->
        {self._render_ai_section(llm_analysis, 'SECTION 10')}
        
        <!-- SECTION 11: SCORING BREAKDOWN -->
        {self._render_scoring_section(result, raw_output, 'SECTION 11')}
        
        <!-- SECTION 12: SANDBOX LINKS -->
        {self._render_sandbox_section(hashes)}
        
        <!-- SECTION 13: RECOMMENDATIONS -->
        {self._render_file_recommendations(result)}
        
        <!-- SECTION 14: RAW DATA -->
        {self._render_raw_data_section(raw_output, 'SECTION 14')}
        
        <div class="text-center mt-3 no-print">
            <button class="btn btn-primary me-2" onclick="window.print()">🖨️ Print Report</button>
            <button class="btn btn-secondary" onclick="downloadJSON()">💾 Download JSON</button>
        </div>
    </div>
    
    <script>{self._get_js(raw_output)}</script>
</body>
</html>"""
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
            
            logger.info(f"[REPORT] File report saved: {output_path}")
            return output_path
            
        except Exception as ex:
            logger.error(f"[REPORT] Failed to generate file report: {ex}", exc_info=True)
            return None

    # ==================== EMAIL REPORT - 12 SECTIONS ====================
    
    def generate_email_report(self, result: Dict, email_path: str, output_path: str) -> str:
        """Generate comprehensive email analysis HTML report with 12 sections."""
        try:
            e = self._escape
            
            verdict = result.get('verdict', 'UNKNOWN')
            composite_score = result.get('composite_score', 0)
            forensics_score = result.get('forensics_score', result.get('forensics', {}).get('forensics_score', 0))
            email_data = result.get('email_data', {})
            advanced = result.get('advanced_analysis', {})
            forensics = result.get('forensics', {})
            ioc_analysis = result.get('ioc_analysis', {})
            detection_rules = result.get('detection_rules', {})
            llm_analysis = result.get('llm_analysis', {})
            raw_output = result.get('raw_output', {})
            
            score_class = 'score-critical' if composite_score >= 80 else 'score-high' if composite_score >= 60 else 'score-medium' if composite_score >= 30 else 'score-low'
            verdict_class = 'danger' if verdict in ['MALICIOUS', 'PHISHING'] else 'warning' if verdict in ['SUSPICIOUS', 'SPAM'] else 'success'
            
            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Analysis Report</title>
    <style>{self._get_css()}</style>
</head>
<body>
    <button class="theme-toggle" onclick="toggleTheme()">🌙</button>
    
    <div class="report-header email-header">
        <h1>📧 EMAIL FORENSIC ANALYSIS REPORT</h1>
        <h3>Subject: {e(email_data.get('subject', 'Unknown'))[:80]}</h3>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Blue Team Assistant.0</p>
    </div>
    
    <div class="container">
        <!-- SECTION 1: EXECUTIVE SUMMARY -->
        <div class="card">
            <div class="card-header bg-{verdict_class}"><h4>📊 SECTION 1: EXECUTIVE SUMMARY</h4></div>
            <div class="card-body">
                <div class="row text-center">
                    <div class="col">
                        <div class="score-box {score_class}">
                            <h2>{composite_score}/100</h2>
                            <p>Composite Score</p>
                        </div>
                    </div>
                    <div class="col">
                        <div class="score-box bg-{verdict_class}" style="color:white;">
                            <h2>{verdict}</h2>
                            <p>Verdict</p>
                        </div>
                    </div>
                    <div class="col">
                        <div class="score-box {'score-high' if forensics_score > 50 else 'score-low'}">
                            <h2>{forensics_score}/100</h2>
                            <p>Forensics Score</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- SECTION 2: EMAIL HEADERS -->
        {self._render_email_headers_section(email_data, advanced)}
        
        <!-- SECTION 3: RECEIVED CHAIN -->
        {self._render_received_chain_section(email_data, raw_output)}
        
        <!-- SECTION 4: X-HEADERS -->
        {self._render_x_headers_section(email_data, raw_output)}
        
        <!-- SECTION 5: AUTHENTICATION -->
        {self._render_auth_section(email_data, raw_output)}
        
        <!-- SECTION 6: CONTENT ANALYSIS -->
        {self._render_content_section(email_data, advanced)}
        
        <!-- SECTION 7: URL ANALYSIS -->
        {self._render_url_section(email_data, advanced)}
        
        <!-- SECTION 8: ATTACHMENTS -->
        {self._render_attachments_section(email_data)}
        
        <!-- SECTION 9: IOC ANALYSIS -->
        {self._render_ioc_section(ioc_analysis, 'SECTION 9')}
        
        <!-- SECTION 10: DETECTION RULES -->
        {self._render_detection_rules_section(detection_rules, 'SECTION 10')}
        
        <!-- SECTION 11: SCORING & VERDICT -->
        {self._render_scoring_section(result, raw_output, 'SECTION 11')}
        
        <!-- SECTION 12: RECOMMENDATIONS -->
        {self._render_email_recommendations(result)}
        
        <!-- RAW DATA -->
        {self._render_raw_data_section(raw_output, 'RAW DATA')}
        
        <div class="text-center mt-3 no-print">
            <button class="btn btn-primary me-2" onclick="window.print()">🖨️ Print Report</button>
            <button class="btn btn-secondary" onclick="downloadJSON()">💾 Download JSON</button>
        </div>
    </div>
    
    <script>{self._get_js(raw_output)}</script>
</body>
</html>"""
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
            
            logger.info(f"[REPORT] Email report saved: {output_path}")
            return output_path
            
        except Exception as ex:
            logger.error(f"[REPORT] Failed to generate email report: {ex}", exc_info=True)
            return None

    # ==================== IOC REPORT ====================
    
    def generate_ioc_report(self, result: Dict, ioc: str, output_path: str) -> str:
        """Generate comprehensive IOC investigation HTML report."""
        try:
            e = self._escape
            
            verdict = result.get('verdict', 'UNKNOWN')
            threat_score = result.get('threat_score', 0)
            ioc_type = result.get('ioc_type', 'unknown')
            sources = result.get('sources', {}) or result.get('threat_intelligence', {}).get('sources', {})
            detection_rules = result.get('detection_rules', {})
            
            score_class = 'score-critical' if threat_score >= 80 else 'score-high' if threat_score >= 60 else 'score-medium' if threat_score >= 30 else 'score-low'
            verdict_class = 'danger' if verdict == 'MALICIOUS' else 'warning' if verdict == 'SUSPICIOUS' else 'success'
            
            # Count flagged sources
            flagged = sum(1 for s, info in sources.items() if isinstance(info, dict) and (info.get('found') or info.get('malicious') or info.get('status') in ['✓', '✓ FLAGGED', 'FLAGGED']))
            
            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IOC Investigation Report - {e(ioc)}</title>
    <style>{self._get_css()}</style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
    <button class="theme-toggle" onclick="toggleTheme()">🌙</button>
    
    <div class="report-header ioc-header">
        <h1>🔍 IOC INVESTIGATION REPORT</h1>
        <h3><code>{e(ioc)}</code></h3>
        <p>Type: {ioc_type.upper()} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </div>
    
    <div class="container">
        <!-- VERDICT -->
        <div class="card">
            <div class="card-header bg-{verdict_class}"><h4>📊 VERDICT & THREAT SCORE</h4></div>
            <div class="card-body">
                <div class="row text-center">
                    <div class="col">
                        <div class="score-box {score_class}">
                            <h2>{threat_score}/100</h2>
                            <p>Threat Score</p>
                        </div>
                    </div>
                    <div class="col">
                        <div class="score-box bg-{verdict_class}" style="color:white;">
                            <h2>{verdict}</h2>
                            <p>Verdict</p>
                        </div>
                    </div>
                    <div class="col">
                        <div class="score-box {'score-high' if flagged > 0 else 'score-low'}">
                            <h2>{flagged}/{len(sources)}</h2>
                            <p>Sources Flagged</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- SOURCE ANALYSIS -->
        {self._render_source_analysis_section(sources)}
        
        <!-- CHART -->
        <div class="card">
            <div class="card-header"><h4>📈 Threat Score by Source</h4></div>
            <div class="card-body">
                <canvas id="sourceChart" height="100"></canvas>
            </div>
        </div>
        
        <!-- DETECTION RULES -->
        {self._render_detection_rules_section(detection_rules, 'DETECTION RULES')}
        
        <!-- RECOMMENDATIONS -->
        {self._render_ioc_recommendations(result, ioc, ioc_type)}
        
        <div class="text-center mt-3 no-print">
            <button class="btn btn-primary" onclick="window.print()">🖨️ Print Report</button>
        </div>
    </div>
    
    <script>
        {self._get_js()}
        {self._get_chart_js(sources)}
    </script>
</body>
</html>"""
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
            
            logger.info(f"[REPORT] IOC report saved: {output_path}")
            return output_path
            
        except Exception as ex:
            logger.error(f"[REPORT] Failed to generate IOC report: {ex}", exc_info=True)
            return None

    # ==================== SECTION RENDERERS ====================
    
    def _render_malware_families(self, yara: Dict) -> str:
        """Render malware families if detected."""
        families = yara.get('interpretation', {}).get('malware_families', [])
        if not families:
            return ""
        badges = "".join(f'<span class="badge badge-danger me-2">{self._escape(f)}</span>' for f in families[:5])
        return f'<div class="mt-3 text-center"><strong>Malware Families:</strong> {badges}</div>'
    
    def _render_script_section(self, static: Dict) -> str:
        """Render Script static analysis section."""
        if not static:
            return ""
        
        file_type = str(static.get('file_type', static.get('script_type', ''))).lower()
        if file_type != 'script' and not static.get('script_type'):
            return ""
        
        e = self._escape
        
        # Threat indicators
        indicators = static.get('threat_indicators', [])
        indicators_html = ""
        for ind in indicators[:10]:
            icon = "🔴" if any(x in ind.lower() for x in ['execution', 'credential', 'obfuscated']) else "🟠"
            indicators_html += f"<li>{icon} {e(ind)}</li>"
        indicators_html = indicators_html or "<li class='text-muted'>None detected</li>"
        
        # Suspicious patterns
        patterns = static.get('suspicious_patterns', {})
        categories = patterns.get('categories', {})
        patterns_html = ""
        for cat, data in categories.items():
            count = data.get('count', 0)
            samples = data.get('samples', [])
            risk_class = 'danger' if cat in ['execution', 'download', 'credential', 'evasion'] else 'warning'
            patterns_html += f'<div class="mb-2"><span class="badge badge-{risk_class}">{e(cat.upper())}: {count}</span>'
            if samples:
                patterns_html += '<ul class="mb-1">'
                for s in samples[:3]:
                    patterns_html += f'<li><code>{e(str(s)[:50])}</code></li>'
                patterns_html += '</ul>'
            patterns_html += '</div>'
        patterns_html = patterns_html or "<p class='text-muted'>No suspicious patterns</p>"
        
        # Obfuscation
        obf = static.get('obfuscation', {})
        obf_html = ""
        if obf.get('likely_obfuscated'):
            techniques = ", ".join(obf.get('techniques', [])[:5])
            obf_html = f'''
            <div class="alert alert-danger">
                <strong>⚠️ OBFUSCATION DETECTED</strong><br>
                <small>Confidence: {obf.get('confidence', 0)}% | Techniques: {e(techniques)}</small>
            </div>'''
        
        # IOCs
        iocs = static.get('iocs', {})
        iocs_html = ""
        if iocs.get('urls'):
            iocs_html += f"<strong>URLs ({len(iocs['urls'])}):</strong><ul>"
            for u in iocs['urls'][:5]:
                iocs_html += f"<li><code>{e(str(u)[:70])}</code></li>"
            iocs_html += "</ul>"
        if iocs.get('ipv4'):
            iocs_html += f"<strong>IPs ({len(iocs['ipv4'])}):</strong><ul>"
            for ip in iocs['ipv4'][:5]:
                iocs_html += f"<li><code>{e(str(ip))}</code></li>"
            iocs_html += "</ul>"
        iocs_html = iocs_html or "<p class='text-muted'>No IOCs extracted</p>"
        
        # Network/File/Registry indicators
        network = static.get('network_indicators', [])
        file_ind = static.get('file_indicators', [])
        registry = static.get('registry_indicators', [])
        
        indicators_detail_html = ""
        if network:
            indicators_detail_html += f"<h6>🌐 Network ({len(network)})</h6><ul>"
            for n in network[:5]:
                indicators_detail_html += f"<li>{e(n)}</li>"
            indicators_detail_html += "</ul>"
        if file_ind:
            indicators_detail_html += f"<h6>📁 File System ({len(file_ind)})</h6><ul>"
            for f in file_ind[:5]:
                indicators_detail_html += f"<li>{e(f)}</li>"
            indicators_detail_html += "</ul>"
        if registry:
            indicators_detail_html += f"<h6>🔑 Registry ({len(registry)})</h6><ul>"
            for r in registry[:5]:
                indicators_detail_html += f"<li>{e(r)}</li>"
            indicators_detail_html += "</ul>"
        
        # Encoded content
        encoded = static.get('encoded_content', [])
        encoded_html = ""
        if encoded:
            encoded_html = f"<h6>🔐 Encoded Content ({len(encoded)} blocks)</h6><div class='bg-light p-2'>"
            for enc in encoded[:3]:
                enc_type = enc.get('type', 'unknown')
                original = enc.get('encoded', '')[:40]
                decoded = enc.get('decoded', '')[:40]
                encoded_html += f"<p><strong>[{e(enc_type.upper())}]</strong><br>"
                encoded_html += f"Encoded: <code>{e(original)}...</code><br>"
                if decoded:
                    encoded_html += f"Decoded: <code>{e(decoded)}...</code></p>"
            encoded_html += "</div>"
        
        return f'''
        <div class="card">
            <div class="card-header bg-info text-white"><h4>📜 SECTION 3: SCRIPT STATIC ANALYSIS</h4></div>
            <div class="card-body">
                <div class="row mb-3">
                    <div class="col-4">
                        <table class="table table-sm">
                            <tr><th>Script Type</th><td>{e(static.get('script_type', 'Unknown').upper())}</td></tr>
                            <tr><th>Threat Score</th><td><span class="badge badge-{"danger" if static.get("threat_score", 0) >= 70 else "warning" if static.get("threat_score", 0) >= 40 else "success"}">{static.get('threat_score', 0)}/100</span></td></tr>
                            <tr><th>Verdict</th><td><strong>{e(static.get('verdict', 'Unknown'))}</strong></td></tr>
                        </table>
                    </div>
                    <div class="col-8">
                        {obf_html}
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-6">
                        <h5>⚠️ Threat Indicators ({len(indicators)})</h5>
                        <ul style="max-height:200px;overflow:auto;">{indicators_html}</ul>
                    </div>
                    <div class="col-6">
                        <h5>🔍 Suspicious Patterns</h5>
                        <div style="max-height:200px;overflow:auto;">{patterns_html}</div>
                    </div>
                </div>
                
                <div class="row mt-3">
                    <div class="col-6">
                        <h5>🎯 Extracted IOCs</h5>
                        <div style="max-height:200px;overflow:auto;">{iocs_html}</div>
                    </div>
                    <div class="col-6">
                        <h5>📊 Behavioral Indicators</h5>
                        <div style="max-height:200px;overflow:auto;">{indicators_detail_html}</div>
                    </div>
                </div>
                
                {encoded_html}
            </div>
        </div>'''
    
    def _render_pe_section(self, static: Dict) -> str:
        """Render PE static analysis section."""
        if not static or static.get('file_type') != 'PE':
            return ""
        
        e = self._escape
        
      
        pe_analysis = static.get('pe_analysis', {})
        headers = pe_analysis.get('headers', {})
        sections = pe_analysis.get('sections', static.get('sections', []))
        
        # Get imports - handle both structures
        imports_data = pe_analysis.get('imports', static.get('imports', []))
        # Flatten if it's a list of dicts with 'dll' and 'function'
        imports = []
        for imp in imports_data[:50]:
            if isinstance(imp, dict):
                dll = imp.get('dll', '')
                func = imp.get('function', '')
                imports.append(f"{dll}:{func}" if dll and func else str(imp))
            else:
                imports.append(str(imp))
        
        sig = static.get('signature', {})
        
        # Map machine code to architecture
        machine_map = {
            '0x14c': 'x86 (32-bit)',
            '0x8664': 'x64 (64-bit)',
            '0x1c0': 'ARM',
            '0xaa64': 'ARM64',
        }
        machine = headers.get('machine', 'N/A')
        architecture = machine_map.get(machine, machine) if machine != 'N/A' else 'N/A'
        
        # Determine PE type
        characteristics = headers.get('characteristics', '')
        if '0x2000' in str(characteristics) or headers.get('is_dll'):
            pe_type = 'DLL'
        else:
            pe_type = 'EXE'
        
        # Format timestamp
        timestamp = headers.get('timestamp', 0)
        if timestamp:
            from datetime import datetime
            try:
                compile_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            except:
                compile_time = str(timestamp)
        else:
            compile_time = 'N/A'
        
        # Subsystem mapping
        subsystem_map = {
            1: 'Native', 2: 'Windows GUI', 3: 'Windows Console',
            5: 'OS/2 Console', 7: 'POSIX Console', 9: 'Windows CE',
            10: 'EFI Application', 14: 'Xbox'
        }
        subsystem = headers.get('subsystem', 0)
        subsystem_str = subsystem_map.get(subsystem, f'Unknown ({subsystem})') if subsystem else 'N/A'
        
        entry_point = headers.get('entry_point', 'N/A')
        if entry_point and entry_point != 'N/A':
            entry_point = f"0x{entry_point:X}" if isinstance(entry_point, int) else entry_point
        
        # Security features
        aslr = "✅" if headers.get('aslr') else "❌"
        dep = "✅" if headers.get('dep') else "❌"
        cfg = "✅" if headers.get('cfg') else "❌"
        
        sections_html = ""
        for s in sections[:12]:
            entropy = s.get('entropy', 0)
            entropy_class = 'text-danger' if entropy > 7.0 else 'text-warning' if entropy > 6.5 else ''
            is_exec = '🔴' if s.get('is_executable') else ''
            is_write = '📝' if s.get('is_writable') else ''
            status = f"{is_exec}{is_write}" or '✅'
            sections_html += f"<tr><td>{e(s.get('name', 'N/A'))}</td><td>{s.get('virtual_size', 0):,}</td><td>{s.get('raw_size', 0):,}</td><td class='{entropy_class}'>{entropy:.2f}</td><td>{status}</td></tr>"
        
        imports_html = "".join(f"<li><code>{e(imp)}</code></li>" for imp in imports[:25])
        if len(imports) > 25:
            imports_html += f"<li class='text-muted'>... and {len(imports)-25} more</li>"
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>🔧 SECTION 3: PE STATIC ANALYSIS</h4></div>
            <div class="card-body">
                <div class="row">
                    <div class="col-6">
                        <h5>PE Header</h5>
                        <table class="table">
                            <tr><th>Architecture</th><td>{e(architecture)}</td></tr>
                            <tr><th>PE Type</th><td>{e(pe_type)}</td></tr>
                            <tr><th>Compile Time</th><td>{e(compile_time)}</td></tr>
                            <tr><th>Entry Point</th><td><code>{e(str(entry_point))}</code></td></tr>
                            <tr><th>Subsystem</th><td>{e(subsystem_str)}</td></tr>
                            <tr><th>Security</th><td>ASLR: {aslr} | DEP: {dep} | CFG: {cfg}</td></tr>
                            <tr><th>Signature</th><td>{'✅ Signed' if sig.get('signed') else '❌ Unsigned'}</td></tr>
                        </table>
                    </div>
                    <div class="col-6">
                        <h5>Sections ({len(sections)})</h5>
                        <table class="table table-striped">
                            <thead><tr><th>Name</th><th>V.Size</th><th>Raw</th><th>Entropy</th><th>Flags</th></tr></thead>
                            <tbody>{sections_html}</tbody>
                        </table>
                    </div>
                </div>
                <h5 class="mt-3">Imports ({len(imports)})</h5>
                <ul style="max-height:200px;overflow:auto;columns:3;">{imports_html}</ul>
            </div>
        </div>"""
    
    def _render_strings_section(self, string_analysis: Dict, raw_output: Dict) -> str:
        """Render string analysis section."""
        e = self._escape
        raw_strings = raw_output.get('file_analysis', {}).get('strings', {})
        
        urls = raw_strings.get('urls', []) or string_analysis.get('urls', [])
        ips = raw_strings.get('ips', []) or string_analysis.get('ips', [])
        registry = string_analysis.get('registry_keys', []) or raw_strings.get('registry', [])
        interesting = string_analysis.get('interesting_strings', []) or raw_strings.get('interesting', [])
        
        urls_html = "".join(f"<li><code>{e(str(u)[:80])}</code></li>" for u in urls[:15]) or "<li class='text-muted'>None found</li>"
        ips_html = "".join(f"<li><code>{e(str(ip))}</code></li>" for ip in ips[:10]) or "<li class='text-muted'>None found</li>"
        reg_html = "".join(f"<li><code>{e(str(r)[:60])}</code></li>" for r in registry[:10]) or "<li class='text-muted'>None found</li>"
        interesting_html = "".join(f"<li><code>{e(str(s)[:70])}</code></li>" for s in interesting[:20]) or "<li class='text-muted'>None found</li>"
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>📝 SECTION 4: STRING ANALYSIS</h4></div>
            <div class="card-body">
                <div class="mb-3">
                    <span class="badge badge-primary me-2">Total: {string_analysis.get('total_strings', raw_strings.get('total_count', 0))}</span>
                    <span class="badge badge-secondary me-2">ASCII: {string_analysis.get('ascii_strings', raw_strings.get('ascii_count', 0))}</span>
                    <span class="badge badge-secondary">Unicode: {string_analysis.get('unicode_strings', raw_strings.get('unicode_count', 0))}</span>
                </div>
                <div class="row">
                    <div class="col">
                        <h6>🔗 URLs ({len(urls)})</h6>
                        <ul style="max-height:150px;overflow:auto;">{urls_html}</ul>
                    </div>
                    <div class="col">
                        <h6>🌐 IP Addresses ({len(ips)})</h6>
                        <ul style="max-height:150px;overflow:auto;">{ips_html}</ul>
                    </div>
                    <div class="col">
                        <h6>📋 Registry Keys ({len(registry)})</h6>
                        <ul style="max-height:150px;overflow:auto;">{reg_html}</ul>
                    </div>
                </div>
                <h6 class="mt-3">⚠️ Interesting Strings ({len(interesting)})</h6>
                <ul style="max-height:200px;overflow:auto;columns:2;">{interesting_html}</ul>
            </div>
        </div>"""
    
    def _render_yara_section(self, yara: Dict) -> str:
        """Render YARA analysis section."""
        e = self._escape
        matches = yara.get('matches', [])
        interpretation = yara.get('interpretation', {})
        families = interpretation.get('malware_families', [])
        tags = interpretation.get('tags', [])
        
        matches_html = "".join(f"<li>✓ <strong>{e(str(m.get('rule', m)) if isinstance(m, dict) else str(m))}</strong></li>" for m in matches[:10]) or "<li class='text-muted'>No matches</li>"
        families_html = "".join(f'<span class="badge badge-danger me-2">{e(f)}</span>' for f in families[:5]) or '<span class="text-muted">None</span>'
        tags_html = "".join(f'<span class="badge badge-secondary me-2">{e(t)}</span>' for t in tags[:10]) or '<span class="text-muted">None</span>'
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>🎯 SECTION 5: YARA ANALYSIS</h4></div>
            <div class="card-body">
                <div class="row">
                    <div class="col"><h5>Matches: {len(matches)}</h5><ul>{matches_html}</ul></div>
                    <div class="col"><h5>Malware Families</h5><p>{families_html}</p></div>
                    <div class="col"><h5>Tags</h5><p>{tags_html}</p></div>
                </div>
            </div>
        </div>"""
    
    def _render_entropy_section(self, result: Dict) -> str:
        """
        Render entropy analysis section.
        
        v1.0.0: Updated to get entropy from multiple sources
        """
        # Try multiple paths for entropy data
        entropy_data = {}
        
        # Path 1: Direct entropy_analysis in result
        if result.get('entropy_analysis'):
            ea = result['entropy_analysis']
            if 'file_entropy' in ea:
                entropy_data = ea['file_entropy']
            else:
                entropy_data = ea
        
        # Path 2: raw_output.file_analysis.tool_outputs.entropy
        if not entropy_data:
            raw_output = result.get('raw_output', {})
            tool_outputs = raw_output.get('file_analysis', {}).get('tool_outputs', {})
            if tool_outputs.get('entropy'):
                entropy_data = tool_outputs['entropy']
        
        # Path 3: static_analysis.entropy_analysis (legacy)
        if not entropy_data:
            static = result.get('static_analysis', {})
            if static.get('entropy_analysis'):
                ea = static['entropy_analysis']
                entropy_data = ea.get('file_entropy', ea)
        
        overall = entropy_data.get('overall_entropy', 0)
        interpretation = entropy_data.get('interpretation', {})
        category = interpretation.get('category', 'unknown')
        description = interpretation.get('description', '')
        
        bar_width = int((overall / 8.0) * 100)
        bar_class = 'bg-danger' if overall > 7.0 else 'bg-warning' if overall > 6.5 else 'bg-success'
        badge_class = 'badge-danger' if overall > 7.0 else 'badge-warning' if overall > 6.5 else 'badge-success'
        
        # Extra info
        chunk_html = ""
        chunk_analysis = entropy_data.get('chunk_analysis', {})
        if chunk_analysis:
            chunk_html = f"""
                <div class="row mt-3">
                    <div class="col">
                        <small class="text-muted">Chunk Analysis: Avg={chunk_analysis.get('average', 0):.2f} | Max={chunk_analysis.get('max', 0):.2f} | Min={chunk_analysis.get('min', 0):.2f}</small>
                    </div>
                </div>"""
        
        warning_html = ""
        if overall > 7.0:
            warning_html = '<p class="text-danger mt-2">⚠️ HIGH ENTROPY - Likely PACKED or ENCRYPTED</p>'
        elif overall > 6.5:
            warning_html = '<p class="text-warning mt-2">⚠️ ELEVATED ENTROPY - May contain compressed/encoded data</p>'
        elif overall < 4.0 and overall > 0:
            warning_html = '<p class="text-info mt-2">ℹ️ LOW ENTROPY - Plain text or low complexity data</p>'
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>📊 SECTION 6: ENTROPY ANALYSIS</h4></div>
            <div class="card-body">
                <div class="row">
                    <div class="col text-center">
                        <h2>{overall:.2f} / 8.00</h2>
                        <p class="text-muted">Overall File Entropy</p>
                    </div>
                    <div class="col-6">
                        <div class="progress" style="height: 25px;">
                            <div class="progress-bar {bar_class}" style="width:{bar_width}%">{bar_width}%</div>
                        </div>
                        <small class="text-muted mt-1">{description if description else 'Entropy measures randomness/complexity'}</small>
                    </div>
                    <div class="col text-center">
                        <span class="badge {badge_class} p-2">{category.upper()}</span>
                        {warning_html}
                    </div>
                </div>
                {chunk_html}
            </div>
        </div>"""
    
    def _render_ioc_section(self, ioc_analysis: Dict, section_num: str) -> str:
        """Render IOC analysis section."""
        e = self._escape
        total = ioc_analysis.get('total_iocs', 0)
        malicious = ioc_analysis.get('malicious_iocs', 0)
        suspicious = ioc_analysis.get('suspicious_iocs', 0)
        results = ioc_analysis.get('results', [])
        
        rows_html = ""
        for r in results[:15]:
            v = r.get('verdict', 'UNKNOWN')
            v_class = 'danger' if v == 'MALICIOUS' else 'warning' if v == 'SUSPICIOUS' else 'success'
            rows_html += f"<tr><td><code>{e(str(r.get('ioc', 'N/A'))[:50])}</code></td><td>{e(r.get('ioc_type', r.get('type', 'unknown')))}</td><td><span class='badge badge-{v_class}'>{v}</span></td><td>{r.get('threat_score', 0)}/100</td></tr>"
        
        if not rows_html:
            rows_html = "<tr><td colspan='4' class='text-center text-muted'>No IOCs analyzed</td></tr>"
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>🎯 {section_num}: IOC ANALYSIS</h4></div>
            <div class="card-body">
                <div class="row text-center mb-3">
                    <div class="col"><h5>Total IOCs</h5><h2>{total}</h2></div>
                    <div class="col"><h5 class="text-danger">Malicious</h5><h2 class="text-danger">{malicious}</h2></div>
                    <div class="col"><h5 class="text-warning">Suspicious</h5><h2 class="text-warning">{suspicious}</h2></div>
                </div>
                <table class="table table-striped">
                    <thead><tr><th>IOC</th><th>Type</th><th>Verdict</th><th>Score</th></tr></thead>
                    <tbody>{rows_html}</tbody>
                </table>
            </div>
        </div>"""
    
    def _render_mitre_section(self, techniques: List) -> str:
        """Render MITRE ATT&CK mapping section."""
        if not techniques:
            return ""
        
        e = self._escape
        
        # MITRE technique database
        tactics = {
            'T1059': ('Execution', 'Command and Scripting Interpreter'),
            'T1059.001': ('Execution', 'PowerShell'),
            'T1027': ('Defense Evasion', 'Obfuscated Files or Information'),
            'T1140': ('Defense Evasion', 'Deobfuscate/Decode Files'),
            'T1547': ('Persistence', 'Boot or Logon Autostart Execution'),
            'T1547.009': ('Persistence', 'Shortcut Modification'),
            'T1053': ('Persistence', 'Scheduled Task/Job'),
            'T1003': ('Credential Access', 'OS Credential Dumping'),
            'T1555': ('Credential Access', 'Credentials from Password Stores'),
            'T1082': ('Discovery', 'System Information Discovery'),
            'T1083': ('Discovery', 'File and Directory Discovery'),
            'T1012': ('Discovery', 'Query Registry'),
            'T1010': ('Discovery', 'Application Window Discovery'),
            'T1105': ('Command and Control', 'Ingress Tool Transfer'),
            'T1071': ('Command and Control', 'Application Layer Protocol'),
            'T1548': ('Privilege Escalation', 'Abuse Elevation Control'),
            'T1134': ('Privilege Escalation', 'Access Token Manipulation'),
            'T1562': ('Defense Evasion', 'Impair Defenses'),
            'T1070': ('Defense Evasion', 'Indicator Removal'),
            'T1112': ('Defense Evasion', 'Modify Registry'),
            'T1222': ('Defense Evasion', 'File and Directory Permissions Modification'),
            'T1560': ('Collection', 'Archive Collected Data'),
            'T1119': ('Collection', 'Automated Collection'),
            'T1115': ('Collection', 'Clipboard Data'),
            'T1041': ('Exfiltration', 'Exfiltration Over C2 Channel'),
            'T1529': ('Impact', 'System Shutdown/Reboot'),
            'T1129': ('Execution', 'Shared Modules'),
            'T1125': ('Collection', 'Video Capture'),
        }
        
        rows = ""
        seen = set()
        for t in techniques[:20]:
            # Handle both structures: our new format and legacy
            tech_id = t.get('technique_id', t.get('id', 'N/A'))
            if tech_id in seen:
                continue
            seen.add(tech_id)
            
            # Get name and tactic from database or from input
            if tech_id in tactics:
                tactic, name = tactics[tech_id]
            else:
                name = t.get('name', 'Unknown Technique')
                tactic = t.get('tactic', t.get('category', 'Unknown'))
            
            source = t.get('source', 'analysis')
            confidence = t.get('confidence', 'medium')
            conf_badge = 'danger' if confidence == 'high' else 'warning' if confidence == 'medium' else 'secondary'
            
            rows += f"""<tr>
                <td><code><a href="https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/" target="_blank">{e(tech_id)}</a></code></td>
                <td>{e(name)}</td>
                <td>{e(tactic)}</td>
                <td><span class="badge badge-{conf_badge}">{e(confidence)}</span> ({e(source)})</td>
            </tr>"""
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>🗺️ SECTION 4: MITRE ATT&CK MAPPING</h4></div>
            <div class="card-body">
                <p class="text-muted">Total techniques detected: {len(seen)}</p>
                <table class="table table-striped">
                    <thead><tr><th>Technique ID</th><th>Name</th><th>Tactic</th><th>Confidence / Source</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
                <a href="https://mitre-attack.github.io/attack-navigator/" target="_blank" class="btn btn-outline-primary btn-sm">
                    🗺️ Open in ATT&CK Navigator
                </a>
            </div>
        </div>"""
    
    def _render_detection_rules_section(self, rules: Dict, section_num: str) -> str:
        """Render detection rules section with accordion."""
        if not rules:
            return ""
        
        e = self._escape
        
        accordions = ""
        rule_types = [
            ('kql', 'KQL (Microsoft Defender / Sentinel)'),
            ('yara', 'YARA Rule'),
            ('sigma', 'SIGMA Rule'),
            ('spl', 'SPL (Splunk)')
        ]
        
        for i, (key, title) in enumerate(rule_types):
            content = rules.get(key, f'No {key.upper()} rule generated')
            accordions += f"""
            <div class="accordion-item">
                <div class="accordion-header">
                    <button class="accordion-button" onclick="toggleAccordion('rule{i}')">{title}</button>
                </div>
                <div class="accordion-body {'show' if i == 0 else ''}" id="rule{i}">
                    <pre>{e(content)}</pre>
                    <button class="btn btn-outline-primary btn-sm mt-2" onclick="copyToClipboard('rule{i}')">📋 Copy</button>
                </div>
            </div>"""
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>🛡️ {section_num}: DETECTION RULES</h4></div>
            <div class="card-body">
                {accordions}
            </div>
        </div>"""
    
    def _render_ai_section(self, llm: Dict, section_num: str) -> str:
        """Render AI analysis section."""
        e = self._escape
        analysis = llm.get('analysis', 'No AI analysis available')
        recommendations = llm.get('recommendations', [])
        
        rec_html = "".join(f"<li>{e(r)}</li>" for r in recommendations[:10])
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>🤖 {section_num}: AI ANALYSIS</h4></div>
            <div class="card-body">
                <p>{e(analysis)}</p>
                {'<h6>AI Recommendations:</h6><ol>' + rec_html + '</ol>' if rec_html else ''}
            </div>
        </div>"""
    
    def _render_scoring_section(self, result: Dict, raw_output: Dict, section_num: str) -> str:
        """Render scoring breakdown section."""
        scoring = raw_output.get('scoring_details', {})
        breakdown = scoring.get('breakdown', {})
        
        bars_html = ""
        for comp, score in breakdown.items():
            score_val = int(score) if isinstance(score, (int, float)) else 0
            bar_class = 'bg-danger' if score_val > 70 else 'bg-warning' if score_val > 30 else 'bg-success'
            bars_html += f"""
            <tr>
                <td>{self._escape(comp)}</td>
                <td>
                    <div class="progress">
                        <div class="progress-bar {bar_class}" style="width:{min(score_val, 100)}%">{score_val}</div>
                    </div>
                </td>
            </tr>"""
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>📊 {section_num}: SCORING BREAKDOWN</h4></div>
            <div class="card-body">
                <div class="row text-center mb-3">
                    <div class="col"><h5>Composite Score</h5><h1>{result.get('composite_score', 0)}/100</h1></div>
                    <div class="col"><h5>Verdict</h5><h1>{result.get('verdict', 'UNKNOWN')}</h1></div>
                    <div class="col"><h5>Confidence</h5><h1>{scoring.get('confidence', 85)}%</h1></div>
                </div>
                <h6>Score Components</h6>
                <table class="table">
                    <thead><tr><th>Component</th><th>Score</th></tr></thead>
                    <tbody>{bars_html or '<tr><td colspan="2" class="text-muted">No breakdown available</td></tr>'}</tbody>
                </table>
            </div>
        </div>"""
    
    def _render_sandbox_section(self, hashes: Dict) -> str:
        """Render sandbox links section."""
        sha256 = hashes.get('sha256', '')
        if not sha256:
            return ""
        
        links = [
            ('🦠 VirusTotal', f'https://www.virustotal.com/gui/file/{sha256}'),
            ('🔬 Hybrid Analysis', f'https://www.hybrid-analysis.com/search?query={sha256}'),
            ('🏃 ANY.RUN', f'https://app.any.run/submissions/#filehash:{sha256}'),
            ('📦 Joe Sandbox', f'https://www.joesandbox.com/search?q={sha256}'),
            ('🗃️ MalwareBazaar', f'https://bazaar.abuse.ch/sample/{sha256}/'),
            ('📊 Triage', f'https://tria.ge/s?q={sha256}'),
            ('🔍 URLhaus', f'https://urlhaus.abuse.ch/browse.php?search={sha256}'),
            ('☁️ ThreatFox', f'https://threatfox.abuse.ch/browse.php?search=ioc%3A{sha256}'),
        ]
        
        links_html = "".join(f'<a href="{url}" target="_blank" class="sandbox-link">{name}</a>' for name, url in links)
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>🔬 SECTION 12: SANDBOX & ANALYSIS LINKS</h4></div>
            <div class="card-body">
                <div class="sandbox-grid">{links_html}</div>
            </div>
        </div>"""
    
    def _render_file_recommendations(self, result: Dict) -> str:
        """Render file analysis recommendations."""
        verdict = result.get('verdict', 'UNKNOWN')
        
        if verdict == 'MALICIOUS':
            return """
            <div class="card" style="border-color:#dc3545;">
                <div class="card-header bg-danger"><h4>🚨 SECTION 13: IMMEDIATE ACTIONS REQUIRED</h4></div>
                <div class="card-body">
                    <ol>
                        <li><strong>BLOCK</strong> file hash on all security controls (EDR, AV, Proxy)</li>
                        <li><strong>ADD</strong> SHA256 and MD5 to blocklist</li>
                        <li><strong>HUNT</strong> for this file across all endpoints</li>
                        <li><strong>CHECK</strong> for lateral movement indicators</li>
                        <li><strong>ISOLATE</strong> affected systems</li>
                        <li><strong>PRESERVE</strong> evidence for forensic analysis</li>
                        <li><strong>REPORT</strong> to threat intel team</li>
                    </ol>
                </div>
            </div>"""
        elif verdict == 'SUSPICIOUS':
            return """
            <div class="card" style="border-color:#ffc107;">
                <div class="card-header bg-warning"><h4>⚠️ SECTION 13: INVESTIGATION REQUIRED</h4></div>
                <div class="card-body">
                    <ol>
                        <li><strong>SUBMIT</strong> to sandbox for dynamic analysis</li>
                        <li><strong>MONITOR</strong> execution behavior</li>
                        <li><strong>REVIEW</strong> in isolated environment</li>
                        <li><strong>CHECK</strong> for similar samples</li>
                        <li><strong>ESCALATE</strong> if confirmed malicious</li>
                    </ol>
                </div>
            </div>"""
        else:
            return """
            <div class="card" style="border-color:#28a745;">
                <div class="card-header bg-success"><h4>✅ SECTION 13: ROUTINE MONITORING</h4></div>
                <div class="card-body">
                    <ul>
                        <li>No immediate action required</li>
                        <li>Continue standard monitoring</li>
                        <li>Document for baseline</li>
                    </ul>
                </div>
            </div>"""
    
    def _render_raw_data_section(self, raw_output: Dict, section_num: str) -> str:
        """Render raw data accordion section."""
        if not raw_output:
            return ""
        
        sections = [
            ('file_analysis', '📁 File Analysis'),
            ('email_analysis', '📧 Email Analysis'),
            ('ioc_analysis', '🎯 IOC Analysis'),
            ('api_responses', '🌐 API Responses'),
            ('scoring_details', '📊 Scoring'),
            ('detection_rules', '🛡️ Detection Rules'),
            ('pipeline_steps', '⚙️ Pipeline'),
        ]
        
        accordions = ""
        for i, (key, title) in enumerate(sections):
            data = raw_output.get(key, {})
            if data:
                json_str = json.dumps(data, indent=2, default=str)
                accordions += f"""
                <div class="accordion-item">
                    <div class="accordion-header">
                        <button class="accordion-button" onclick="toggleAccordion('raw{i}')">{title}</button>
                    </div>
                    <div class="accordion-body" id="raw{i}">
                        <pre style="font-size:11px;">{self._escape(json_str)}</pre>
                        <button class="btn btn-outline-primary btn-sm mt-2" onclick="copyToClipboard('raw{i}')">📋 Copy</button>
                    </div>
                </div>"""
        
        # Full export
        full_json = json.dumps(raw_output, indent=2, default=str)
        accordions += f"""
        <div class="accordion-item">
            <div class="accordion-header">
                <button class="accordion-button" onclick="toggleAccordion('rawFull')">📄 Full JSON Export</button>
            </div>
            <div class="accordion-body" id="rawFull">
                <pre style="font-size:10px;max-height:500px;">{self._escape(full_json)}</pre>
                <button class="btn btn-outline-primary btn-sm mt-2" onclick="copyToClipboard('rawFull')">📋 Copy</button>
                <button class="btn btn-outline-secondary btn-sm mt-2" onclick="downloadJSON()">💾 Download</button>
            </div>
        </div>"""
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>📄 {section_num}: RAW DATA</h4></div>
            <div class="card-body">{accordions}</div>
        </div>"""
    
    # ==================== EMAIL SECTION RENDERERS ====================
    
    def _render_email_headers_section(self, email_data: Dict, advanced: Dict) -> str:
        """Render email headers section."""
        e = self._escape
        anomalies = advanced.get('header_analysis', {}).get('anomalies', [])
        
        anomalies_html = ""
        if anomalies:
            anomalies_html = '<div class="alert alert-warning mt-3"><strong>⚠️ Anomalies:</strong><ul>'
            anomalies_html += "".join(f"<li>{e(a)}</li>" for a in anomalies)
            anomalies_html += "</ul></div>"
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>📧 SECTION 2: EMAIL HEADERS</h4></div>
            <div class="card-body">
                <table class="table">
                    <tr><th width="15%">From</th><td>{e(email_data.get('from', 'N/A'))}</td></tr>
                    <tr><th>To</th><td>{e(email_data.get('to', 'N/A'))}</td></tr>
                    <tr><th>Subject</th><td>{e(email_data.get('subject', 'N/A'))}</td></tr>
                    <tr><th>Date</th><td>{e(email_data.get('date', 'N/A'))}</td></tr>
                    <tr><th>Message-ID</th><td><code>{e(email_data.get('message_id', 'N/A'))}</code></td></tr>
                    <tr><th>Reply-To</th><td>{e(email_data.get('reply_to', 'N/A'))}</td></tr>
                </table>
                {anomalies_html}
            </div>
        </div>"""
    
    def _render_received_chain_section(self, email_data: Dict, raw_output: Dict) -> str:
        """Render received chain section."""
        e = self._escape
        headers = raw_output.get('email_analysis', {}).get('headers', {})
        received = headers.get('received_chain', [])
        
        chain_html = ""
        for i, hop in enumerate(received[:10], 1):
            chain_html += f'<div class="alert alert-info mb-2"><strong>Hop {i}:</strong><br><code style="font-size:11px;">{e(str(hop)[:300])}</code></div>'
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>🔗 SECTION 3: RECEIVED CHAIN (HOP ANALYSIS)</h4></div>
            <div class="card-body">
                <p><strong>Total Hops:</strong> {len(received)}</p>
                {chain_html or '<p class="text-muted">No received headers found</p>'}
            </div>
        </div>"""
    
    def _render_x_headers_section(self, email_data: Dict, raw_output: Dict) -> str:
        """Render X-Headers section."""
        e = self._escape
        headers = raw_output.get('email_analysis', {}).get('headers', {})
        x_headers = headers.get('x_headers', {})
        
        rows = ""
        for name, value in list(x_headers.items())[:20]:
            rows += f"<tr><th>{e(name)}</th><td><code>{e(str(value)[:100])}</code></td></tr>"
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>📋 SECTION 4: X-HEADERS</h4></div>
            <div class="card-body">
                <table class="table table-striped">
                    {rows or '<tr><td class="text-muted">No X-Headers found</td></tr>'}
                </table>
            </div>
        </div>"""
    
    def _render_auth_section(self, email_data: Dict, raw_output: Dict) -> str:
        """Render authentication section."""
        spf = email_data.get('spf', 'none')
        dkim = email_data.get('dkim', 'none')
        dmarc = email_data.get('dmarc', 'none')
        
        def badge(result):
            if str(result).lower() == 'pass':
                return '<span class="badge badge-success">✓ PASS</span>'
            elif str(result).lower() == 'fail':
                return '<span class="badge badge-danger">✗ FAIL</span>'
            return '<span class="badge badge-secondary">⚪ NONE</span>'
        
        all_pass = str(spf).lower() == 'pass' and str(dkim).lower() == 'pass' and str(dmarc).lower() == 'pass'
        overall = '<span class="badge badge-success p-2">✓ ALL PASSED</span>' if all_pass else '<span class="badge badge-danger p-2">✗ ISSUES DETECTED</span>'
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>🔐 SECTION 5: AUTHENTICATION STATUS</h4></div>
            <div class="card-body">
                <div class="row text-center mb-3">
                    <div class="col"><h5>SPF</h5>{badge(spf)}</div>
                    <div class="col"><h5>DKIM</h5>{badge(dkim)}</div>
                    <div class="col"><h5>DMARC</h5>{badge(dmarc)}</div>
                </div>
                <div class="text-center">{overall}</div>
            </div>
        </div>"""
    
    def _render_content_section(self, email_data: Dict, advanced: Dict) -> str:
        """Render content analysis section."""
        e = self._escape
        html_obf = advanced.get('html_obfuscation', {})
        qr = advanced.get('qr_detection', {})
        brand = advanced.get('brand_impersonation', [])
        
        alerts = []
        if html_obf.get('risk_score', 0) > 50:
            alerts.append(f"⚠️ HTML Obfuscation detected (Risk: {html_obf.get('risk_score')})")
        if qr.get('qr_codes_found', 0) > 0:
            alerts.append(f"⚠️ QR Codes detected: {qr.get('qr_codes_found')}")
        if brand:
            alerts.append(f"⚠️ Brand Impersonation: {', '.join(b.get('brand', 'Unknown') for b in brand[:3])}")
        
        alerts_html = '<div class="alert alert-danger">' + '<br>'.join(alerts) + '</div>' if alerts else ''
        body = email_data.get('body_text', '')[:500]
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>📄 SECTION 6: CONTENT ANALYSIS</h4></div>
            <div class="card-body">
                {alerts_html}
                <h6>Body Preview (First 500 chars)</h6>
                <pre style="max-height:200px;">{e(body) or '<em>No text content</em>'}</pre>
            </div>
        </div>"""
    
    def _render_url_section(self, email_data: Dict, advanced: Dict) -> str:
        """Render URL analysis section."""
        e = self._escape
        urls = email_data.get('urls', [])
        mismatches = advanced.get('link_mismatches', [])
        lookalikes = advanced.get('lookalike_domains', [])
        
        alerts = []
        if mismatches:
            alerts.append(f'<div class="alert alert-danger">⚠️ Link-Text Mismatches: {len(mismatches)}</div>')
        for l in lookalikes[:3]:
            sim = l.get('similarity', 0)
            sim_str = f"{sim:.0%}" if isinstance(sim, float) and sim <= 1 else f"{sim}%"
            alerts.append(f'<div class="alert alert-warning">⚠️ Lookalike: {e(l.get("domain", ""))} → {e(l.get("legitimate", ""))} ({sim_str})</div>')
        
        urls_html = "".join(f"<li><code>{e(str(u)[:80])}</code></li>" for u in urls[:15]) or '<li class="text-muted">No URLs found</li>'
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>🔗 SECTION 7: URL ANALYSIS</h4></div>
            <div class="card-body">
                {"".join(alerts)}
                <h6>URLs Found ({len(urls)})</h6>
                <ul style="max-height:200px;overflow:auto;">{urls_html}</ul>
            </div>
        </div>"""
    
    def _render_attachments_section(self, email_data: Dict) -> str:
        """Render attachments section."""
        e = self._escape
        attachments = email_data.get('attachments', [])
        
        rows = ""
        for a in attachments[:10]:
            sus = a.get('suspicious', False)
            rows += f"""<tr class="{'table-danger' if sus else ''}">
                <td>{e(a.get('filename', 'N/A'))}</td>
                <td>{e(a.get('content_type', 'N/A'))}</td>
                <td>{a.get('size', 0):,}</td>
                <td><code style="font-size:10px;">{e(str(a.get('sha256', a.get('md5', 'N/A')))[:32])}</code></td>
                <td>{'⚠️' if sus else '✅'}</td>
            </tr>"""
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>📎 SECTION 8: ATTACHMENTS</h4></div>
            <div class="card-body">
                <p><strong>Total:</strong> {len(attachments)}</p>
                <table class="table table-striped">
                    <thead><tr><th>Filename</th><th>Type</th><th>Size</th><th>Hash</th><th>Status</th></tr></thead>
                    <tbody>{rows or '<tr><td colspan="5" class="text-muted">No attachments</td></tr>'}</tbody>
                </table>
            </div>
        </div>"""
    
    def _render_email_recommendations(self, result: Dict) -> str:
        """Render email analysis recommendations."""
        verdict = result.get('verdict', 'UNKNOWN')
        
        if verdict in ['MALICIOUS', 'PHISHING']:
            return """
            <div class="card" style="border-color:#dc3545;">
                <div class="card-header bg-danger"><h4>🚨 SECTION 12: IMMEDIATE ACTIONS REQUIRED</h4></div>
                <div class="card-body">
                    <ol>
                        <li><strong>DELETE</strong> email from all user mailboxes</li>
                        <li><strong>BLOCK</strong> sender domain on email gateway</li>
                        <li><strong>ADD</strong> sender to blocklist</li>
                        <li><strong>ADD</strong> URLs to proxy blocklist</li>
                        <li><strong>CHECK</strong> if any user clicked links</li>
                        <li><strong>CHECK</strong> if any user opened attachments</li>
                        <li><strong>NOTIFY</strong> affected users</li>
                        <li><strong>REPORT</strong> to anti-phishing services</li>
                    </ol>
                </div>
            </div>"""
        elif verdict in ['SUSPICIOUS', 'SPAM']:
            return """
            <div class="card" style="border-color:#ffc107;">
                <div class="card-header bg-warning"><h4>⚠️ SECTION 12: INVESTIGATION REQUIRED</h4></div>
                <div class="card-body">
                    <ol>
                        <li><strong>QUARANTINE</strong> email pending analysis</li>
                        <li><strong>SUBMIT</strong> attachments to sandbox</li>
                        <li><strong>VERIFY</strong> sender legitimacy</li>
                        <li><strong>MONITOR</strong> for similar emails</li>
                    </ol>
                </div>
            </div>"""
        else:
            return """
            <div class="card" style="border-color:#28a745;">
                <div class="card-header bg-success"><h4>✅ SECTION 12: ROUTINE MONITORING</h4></div>
                <div class="card-body">
                    <ul><li>No immediate action required</li><li>Continue standard monitoring</li></ul>
                </div>
            </div>"""
    
    # ==================== IOC SECTION RENDERERS ====================
    
    def _render_source_analysis_section(self, sources: Dict) -> str:
        """Render detailed source analysis section."""
        e = self._escape
        
        rows = ""
        for name, info in sources.items():
            if not isinstance(info, dict):
                continue
            
            status = info.get('status', '')
            is_flagged = status in ['✓', '✓ FLAGGED', 'FLAGGED'] or info.get('malicious') or info.get('found')
            
            if is_flagged:
                badge = '<span class="badge badge-danger">🚨 FLAGGED</span>'
                row_class = 'table-danger'
            elif info.get('error'):
                badge = '<span class="badge badge-secondary">⚠️ ERROR</span>'
                row_class = ''
            else:
                badge = '<span class="badge badge-success">✅ CLEAN</span>'
                row_class = ''
            
            details = ''
            if info.get('detections'):
                details = f"Detections: {info['detections']}"
            elif info.get('fraud_score'):
                details = f"Fraud: {info['fraud_score']}%"
            elif info.get('abuse_confidence_score'):
                details = f"Abuse: {info['abuse_confidence_score']}%"
            elif info.get('pulse_count'):
                details = f"Pulses: {info['pulse_count']}"
            elif info.get('error'):
                details = e(str(info['error'])[:50])
            
            rows += f'<tr class="{row_class}"><td><strong>{e(name.upper())}</strong></td><td>{badge}</td><td>{e(details)}</td></tr>'
        
        return f"""
        <div class="card">
            <div class="card-header"><h4>🔎 DETAILED SOURCE ANALYSIS ({len(sources)} Sources)</h4></div>
            <div class="card-body">
                <table class="table table-striped">
                    <thead><tr><th>Source</th><th>Status</th><th>Details</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>"""
    
    def _render_ioc_recommendations(self, result: Dict, ioc: str, ioc_type: str) -> str:
        """Render IOC recommendations."""
        verdict = result.get('verdict', 'UNKNOWN')
        e = self._escape
        
        if verdict == 'MALICIOUS':
            return f"""
            <div class="card" style="border-color:#dc3545;">
                <div class="card-header bg-danger"><h4>🚨 IMMEDIATE ACTIONS REQUIRED</h4></div>
                <div class="card-body">
                    <ol>
                        <li><strong>BLOCK</strong> this {e(ioc_type)} immediately</li>
                        <li><strong>ADD</strong> to firewall/proxy blocklist</li>
                        <li><strong>HUNT</strong> for historical connections</li>
                        <li><strong>INVESTIGATE</strong> any systems that communicated</li>
                        <li><strong>SHARE</strong> with threat intel team</li>
                    </ol>
                </div>
            </div>"""
        elif verdict == 'SUSPICIOUS':
            return f"""
            <div class="card" style="border-color:#ffc107;">
                <div class="card-header bg-warning"><h4>⚠️ INVESTIGATION REQUIRED</h4></div>
                <div class="card-body">
                    <ol>
                        <li><strong>MONITOR</strong> traffic to this {e(ioc_type)}</li>
                        <li><strong>INVESTIGATE</strong> context</li>
                        <li><strong>CHECK</strong> additional sources</li>
                        <li><strong>ESCALATE</strong> if confirmed</li>
                    </ol>
                </div>
            </div>"""
        else:
            return """
            <div class="card" style="border-color:#28a745;">
                <div class="card-header bg-success"><h4>✅ ROUTINE MONITORING</h4></div>
                <div class="card-body">
                    <ul><li>No immediate action required</li><li>Continue monitoring</li></ul>
                </div>
            </div>"""
    
    def _get_chart_js(self, sources: Dict) -> str:
        """Generate Chart.js script for sources."""
        labels = []
        scores = []
        colors = []
        
        for name, info in sources.items():
            if not isinstance(info, dict):
                continue
            labels.append(name.upper())
            
            score = 0
            if info.get('status') in ['✓', '✓ FLAGGED', 'FLAGGED'] or info.get('malicious') or info.get('found'):
                score = 80
            if info.get('detections'):
                try:
                    det = info['detections']
                    if isinstance(det, str) and '/' in det:
                        parts = det.split('/')
                        score = int(int(parts[0]) / max(int(parts[1]), 1) * 100)
                    elif isinstance(det, int):
                        score = min(det * 10, 100)
                except:
                    score = 50
            elif info.get('fraud_score'):
                score = int(info['fraud_score'])
            elif info.get('abuse_confidence_score'):
                score = int(info['abuse_confidence_score'])
            
            scores.append(score)
            colors.append('#dc3545' if score > 50 else '#ffc107' if score > 20 else '#28a745')
        
        return f"""
        const ctx = document.getElementById('sourceChart');
        if (ctx) {{
            new Chart(ctx.getContext('2d'), {{
                type: 'bar',
                data: {{
                    labels: {json.dumps(labels[:15])},
                    datasets: [{{
                        label: 'Threat Score',
                        data: {json.dumps(scores[:15])},
                        backgroundColor: {json.dumps(colors[:15])}
                    }}]
                }},
                options: {{
                    responsive: true,
                    scales: {{ y: {{ beginAtZero: true, max: 100 }} }},
                    plugins: {{ legend: {{ display: false }} }}
                }}
            }});
        }}
        """
    
    # ==================== ALIAS METHODS FOR COMPATIBILITY ====================
    
    def generate_advanced_file_report(self, result: Dict, file_path: str, output_path: str) -> str:
        """Alias for generate_file_report with path extraction."""
        filename = Path(file_path).name if file_path else 'unknown'
        return self.generate_file_report(result, filename, output_path)
    
    def generate_advanced_email_report(self, result: Dict, output_path: str) -> str:
        """Alias for generate_email_report."""
        email_path = result.get('email_path', 'email.eml')
        return self.generate_email_report(result, email_path, output_path)
    
    def generate_advanced_ioc_report(self, result: Dict, ioc: str, output_path: str) -> str:
        """Alias for generate_ioc_report."""
        return self.generate_ioc_report(result, ioc, output_path)

