"""
Author: Ugur AtesAdvanced HTML Report Generator with Chart.js, Timeline, MITRE Heatmap."""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger(__name__)
class AdvancedReportGenerator:
    """
    Generate advanced HTML reports with:
    - Chart.js graphs
    - Timeline visualization
    - MITRE heatmap
    - Dark/light mode
    """
    
    @staticmethod
    def generate_advanced_ioc_report(result: Dict, ioc: str, output_path: str) -> str:
        """Generate advanced IOC report with charts."""
        
        # Prepare chart data
        sources_data = AdvancedReportGenerator._prepare_source_chart_data(result)
        verdict_data = AdvancedReportGenerator._prepare_verdict_data(result)
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IOC Analysis Report - {ioc}</title>
    
    <!-- Bootstrap 5 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    
    <!-- Custom Theme CSS -->
    <style>
{AdvancedReportGenerator._get_embedded_css()}
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="report-header">
            <h1>🔍 IOC Analysis Report</h1>
            <p class="lead">IOC: <code>{ioc}</code></p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
        
        <div class="container mt-4">
            <!-- Executive Summary -->
            <div class="card mb-4">
                <div class="card-header">
                    <h4>📊 Executive Summary</h4>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-4">
                            <h5>Verdict</h5>
                            <h2><span class="badge bg-{AdvancedReportGenerator._verdict_class(result.get('verdict'))}">{result.get('verdict', 'UNKNOWN')}</span></h2>
                        </div>
                        <div class="col-md-4">
                            <h5>Threat Score</h5>
                            <h2>{result.get('threat_score', 0)}/100</h2>
                        </div>
                        <div class="col-md-4">
                            <h5>IOC Type</h5>
                            <h2>{result.get('ioc_type', 'Unknown')}</h2>
                        </div>
                    </div>
                    <hr>
                    <div class="row">
                        <div class="col-md-6">
                            <p><strong>Sources Checked:</strong> {result.get('sources_checked', 0) or result.get('threat_intelligence', {}).get('sources_checked', 0)}</p>
                        </div>
                        <div class="col-md-6">
                            <p><strong>Sources Flagged:</strong> {result.get('sources_flagged', 0) or result.get('threat_intelligence', {}).get('sources_flagged', 0)}</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Charts -->
            <div class="row">
                <div class="col-md-8">
                    <div class="card mb-4">
                        <div class="card-header">
                            <h5>📈 Threat Score by Source</h5>
                        </div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="sourceScoreChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card mb-4">
                        <div class="card-header">
                            <h5>🎯 Verdict Distribution</h5>
                        </div>
                        <div class="card-body">
                            <div class="chart-container" style="height: 300px;">
                                <canvas id="verdictChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Detailed Sources -->
            {AdvancedReportGenerator._render_detailed_sources(result)}
            
            <!-- LLM Analysis -->
            {AdvancedReportGenerator._render_llm_analysis(result)}
        </div>
    </div>
    
    <!-- Theme Toggle Script -->
    <script>
{AdvancedReportGenerator._get_theme_script()}
    </script>
    
    <!-- Chart Data & Initialization -->
    <script>
        const sourcesData = {json.dumps(sources_data)};
        const verdictData = {json.dumps(verdict_data)};
        
        // Create charts when page loads
        window.addEventListener('load', function() {{
            createSourceScoreChart('sourceScoreChart', sourcesData);
            createVerdictChart('verdictChart', verdictData);
        }});
        
{AdvancedReportGenerator._get_chart_functions()}
    </script>
</body>
</html>
        """
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"[REPORT] Advanced IOC report saved: {output_path}")
        return output_path
    
    @staticmethod
    def _prepare_source_chart_data(result: Dict) -> List[Dict]:
        """Prepare data for source score chart."""
        # Try multiple key paths for backward compatibility
        sources = (
            result.get('sources', {}) or
            result.get('threat_intel_results', {}) or
            result.get('threat_intelligence', {}).get('sources', {})
        )
        
        data = []
        for name, info in sources.items():
            score = 0
            if isinstance(info, dict):
                # Calculate score based on various indicators
                if info.get('score'):
                    score = info.get('score')
                elif info.get('fraud_score'):
                    score = info.get('fraud_score')
                elif info.get('confidence'):
                    score = info.get('confidence')
                elif info.get('detections'):
                    detections = info.get('detections', '')
                    if isinstance(detections, str) and '/' in detections:
                        try:
                            mal, total = detections.split('/')
                            score = int(int(mal) / int(total) * 100) if int(total) > 0 else 0
                        except:
                            score = 50
                    else:
                        score = min(int(detections) * 10, 100) if isinstance(detections, int) else 50
                elif info.get('status') == '✓':
                    score = 50  # Default for flagged
            
            data.append({
                'name': name.upper(),
                'score': score
            })
        
        return sorted(data, key=lambda x: x['score'], reverse=True)[:15]  # Top 15
    
    @staticmethod
    def _prepare_verdict_data(result: Dict) -> Dict:
        """Prepare verdict distribution data."""
        # Try multiple key paths for backward compatibility
        sources = (
            result.get('sources', {}) or
            result.get('threat_intel_results', {}) or
            result.get('threat_intelligence', {}).get('sources', {})
        )
        
        verdicts = {'malicious': 0, 'suspicious': 0, 'clean': 0, 'unknown': 0}
        
        for info in sources.values():
            if not isinstance(info, dict):
                continue
            
            status = info.get('status', '')
            is_flagged = (
                status in ['✓', '✓ FLAGGED', 'FLAGGED'] or
                info.get('malicious', False) or
                (info.get('score', 0) or 0) > 30 or
                (info.get('fraud_score', 0) or 0) > 50
            )
            
            if is_flagged:
                verdicts['malicious'] += 1
            elif info.get('error'):
                verdicts['unknown'] += 1
            elif status == '✗':
                verdicts['clean'] += 1
            else:
                verdicts['clean'] += 1
        
        return verdicts
    
    @staticmethod
    def _verdict_class(verdict: str) -> str:
        """Get Bootstrap class for verdict."""
        classes = {
            'MALICIOUS': 'danger',
            'SUSPICIOUS': 'warning',
            'CLEAN': 'success',
            'UNKNOWN': 'secondary'
        }
        return classes.get(verdict, 'secondary')
    
    @staticmethod
    def _render_detailed_sources(result: Dict) -> str:
        """Render detailed source information."""
        # Try multiple key paths for backward compatibility
        sources = (
            result.get('sources', {}) or
            result.get('threat_intel_results', {}) or
            result.get('threat_intelligence', {}).get('sources', {})
        )
        
        html = """
        <div class="card mb-4">
            <div class="card-header">
                <h5>🔎 Detailed Source Analysis (22 Sources)</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped table-bordered">
                        <thead>
                            <tr>
                                <th>Source</th>
                                <th>Status</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        
        def _parse_detections(value) -> int:
            """Parse detection count from various formats."""
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                # Handle "1/95" format
                if '/' in value:
                    try:
                        return int(value.split('/')[0])
                    except:
                        return 0
                try:
                    return int(value)
                except:
                    return 0
            return 0
        
        for name, info in sources.items():
            if not isinstance(info, dict):
                continue
            
            status = '✅ CLEAN'
            details = 'No threats found'
            
            if info.get('error'):
                status = '⚠️ ERROR'
                details = info.get('error', 'Unknown error')
            elif info.get('found') or _parse_detections(info.get('detections', 0)) > 0 or info.get('status') in ['✓', '✓ FLAGGED', 'FLAGGED']:
                status = '🚨 FLAGGED'
                # Build better details
                if info.get('detections'):
                    details = f"Detections: {info.get('detections')}"
                elif info.get('fraud_score'):
                    details = f"Fraud Score: {info.get('fraud_score')}%"
                elif info.get('confidence'):
                    details = f"Confidence: {info.get('confidence')}%"
                elif info.get('score'):
                    details = f"Score: {info.get('score')}/100"
                else:
                    details = str(info)[:100]
            
            html += f"""
                            <tr>
                                <td><strong>{name.upper()}</strong></td>
                                <td>{status}</td>
                                <td><small>{details}</small></td>
                            </tr>
            """
        
        html += """
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
        
        return html
    
    @staticmethod
    def _render_llm_analysis(result: Dict) -> str:
        """Render LLM analysis section."""
        llm = result.get('llm_analysis', {})
        
        if not llm or not llm.get('analysis'):
            return ""
        
        html = f"""
        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h5>🤖 AI Analysis</h5>
            </div>
            <div class="card-body">
                <p class="lead">{llm.get('analysis', 'No analysis available')}</p>
                
                <h6 class="mt-4">Recommendations:</h6>
                <ol>
        """
        
        for rec in llm.get('recommendations', []):
            html += f"<li>{rec}</li>"
        
        html += """
                </ol>
            </div>
        </div>
        """
        
        return html
    
    @staticmethod
    def _get_embedded_css() -> str:
        """Get embedded CSS for report."""
        try:
            css_path = Path(__file__).parent.parent.parent / 'static' / 'css' / 'themes.css'
            if css_path.exists():
                with open(css_path, 'r') as f:
                    return f.read()
        except:
            pass
        
        # Fallback minimal CSS
        return """
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --text-primary: #212529;
            --border-color: #dee2e6;
        }
        [data-theme="dark"] {
            --bg-primary: #1a1d23;
            --bg-secondary: #242831;
            --text-primary: #e9ecef;
            --border-color: #495057;
        }
        body { background-color: var(--bg-primary); color: var(--text-primary); }
        .card { background-color: var(--bg-secondary); }
        .chart-container { height: 400px; margin: 20px 0; }
        """
    
    @staticmethod
    def _get_theme_script() -> str:
        """Get theme toggle script."""
        try:
            js_path = Path(__file__).parent.parent.parent / 'static' / 'js' / 'theme.js'
            if js_path.exists():
                with open(js_path, 'r') as f:
                    return f.read()
        except:
            pass
        
        # Fallback minimal theme script
        return """
        (function() {
            const theme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-theme', theme);
            
            const toggle = document.createElement('button');
            toggle.textContent = theme === 'dark' ? '☀️' : '🌙';
            toggle.style.cssText = 'position:fixed;top:20px;right:20px;z-index:1000;';
            toggle.onclick = () => {
                const newTheme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
                document.documentElement.setAttribute('data-theme', newTheme);
                localStorage.setItem('theme', newTheme);
                toggle.textContent = newTheme === 'dark' ? '☀️' : '🌙';
            };
            document.body.appendChild(toggle);
        })();
        """
    
    @staticmethod
    def _get_chart_functions() -> str:
        """Get chart creation functions."""
        try:
            js_path = Path(__file__).parent.parent.parent / 'static' / 'js' / 'charts.js'
            if js_path.exists():
                with open(js_path, 'r') as f:
                    return f.read()
        except:
            pass
        
        # Fallback minimal chart functions
        return """
        function createSourceScoreChart(canvasId, sourcesData) {
            new Chart(document.getElementById(canvasId), {
                type: 'bar',
                data: {
                    labels: sourcesData.map(s => s.name),
                    datasets: [{
                        label: 'Threat Score',
                        data: sourcesData.map(s => s.score),
                        backgroundColor: sourcesData.map(s => s.score > 70 ? '#dc3545' : s.score > 40 ? '#ffc107' : '#28a745')
                    }]
                },
                options: { scales: { y: { beginAtZero: true, max: 100 } } }
            });
        }
        
        function createVerdictChart(canvasId, verdictData) {
            new Chart(document.getElementById(canvasId), {
                type: 'doughnut',
                data: {
                    labels: ['Malicious', 'Clean', 'Unknown'],
                    datasets: [{
                        data: [verdictData.malicious, verdictData.clean, verdictData.unknown],
                        backgroundColor: ['#dc3545', '#28a745', '#6c757d']
                    }]
                }
            });
        }
        """

    @staticmethod
    def generate_advanced_email_report(result: Dict, output_path: str) -> str:
        """Generate advanced email analysis report with timeline."""
        
        email_data = result.get('email_analysis', {})
        forensics = result.get('email_forensics', {})
        
        # Prepare timeline data
        timeline_data = []
        if forensics.get('timeline'):
            for hop in forensics['timeline']:
                timeline_data.append({
                    'timestamp': hop.get('timestamp', ''),
                    'from_server': hop.get('from', 'Unknown'),
                    'from_ip': hop.get('ip', 'Unknown'),
                    'delay': hop.get('delay', 0)
                })
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Analysis Report</title>
    
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    
    <style>
{AdvancedReportGenerator._get_embedded_css()}
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="report-header">
            <h1>📧 Email Analysis Report</h1>
            <p class="lead">From: {email_data.get('from', 'Unknown')}</p>
            <p>Subject: {email_data.get('subject', 'No Subject')}</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
        
        <div class="container mt-4">
            <!-- Executive Summary -->
            <div class="card mb-4">
                <div class="card-header">
                    <h4>📊 Executive Summary</h4>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-4">
                            <h5>Verdict</h5>
                            <h2><span class="badge bg-{AdvancedReportGenerator._verdict_class(result.get('verdict'))}">{result.get('verdict', 'UNKNOWN')}</span></h2>
                        </div>
                        <div class="col-md-4">
                            <h5>Threat Score</h5>
                            <h2>{result.get('threat_score', 0)}/100</h2>
                        </div>
                        <div class="col-md-4">
                            <h5>Attachments</h5>
                            <h2>{len(email_data.get('attachments', []))}</h2>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Email Timeline -->
            {AdvancedReportGenerator._render_email_timeline(timeline_data)}
            
            <!-- Authentication Results -->
            {AdvancedReportGenerator._render_auth_results(forensics)}
            
            <!-- Threat Indicators -->
            {AdvancedReportGenerator._render_email_threats(email_data)}
            
            <!-- Forensics Details -->
            {AdvancedReportGenerator._render_forensics_details(forensics)}
        </div>
    </div>
    
    <script>
{AdvancedReportGenerator._get_theme_script()}
    </script>
    
    <script>
        const timelineData = {json.dumps(timeline_data)};
        
        window.addEventListener('load', function() {{
            if (timelineData.length > 0) {{
                createEmailTimelineChart('emailTimelineChart', timelineData);
            }}
        }});
        
{AdvancedReportGenerator._get_chart_functions()}
    </script>
</body>
</html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"[REPORT] Advanced email report saved: {output_path}")
        return output_path
    
    @staticmethod
    def _render_email_timeline(timeline_data: List[Dict]) -> str:
        """Render email relay timeline."""
        if not timeline_data:
            return ""
        
        html = """
        <div class="card mb-4">
            <div class="card-header">
                <h5>🕒 Email Relay Timeline</h5>
            </div>
            <div class="card-body">
                <div class="chart-container">
                    <canvas id="emailTimelineChart"></canvas>
                </div>
                
                <div class="timeline mt-4">
        """
        
        for i, hop in enumerate(timeline_data):
            html += f"""
                <div class="timeline-item">
                    <div class="timeline-dot"></div>
                    <div class="timeline-content">
                        <h6>Hop {i + 1}</h6>
                        <p><strong>From:</strong> {hop['from_server']}<br>
                        <strong>IP:</strong> {hop['from_ip']}<br>
                        <strong>Time:</strong> {hop['timestamp']}</p>
                    </div>
                </div>
            """
        
        html += """
                </div>
            </div>
        </div>
        """
        
        return html
    
    @staticmethod
    def _render_auth_results(forensics: Dict) -> str:
        """Render authentication results."""
        auth = forensics.get('authentication', {})
        if not auth:
            return ""
        
        spf = auth.get('spf', {})
        dkim = auth.get('dkim', {})
        dmarc = auth.get('dmarc', {})
        
        def status_badge(result):
            if result == 'pass':
                return '<span class="badge bg-success">PASS</span>'
            elif result == 'fail':
                return '<span class="badge bg-danger">FAIL</span>'
            else:
                return '<span class="badge bg-warning">UNKNOWN</span>'
        
        html = f"""
        <div class="card mb-4">
            <div class="card-header">
                <h5>🔐 Email Authentication</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-4">
                        <h6>SPF</h6>
                        {status_badge(spf.get('result', 'unknown'))}
                        <p><small>{spf.get('details', 'No details')}</small></p>
                    </div>
                    <div class="col-md-4">
                        <h6>DKIM</h6>
                        {status_badge(dkim.get('result', 'unknown'))}
                        <p><small>{dkim.get('details', 'No details')}</small></p>
                    </div>
                    <div class="col-md-4">
                        <h6>DMARC</h6>
                        {status_badge(dmarc.get('result', 'unknown'))}
                        <p><small>{dmarc.get('details', 'No details')}</small></p>
                    </div>
                </div>
            </div>
        </div>
        """
        
        return html
    
    @staticmethod
    def _render_email_threats(email_data: Dict) -> str:
        """Render detected email threats."""
        threats = []
        
        if email_data.get('suspicious_links'):
            threats.append(('Suspicious Links', len(email_data['suspicious_links']), 'warning'))
        
        if email_data.get('malicious_attachments'):
            threats.append(('Malicious Attachments', len(email_data['malicious_attachments']), 'danger'))
        
        if email_data.get('phishing_indicators'):
            threats.append(('Phishing Indicators', len(email_data['phishing_indicators']), 'danger'))
        
        if not threats:
            return ""
        
        html = """
        <div class="card mb-4">
            <div class="card-header">
                <h5>⚠️ Detected Threats</h5>
            </div>
            <div class="card-body">
                <div class="row">
        """
        
        for threat_name, count, severity in threats:
            html += f"""
                <div class="col-md-4">
                    <div class="alert alert-{severity}">
                        <h6>{threat_name}</h6>
                        <h3>{count}</h3>
                    </div>
                </div>
            """
        
        html += """
                </div>
            </div>
        </div>
        """
        
        return html
    
    @staticmethod
    def _render_forensics_details(forensics: Dict) -> str:
        """Render forensics details."""
        if not forensics:
            return ""
        
        html = """
        <div class="card mb-4">
            <div class="card-header">
                <h5>🔬 Forensics Details</h5>
            </div>
            <div class="card-body">
        """
        
        # Infrastructure fingerprint
        infra = forensics.get('infrastructure_fingerprint', {})
        if infra:
            html += f"""
            <h6>Infrastructure Analysis</h6>
            <ul>
                <li><strong>Mail Server:</strong> {infra.get('mail_server', 'Unknown')}</li>
                <li><strong>MTA:</strong> {infra.get('mta', 'Unknown')}</li>
                <li><strong>Infrastructure Type:</strong> {infra.get('type', 'Unknown')}</li>
            </ul>
            """
        
        # Sender reputation
        reputation = forensics.get('sender_reputation', {})
        if reputation:
            html += f"""
            <h6 class="mt-3">Sender Reputation</h6>
            <ul>
                <li><strong>Score:</strong> {reputation.get('score', 'Unknown')}</li>
                <li><strong>Status:</strong> {reputation.get('status', 'Unknown')}</li>
            </ul>
            """
        
        html += """
            </div>
        </div>
        """
        
        return html
    @staticmethod
    def generate_advanced_file_report(result: Dict, file_path: str, output_path: str) -> str:
        """Generate advanced file analysis report with sandbox visualization."""
        
        # Prepare sandbox data for radar chart
        sandbox_data = []
        sandbox_results = result.get('sandbox_analysis', {})
        
        if isinstance(sandbox_results, dict):
            for sandbox_name, sandbox_result in sandbox_results.items():
                if isinstance(sandbox_result, dict) and not sandbox_result.get('error'):
                    sandbox_data.append({
                        'name': sandbox_name,
                        'file_ops': min(sandbox_result.get('file_operations', 0), 100),
                        'registry': min(sandbox_result.get('registry_operations', 0), 100),
                        'network': min(sandbox_result.get('network_operations', 0), 100),
                        'process': min(sandbox_result.get('process_operations', 0), 100),
                        'api_calls': min(sandbox_result.get('api_calls', 0) / 10, 100)
                    })
        
        # File info
        file_info = result.get('file_info', {})
        pe_analysis = result.get('pe_analysis', {})
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Analysis Report - {Path(file_path).name}</title>
    
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    
    <style>
{AdvancedReportGenerator._get_embedded_css()}
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="report-header">
            <h1>📄 File Analysis Report</h1>
            <p class="lead">File: {Path(file_path).name}</p>
            <p>Type: {file_info.get('extension', 'Unknown').lstrip('.')} | Size: {file_info.get('size', 0):,} bytes ({file_info.get('size_mb', 0)} MB)</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
        
        <div class="container mt-4">
            <!-- Executive Summary -->
            <div class="card mb-4">
                <div class="card-header">
                    <h4>📊 Executive Summary</h4>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-3">
                            <h5>Verdict</h5>
                            <h2><span class="badge bg-{AdvancedReportGenerator._verdict_class(result.get('verdict'))}">{result.get('verdict', 'UNKNOWN')}</span></h2>
                        </div>
                        <div class="col-md-3">
                            <h5>Threat Score</h5>
                            <h2>{result.get('threat_score', 0)}/100</h2>
                        </div>
                        <div class="col-md-3">
                            <h5>Deep Static Risk</h5>
                            <h2>{pe_analysis.get('deep_static_risk_score', 0)}/100</h2>
                        </div>
                        <div class="col-md-3">
                            <h5>YARA Matches</h5>
                            <h2>{len(result.get('yara_matches', []))}</h2>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Sandbox Radar Chart -->
            {AdvancedReportGenerator._render_sandbox_radar(sandbox_data)}
            
            <!-- Deep Static Analysis -->
            {AdvancedReportGenerator._render_deep_static_analysis(pe_analysis)}
            
            <!-- Hash Reputation -->
            {AdvancedReportGenerator._render_hash_reputation(result)}
            
            <!-- YARA Matches -->
            {AdvancedReportGenerator._render_yara_matches(result)}
        </div>
    </div>
    
    <script>
{AdvancedReportGenerator._get_theme_script()}
    </script>
    
    <script>
        const sandboxData = {json.dumps(sandbox_data)};
        
        window.addEventListener('load', function() {{
            if (sandboxData.length > 0) {{
                createSandboxRadarChart('sandboxRadarChart', sandboxData);
            }}
        }});
        
{AdvancedReportGenerator._get_chart_functions()}
    </script>
</body>
</html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"[REPORT] Advanced file report saved: {output_path}")
        return output_path
    
    @staticmethod
    def _render_sandbox_radar(sandbox_data: List[Dict]) -> str:
        """Render sandbox behavioral radar chart."""
        if not sandbox_data:
            return ""
        
        html = """
        <div class="card mb-4">
            <div class="card-header">
                <h5>🎯 Sandbox Behavioral Analysis</h5>
            </div>
            <div class="card-body">
                <div class="chart-container">
                    <canvas id="sandboxRadarChart"></canvas>
                </div>
            </div>
        </div>
        """
        
        return html
    
    @staticmethod
    def _render_deep_static_analysis(pe_analysis: Dict) -> str:
        """Render deep static analysis results."""
        cert = pe_analysis.get('certificate_analysis', {})
        compiler = pe_analysis.get('compiler_analysis', {})
        overlay = pe_analysis.get('overlay_analysis', {})
        
        if not any([cert, compiler, overlay]):
            return ""
        
        html = """
        <div class="card mb-4">
            <div class="card-header">
                <h5>🔬 Deep Static Analysis</h5>
            </div>
            <div class="card-body">
                <div class="row">
        """
        
        # Certificate
        if cert:
            cert_trust = cert.get('trust', {})
            html += f"""
                <div class="col-md-4">
                    <h6>Digital Signature</h6>
                    <p><strong>Signed:</strong> {'Yes' if cert.get('signature', {}).get('signed') else 'No'}</p>
                    <p><strong>Valid:</strong> {'Yes' if cert.get('signature', {}).get('valid') else 'No'}</p>
                    <p><strong>Trust:</strong> {cert_trust.get('reason', 'Unknown')}</p>
                    <p><strong>Risk:</strong> {cert.get('risk_score', 0)}/100</p>
                </div>
            """
        
        # Compiler
        if compiler:
            compiler_det = compiler.get('detection', {})
            html += f"""
                <div class="col-md-4">
                    <h6>Compiler</h6>
                    <p><strong>Compiler:</strong> {compiler_det.get('compiler', 'Unknown')}</p>
                    <p><strong>Version:</strong> {compiler_det.get('version', 'Unknown')}</p>
                    <p><strong>PDB Path:</strong> {'Yes' if compiler_det.get('pdb_path') else 'No'}</p>
                    <p><strong>Risk:</strong> {compiler.get('risk_score', 0)}/100</p>
                </div>
            """
        
        # Overlay
        if overlay:
            html += f"""
                <div class="col-md-4">
                    <h6>Overlay</h6>
                    <p><strong>Has Overlay:</strong> {'Yes' if overlay.get('has_overlay') else 'No'}</p>
                    <p><strong>Size:</strong> {overlay.get('overlay_size', 0)} bytes</p>
                    <p><strong>Entropy:</strong> {overlay.get('characteristics', {}).get('entropy', 0):.2f}</p>
                    <p><strong>Risk:</strong> {overlay.get('risk_score', 0)}/100</p>
                </div>
            """
        
        html += """
                </div>
            </div>
        </div>
        """
        
        return html
    
    @staticmethod
    def _render_hash_reputation(result: Dict) -> str:
        """Render hash reputation from 22 sources."""
        reputation = result.get('hash_reputation', {})
        if not reputation:
            return ""
        
        sources = reputation.get('sources', {})
        flagged = [name for name, info in sources.items() if isinstance(info, dict) and (info.get('found') or info.get('detections', 0) > 0)]
        
        html = f"""
        <div class="card mb-4">
            <div class="card-header">
                <h5>🔍 Hash Reputation (22 Sources)</h5>
            </div>
            <div class="card-body">
                <p><strong>Sources Checked:</strong> {len(sources)}</p>
                <p><strong>Sources Flagged:</strong> {len(flagged)}</p>
                
                {f'<div class="alert alert-danger"><strong>Flagged by:</strong> {", ".join(flagged)}</div>' if flagged else '<div class="alert alert-success">Clean across all sources</div>'}
            </div>
        </div>
        """
        
        return html
    
    @staticmethod
    def _render_yara_matches(result: Dict) -> str:
        """Render YARA rule matches."""
        yara_matches = result.get('yara_matches', [])
        if not yara_matches:
            return ""
        
        html = """
        <div class="card mb-4">
            <div class="card-header">
                <h5>🎯 YARA Rule Matches</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Rule</th>
                                <th>Tags</th>
                                <th>Strings</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        
        for match in yara_matches:
            rule_name = match.get('rule', 'Unknown')
            tags = ', '.join(match.get('tags', []))
            strings_count = len(match.get('strings', []))
            
            html += f"""
                        <tr>
                            <td><strong>{rule_name}</strong></td>
                            <td>{tags}</td>
                            <td>{strings_count} matches</td>
                        </tr>
            """
        
        html += """
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
        
        return html
    
    @staticmethod
    def render_raw_data_section(raw_output: Dict) -> str:
        """
        Render raw data as collapsible accordion sections.
        
        Args:
            raw_output: Raw output dictionary from analysis
        
        Returns:
            HTML string with accordion view
        """
        if not raw_output:
            return "<p>No raw data available.</p>"
        
        html = """
        <div class="card mb-4">
            <div class="card-header bg-dark text-white">
                <h5>📄 Raw Analysis Data</h5>
                <small class="text-muted">Complete raw output from all analysis steps</small>
            </div>
            <div class="card-body">
                <div class="accordion" id="rawDataAccordion">
        """
        
        accordion_id = 0
        sections = [
            ('file_analysis', '📁 File Analysis', 'Raw file analysis data'),
            ('email_analysis', '📧 Email Analysis', 'Raw email analysis data'),
            ('ioc_analysis', '🎯 IOC Analysis', 'IOC investigation results'),
            ('api_responses', '🌐 API Responses', 'Raw API responses from threat intel'),
            ('scoring_details', '📊 Scoring Details', 'Score breakdown and weights'),
            ('detection_rules', '🛡️ Detection Rules', 'Generated detection rules'),
            ('pipeline_steps', '⚙️ Pipeline Steps', 'Analysis pipeline execution'),
        ]
        
        for key, title, description in sections:
            data = raw_output.get(key, {})
            if data:
                accordion_id += 1
                collapsed = 'collapsed' if accordion_id > 1 else ''
                show = 'show' if accordion_id == 1 else ''
                
                html += f"""
                    <div class="accordion-item">
                        <h2 class="accordion-header" id="heading_{accordion_id}">
                            <button class="accordion-button {collapsed}" type="button" 
                                    data-bs-toggle="collapse" data-bs-target="#collapse_{accordion_id}">
                                {title}
                            </button>
                        </h2>
                        <div id="collapse_{accordion_id}" class="accordion-collapse collapse {show}" 
                             data-bs-parent="#rawDataAccordion">
                            <div class="accordion-body">
                                <p class="text-muted small">{description}</p>
                                <pre class="bg-dark text-light p-3" style="max-height: 400px; overflow: auto; font-size: 12px;">
{json.dumps(data, indent=2, default=str)}
                                </pre>
                                <button class="btn btn-sm btn-outline-primary mt-2" 
                                        onclick="navigator.clipboard.writeText(document.getElementById('collapse_{accordion_id}').querySelector('pre').textContent).then(() => alert('Copied!'))">
                                    📋 Copy to Clipboard
                                </button>
                            </div>
                        </div>
                    </div>
                """
        
        # Full JSON export
        accordion_id += 1
        html += f"""
                    <div class="accordion-item">
                        <h2 class="accordion-header" id="heading_{accordion_id}">
                            <button class="accordion-button collapsed" type="button" 
                                    data-bs-toggle="collapse" data-bs-target="#collapse_{accordion_id}">
                                📄 Full JSON Export
                            </button>
                        </h2>
                        <div id="collapse_{accordion_id}" class="accordion-collapse collapse" 
                             data-bs-parent="#rawDataAccordion">
                            <div class="accordion-body">
                                <p class="text-muted small">Complete raw analysis data in JSON format</p>
                                <pre class="bg-dark text-light p-3" style="max-height: 500px; overflow: auto; font-size: 11px;">
{json.dumps(raw_output, indent=2, default=str)}
                                </pre>
                                <button class="btn btn-sm btn-outline-success mt-2" 
                                        onclick="navigator.clipboard.writeText(document.getElementById('collapse_{accordion_id}').querySelector('pre').textContent).then(() => alert('Copied!'))">
                                    📋 Copy Full JSON
                                </button>
                                <a class="btn btn-sm btn-outline-info mt-2 ms-2" 
                                   href="data:application/json;charset=utf-8,{json.dumps(raw_output, default=str).replace('"', '%22')}"
                                   download="raw_analysis_data.json">
                                    💾 Download JSON
                                </a>
                            </div>
                        </div>
                    </div>
        """
        
        html += """
                </div>
            </div>
        </div>
        """
        
        return html
    
    @staticmethod  
    def render_sandbox_links_section(hashes: Dict, sandbox_results: Dict = None) -> str:
        """
        Render sandbox analysis links with clickable URLs.
        
        Args:
            hashes: File hashes dict
            sandbox_results: Optional sandbox analysis results
        
        Returns:
            HTML string with sandbox links
        """
        sha256 = hashes.get('sha256', '')
        md5 = hashes.get('md5', '')
        
        if not sha256:
            return "<p>No hash available for sandbox lookups.</p>"
        
        html = """
        <div class="card mb-4">
            <div class="card-header bg-info text-white">
                <h5>🔒 Sandbox & Analysis Links</h5>
            </div>
            <div class="card-body">
                <div class="row">
        """
        
        sandboxes = [
            ('VirusTotal', f'https://www.virustotal.com/gui/file/{sha256}', '🦠'),
            ('Hybrid Analysis', f'https://www.hybrid-analysis.com/search?query={sha256}', '🔬'),
            ('ANY.RUN', f'https://app.any.run/submissions/#filehash:{sha256}', '🏃'),
            ('Joe Sandbox', f'https://www.joesandbox.com/search?q={sha256}', '📦'),
            ('MalwareBazaar', f'https://bazaar.abuse.ch/sample/{sha256}/', '🗃️'),
            ('Triage', f'https://tria.ge/s?q={sha256}', '📊'),
            ('URLhaus', f'https://urlhaus.abuse.ch/browse.php?search={sha256}', '🔗'),
            ('ThreatFox', f'https://threatfox.abuse.ch/browse.php?search=ioc%3A{sha256}', '🦊'),
        ]
        
        for name, url, icon in sandboxes:
            # Check if we have results from this sandbox
            status = '⚪'
            if sandbox_results:
                key = name.lower().replace(' ', '_').replace('.', '')
                if key in sandbox_results:
                    sb_data = sandbox_results[key]
                    if sb_data.get('found') or sb_data.get('status') == 'found':
                        status = '🟢'
                    elif sb_data.get('error'):
                        status = '🔴'
                    else:
                        status = '⚪'
            
            html += f"""
                    <div class="col-md-3 mb-3">
                        <a href="{url}" target="_blank" class="btn btn-outline-secondary w-100">
                            {icon} {name} {status}
                        </a>
                    </div>
            """
        
        html += """
                </div>
                <p class="text-muted small mt-3">
                    🟢 Report found | ⚪ Not checked | 🔴 Error/Not found
                </p>
            </div>
        </div>
        """
        
        return html
