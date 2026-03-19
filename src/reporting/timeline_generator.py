"""
Author: Ugur Ates
Timeline Attack Flow Generator - Visualize attack chain and kill chain phases.

v1.0.0 Features:
- Attack timeline generation
- Cyber Kill Chain mapping
- MITRE ATT&CK flow visualization
- Mermaid diagram export
- JSON timeline for frontend
- HTML interactive timeline
- Event correlation

Best Practice: Used for incident investigation and threat hunting
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)
class KillChainPhase(Enum):
    """Lockheed Martin Cyber Kill Chain phases."""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"
class AttackStage(Enum):
    """Generic attack stages."""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
@dataclass
class TimelineEvent:
    """Single event in attack timeline."""
    timestamp: str
    phase: str
    technique: str
    technique_id: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    severity: str = "medium"
    source: str = ""
    iocs: List[str] = field(default_factory=list)
@dataclass
class AttackFlow:
    """Complete attack flow."""
    name: str
    description: str = ""
    events: List[TimelineEvent] = field(default_factory=list)
    kill_chain: Dict[str, List[str]] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    total_duration: str = ""
    severity: str = "medium"
    metadata: Dict = field(default_factory=dict)
class TimelineGenerator:
    """
    Generate attack timelines and flow visualizations.
    
    Features:
    - Chronological event ordering
    - Kill chain phase mapping
    - MITRE ATT&CK correlation
    - Multiple export formats
    """
    
    # Technique to Kill Chain mapping
    TECHNIQUE_TO_KILL_CHAIN = {
        # Reconnaissance
        'T1595': KillChainPhase.RECONNAISSANCE,
        'T1592': KillChainPhase.RECONNAISSANCE,
        'T1589': KillChainPhase.RECONNAISSANCE,
        
        # Delivery
        'T1566': KillChainPhase.DELIVERY,
        'T1566.001': KillChainPhase.DELIVERY,
        'T1566.002': KillChainPhase.DELIVERY,
        'T1189': KillChainPhase.DELIVERY,
        
        # Exploitation/Execution
        'T1059': KillChainPhase.EXPLOITATION,
        'T1059.001': KillChainPhase.EXPLOITATION,
        'T1059.003': KillChainPhase.EXPLOITATION,
        'T1059.005': KillChainPhase.EXPLOITATION,
        'T1204': KillChainPhase.EXPLOITATION,
        
        # Installation/Persistence
        'T1547': KillChainPhase.INSTALLATION,
        'T1547.001': KillChainPhase.INSTALLATION,
        'T1053': KillChainPhase.INSTALLATION,
        'T1543': KillChainPhase.INSTALLATION,
        
        # C2
        'T1071': KillChainPhase.COMMAND_AND_CONTROL,
        'T1071.001': KillChainPhase.COMMAND_AND_CONTROL,
        'T1105': KillChainPhase.COMMAND_AND_CONTROL,
        'T1573': KillChainPhase.COMMAND_AND_CONTROL,
        
        # Actions
        'T1486': KillChainPhase.ACTIONS_ON_OBJECTIVES,
        'T1490': KillChainPhase.ACTIONS_ON_OBJECTIVES,
        'T1003': KillChainPhase.ACTIONS_ON_OBJECTIVES,
        'T1041': KillChainPhase.ACTIONS_ON_OBJECTIVES,
    }
    
    # Indicator to technique mapping
    INDICATOR_TO_TECHNIQUE = {
        'download': ('T1105', 'Ingress Tool Transfer'),
        'powershell': ('T1059.001', 'PowerShell'),
        'cmd': ('T1059.003', 'Windows Command Shell'),
        'vbscript': ('T1059.005', 'Visual Basic'),
        'registry run': ('T1547.001', 'Registry Run Keys'),
        'scheduled task': ('T1053.005', 'Scheduled Task'),
        'service': ('T1543.003', 'Windows Service'),
        'http': ('T1071.001', 'Web Protocols'),
        'credential': ('T1003', 'OS Credential Dumping'),
        'encrypt': ('T1486', 'Data Encrypted for Impact'),
        'shadow': ('T1490', 'Inhibit System Recovery'),
        'injection': ('T1055', 'Process Injection'),
        'obfuscate': ('T1027', 'Obfuscated Files'),
        'base64': ('T1140', 'Deobfuscate/Decode'),
        'defender': ('T1562.001', 'Disable Security Tools'),
    }
    
    def __init__(self):
        """Initialize generator."""
        pass
    
    def generate_from_analysis(self, analysis_result: Dict) -> AttackFlow:
        """
        Generate attack flow from file/email analysis.
        
        Args:
            analysis_result: Analysis result dict
        
        Returns:
            AttackFlow object
        """
        events = []
        techniques_seen = set()
        
        # Extract file info
        file_info = analysis_result.get('file_info', {})
        file_name = file_info.get('file_name', 'Unknown')
        
        # 1. Initial detection event
        events.append(TimelineEvent(
            timestamp=datetime.now().isoformat(),
            phase=AttackStage.INITIAL_ACCESS.value,
            technique="File Detected",
            description=f"Suspicious file detected: {file_name}",
            source="file_analysis",
            severity=self._score_to_severity(
                analysis_result.get('composite_score', 0)
            )
        ))
        
        # 2. From threat indicators
        static = analysis_result.get('static_analysis', {})
        indicators = static.get('threat_indicators', [])
        
        for indicator in indicators:
            event = self._indicator_to_event(indicator)
            if event:
                events.append(event)
                if event.technique_id:
                    techniques_seen.add(event.technique_id)
        
        # 3. From capabilities (capa)
        caps = analysis_result.get('capabilities', {})
        for att in caps.get('attack_techniques', []):
            tech_id = att.get('id', '')
            if tech_id and tech_id not in techniques_seen:
                events.append(TimelineEvent(
                    timestamp=datetime.now().isoformat(),
                    phase=self._technique_to_stage(tech_id),
                    technique=att.get('technique', tech_id),
                    technique_id=tech_id,
                    description=f"Capability: {att.get('capability', '')}",
                    source="capa",
                    severity="high"
                ))
                techniques_seen.add(tech_id)
        
        # 4. From suspicious patterns
        patterns = static.get('suspicious_patterns', {}).get('categories', {})
        for category, data in patterns.items():
            event = self._pattern_to_event(category, data)
            if event:
                events.append(event)
        
        # 5. From sandbox behaviors
        sandbox = analysis_result.get('sandbox_analysis', {})
        for tech_id in sandbox.get('mitre_techniques', []):
            if tech_id.startswith('T') and tech_id not in techniques_seen:
                events.append(TimelineEvent(
                    timestamp=datetime.now().isoformat(),
                    phase=self._technique_to_stage(tech_id),
                    technique=tech_id,
                    technique_id=tech_id,
                    description="Observed in sandbox execution",
                    source="sandbox",
                    severity="critical"
                ))
                techniques_seen.add(tech_id)
        
        # Sort events by phase (rough kill chain order)
        events = self._sort_by_kill_chain(events)
        
        # Build kill chain mapping
        kill_chain = self._build_kill_chain(events)
        
        # Create flow
        flow = AttackFlow(
            name=f"Analysis: {file_name}",
            description=f"Attack flow for {file_name}",
            events=events,
            kill_chain=kill_chain,
            mitre_techniques=list(techniques_seen),
            severity=self._score_to_severity(
                analysis_result.get('composite_score', 0)
            ),
            metadata={
                'file_name': file_name,
                'sha256': analysis_result.get('hashes', {}).get('sha256', ''),
                'analysis_date': datetime.now().isoformat(),
                'verdict': analysis_result.get('verdict', 'Unknown'),
                'score': analysis_result.get('composite_score', 0)
            }
        )
        
        return flow
    
    def _indicator_to_event(self, indicator: str) -> Optional[TimelineEvent]:
        """Convert indicator to timeline event."""
        indicator_lower = indicator.lower()
        
        for keyword, (tech_id, tech_name) in self.INDICATOR_TO_TECHNIQUE.items():
            if keyword in indicator_lower:
                return TimelineEvent(
                    timestamp=datetime.now().isoformat(),
                    phase=self._technique_to_stage(tech_id),
                    technique=tech_name,
                    technique_id=tech_id,
                    description=indicator,
                    source="static_analysis",
                    severity="medium"
                )
        
        return None
    
    def _pattern_to_event(self, category: str, data: Dict) -> Optional[TimelineEvent]:
        """Convert suspicious pattern to event."""
        category_mapping = {
            'download': (AttackStage.INITIAL_ACCESS, 'T1105', 'Tool Transfer'),
            'execution': (AttackStage.EXECUTION, 'T1059', 'Command Execution'),
            'persistence': (AttackStage.PERSISTENCE, 'T1547', 'Persistence'),
            'evasion': (AttackStage.DEFENSE_EVASION, 'T1027', 'Defense Evasion'),
            'credential': (AttackStage.CREDENTIAL_ACCESS, 'T1003', 'Credential Access'),
            'encoding': (AttackStage.DEFENSE_EVASION, 'T1140', 'Deobfuscation'),
            'network': (AttackStage.INITIAL_ACCESS, 'T1071', 'Network Communication'),
        }
        
        if category in category_mapping:
            stage, tech_id, tech_name = category_mapping[category]
            samples = data.get('samples', [])
            
            return TimelineEvent(
                timestamp=datetime.now().isoformat(),
                phase=stage.value,
                technique=tech_name,
                technique_id=tech_id,
                description=f"{category}: {data.get('count', 0)} patterns",
                evidence=samples[:3],
                source="pattern_analysis",
                severity="medium" if data.get('count', 0) < 5 else "high"
            )
        
        return None
    
    def _technique_to_stage(self, tech_id: str) -> str:
        """Map technique to attack stage."""
        stage_mapping = {
            'T1566': AttackStage.INITIAL_ACCESS,
            'T1059': AttackStage.EXECUTION,
            'T1547': AttackStage.PERSISTENCE,
            'T1053': AttackStage.PERSISTENCE,
            'T1055': AttackStage.DEFENSE_EVASION,
            'T1027': AttackStage.DEFENSE_EVASION,
            'T1140': AttackStage.DEFENSE_EVASION,
            'T1562': AttackStage.DEFENSE_EVASION,
            'T1003': AttackStage.CREDENTIAL_ACCESS,
            'T1082': AttackStage.DISCOVERY,
            'T1071': AttackStage.INITIAL_ACCESS,
            'T1105': AttackStage.INITIAL_ACCESS,
            'T1486': AttackStage.IMPACT,
            'T1490': AttackStage.IMPACT,
        }
        
        # Check base technique
        base_tech = tech_id.split('.')[0] if '.' in tech_id else tech_id
        
        if tech_id in stage_mapping:
            return stage_mapping[tech_id].value
        if base_tech in stage_mapping:
            return stage_mapping[base_tech].value
        
        return AttackStage.EXECUTION.value
    
    def _score_to_severity(self, score: int) -> str:
        """Convert score to severity."""
        if score >= 70:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 30:
            return "medium"
        return "low"
    
    def _sort_by_kill_chain(self, events: List[TimelineEvent]) -> List[TimelineEvent]:
        """Sort events by kill chain phase."""
        phase_order = {
            AttackStage.INITIAL_ACCESS.value: 0,
            AttackStage.EXECUTION.value: 1,
            AttackStage.PERSISTENCE.value: 2,
            AttackStage.PRIVILEGE_ESCALATION.value: 3,
            AttackStage.DEFENSE_EVASION.value: 4,
            AttackStage.CREDENTIAL_ACCESS.value: 5,
            AttackStage.DISCOVERY.value: 6,
            AttackStage.LATERAL_MOVEMENT.value: 7,
            AttackStage.COLLECTION.value: 8,
            AttackStage.EXFILTRATION.value: 9,
            AttackStage.IMPACT.value: 10,
        }
        
        return sorted(events, key=lambda e: phase_order.get(e.phase, 99))
    
    def _build_kill_chain(self, events: List[TimelineEvent]) -> Dict[str, List[str]]:
        """Build kill chain mapping."""
        kill_chain = {}
        
        for event in events:
            if event.technique_id:
                kc_phase = self.TECHNIQUE_TO_KILL_CHAIN.get(
                    event.technique_id,
                    KillChainPhase.EXPLOITATION
                )
                
                phase_name = kc_phase.value
                if phase_name not in kill_chain:
                    kill_chain[phase_name] = []
                
                if event.technique_id not in kill_chain[phase_name]:
                    kill_chain[phase_name].append(event.technique_id)
        
        return kill_chain
    
    def export_mermaid(self, flow: AttackFlow) -> str:
        """
        Export attack flow as Mermaid diagram.
        
        Returns:
            Mermaid diagram string
        """
        lines = ["```mermaid", "flowchart TD"]
        
        # Style definitions
        lines.append("    classDef critical fill:#dc3545,color:white")
        lines.append("    classDef high fill:#fd7e14,color:white")
        lines.append("    classDef medium fill:#ffc107,color:black")
        lines.append("    classDef low fill:#28a745,color:white")
        lines.append("")
        
        # Create nodes and connections
        prev_node = None
        node_id = 0
        
        for event in flow.events:
            node_name = f"N{node_id}"
            technique = event.technique.replace('"', "'")[:30]
            
            if event.technique_id:
                label = f"{event.technique_id}: {technique}"
            else:
                label = technique
            
            lines.append(f'    {node_name}["{label}"]')
            
            # Apply style
            if event.severity == "critical":
                lines.append(f"    class {node_name} critical")
            elif event.severity == "high":
                lines.append(f"    class {node_name} high")
            elif event.severity == "medium":
                lines.append(f"    class {node_name} medium")
            else:
                lines.append(f"    class {node_name} low")
            
            # Connect to previous
            if prev_node:
                lines.append(f"    {prev_node} --> {node_name}")
            
            prev_node = node_name
            node_id += 1
        
        lines.append("```")
        
        return "\n".join(lines)
    
    def export_json(self, flow: AttackFlow) -> str:
        """Export attack flow as JSON."""
        return json.dumps(asdict(flow), indent=2, default=str)
    
    def export_html_timeline(self, flow: AttackFlow) -> str:
        """
        Export as interactive HTML timeline.
        
        Returns:
            HTML string
        """
        events_json = json.dumps([asdict(e) for e in flow.events], default=str)
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Attack Timeline: {flow.name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .timeline {{ position: relative; margin: 20px 0; padding-left: 40px; }}
        .timeline::before {{
            content: '';
            position: absolute;
            left: 15px;
            top: 0;
            bottom: 0;
            width: 4px;
            background: #ddd;
        }}
        .event {{
            position: relative;
            margin-bottom: 20px;
            padding: 15px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .event::before {{
            content: '';
            position: absolute;
            left: -33px;
            top: 20px;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            border: 3px solid white;
        }}
        .event.critical::before {{ background: #dc3545; }}
        .event.high::before {{ background: #fd7e14; }}
        .event.medium::before {{ background: #ffc107; }}
        .event.low::before {{ background: #28a745; }}
        .phase {{ color: #666; font-size: 12px; text-transform: uppercase; }}
        .technique {{ font-weight: bold; font-size: 16px; margin: 5px 0; }}
        .technique-id {{ color: #0066cc; font-family: monospace; }}
        .description {{ color: #333; margin: 10px 0; }}
        .evidence {{ font-size: 12px; color: #666; font-family: monospace; }}
        .header {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{ margin: 0; }}
        .header .meta {{ opacity: 0.8; margin-top: 10px; }}
        .kill-chain {{
            display: flex;
            gap: 10px;
            margin: 20px 0;
            flex-wrap: wrap;
        }}
        .kc-phase {{
            padding: 10px 15px;
            background: #e9ecef;
            border-radius: 20px;
            font-size: 12px;
        }}
        .kc-phase.active {{
            background: #667eea;
            color: white;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 Attack Timeline</h1>
        <div class="meta">
            <strong>{flow.name}</strong><br>
            Verdict: {flow.metadata.get('verdict', 'Unknown')} | 
            Score: {flow.metadata.get('score', 0)}/100 |
            Techniques: {len(flow.mitre_techniques)}
        </div>
    </div>
    
    <h3>Kill Chain Coverage</h3>
    <div class="kill-chain">
        <span class="kc-phase {'active' if 'reconnaissance' in flow.kill_chain else ''}">Reconnaissance</span>
        <span class="kc-phase {'active' if 'delivery' in flow.kill_chain else ''}">Delivery</span>
        <span class="kc-phase {'active' if 'exploitation' in flow.kill_chain else ''}">Exploitation</span>
        <span class="kc-phase {'active' if 'installation' in flow.kill_chain else ''}">Installation</span>
        <span class="kc-phase {'active' if 'command_and_control' in flow.kill_chain else ''}">C2</span>
        <span class="kc-phase {'active' if 'actions_on_objectives' in flow.kill_chain else ''}">Actions</span>
    </div>
    
    <h3>Event Timeline</h3>
    <div class="timeline" id="timeline"></div>
    
    <script>
        const events = {events_json};
        const timeline = document.getElementById('timeline');
        
        events.forEach(event => {{
            const div = document.createElement('div');
            div.className = 'event ' + event.severity;
            
            let html = `
                <div class="phase">${{event.phase}}</div>
                <div class="technique">
                    ${{event.technique_id ? '<span class="technique-id">' + event.technique_id + '</span> ' : ''}}
                    ${{event.technique}}
                </div>
                <div class="description">${{event.description}}</div>
            `;
            
            if (event.evidence && event.evidence.length > 0) {{
                html += '<div class="evidence">Evidence:<br>';
                event.evidence.forEach(e => {{
                    html += '• ' + e.substring(0, 60) + '<br>';
                }});
                html += '</div>';
            }}
            
            div.innerHTML = html;
            timeline.appendChild(div);
        }});
    </script>
</body>
</html>"""
        
        return html
# ==================== HELPER FUNCTIONS ====================

def generate_attack_timeline(analysis_result: Dict) -> Dict:
    """
    Generate attack timeline from analysis.
    
    Args:
        analysis_result: Analysis result dict
    
    Returns:
        Timeline dict
    """
    generator = TimelineGenerator()
    flow = generator.generate_from_analysis(analysis_result)
    return asdict(flow)
def export_timeline_mermaid(analysis_result: Dict) -> str:
    """Export timeline as Mermaid diagram."""
    generator = TimelineGenerator()
    flow = generator.generate_from_analysis(analysis_result)
    return generator.export_mermaid(flow)
def export_timeline_html(analysis_result: Dict, output_path: str) -> str:
    """Export timeline as HTML file."""
    generator = TimelineGenerator()
    flow = generator.generate_from_analysis(analysis_result)
    html = generator.export_html_timeline(flow)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    logger.info(f"[TIMELINE] Exported to: {output_path}")
    return output_path
