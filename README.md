# Blue Team Assistant

LLM supported Toolkit for Blue Team/<img width="1189" height="983" alt="Ekran görüntüsü 2026-01-08 113358" src="https://github.com/user-attachments/assets/2c91250b-c5c6-41b0-b47d-fca6e2765e16" />
 SOC Operations
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/ugur-ates/blue-team-assistant)

Blue Team Assistant is a comprehensive, local-first security analysis toolkit designed for Tier 2/3 SOC analysts, incident responders, and threat hunters. It integrates 20+ threat intelligence sources, professional malware analysis tools, and AI-powered analysis with local LLM support via Ollama.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [CLI Commands](#cli-commands)
  - [MCP Server Mode](#mcp-server-mode)
- [Analysis Modules](#analysis-modules)
  - [File Analyzers](#file-analyzers)
  - [Email Analysis](#email-analysis)
  - [IOC Investigation](#ioc-investigation)
- [LLM Integration](#llm-integration)
  - [Ollama Setup](#ollama-setup-recommended)
  - [LLM Analysis Features](#llm-analysis-features)
  - [Cloud Providers](#cloud-providers-optional)
- [Threat Intelligence Sources](#threat-intelligence-sources)
- [Scoring System](#scoring-system)
- [Detection Rule Generation](#detection-rule-generation)
- [Reporting](#reporting)
- [False Positive Filtering](#false-positive-filtering)
- [Project Structure](#project-structure)
- [API Reference](#api-reference)
- [Roadmap](#roadmap)
  - [v2.0.0 Features](#v200-future)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **Multi-Source Threat Intelligence** | 20+ integrated sources including VirusTotal, Shodan, AbuseIPDB, AlienVault OTX |
| **Professional Malware Analysis** | PE/ELF/Mach-O parsing, entropy analysis, YARA scanning, string extraction |
| **Email Forensics** | Header analysis, attachment extraction, phishing detection, URL chain analysis |
| **Local-First Architecture** | Ollama LLM integration for offline AI analysis |
| **Automated Detection Rules** | YARA, Sigma, KQL, Snort/Suricata rule generation |
| **Interactive HTML Reports** | Professional reports with MITRE ATT&CK mapping |
| **False Positive Filtering** | Intelligent filtering for CA domains, version strings, namespaces |

### Key Differentiators

- **Zero Cloud Dependency**: All analysis can run locally with Ollama
- **Aviation-Focused Threat Intel**: Specialized for critical infrastructure
- **Production-Grade Scoring**: Tool-based composite scoring with confidence levels
- **Real-Time Investigation**: Async operations for fast multi-source lookups

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Blue Team Assistant                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
│  │   CLI       │  │ MCP Server  │  │   Python    │                 │
│  │ soc_agent   │  │   server    │  │    API      │                 │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                 │
│         │                │                │                         │
│         └────────────────┼────────────────┘                         │
│                          ▼                                          │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                      TOOLS LAYER                               │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐  │ │
│  │  │  Malware    │ │   Email     │ │    IOC Investigator     │  │ │
│  │  │  Analyzer   │ │  Analyzer   │ │  (IP/Domain/URL/Hash)   │  │ │
│  │  └──────┬──────┘ └──────┬──────┘ └───────────┬─────────────┘  │ │
│  └─────────┼───────────────┼───────────────────┼─────────────────┘ │
│            │               │                   │                    │
│            ▼               ▼                   ▼                    │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                    ANALYZERS LAYER                             │ │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐       │ │
│  │  │   PE   │ │  ELF   │ │ Office │ │  PDF   │ │ Script │       │ │
│  │  │Analyzer│ │Analyzer│ │Analyzer│ │Analyzer│ │Analyzer│       │ │
│  │  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘       │ │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐       │ │
│  │  │Archive │ │  APK   │ │ Mach-O │ │Firmware│ │  YARA  │       │ │
│  │  │Analyzer│ │Analyzer│ │Analyzer│ │Analyzer│ │Scanner │       │ │
│  │  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘       │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                          │                                          │
│                          ▼                                          │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                  INTEGRATIONS LAYER                            │ │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌───────────────┐  │ │
│  │  │ Threat Intel    │  │   Sandboxes     │  │  LLM Analyzer │  │ │
│  │  │ (20+ sources)   │  │ (VT/HA/Joe/etc) │  │   (Ollama)    │  │ │
│  │  └─────────────────┘  └─────────────────┘  └───────────────┘  │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                          │                                          │
│                          ▼                                          │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                    OUTPUT LAYER                                │ │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐       │ │
│  │  │  HTML  │ │Markdown│ │  JSON  │ │  PDF   │ │ MITRE  │       │ │
│  │  │ Report │ │ Report │ │ Export │ │Summary │ │Navigator│       │ │
│  │  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘       │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Installation

### Prerequisites

- Python 3.10+
- Ollama (for local LLM analysis)
- Optional: capa, FLOSS, Detect It Easy (DIE) for professional analysis

### Quick Start

```bash
# Clone repository
git clone https://github.com/ugur-ates/blue-team-assistant.git
cd blue-team-assistant

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Copy and configure
cp config.yaml.example config.yaml
# Edit config.yaml with your API keys

# Verify installation
python test_setup.py
```

### Installing Professional Tools (Optional)

```bash
# capa - Capability detection
pip install flare-capa

# FLOSS - Obfuscated string extraction
# Download from: https://github.com/mandiant/flare-floss/releases

# Detect It Easy (DIE)
# Download from: https://github.com/horsicq/DIE-engine/releases
```

### Ollama Setup

For AI-powered analysis, install Ollama (see [LLM Integration](#llm-integration) for details):

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull recommended model
ollama pull llama3.1:8b

# Verify
ollama list
```

---

## Configuration

Edit `config.yaml` with your settings:

```yaml
# API Keys
api_keys:
  virustotal: "your-vt-api-key"
  abuseipdb: "your-abuseipdb-key"
  shodan: "your-shodan-key"
  alienvault: "your-otx-key"
  # ... more keys

# LLM Configuration
llm:
  provider: "ollama"           # ollama, openai, anthropic
  model: "llama3.1:8b"
  base_url: "http://localhost:11434"
  temperature: 0.3
  max_tokens: 2000

# Analysis Options
analysis:
  enable_llm: true
  enable_sandbox_check: true
  enable_yara: true
  max_iocs_to_investigate: 30
  timeout: 30

# Output Settings
output:
  default_format: "html"
  include_raw_data: false
  generate_mitre_mapping: true
```

### API Key Sources

| Source | Free Tier | Registration URL |
|--------|-----------|------------------|
| VirusTotal | 500 req/day | https://www.virustotal.com/gui/join-us |
| AbuseIPDB | 1000 req/day | https://www.abuseipdb.com/register |
| Shodan | 100 req/month | https://account.shodan.io/register |
| AlienVault OTX | Unlimited | https://otx.alienvault.com/accounts/signup |
| IPQualityScore | 5000 req/month | https://www.ipqualityscore.com/create-account |
| GreyNoise | 50 req/day | https://viz.greynoise.io/signup |

---

## Usage

### CLI Commands

#### File Analysis

```bash
# Basic file analysis
python -m src.soc_agent file malware.exe

# With HTML report
python -m src.soc_agent file malware.exe --report analysis.html

# With JSON output
python -m src.soc_agent file malware.exe --json results.json

# Verbose mode
python -m src.soc_agent file malware.exe --verbose
```

#### IOC Investigation

```bash
# Single IOC
python -m src.soc_agent ioc 185.220.101.1

# Multiple IOCs
python -m src.soc_agent ioc 185.220.101.1 evil.com abc123hash

# From file
python -m src.soc_agent ioc --file iocs.txt --report ioc_report.html
```

#### Email Analysis

```bash
# Analyze .eml file
python -m src.soc_agent email suspicious.eml --report email_report.html

# With attachment extraction
python -m src.soc_agent email phishing.eml --extract-attachments ./attachments/
```

#### URL Decoding

```bash
# Microsoft Safelinks
python -m src.soc_agent decode-url "https://nam02.safelinks.protection.outlook.com/?url=..."

# Proofpoint
python -m src.soc_agent decode-url "https://urldefense.proofpoint.com/v2/url?u=..."
```

### MCP Server Mode

For integration with Claude Desktop or other MCP clients:

```bash
# Start MCP server
python -m src.server

# Or with custom config
python -m src.server --config /path/to/config.yaml
```

Add to Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "blue-team-assistant": {
      "command": "python",
      "args": ["-m", "src.server"],
      "cwd": "/path/to/blue-team-assistant"
    }
  }
}
```

---

## Analysis Modules

### File Analyzers

#### PE Analyzer (Windows Executables)

Analyzes Windows PE files (.exe, .dll, .sys):

```python
from src.analyzers.pe_analyzer import PEAnalyzer

analyzer = PEAnalyzer()
result = analyzer.analyze("sample.exe")

# Returns:
# - Headers: Machine type, compile time, entry point
# - Sections: Name, entropy, flags (executable/writable)
# - Imports: DLLs and functions
# - Exports: Exported functions
# - Resources: Embedded resources
# - Security: ASLR, DEP, CFG status
# - Signatures: Digital signature info
```

**Key Features:**
- Architecture detection (x86/x64)
- Compile timestamp analysis
- Section entropy calculation
- Import/Export table parsing
- Resource extraction
- Authenticode signature verification

#### ELF Analyzer (Linux Executables)

```python
from src.analyzers.elf_analyzer import ELFAnalyzer

analyzer = ELFAnalyzer()
result = analyzer.analyze("linux_binary")
```

#### Office Analyzer (Documents)

Analyzes Microsoft Office documents for malicious content:

```python
from src.analyzers.office_analyzer import OfficeAnalyzer

analyzer = OfficeAnalyzer()
result = analyzer.analyze("document.docx")

# Detects:
# - VBA Macros
# - OLE objects
# - Embedded executables
# - External links
# - DDE attacks
```

#### PDF Analyzer

```python
from src.analyzers.pdf_analyzer import PDFAnalyzer

analyzer = PDFAnalyzer()
result = analyzer.analyze("document.pdf")

# Detects:
# - JavaScript
# - Embedded files
# - Launch actions
# - URI actions
# - Suspicious streams
```

#### Script Analyzer

Analyzes scripts for malicious patterns:

```python
from src.analyzers.script_analyzer import ScriptAnalyzer

analyzer = ScriptAnalyzer()
result = analyzer.analyze("script.ps1")

# Supports:
# - PowerShell (.ps1)
# - Batch files (.bat, .cmd)
# - VBScript (.vbs)
# - JavaScript (.js)
# - Python (.py)
```

**Detection Patterns:**
- Base64 encoded commands
- Download cradles
- Obfuscation techniques
- Credential harvesting
- Persistence mechanisms

### Email Analysis

#### Email Analyzer

Comprehensive email forensics:

```python
from src.tools.email_analyzer import EmailAnalyzer

analyzer = EmailAnalyzer(config)
result = await analyzer.analyze("email.eml")

# Analysis includes:
# - Header analysis (SPF, DKIM, DMARC)
# - Sender reputation
# - URL extraction and analysis
# - Attachment analysis
# - Phishing indicators
# - Authentication results
```

#### Advanced Phishing Detection

```python
from src.analyzers.advanced_phishing_detector import AdvancedPhishingDetector

detector = AdvancedPhishingDetector()
result = detector.analyze(email_data)

# Detects:
# - Lookalike domains (homograph attacks)
# - URL shorteners
# - Suspicious reply-to addresses
# - Urgency language patterns
# - Brand impersonation
```

#### URL Chain Analysis

Follows redirect chains to find final destinations:

```python
from src.analyzers.url_chain_analyzer import URLChainAnalyzer

analyzer = URLChainAnalyzer()
chain = await analyzer.analyze("https://bit.ly/xyz")

# Returns:
# - Full redirect chain
# - Final URL
# - Each hop's status code
# - Suspicious redirects
```

### IOC Investigation

#### Multi-Source Investigation

```python
from src.tools.ioc_investigator import IOCInvestigator

investigator = IOCInvestigator(config)
result = await investigator.investigate("185.220.101.1")

# Queries 20+ sources simultaneously:
# - Threat intelligence platforms
# - Reputation services
# - Blacklists
# - Passive DNS
```

#### Supported IOC Types

| Type | Example | Detection Method |
|------|---------|------------------|
| IPv4 | 185.220.101.1 | Regex + validation |
| IPv6 | 2001:db8::1 | Regex + validation |
| Domain | evil.com | TLD validation |
| URL | https://evil.com/path | URL parsing |
| MD5 | d41d8cd98f00b204e9800998ecf8427e | 32 hex chars |
| SHA1 | da39a3ee5e6b4b0d3255bfef95601890afd80709 | 40 hex chars |
| SHA256 | e3b0c44298fc1c149afbf4c8996fb924... | 64 hex chars |
| Email | attacker@evil.com | Email regex |

---

## LLM Integration

Blue Team Assistant supports multiple LLM providers for AI-powered analysis. The **local-first approach** using Ollama is recommended for sensitive environments.

### Provider Comparison

| Provider | Privacy | Cost | Speed | Best For |
|----------|---------|------|-------|----------|
| **Ollama (Local)** | ✅ Full privacy | Free | Medium | Critical infrastructure, sensitive data |
| **Anthropic Claude** | ⚠️ Cloud | Paid | Fast | Non-sensitive, high-quality analysis |
| **OpenAI** | ⚠️ Cloud | Paid | Fast | General purpose |

### Ollama Setup (Recommended)

#### Installation

```bash
# Linux
curl -fsSL https://ollama.com/install.sh | sh

# macOS
brew install ollama

# Windows
# Download from: https://ollama.com/download/windows
```

#### Pull Recommended Models

```bash
# Best balance of speed and quality (RECOMMENDED)
ollama pull llama3.1:8b

# Faster, lighter model
ollama pull llama3.2:3b

# More capable, slower
ollama pull llama3.1:70b

# Security-focused models
ollama pull mistral:7b
ollama pull qwen2.5:7b

# Verify installation
ollama list
```

#### Model Recommendations

| Model | VRAM | Speed | Quality | Use Case |
|-------|------|-------|---------|----------|
| `llama3.2:3b` | 4GB | ⚡⚡⚡ | ★★☆ | Quick triage, low resources |
| `llama3.1:8b` | 8GB | ⚡⚡ | ★★★ | **Recommended default** |
| `mistral:7b` | 8GB | ⚡⚡ | ★★★ | Good for technical analysis |
| `qwen2.5:7b` | 8GB | ⚡⚡ | ★★★ | Multilingual support |
| `llama3.1:70b` | 48GB | ⚡ | ★★★★ | Deep analysis, high accuracy |

#### Configuration

```yaml
# config.yaml
llm:
  provider: "ollama"              # Use local Ollama
  ollama_endpoint: "http://localhost:11434"
  ollama_model: "llama3.1:8b"     # Model to use
  temperature: 0.3                 # Lower = more consistent
  timeout: 120                     # Seconds (local can be slower)
```

#### Verify Ollama is Running

```bash
# Check Ollama status
curl http://localhost:11434/api/tags

# Test generation
curl http://localhost:11434/api/generate -d '{
  "model": "llama3.1:8b",
  "prompt": "What is malware?",
  "stream": false
}'
```

### LLM Analysis Features

The LLM provides intelligent analysis across all modules:

#### IOC Analysis

```python
# LLM analyzes threat intelligence results
{
    "verdict": "MALICIOUS",
    "analysis": "This IP (185.220.101.1) is a known Tor exit node flagged 
                 by 8/15 sources. Associated with scanning activity and 
                 potential C2 communication patterns.",
    "recommendations": [
        "Block at perimeter firewall immediately",
        "Search SIEM for historical connections",
        "Check for lateral movement indicators",
        "Update threat intelligence feeds"
    ]
}
```

#### Malware Analysis

```python
# LLM provides behavior interpretation
{
    "verdict": "LIKELY MALICIOUS",
    "analysis": "PE file exhibits multiple evasion techniques including 
                 high entropy sections (possible packing), anti-VM checks,
                 and suspicious API imports (CreateRemoteThread, VirtualAllocEx).",
    "mitre_mapping": ["T1055", "T1027", "T1497"],
    "recommendations": [
        "Detonate in isolated sandbox",
        "Extract and analyze packed payload",
        "Create detection signatures",
        "Hunt for similar samples"
    ]
}
```

#### Email Analysis

```python
# LLM provides phishing assessment
{
    "verdict": "PHISHING",
    "analysis": "Email impersonates Microsoft with lookalike domain 
                 (micros0ft-support.com). Contains urgency language,
                 mismatched display/actual URLs, and suspicious attachment.",
    "indicators": [
        "Sender domain age: 2 days",
        "SPF: fail, DKIM: none",
        "URL redirects to credential harvester"
    ],
    "recommendations": [
        "Block sender domain organization-wide",
        "Alert affected users",
        "Reset credentials if clicked",
        "Report to anti-phishing feeds"
    ]
}
```

### Cloud Providers (Optional)

#### Anthropic Claude

```yaml
# config.yaml
llm:
  provider: "anthropic"

api_keys:
  anthropic: "sk-ant-api03-..."
```

#### OpenAI

```yaml
# config.yaml  
llm:
  provider: "openai"
  openai_model: "gpt-4o"

api_keys:
  openai: "sk-..."
```

### Disabling LLM Analysis

For pure tool-based analysis without LLM:

```yaml
# config.yaml
analysis:
  enable_llm: false
```

Or via CLI:

```bash
python -m src.soc_agent file sample.exe --no-llm
```

### Performance Tuning

```yaml
# config.yaml - Performance optimizations
llm:
  provider: "ollama"
  ollama_model: "llama3.1:8b"
  temperature: 0.1        # Lower = faster, more deterministic
  timeout: 60             # Reduce for faster failures
  
analysis:
  enable_llm: true
  llm_retry_count: 2      # Retries on failure
  llm_cache_results: true # Cache identical queries
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| "Connection refused" | Start Ollama: `ollama serve` |
| "Model not found" | Pull model: `ollama pull llama3.1:8b` |
| Slow responses | Use smaller model: `llama3.2:3b` |
| Out of memory | Use quantized: `llama3.1:8b-q4_0` |
| JSON parse errors | Check model supports JSON format |

---

## Threat Intelligence Sources

### Primary Sources (9)

| Source | Type | Coverage |
|--------|------|----------|
| **VirusTotal** | Multi-AV | Files, URLs, IPs, Domains |
| **AbuseIPDB** | IP Reputation | IP addresses |
| **Shodan** | Internet Scanner | IPs, Ports, Services |
| **AlienVault OTX** | Threat Intel | All IOC types |
| **IPQualityScore** | Fraud Detection | IPs, Emails, URLs |
| **URLhaus** | Malware URLs | URLs, Domains |
| **MalwareBazaar** | Malware Samples | Hashes |
| **ThreatFox** | IOC Database | All IOC types |
| **PhishTank** | Phishing URLs | URLs |

### Extended Sources (14+)

| Source | Specialty |
|--------|-----------|
| **GreyNoise** | Internet scanners/noise |
| **Censys** | Internet-wide scanning |
| **Pulsedive** | Threat intelligence |
| **CIRCL** | Passive DNS/SSL |
| **Criminal IP** | Cyber threat intel |
| **IP2Proxy** | Proxy/VPN detection |
| **Spamhaus** | Spam/botnet lists |
| **Cisco Talos** | IP reputation |
| **ThreatCrowd** | Threat search engine |
| **FeodoTracker** | Botnet C2 tracking |
| **Triage** | Malware sandbox |
| **ThreatZone** | Cloud sandbox |
| **Tor Exit Nodes** | Tor detection |
| **C2 Trackers** | C2 infrastructure |

### Sandbox Integrations

| Sandbox | Features |
|---------|----------|
| **VirusTotal** | Multi-AV, behavior |
| **Hybrid Analysis** | Full behavior analysis |
| **Joe Sandbox** | Deep analysis |
| **Triage** | Quick triage |
| **ANY.RUN** | Interactive analysis |

---

## Scoring System

### Tool-Based Composite Scoring

The scoring system uses multiple signals to calculate a threat score (0-100):

```python
from src.scoring.tool_based_scoring import ToolBasedScoring

scorer = ToolBasedScoring()
score, factors = scorer.calculate_score(analysis_results)

# Score breakdown:
# 0-29:   CLEAN
# 30-49:  SUSPICIOUS  
# 50-69:  LIKELY MALICIOUS
# 70-100: MALICIOUS
```

### Scoring Factors

| Factor | Weight | Description |
|--------|--------|-------------|
| AV Detections | 40% | Multi-engine detection ratio |
| Behavioral | 25% | Suspicious behaviors detected |
| Reputation | 20% | Source reputation scores |
| Static Analysis | 15% | Code/structure anomalies |

### Intelligent Scoring

Applies context-aware adjustments:

```python
from src.scoring.intelligent_scoring import IntelligentScoring

# Adjustments applied:
# - Signed by trusted CA: -20 points
# - High entropy packer: +15 points
# - Known good hash: -50 points
# - Sandbox evasion detected: +25 points
```

---

## Detection Rule Generation

### Automatic Rule Generation

```python
from src.detection.rule_generator import RuleGenerator

rules = RuleGenerator.generate_rules(analysis_results)

# Generates:
# - YARA rules
# - Sigma rules
# - KQL queries (Microsoft Defender)
# - Snort/Suricata rules
```

### YARA Rules

```yara
rule MAL_Sample_abc123 {
    meta:
        description = "Auto-generated rule for malware sample"
        author = "Blue Team Assistant"
        date = "2025-01-07"
        hash = "abc123..."
        
    strings:
        $s1 = "CreateRemoteThread" ascii
        $s2 = "VirtualAllocEx" ascii
        $s3 = { 4D 5A 90 00 }
        
    condition:
        uint16(0) == 0x5A4D and 2 of ($s*)
}
```

### Sigma Rules

```yaml
title: Suspicious Process Execution
status: experimental
description: Detects execution patterns from analyzed sample
author: Blue Team Assistant
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'powershell -enc'
            - 'cmd /c whoami'
    condition: selection
```

### KQL Queries (Microsoft Defender)

```kql
DeviceProcessEvents
| where FileName =~ "malware.exe"
    or SHA256 == "abc123..."
| where ProcessCommandLine has_any (
    "CreateRemoteThread",
    "VirtualAllocEx"
)
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

---

## Reporting

### HTML Reports

Interactive HTML reports with:

- Executive summary
- Threat score visualization
- MITRE ATT&CK mapping
- Timeline view
- IOC tables with copy buttons
- Detection rules
- Raw data (collapsible)

```bash
python -m src.soc_agent file sample.exe --report report.html
```

### Report Sections

1. **Executive Summary**: Quick verdict, score, key findings
2. **File Information**: Hashes, size, type, metadata
3. **Static Analysis**: PE headers, sections, imports
4. **Threat Intelligence**: Multi-source lookup results
5. **Behavioral Indicators**: Suspicious patterns detected
6. **MITRE ATT&CK**: Mapped techniques with descriptions
7. **Detection Rules**: Ready-to-use YARA/Sigma/KQL
8. **IOC List**: Extracted indicators
9. **Recommendations**: Actionable next steps

### MITRE ATT&CK Mapping

```python
from src.utils.mitre_mapper import MITREMapper

mapper = MITREMapper()
techniques = mapper.map_behaviors(analysis_results)

# Returns:
# - Technique ID (T1055)
# - Technique name
# - Tactic
# - Description
# - Detection guidance
```

### MITRE Navigator Export

Generates JSON for ATT&CK Navigator:

```python
from src.reporting.mitre_navigator import MITRENavigator

navigator = MITRENavigator()
layer = navigator.generate_layer(techniques)
# Import into https://mitre-attack.github.io/attack-navigator/
```

---

## False Positive Filtering

### Trusted Infrastructure Whitelist

Automatically filters known legitimate infrastructure:

```python
# Certificate Authorities
TRUSTED_DOMAINS = {
    'digicert.com', 'verisign.com', 'letsencrypt.org',
    'comodo.com', 'godaddy.com', 'globalsign.com',
    # ... more CAs
}

# CDNs and Infrastructure
TRUSTED_DOMAINS.update({
    'akamai.net', 'cloudflare.com', 'fastly.net',
    'amazonaws.com', 'azure.com', 'googleapis.com',
})
```

### Version String IP Filtering

Prevents version numbers from being flagged as IPs:

```python
# Filtered automatically:
# 6.0.0.0 -> Version string, not IP
# 1.0.0.0 -> Version string, not IP
# 2.0.0.0 -> Version string, not IP
```

### Namespace Filtering

Prevents .NET/COM namespaces from being flagged as domains:

```python
# Filtered automatically:
# microsoft.windows.common -> Namespace, not domain
# nullsoft.nsis.exehead -> Namespace, not domain
# system.runtime.interopservices -> Namespace, not domain
```

### TLD Validation

Strict TLD validation against known TLD list:

```python
# Only valid TLDs pass:
# evil.com -> ✓ Valid (.com is known)
# evil.xyz -> ✓ Valid (.xyz is known)
# l.nlbqt -> ✗ Filtered (.nlbqt not a TLD)
# b.wojby -> ✗ Filtered (.wojby not a TLD)
```

---

## Project Structure

```
blue-team-assistant/
├── src/
│   ├── __init__.py              # Package metadata
│   ├── soc_agent.py             # Main CLI application
│   ├── server.py                # MCP server
│   │
│   ├── tools/                   # High-level analysis tools
│   │   ├── malware_analyzer.py  # File analysis orchestrator
│   │   ├── email_analyzer.py    # Email forensics
│   │   ├── ioc_investigator.py  # IOC lookup
│   │   ├── dns_tools.py         # DNS utilities
│   │   └── external_tool_runner.py  # capa/FLOSS/DIE
│   │
│   ├── analyzers/               # File type analyzers
│   │   ├── pe_analyzer.py       # Windows PE
│   │   ├── elf_analyzer.py      # Linux ELF
│   │   ├── macho_analyzer.py    # macOS Mach-O
│   │   ├── office_analyzer.py   # MS Office
│   │   ├── pdf_analyzer.py      # PDF documents
│   │   ├── script_analyzer.py   # Scripts
│   │   ├── archive_analyzer.py  # Archives
│   │   ├── apk_analyzer.py      # Android APK
│   │   ├── firmware_analyzer.py # Firmware
│   │   ├── file_type_router.py  # Type detection
│   │   └── ...                  # More analyzers
│   │
│   ├── integrations/            # External services
│   │   ├── threat_intel.py      # Primary TI sources
│   │   ├── threat_intel_extended.py  # Extended sources
│   │   ├── llm_analyzer.py      # Ollama/OpenAI/Claude
│   │   ├── sandbox_integration.py    # Sandbox queries
│   │   └── sandbox_submitter.py      # Sample submission
│   │
│   ├── scoring/                 # Threat scoring
│   │   ├── tool_based_scoring.py     # Composite scoring
│   │   ├── intelligent_scoring.py    # Context-aware
│   │   ├── false_positive_filter.py  # FP filtering
│   │   └── signature_verifier.py     # Code signing
│   │
│   ├── detection/               # Rule generation
│   │   ├── rule_generator.py    # YARA/Sigma/KQL
│   │   └── llm_rule_generator.py    # AI-assisted rules
│   │
│   ├── reporting/               # Output generation
│   │   ├── html_report_generator.py  # HTML reports
│   │   ├── markdown_generator.py     # Markdown
│   │   ├── executive_summary.py      # PDF summary
│   │   ├── mitre_navigator.py        # ATT&CK export
│   │   └── soc_output_formatter.py   # Console output
│   │
│   ├── decoders/                # URL decoders
│   │   ├── safelinks_decoder.py     # Microsoft
│   │   └── proofpoint_decoder.py    # Proofpoint
│   │
│   └── utils/                   # Utilities
│       ├── config.py            # Configuration
│       ├── ioc_extractor.py     # IOC extraction
│       ├── entropy_analyzer.py  # Entropy calculation
│       ├── string_extractor.py  # String extraction
│       ├── yara_scanner.py      # YARA scanning
│       ├── mitre_mapper.py      # ATT&CK mapping
│       └── helpers.py           # Common functions
│
├── static/                      # Web assets
│   ├── css/                     # Stylesheets
│   └── js/                      # JavaScript
│
├── templates/                   # HTML templates
│   └── ioc_report.html
│
├── config.yaml.example          # Configuration template
├── requirements.txt             # Dependencies
├── test_setup.py               # Installation verification
├── LICENSE                      # MIT License
└── README.md                    # This file
```

---

## API Reference

### MalwareAnalyzer

```python
from src.tools.malware_analyzer import MalwareAnalyzer

analyzer = MalwareAnalyzer(config)
result = await analyzer.analyze(file_path, options={
    'enable_sandbox': True,
    'enable_yara': True,
    'enable_llm': True,
    'max_iocs': 30
})

# Result structure:
{
    'file_info': {...},
    'static_analysis': {...},
    'threat_intel': {...},
    'score': 75,
    'verdict': 'LIKELY MALICIOUS',
    'mitre_techniques': [...],
    'detection_rules': {...},
    'recommendations': [...]
}
```

### IOCInvestigator

```python
from src.tools.ioc_investigator import IOCInvestigator

investigator = IOCInvestigator(config)
result = await investigator.investigate("185.220.101.1")

# Result structure:
{
    'ioc': '185.220.101.1',
    'ioc_type': 'ipv4',
    'threat_score': 85,
    'verdict': 'MALICIOUS',
    'sources': {
        'virustotal': {...},
        'abuseipdb': {...},
        'shodan': {...}
    },
    'sources_checked': 15,
    'sources_flagged': 8
}
```

### EmailAnalyzer

```python
from src.tools.email_analyzer import EmailAnalyzer

analyzer = EmailAnalyzer(config)
result = await analyzer.analyze("email.eml")

# Result structure:
{
    'headers': {...},
    'authentication': {
        'spf': 'pass',
        'dkim': 'pass',
        'dmarc': 'pass'
    },
    'sender_reputation': {...},
    'urls': [...],
    'attachments': [...],
    'phishing_indicators': [...],
    'verdict': 'SUSPICIOUS'
}
```

---

## Roadmap

### v1.0.0 (Current)
✅ Multi-source threat intelligence (20+ sources)  
✅ Professional malware analysis (PE/ELF/Office/PDF)  
✅ Email forensics & phishing detection  
✅ Local LLM integration (Ollama)  
✅ Automated detection rule generation  
✅ Interactive HTML reports  
✅ MCP Server for Claude Desktop  

### v1.1.0 (Planned)
🔲 MISP integration for threat sharing  
🔲 Elasticsearch/OpenSearch output  
🔲 Custom YARA rule management  
🔲 Batch processing improvements  
🔲 Report templating system  

### v2.0.0 (Future)

#### 🧠 Security-Focused LLM Integration

Fine-tuned cybersecurity LLMs for enhanced analysis:

```yaml
# Planned config
llm:
  provider: "security-llm"
  models:
    - SecBERT          # Security-specific embeddings
    - MalBERTa         # Malware classification
    - PhishLLM         # Phishing detection
    - ThreatGPT        # Threat intelligence analysis
  
  custom_models:
    - path: "./models/soc-analyst-7b"  # Custom fine-tuned
      specialty: "incident-response"
```

**Planned Capabilities:**
- Malware family classification with high accuracy
- Automated threat report generation
- Attack pattern recognition
- IOC correlation and enrichment
- Natural language threat hunting queries

---

#### 🌐 Local Web Application (SOC Dashboard)

Browser-based interface for team collaboration:

```
┌─────────────────────────────────────────────────────────────┐
│  Blue Team Assistant - SOC Dashboard                    v2.0│
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ Active      │ │ Threats     │ │ Pending     │           │
│  │ Cases: 12   │ │ Today: 847  │ │ Review: 5   │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Recent Investigations                                │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ 🔴 malware.exe    │ MALICIOUS │ 92/100 │ 10:32 AM  │   │
│  │ 🟡 phishing.eml   │ SUSPICIOUS│ 67/100 │ 10:15 AM  │   │
│  │ 🟢 update.msi     │ CLEAN     │ 12/100 │ 09:45 AM  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  [Upload File] [Investigate IOC] [Email Analysis] [Reports]│
└─────────────────────────────────────────────────────────────┘
```

**Planned Features:**
- Real-time analysis dashboard
- Team collaboration & case management
- Investigation history & search
- Customizable widgets
- Dark/Light theme
- Role-based access control
- REST API for integrations

---

#### 🐝 TheHive & Cortex Integration

Seamless SOAR platform integration:

```yaml
# Planned config
integrations:
  thehive:
    enabled: true
    url: "https://thehive.local:9000"
    api_key: "your-hive-api-key"
    organization: "SOC-Team"
    
    auto_create_case: true      # Create case on MALICIOUS verdict
    auto_add_observables: true  # Add IOCs as observables
    case_template: "malware-analysis"
    
  cortex:
    enabled: true
    url: "https://cortex.local:9001"
    api_key: "your-cortex-api-key"
    
    analyzers:
      - VirusTotal_GetReport
      - AbuseIPDB_1_0
      - Shodan_DNSResolve
      - MISP_2_1
    
    responders:
      - Mailer_1_0
      - Wazuh_1_0
```

**Planned Workflow:**
```
Blue Team Assistant Analysis
         │
         ▼
   ┌─────────────┐
   │ MALICIOUS   │──────────────────┐
   │ Detected    │                  │
   └─────────────┘                  ▼
         │                 ┌─────────────────┐
         │                 │   TheHive       │
         │                 │   Auto-Create   │
         │                 │   Case #1234    │
         │                 └────────┬────────┘
         │                          │
         ▼                          ▼
   ┌─────────────┐         ┌─────────────────┐
   │ Cortex      │◄────────│   Observables   │
   │ Enrichment  │         │   - Hash        │
   └─────────────┘         │   - IPs         │
         │                 │   - Domains     │
         ▼                 └─────────────────┘
   ┌─────────────┐
   │ Auto        │
   │ Responders  │
   └─────────────┘
```

---

#### 🔬 Ghidra Automation Integration

Automated reverse engineering for deep malware analysis:

```yaml
# Planned config
reverse_engineering:
  ghidra:
    enabled: true
    install_path: "/opt/ghidra"
    headless: true
    
    auto_analysis:
      - decompile_functions     # Auto-decompile suspicious functions
      - extract_strings         # Enhanced string extraction
      - identify_crypto         # Crypto algorithm detection
      - find_c2_patterns        # C2 communication patterns
      - detect_packers          # Packer/crypter identification
    
    scripts:
      - FindCryptoPrimitives.java
      - ExtractIOCs.java
      - IdentifyMalwareFamily.java
      - GenerateYaraSignature.java
```

**Planned Capabilities:**

| Feature | Description |
|---------|-------------|
| **Auto-Decompilation** | Automatic function decompilation |
| **Crypto Detection** | Identify encryption algorithms |
| **C2 Extraction** | Find command & control patterns |
| **String Decryption** | Decrypt obfuscated strings |
| **API Mapping** | Map suspicious API calls to MITRE |
| **YARA Generation** | Generate signatures from binary patterns |
| **Call Graph Analysis** | Visualize function relationships |

**Example Output:**
```json
{
  "ghidra_analysis": {
    "decompiled_functions": 247,
    "suspicious_functions": [
      {
        "name": "FUN_00401a20",
        "behavior": "Process Injection",
        "apis": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "mitre": "T1055.001"
      }
    ],
    "crypto_detected": [
      {"algorithm": "AES-256-CBC", "key_location": "0x00405000"},
      {"algorithm": "RC4", "key_derivation": "hardcoded"}
    ],
    "c2_patterns": [
      {"type": "HTTP", "url_pattern": "/gate.php?id=*"},
      {"type": "DNS", "domain_generation": "DGA detected"}
    ],
    "generated_yara": "rule MAL_Sample_Ghidra {...}"
  }
}
```

---

#### 🖥️ Interactive SOC Agent

Terminal-based interactive investigation interface:

```
┌─────────────────────────────────────────────────────────────┐
│  Blue Team Assistant - Interactive Mode              v2.0   │
│  Type 'help' for commands, 'exit' to quit                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  soc> analyze malware.exe                                   │
│  [████████████████████████████████████████] 100%            │
│                                                             │
│  ╔═══════════════════════════════════════════════════════╗  │
│  ║  VERDICT: MALICIOUS (87/100)                          ║  │
│  ║  Family: Emotet                                       ║  │
│  ║  MITRE: T1055, T1027, T1071                          ║  │
│  ╚═══════════════════════════════════════════════════════╝  │
│                                                             │
│  soc> investigate 185.220.101.1                            │
│  [Querying 20 sources...]                                   │
│  ✓ VirusTotal: 15/87 detections                            │
│  ✓ AbuseIPDB: 100% confidence malicious                    │
│  ✓ Shodan: Tor exit node detected                          │
│                                                             │
│  soc> export case --format thehive                         │
│  ✓ Case #4521 created in TheHive                           │
│                                                             │
│  soc> hunt "powershell -enc" --last 24h                    │
│  Found 3 matches in SIEM...                                 │
│                                                             │
│  soc> help                                                  │
│  Commands:                                                  │
│    analyze <file>      - Analyze file                       │
│    investigate <ioc>   - Investigate IOC                    │
│    email <file>        - Analyze email                      │
│    hunt <query>        - Threat hunt in SIEM                │
│    export <format>     - Export to TheHive/MISP             │
│    report <type>       - Generate report                    │
│    history             - Show analysis history              │
│    config              - Show/edit configuration            │
│    exit                - Exit interactive mode              │
│                                                             │
│  soc> _                                                     │
└─────────────────────────────────────────────────────────────┘
```

**Planned Features:**
- Tab completion for commands and file paths
- Command history with arrow keys
- Real-time progress indicators
- Color-coded output (severity-based)
- Session persistence
- Pipeline support (`analyze file.exe | export thehive`)
- Scripting support for automation
- Multi-window TUI with tmux-like splits

---

### Contributing to Roadmap

Have ideas for v2.0? We welcome contributions!

1. **Feature Requests**: Open an issue with `[Feature Request]` tag
2. **Discussions**: Join discussions in GitHub Discussions
3. **Pull Requests**: PRs for roadmap items are welcome

Priority is given to features that:
- Enhance SOC analyst workflow
- Improve detection accuracy
- Maintain local-first privacy
- Support aviation/critical infrastructure

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/blue-team-assistant.git

# Install dev dependencies
pip install -r requirements.txt
pip install pytest black flake8

# Run tests
pytest

# Format code
black src/

# Lint
flake8 src/
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author

**Ugur Ates**
- GitHub: [@ugur-ates](https://github.com/ugurrates)
- Medium: [@ugur.can.ates](https://medium.com/@ugur.can.ates)
- LinkedIn: [Ugur Ates](https://www.linkedin.com/in/ugurcanates/)

---

## Acknowledgments

- [MITRE ATT&CK](https://attack.mitre.org/) for the framework
- [VirusTotal](https://www.virustotal.com/) for threat intelligence
- [Ollama](https://ollama.com/) for local LLM support
- [Mandiant FLARE](https://github.com/mandiant) for capa and FLOSS

---

## Disclaimer

This tool is intended for authorized security testing and research only. Users are responsible for ensuring they have proper authorization before analyzing any files or investigating any indicators. The author is not responsible for any misuse of this tool.
