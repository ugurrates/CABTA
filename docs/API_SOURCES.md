# 🔌 Threat Intelligence Sources

## Overview

Blue Team Assistant integrates with **20+ threat intelligence sources** to provide comprehensive IOC analysis. This document describes each source and how to obtain API keys.

---

## Source Categories

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      THREAT INTELLIGENCE SOURCES                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   REPUTATION    │  │  THREAT INTEL   │  │   SANDBOXES     │             │
│  │                 │  │                 │  │                 │             │
│  │  • VirusTotal   │  │  • AlienVault   │  │  • Hybrid       │             │
│  │  • AbuseIPDB    │  │  • ThreatFox    │  │  • Triage       │             │
│  │  • IPQuality    │  │  • URLhaus      │  │  • ANY.RUN      │             │
│  │  • GreyNoise    │  │  • MalwareBazaar│  │  • Joe Sandbox  │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   PASSIVE DNS   │  │    SCANNING     │  │   PHISHING      │             │
│  │                 │  │                 │  │                 │             │
│  │  • Shodan       │  │  • Censys       │  │  • PhishTank    │             │
│  │  • SecurityTrails│ │  • BinaryEdge   │  │  • OpenPhish    │             │
│  │  • PassiveTotal │  │                 │  │  • URLScan      │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Source Information

### 🔴 VirusTotal

**Type:** Multi-engine antivirus scanning
**IOC Types:** IP, Domain, URL, Hash
**Free Tier:** 500 requests/day
**Weight in Scoring:** 25/100

**What it provides:**
- Antivirus detection results (70+ engines)
- Community votes
- Behavioral analysis
- First/last seen dates

**Get API Key:**
1. Register at https://www.virustotal.com
2. Go to Profile → API Key
3. Copy your key

```yaml
api_keys:
  virustotal: "your-key-here"
```

---

### 🔵 AbuseIPDB

**Type:** IP reputation database
**IOC Types:** IP only
**Free Tier:** 1,000 requests/day
**Weight in Scoring:** 20/100

**What it provides:**
- Abuse confidence score (0-100%)
- Report count
- Last reported date
- ISP/Country information

**Get API Key:**
1. Register at https://www.abuseipdb.com
2. Go to Account → API
3. Generate key

```yaml
api_keys:
  abuseipdb: "your-key-here"
```

---

### 🟢 Shodan

**Type:** Internet scanning/OSINT
**IOC Types:** IP, Domain
**Free Tier:** 100 queries/month
**Weight in Scoring:** 15/100

**What it provides:**
- Open ports
- Running services
- SSL certificates
- Organization info
- Vulnerabilities

**Get API Key:**
1. Register at https://account.shodan.io
2. Go to Account
3. Copy API Key

```yaml
api_keys:
  shodan: "your-key-here"
```

---

### 🟡 AlienVault OTX

**Type:** Open threat exchange
**IOC Types:** IP, Domain, URL, Hash
**Free Tier:** Unlimited
**Weight in Scoring:** 15/100

**What it provides:**
- Pulse (threat report) count
- Pulse details
- Related indicators
- Tags and references

**Get API Key:**
1. Register at https://otx.alienvault.com
2. Go to Settings → API
3. Copy OTX Key

```yaml
api_keys:
  alienvault: "your-key-here"
```

---

### 🟣 GreyNoise

**Type:** Internet scanner detection
**IOC Types:** IP only
**Free Tier:** 50 queries/day
**Weight in Scoring:** 10/100

**What it provides:**
- Is this IP scanning the internet?
- Classification (benign/malicious)
- Actor name (if known)
- Last seen date

**Get API Key:**
1. Register at https://viz.greynoise.io
2. Go to Account → API Key
3. Copy key

```yaml
api_keys:
  greynoise: "your-key-here"
```

---

### 🔶 IPQualityScore

**Type:** Fraud/abuse detection
**IOC Types:** IP, Email, Domain
**Free Tier:** 5,000 requests/month
**Weight in Scoring:** 15/100

**What it provides:**
- Fraud score (0-100)
- Proxy/VPN detection
- Bot detection
- Recent abuse

**Get API Key:**
1. Register at https://www.ipqualityscore.com
2. Go to Settings → API Key
3. Copy key

```yaml
api_keys:
  ipqualityscore: "your-key-here"
```

---

### 🔷 Hybrid Analysis

**Type:** Malware sandbox
**IOC Types:** Hash, URL
**Free Tier:** 100 searches/month
**Weight in Scoring:** 20/100

**What it provides:**
- Sandbox analysis results
- Threat score
- MITRE ATT&CK mapping
- Network indicators

**Get API Key:**
1. Register at https://www.hybrid-analysis.com
2. Go to Profile → API Key
3. Request API access

```yaml
api_keys:
  hybrid_analysis: "your-key-here"
```

---

### 🔸 Triage (Hatching)

**Type:** Malware sandbox
**IOC Types:** Hash
**Free Tier:** Limited
**Weight in Scoring:** 15/100

**What it provides:**
- Detailed sandbox analysis
- Malware family identification
- Extracted configurations
- Network IOCs

**Get API Key:**
1. Register at https://tria.ge
2. Go to Account → API
3. Generate key

```yaml
api_keys:
  triage: "your-key-here"
```

---

### 🆓 Free Sources (No API Key Required)

These sources work without authentication:

| Source | Type | IOC Types | Data |
|--------|------|-----------|------|
| **URLhaus** | Malicious URLs | URL, Domain | Malware distribution URLs |
| **ThreatFox** | IOC Database | IP, Domain, URL, Hash | Recent IOCs |
| **MalwareBazaar** | Malware samples | Hash | Sample metadata |
| **OpenPhish** | Phishing | URL, Domain | Phishing URLs |

---

## Configuration Example

Complete `config.yaml` with all sources:

```yaml
api_keys:
  # Essential (highly recommended)
  virustotal: "your-vt-key"
  abuseipdb: "your-abuseipdb-key"
  
  # Recommended
  shodan: "your-shodan-key"
  alienvault: "your-otx-key"
  hybrid_analysis: "your-ha-key"
  
  # Optional (enhanced coverage)
  greynoise: "your-greynoise-key"
  ipqualityscore: "your-ipqs-key"
  triage: "your-triage-key"
  censys_id: "your-censys-id"
  censys_secret: "your-censys-secret"
  urlscan: "your-urlscan-key"
  securitytrails: "your-st-key"
```

---

## Source Reliability & Scoring

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SOURCE WEIGHT DISTRIBUTION                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  VirusTotal       ████████████████████████████  25%   (most reliable)       │
│  AbuseIPDB        ████████████████████  20%                                 │
│  Hybrid Analysis  ████████████████████  20%                                 │
│  MalwareBazaar    ███████████████  15%                                      │
│  AlienVault OTX   ███████████████  15%                                      │
│  Shodan           ███████████████  15%                                      │
│  IPQualityScore   ███████████████  15%                                      │
│  GreyNoise        ██████████  10%                                           │
│  Others           ██████████  10%  (each)                                   │
│                                                                             │
│  Note: Weights are normalized. A single source cannot exceed 100.           │
│        Multiple sources flagging = higher confidence.                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Rate Limits & Best Practices

### Handling Rate Limits

Blue Team Assistant automatically:
- Respects API rate limits
- Uses timeouts (15s default)
- Falls back gracefully on errors

### Best Practices

1. **Start with Free Tiers**: All sources have free tiers sufficient for personal/small team use.

2. **Prioritize Essential Sources**: 
   - VirusTotal (best overall)
   - AbuseIPDB (best for IPs)
   - Hybrid Analysis (best for files)

3. **Cache Results**: For bulk analysis, consider implementing caching to avoid repeated API calls.

4. **Monitor Usage**: Track your API usage to avoid hitting limits during investigations.

---

## Troubleshooting

### "No API key configured"
```
Source returns: "No valid API key configured"
```
**Solution:** Add the API key to config.yaml

### "Rate limit exceeded"
```
Source returns: "HTTP 429" or "Rate limit"
```
**Solution:** Wait and retry, or upgrade your API tier

### "Timeout"
```
Source returns: "Timeout after 15s"
```
**Solution:** Network issue or API unavailable, result will be skipped

### "Error"
```
Source returns: "Error"
```
**Solution:** Check API key validity or API status page
