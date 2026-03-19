# Example Test Files

This directory contains synthetic test files for demonstrating CABTA's analysis capabilities.

**All data is synthetic** - no real infrastructure, credentials, or threat actors are referenced.

## Files

| File | Purpose | Expected Result |
|------|---------|----------------|
| `sample_c2_config.txt` | Simulated C2 beacon configuration | MALICIOUS (90-100/100) - C2 patterns, persistence, lateral movement |
| `sample_ioc_list.txt` | List of synthetic IOCs for bulk investigation | Mixed verdicts based on TI source responses |

## Usage

1. **Text Analysis**: Upload `sample_c2_config.txt` via File Analysis page
2. **IOC Investigation**: Copy IOCs from `sample_ioc_list.txt` into IOC Investigation page
