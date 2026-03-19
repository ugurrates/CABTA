"""
Blue Team Assistant - Shared test fixtures.
Author: Ugur Ates
"""

import pytest
import os
import tempfile
import struct
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch


# ---------------------------------------------------------------------------
# Configuration fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_config():
    """Minimal config with no real API keys."""
    return {
        'api_keys': {
            'virustotal': 'test_vt_key_000000000000000000000000',
            'abuseipdb': 'test_abuseipdb_key',
            'shodan': '',
            'alienvault': '',
            'greynoise': '',
            'censys_id': '',
            'censys_secret': '',
            'pulsedive': '',
            'criminalip': '',
            'ipqualityscore': '',
            'phishtank': '',
            'hybridanalysis': '',
            'anyrun': '',
            'triage': '',
            'threatzone': '',
            'joesandbox': '',
            'ip2proxy': '',
            'anthropic': '',
        },
        'rate_limits': {
            'virustotal': {'requests_per_minute': 4},
            'abuseipdb': {'requests_per_day': 1000},
            'shodan': {'requests_per_month': 100},
            'concurrent_requests': 5,
        },
        'timeouts': {
            'api_timeout': 5,
            'sandbox_timeout': 10,
        },
        'scoring': {
            'clean_threshold': 5,
            'low_risk_threshold': 30,
            'suspicious_threshold': 60,
            'malicious_threshold': 80,
        },
        'analysis': {
            'max_archive_depth': 3,
            'max_file_size_mb': 100,
            'enable_sandboxes': False,
            'enable_llm': False,
        },
        'output': {
            'report_format': 'html',
            'save_reports': False,
            'reports_dir': './reports',
        },
        'logging': {
            'level': 'WARNING',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        },
    }


# ---------------------------------------------------------------------------
# Sample file fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_pe_file(tmp_path):
    """Create a minimal PE-like file (MZ + PE signature)."""
    pe_file = tmp_path / "sample.exe"
    # MZ header (DOS stub)
    data = bytearray(512)
    data[0:2] = b'MZ'
    # PE offset at 0x3C
    pe_offset = 128
    struct.pack_into('<I', data, 0x3C, pe_offset)
    # PE signature
    data[pe_offset:pe_offset + 4] = b'PE\x00\x00'
    # Machine type: x86
    struct.pack_into('<H', data, pe_offset + 4, 0x14c)
    pe_file.write_bytes(bytes(data))
    return str(pe_file)


@pytest.fixture
def sample_elf_file(tmp_path):
    """Create a minimal ELF file."""
    elf_file = tmp_path / "sample.elf"
    data = bytearray(64)
    data[0:4] = b'\x7fELF'
    data[4] = 2      # ELF64
    data[5] = 1      # Little endian
    data[6] = 1      # ELF version
    elf_file.write_bytes(bytes(data))
    return str(elf_file)


@pytest.fixture
def sample_pdf_file(tmp_path):
    """Create a minimal PDF file."""
    pdf_file = tmp_path / "sample.pdf"
    content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [] /Count 0 >>
endobj
xref
0 3
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
trailer
<< /Size 3 /Root 1 0 R >>
startxref
109
%%EOF
"""
    pdf_file.write_bytes(content)
    return str(pdf_file)


@pytest.fixture
def sample_office_file(tmp_path):
    """Create a minimal OLE compound file (old .doc)."""
    doc_file = tmp_path / "sample.doc"
    data = bytearray(512)
    # OLE magic
    data[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    doc_file.write_bytes(bytes(data))
    return str(doc_file)


@pytest.fixture
def sample_script_file(tmp_path):
    """Create a sample PowerShell script."""
    ps_file = tmp_path / "sample.ps1"
    content = """# Sample PowerShell script
param([string]$Target)
Write-Host "Scanning $Target"
$result = Invoke-WebRequest -Uri "http://example.com/test"
"""
    ps_file.write_text(content, encoding='utf-8')
    return str(ps_file)


@pytest.fixture
def sample_batch_file(tmp_path):
    """Create a sample batch file."""
    bat_file = tmp_path / "sample.bat"
    content = "@echo off\r\necho Hello World\r\npause\r\n"
    bat_file.write_text(content, encoding='utf-8')
    return str(bat_file)


@pytest.fixture
def sample_eml_file(tmp_path):
    """Create a minimal .eml email file."""
    eml_file = tmp_path / "sample.eml"
    content = """From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Thu, 01 Jan 2025 12:00:00 +0000
Message-ID: <test123@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

This is a test email body.
Visit http://malicious-site.xyz/phish for details.
"""
    eml_file.write_text(content, encoding='utf-8')
    return str(eml_file)


@pytest.fixture
def sample_unknown_file(tmp_path):
    """Create a file with unknown type."""
    unk_file = tmp_path / "sample.xyz"
    unk_file.write_bytes(os.urandom(256))
    return str(unk_file)


# ---------------------------------------------------------------------------
# IOC / TI result fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_ioc_results():
    """Mock IOC investigation results from multiple sources."""
    return {
        'ioc': '185.220.101.1',
        'ioc_type': 'ipv4',
        'sources': {
            'virustotal': {
                'status': '✓',
                'score': 75,
                'message': '12/90 vendors flagged as malicious',
                'detections': 12,
                'total_engines': 90,
            },
            'abuseipdb': {
                'status': '✓',
                'score': 95,
                'message': 'Confidence: 95%, Reports: 2341',
                'confidence': 95,
                'total_reports': 2341,
            },
            'shodan': {
                'status': '✗',
                'score': 0,
                'message': 'No data found',
            },
            'alienvault': {
                'status': '✓',
                'score': 60,
                'message': '5 pulses reference this IOC',
                'pulse_count': 5,
            },
        },
        'threat_score': 57,
        'sources_checked': 4,
        'sources_flagged': 3,
    }


@pytest.fixture
def sample_clean_ioc_results():
    """Mock IOC results for a clean/benign indicator."""
    return {
        'ioc': '8.8.8.8',
        'ioc_type': 'ipv4',
        'sources': {
            'virustotal': {
                'status': '✗',
                'score': 0,
                'message': '0/90 vendors flagged',
            },
            'abuseipdb': {
                'status': '✗',
                'score': 0,
                'message': 'Confidence: 0%',
            },
        },
        'threat_score': 0,
        'sources_checked': 2,
        'sources_flagged': 0,
    }


# ---------------------------------------------------------------------------
# Analysis result fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_file_analysis_result():
    """Mock file analysis result (PE malware)."""
    return {
        'file_path': '/tmp/malware.exe',
        'file_type': 'PE',
        'hashes': {
            'md5': 'd41d8cd98f00b204e9800998ecf8427e',
            'sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        },
        'pe_analysis': {
            'threat_score': 65,
            'suspicious_imports': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
            'anomalies': ['High entropy .text section'],
            'high_entropy_sections': True,
        },
        'capabilities': {
            'success': True,
            'capabilities': [
                {'name': 'inject into process', 'namespace': 'host-interaction/process/inject', 'attack_ids': ['T1055']},
            ],
            'attack_techniques': ['T1055'],
            'threat_score': 70,
        },
        'strings': {
            'success': True,
            'decoded_count': 15,
            'urls': ['http://evil.com/callback'],
            'suspicious_strings': ['VirtualAllocEx', 'NtUnmapViewOfSection'],
            'threat_score': 50,
        },
        'packer_detection': {
            'packers': [],
            'protectors': [],
            'compilers': ['Microsoft Visual C++ 2019'],
        },
        'yara_matches': [
            {'rule': 'suspicious_pe', 'namespace': 'default', 'tags': ['malware']},
        ],
        'hash_score': 60,
        'ioc_results': [],
        'sandbox_results': {},
        'static_analysis': {
            'threat_score': 55,
            'file_type': 'PE',
        },
        'threat_score': 65,
        'verdict': 'SUSPICIOUS',
    }


@pytest.fixture
def sample_email_analysis_result():
    """Mock email analysis result."""
    return {
        'file_path': '/tmp/phishing.eml',
        'sender': 'attacker@evil-domain.xyz',
        'subject': 'Urgent: Verify your account',
        'authentication': {
            'spf': 'fail',
            'dkim': 'none',
            'dmarc': 'fail',
        },
        'urls': ['http://evil-domain.xyz/login', 'http://bit.ly/abc123'],
        'attachments': [],
        'threat_score': 80,
        'verdict': 'MALICIOUS',
    }
