"""
Tests for Shellcode Detection module.
"""

import struct
import pytest

from src.analyzers.shellcode_detector import (
    ShellcodeDetector,
    ShellcodeMatch,
    ShellcodeReport,
    KNOWN_API_HASHES_ROR13,
)


@pytest.fixture
def detector():
    return ShellcodeDetector()


# ---------- NOP sled ----------

class TestNopSled:
    def test_short_nop_not_flagged(self, detector):
        data = b'\x90' * 4 + b'\xcc' * 100
        report = detector.scan(data)
        assert not any(m.technique == 'nop_sled' for m in report.matches)

    def test_long_nop_flagged(self, detector):
        data = b'\x90' * 64 + b'\xcc' * 100
        report = detector.scan(data)
        nop_matches = [m for m in report.matches if m.technique == 'nop_sled']
        assert len(nop_matches) >= 1
        assert nop_matches[0].length == 64
        assert nop_matches[0].severity in ('HIGH', 'MEDIUM')

    def test_nop_sled_confidence_scales(self, detector):
        data_short = b'\x90' * 10 + b'\xcc' * 100
        data_long = b'\x90' * 100 + b'\xcc' * 100
        r_short = detector.scan(data_short)
        r_long = detector.scan(data_long)
        nop_s = [m for m in r_short.matches if m.technique == 'nop_sled']
        nop_l = [m for m in r_long.matches if m.technique == 'nop_sled']
        if nop_s and nop_l:
            assert nop_l[0].confidence >= nop_s[0].confidence


# ---------- Framework signatures ----------

class TestFrameworkSignatures:
    def test_metasploit_x86_stager(self, detector):
        # Metasploit reverse_tcp x86 stager prefix
        data = b'\xfc\xe8\x82\x00\x00\x00' + b'\xcc' * 200
        report = detector.scan(data)
        msf = [m for m in report.matches if m.technique == 'framework_metasploit']
        assert len(msf) >= 1
        assert msf[0].severity == 'CRITICAL'

    def test_metasploit_x64_stager(self, detector):
        data = b'\xfc\x48\x83\xe4\xf0\xe8' + b'\xcc' * 200
        report = detector.scan(data)
        msf = [m for m in report.matches if m.technique == 'framework_metasploit']
        assert len(msf) >= 1

    def test_cobalt_strike_beacon(self, detector):
        data = b'\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5' + b'\x00' * 200
        report = detector.scan(data)
        cs = [m for m in report.matches if m.technique == 'framework_cobalt_strike']
        assert len(cs) >= 1
        assert cs[0].severity == 'CRITICAL'

    def test_clean_data_no_framework(self, detector):
        data = bytes(range(256)) * 4
        report = detector.scan(data)
        frameworks = [m for m in report.matches
                      if m.technique.startswith('framework_')]
        assert len(frameworks) == 0


# ---------- API hashing ----------

class TestApiHashing:
    def test_ror13_loop_detected(self, detector):
        # ROR13 instruction: C1 CA 0D
        data = b'\x31\xd2' + b'\xc1\xca\x0d' + b'\x03\xd0' * 50 + b'\xcc' * 100
        report = detector.scan(data)
        api = [m for m in report.matches if m.technique == 'api_hashing']
        assert len(api) >= 1

    def test_known_hash_push_detected(self, detector):
        # Build data with push imm32 for known API hashes
        known_hashes = list(KNOWN_API_HASHES_ROR13.keys())[:3]
        payload = b'\x90' * 10
        for h in known_hashes:
            payload += b'\x68' + struct.pack('<I', h)
        payload += b'\xcc' * 100
        report = detector.scan(payload)
        api = [m for m in report.matches if m.technique == 'api_hashing']
        assert len(api) >= 1
        assert api[0].severity == 'CRITICAL'


# ---------- Syscalls ----------

class TestSyscalls:
    def test_int80_detected(self, detector):
        # Some code context then int 0x80
        data = b'\x31\xc0\xb0\x01\x31\xdb' + b'\xcd\x80' + b'\xcc' * 100
        report = detector.scan(data, arch='x86')
        syscalls = [m for m in report.matches if m.technique == 'syscall']
        assert len(syscalls) >= 1

    def test_syscall_x64(self, detector):
        data = b'\x48\x89\xc7\x48\x31\xf6' + b'\x0f\x05' + b'\xcc' * 100
        report = detector.scan(data, arch='x64')
        syscalls = [m for m in report.matches if m.technique == 'syscall']
        assert len(syscalls) >= 1

    def test_sysenter(self, detector):
        data = b'\x31\xc0\xb0\x01' + b'\x0f\x34' + b'\xcc' * 100
        report = detector.scan(data, arch='x86')
        syscalls = [m for m in report.matches if m.technique == 'syscall']
        assert len(syscalls) >= 1


# ---------- GetPC / GetEIP ----------

class TestGetPC:
    def test_call_pop_detected(self, detector):
        # call $+5 (E8 00 00 00 00) + pop eax (58)
        data = b'\xe8\x00\x00\x00\x00\x58' + b'\xcc' * 100
        report = detector.scan(data)
        getpc = [m for m in report.matches if m.technique == 'getpc_call_pop']
        assert len(getpc) >= 1
        assert 'eax' in getpc[0].description

    def test_call_pop_various_regs(self, detector):
        # pop ebx = 5B
        data = b'\xe8\x00\x00\x00\x00\x5b' + b'\xcc' * 100
        report = detector.scan(data)
        getpc = [m for m in report.matches if m.technique == 'getpc_call_pop']
        assert len(getpc) >= 1
        assert 'ebx' in getpc[0].description

    def test_fstenv_detected(self, detector):
        data = b'\xd9\x74\x24\xf4' + b'\x5e' + b'\xcc' * 100
        report = detector.scan(data)
        fpu = [m for m in report.matches if m.technique == 'getpc_fpu']
        assert len(fpu) >= 1


# ---------- XOR encoding ----------

class TestXorEncoding:
    def test_xor_encoded_mz_header(self, detector):
        # XOR encode "MZ" + padding with key 0x41
        cleartext = b'MZ' + b'\x00' * 200 + b'\xcc' * 100
        key = 0x41
        encoded = bytes(b ^ key for b in cleartext)
        report = detector.scan(encoded)
        xor = [m for m in report.matches if m.technique == 'xor_encoding']
        assert len(xor) >= 1
        assert '0x41' in xor[0].description

    def test_xor_encoded_http(self, detector):
        cleartext = b'http://evil.com/payload' + b'\x00' * 200
        key = 0x5A
        encoded = bytes(b ^ key for b in cleartext)
        report = detector.scan(encoded)
        xor = [m for m in report.matches if m.technique == 'xor_encoding']
        assert len(xor) >= 1

    def test_clean_data_no_xor_false_positive(self, detector):
        # Structured non-random data should not trigger XOR
        data = b'This is a normal text file with no shellcode.\n' * 20
        report = detector.scan(data)
        xor = [m for m in report.matches if m.technique.startswith('xor_encoding')]
        # May get 0 or very few low-confidence matches; no CRITICAL
        critical_xor = [m for m in xor if m.severity == 'CRITICAL']
        assert len(critical_xor) == 0


# ---------- Heap spray ----------

class TestHeapSpray:
    def test_0c_spray_detected(self, detector):
        data = b'\x0c' * 256 + b'\xfc\xe8' + b'\xcc' * 100
        report = detector.scan(data)
        spray = [m for m in report.matches if m.technique == 'heap_spray']
        assert len(spray) >= 1

    def test_short_spray_not_flagged(self, detector):
        data = b'\x0c' * 16 + b'\xcc' * 200
        report = detector.scan(data)
        spray = [m for m in report.matches if m.technique == 'heap_spray']
        assert len(spray) == 0


# ---------- ROP chain ----------

class TestRopChain:
    def test_rop_chain_detected(self, detector):
        # Build a fake ROP chain: 8 addresses in typical image range
        chain = b''
        for i in range(8):
            addr = 0x7FFE0000 + i * 0x100
            chain += struct.pack('<I', addr)
        data = chain + b'\xcc' * 100
        report = detector.scan(data, arch='x86')
        rop = [m for m in report.matches if m.technique == 'rop_chain']
        assert len(rop) >= 1

    def test_few_addresses_not_flagged(self, detector):
        chain = b''
        for i in range(3):
            chain += struct.pack('<I', 0x00401000 + i * 4)
        data = chain + b'\x00' * 200
        report = detector.scan(data, arch='x86')
        rop = [m for m in report.matches if m.technique == 'rop_chain']
        assert len(rop) == 0


# ---------- Report structure ----------

class TestReportStructure:
    def test_empty_data(self, detector):
        report = detector.scan(b'')
        assert not report.has_shellcode
        assert report.threat_score == 0

    def test_clean_file(self, detector):
        data = b'Hello World! This is a clean file.\n' * 100
        report = detector.scan(data)
        assert report.threat_score < 30

    def test_to_dict(self, detector):
        data = b'\xfc\xe8\x82\x00\x00\x00' + b'\x90' * 32 + b'\xcc' * 200
        report = detector.scan(data)
        d = report.to_dict()
        assert 'has_shellcode' in d
        assert 'threat_score' in d
        assert 'matches' in d
        assert 'mitre_techniques' in d
        assert isinstance(d['matches'], list)

    def test_mitre_mapping(self, detector):
        data = b'\xfc\xe8\x82\x00\x00\x00' + b'\xcc' * 200
        report = detector.scan(data)
        assert len(report.mitre_techniques) > 0

    def test_scan_file(self, detector, tmp_path):
        target = tmp_path / "shellcode.bin"
        target.write_bytes(b'\xe8\x00\x00\x00\x00\x58' + b'\xcc' * 200)
        report = detector.scan_file(str(target))
        assert report.has_shellcode

    def test_scan_file_nonexistent(self, detector):
        report = detector.scan_file('/nonexistent/path.bin')
        assert 'Error' in report.summary


class TestShellcodeMatch:
    def test_to_dict(self):
        m = ShellcodeMatch(
            technique='nop_sled',
            offset=0,
            length=32,
            confidence=0.8,
            description='NOP sled (32 bytes)',
            severity='HIGH',
            arch='x86',
            raw_bytes=b'\x90' * 16,
        )
        d = m.to_dict()
        assert d['technique'] == 'nop_sled'
        assert d['confidence'] == 0.8
        assert d['raw_hex'] == '90' * 16
