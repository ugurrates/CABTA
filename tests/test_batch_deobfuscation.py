"""
Tests for Batch/CMD deobfuscation engine.
"""

import pytest

from src.analyzers.deobfuscators.batch_deobfuscator import BatchDeobfuscator


@pytest.fixture
def bat_deob():
    return BatchDeobfuscator()


# ========== Caret Removal ==========

class TestBatchCaretRemoval:
    def test_basic_caret(self, bat_deob):
        code = "c^m^d /c who^ami"
        r = bat_deob.deobfuscate(code)
        assert 'cmd /c whoami' in r['deobfuscated']

    def test_heavy_caret(self, bat_deob):
        code = "p^o^w^e^r^s^h^e^l^l"
        r = bat_deob.deobfuscate(code)
        assert 'powershell' in r['deobfuscated']

    def test_preserves_newline_caret(self, bat_deob):
        code = "echo hello^\nworld"
        r = bat_deob.deobfuscate(code)
        # Caret before newline is preserved (line continuation)
        assert '^\n' in r['deobfuscated']


# ========== Double Percent ==========

class TestBatchDoublePercent:
    def test_basic_double_percent(self, bat_deob):
        code = "for %%A in (1 2 3) do echo %%A"
        r = bat_deob.deobfuscate(code)
        assert '%%' not in r['deobfuscated']
        assert '%A' in r['deobfuscated']


# ========== SET Variable Building ==========

class TestBatchSetVariables:
    def test_basic_set_expansion(self, bat_deob):
        code = "set a=hello\necho %a%"
        r = bat_deob.deobfuscate(code)
        assert 'hello' in r['deobfuscated']

    def test_multi_var_concat(self, bat_deob):
        code = "set a=pow\nset b=ershell\n%a%%b%"
        r = bat_deob.deobfuscate(code)
        assert 'powershell' in r['deobfuscated']

    def test_quoted_set(self, bat_deob):
        code = 'set "x=cmd"\n%x% /c whoami'
        r = bat_deob.deobfuscate(code)
        assert 'cmd /c whoami' in r['deobfuscated']

    def test_delayed_expansion(self, bat_deob):
        code = "set myvar=test\necho !myvar!"
        r = bat_deob.deobfuscate(code)
        assert 'test' in r['deobfuscated']


# ========== Environment Variable Expansion ==========

class TestBatchEnvVars:
    def test_comspec(self, bat_deob):
        code = "%ComSpec% /c whoami"
        r = bat_deob.deobfuscate(code)
        assert 'cmd.exe' in r['deobfuscated']

    def test_systemroot(self, bat_deob):
        code = "%SystemRoot%\\system32\\calc.exe"
        r = bat_deob.deobfuscate(code)
        assert 'Windows' in r['deobfuscated']

    def test_appdata(self, bat_deob):
        code = "%APPDATA%\\malware.exe"
        r = bat_deob.deobfuscate(code)
        assert 'AppData' in r['deobfuscated']


# ========== Substring Extraction ==========

class TestBatchSubstring:
    def test_basic_substring(self, bat_deob):
        # %comspec:~0,1% should extract 'C' from 'C:\Windows\system32\cmd.exe'
        code = "%comspec:~0,1%"
        r = bat_deob.deobfuscate(code)
        assert 'C' in r['deobfuscated']

    def test_mid_substring(self, bat_deob):
        # %comspec:~-7,3% should extract 'cmd' from 'C:\Windows\system32\cmd.exe'
        code = "%comspec:~-7,3%"
        r = bat_deob.deobfuscate(code)
        assert 'cmd' in r['deobfuscated']


# ========== CALL Obfuscation ==========

class TestBatchCall:
    def test_call_cmd(self, bat_deob):
        code = "call cmd /c whoami"
        r = bat_deob.deobfuscate(code)
        assert 'cmd /c whoami' in r['deobfuscated']
        assert not r['deobfuscated'].strip().startswith('call')

    def test_call_powershell(self, bat_deob):
        code = "call powershell -ep bypass"
        r = bat_deob.deobfuscate(code)
        assert 'powershell -ep bypass' in r['deobfuscated']


# ========== Echo Off Removal ==========

class TestBatchEchoOff:
    def test_echo_off(self, bat_deob):
        code = "@echo off\ncmd /c whoami"
        r = bat_deob.deobfuscate(code)
        assert 'echo off' not in r['deobfuscated'].lower()
        assert 'whoami' in r['deobfuscated']


# ========== Multi-Layer ==========

class TestBatchMultiLayer:
    def test_caret_then_env_var(self, bat_deob):
        code = "%C^o^m^S^p^e^c% /c whoami"
        r = bat_deob.deobfuscate(code)
        # Carets should be removed first, then env var expanded
        assert 'whoami' in r['deobfuscated']

    def test_result_structure(self, bat_deob):
        r = bat_deob.deobfuscate("echo hello")
        assert 'original' in r
        assert 'deobfuscated' in r
        assert 'layers' in r
        assert 'techniques_found' in r

    def test_techniques_tracked(self, bat_deob):
        code = "c^m^d /c who^ami"
        r = bat_deob.deobfuscate(code)
        assert len(r['techniques_found']) >= 1
        assert 'caret_removal' in r['techniques_found']
