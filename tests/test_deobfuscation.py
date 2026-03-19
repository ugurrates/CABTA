"""
Tests for PowerShell and VBScript deobfuscation engines.
"""

import base64
import pytest

from src.analyzers.deobfuscators.powershell_deobfuscator import PowerShellDeobfuscator
from src.analyzers.deobfuscators.vbscript_deobfuscator import VBScriptDeobfuscator


@pytest.fixture
def ps_deob():
    return PowerShellDeobfuscator()


@pytest.fixture
def vbs_deob():
    return VBScriptDeobfuscator()


# ========== PowerShell ==========

class TestPSBacktickRemoval:
    def test_basic_backtick(self, ps_deob):
        r = ps_deob.deobfuscate("I`EX")
        assert 'IEX' in r['deobfuscated']

    def test_multiple_backticks(self, ps_deob):
        r = ps_deob.deobfuscate("Ne`w-Ob`je`ct")
        assert 'New-Object' in r['deobfuscated']

    def test_preserves_escape_n(self, ps_deob):
        r = ps_deob.deobfuscate("Write-Host `n")
        assert '`n' in r['deobfuscated']


class TestPSStringConcat:
    def test_single_quotes(self, ps_deob):
        r = ps_deob.deobfuscate("'Inv'+'oke'+'-Exp'+'ression'")
        assert 'Invoke-Expression' in r['deobfuscated']

    def test_double_quotes(self, ps_deob):
        r = ps_deob.deobfuscate('"Net"+".Web"+"Client"')
        assert 'Net.WebClient' in r['deobfuscated']


class TestPSCharArray:
    def test_basic_char_array(self, ps_deob):
        # IEX = [char]73+[char]69+[char]88
        code = "[char]73+[char]69+[char]88"
        r = ps_deob.deobfuscate(code)
        assert 'IEX' in r['deobfuscated']

    def test_char_array_case_insensitive(self, ps_deob):
        # Mixed case [Char]/[CHAR]/[char] - should all resolve to characters
        code = "[Char]72+[CHAR]69+[char]76+[char]76+[char]79"
        r = ps_deob.deobfuscate(code)
        assert 'HELLO' in r['deobfuscated']


class TestPSFormatOperator:
    def test_basic_format(self, ps_deob):
        code = "'{0}{1}'-f 'IE','X'"
        r = ps_deob.deobfuscate(code)
        assert 'IEX' in r['deobfuscated']


class TestPSReplaceChain:
    def test_single_replace(self, ps_deob):
        code = "'xEX'.Replace('x','I')"
        r = ps_deob.deobfuscate(code)
        assert 'IEX' in r['deobfuscated']

    def test_multiple_replace(self, ps_deob):
        code = "'xEy'.Replace('x','I').Replace('y','X')"
        r = ps_deob.deobfuscate(code)
        assert 'IEX' in r['deobfuscated']


class TestPSBase64:
    def test_encoded_command(self, ps_deob):
        # Encode "Write-Host Hello" as UTF-16LE base64
        payload = "Write-Host Hello"
        encoded = base64.b64encode(payload.encode('utf-16-le')).decode()
        code = f"-EncodedCommand {encoded}"
        r = ps_deob.deobfuscate(code)
        assert 'Write-Host Hello' in r['deobfuscated']

    def test_enc_shorthand(self, ps_deob):
        payload = "Write-Host Hello"
        encoded = base64.b64encode(payload.encode('utf-16-le')).decode()
        code = f"-enc {encoded}"
        r = ps_deob.deobfuscate(code)
        assert 'Write-Host Hello' in r['deobfuscated']

    def test_convert_frombase64(self, ps_deob):
        payload = "malicious"
        encoded = base64.b64encode(payload.encode()).decode()
        code = f"[Convert]::FromBase64String('{encoded}')"
        r = ps_deob.deobfuscate(code)
        assert 'malicious' in r['deobfuscated']


class TestPSReverseString:
    def test_basic_reverse(self, ps_deob):
        code = "'XEI'[-1..-3]"
        r = ps_deob.deobfuscate(code)
        assert 'IEX' in r['deobfuscated']


class TestPSIEXUnwrap:
    def test_iex_parentheses(self, ps_deob):
        code = "IEX('Write-Host Hello')"
        r = ps_deob.deobfuscate(code)
        assert 'Write-Host Hello' in r['deobfuscated']

    def test_invoke_expression(self, ps_deob):
        code = "Invoke-Expression 'Get-Process'"
        r = ps_deob.deobfuscate(code)
        assert 'Get-Process' in r['deobfuscated']


class TestPSMultiLayer:
    def test_concat_then_backtick(self, ps_deob):
        code = "'I`E'+'X'"
        r = ps_deob.deobfuscate(code)
        assert 'IEX' in r['deobfuscated']
        assert len(r['techniques_found']) >= 1

    def test_result_structure(self, ps_deob):
        r = ps_deob.deobfuscate("plain code")
        assert 'original' in r
        assert 'deobfuscated' in r
        assert 'layers' in r
        assert 'techniques_found' in r


class TestPSCaretRemoval:
    def test_caret_removal(self, ps_deob):
        code = "c^m^d /c who^ami"
        r = ps_deob.deobfuscate(code)
        assert 'cmd /c whoami' in r['deobfuscated']


# ========== VBScript ==========

class TestVBSChrDecode:
    def test_basic_chr(self, vbs_deob):
        # Chr(73) & Chr(69) & Chr(88) = "I" & "E" & "X"
        code = 'Chr(73) & Chr(69) & Chr(88)'
        r = vbs_deob.deobfuscate(code)
        assert 'IEX' in r['deobfuscated']

    def test_hex_chr(self, vbs_deob):
        code = 'Chr(&H49)'  # 0x49 = 'I'
        r = vbs_deob.deobfuscate(code)
        assert 'I' in r['deobfuscated']

    def test_chrw(self, vbs_deob):
        code = 'ChrW(72)'  # 'H'
        r = vbs_deob.deobfuscate(code)
        assert 'H' in r['deobfuscated']


class TestVBSStringConcat:
    def test_basic_concat(self, vbs_deob):
        code = '"AB" & "CD" & "EF"'
        r = vbs_deob.deobfuscate(code)
        assert 'ABCDEF' in r['deobfuscated']


class TestVBSReplace:
    def test_basic_replace(self, vbs_deob):
        code = 'Replace("xEX", "x", "I")'
        r = vbs_deob.deobfuscate(code)
        assert 'IEX' in r['deobfuscated']


class TestVBSStrReverse:
    def test_basic_reverse(self, vbs_deob):
        code = 'StrReverse("XEI")'
        r = vbs_deob.deobfuscate(code)
        assert 'IEX' in r['deobfuscated']


class TestVBSExecuteUnwrap:
    def test_execute(self, vbs_deob):
        code = 'Execute("WScript.Echo 1")'
        r = vbs_deob.deobfuscate(code)
        assert 'WScript.Echo 1' in r['deobfuscated']

    def test_executeglobal(self, vbs_deob):
        code = 'ExecuteGlobal("Dim x")'
        r = vbs_deob.deobfuscate(code)
        assert 'Dim x' in r['deobfuscated']


class TestVBSMultiLayer:
    def test_chr_then_concat(self, vbs_deob):
        # Chr resolves first, then concat
        code = 'Chr(65) & Chr(66)'
        r = vbs_deob.deobfuscate(code)
        assert 'AB' in r['deobfuscated']
        assert len(r['techniques_found']) >= 1

    def test_result_structure(self, vbs_deob):
        r = vbs_deob.deobfuscate("plain code")
        assert 'original' in r
        assert 'deobfuscated' in r
        assert 'layers' in r
