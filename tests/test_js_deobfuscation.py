"""
Tests for JavaScript deobfuscation engine.
"""

import pytest

from src.analyzers.deobfuscators.javascript_deobfuscator import JavaScriptDeobfuscator


@pytest.fixture
def js_deob():
    return JavaScriptDeobfuscator()


# ========== Hex Escapes ==========

class TestJSHexEscapes:
    def test_basic_hex(self, js_deob):
        code = r"\x48\x45\x4c\x4c\x4f"
        r = js_deob.deobfuscate(code)
        assert 'HELLO' in r['deobfuscated']

    def test_mixed_case_hex(self, js_deob):
        code = r"\x48\x45\x4C\x4C\x4F"
        r = js_deob.deobfuscate(code)
        assert 'HELLO' in r['deobfuscated']


# ========== Unicode Escapes ==========

class TestJSUnicodeEscapes:
    def test_basic_unicode(self, js_deob):
        code = r"\u0048\u0045\u004C\u004C\u004F"
        r = js_deob.deobfuscate(code)
        assert 'HELLO' in r['deobfuscated']

    def test_unicode_mixed_content(self, js_deob):
        code = r"var x = '\u0041\u0042\u0043'"
        r = js_deob.deobfuscate(code)
        assert 'ABC' in r['deobfuscated']


# ========== Octal Escapes ==========

class TestJSOctalEscapes:
    def test_basic_octal(self, js_deob):
        # 'H'=110, 'I'=111 in octal
        code = "'\\110\\111'"
        r = js_deob.deobfuscate(code)
        assert 'HI' in r['deobfuscated']


# ========== String.fromCharCode ==========

class TestJSFromCharCode:
    def test_basic_fromcharcode(self, js_deob):
        code = "String.fromCharCode(73,69,88)"
        r = js_deob.deobfuscate(code)
        assert 'IEX' in r['deobfuscated']

    def test_fromcharcode_with_spaces(self, js_deob):
        code = "String.fromCharCode( 72, 69, 76, 76, 79 )"
        r = js_deob.deobfuscate(code)
        assert 'HELLO' in r['deobfuscated']


# ========== unescape ==========

class TestJSUnescape:
    def test_basic_unescape(self, js_deob):
        code = "unescape('%49%45%58')"
        r = js_deob.deobfuscate(code)
        assert 'IEX' in r['deobfuscated']

    def test_decodeuricomponent(self, js_deob):
        code = "decodeURIComponent('%48%45%4C%4C%4F')"
        r = js_deob.deobfuscate(code)
        assert 'HELLO' in r['deobfuscated']


# ========== atob ==========

class TestJSAtob:
    def test_basic_atob(self, js_deob):
        import base64
        encoded = base64.b64encode(b"malicious_payload").decode()
        code = f"atob('{encoded}')"
        r = js_deob.deobfuscate(code)
        assert 'malicious_payload' in r['deobfuscated']


# ========== parseInt ==========

class TestJSParseInt:
    def test_hex_parseint(self, js_deob):
        code = "parseInt('ff',16)"
        r = js_deob.deobfuscate(code)
        assert '255' in r['deobfuscated']

    def test_binary_parseint(self, js_deob):
        code = "parseInt('1010',2)"
        r = js_deob.deobfuscate(code)
        assert '10' in r['deobfuscated']


# ========== String Concat ==========

class TestJSStringConcat:
    def test_single_quotes(self, js_deob):
        code = "'hel'+'lo'+' world'"
        r = js_deob.deobfuscate(code)
        assert 'hello world' in r['deobfuscated']

    def test_double_quotes(self, js_deob):
        code = '"ev"+"al"'
        r = js_deob.deobfuscate(code)
        assert 'eval' in r['deobfuscated']


# ========== eval unwrap ==========

class TestJSEvalUnwrap:
    def test_basic_eval(self, js_deob):
        code = "eval('alert(1)')"
        r = js_deob.deobfuscate(code)
        assert 'alert(1)' in r['deobfuscated']

    def test_function_constructor(self, js_deob):
        code = "new Function('return document.cookie')"
        r = js_deob.deobfuscate(code)
        assert 'return document.cookie' in r['deobfuscated']


# ========== Multi-layer ==========

class TestJSMultiLayer:
    def test_fromcharcode_then_eval(self, js_deob):
        # String.fromCharCode resolves first, then eval unwraps
        code = "eval(String.fromCharCode(97,108,101,114,116,40,49,41))"
        r = js_deob.deobfuscate(code)
        assert 'alert(1)' in r['deobfuscated']

    def test_result_structure(self, js_deob):
        r = js_deob.deobfuscate("plain code")
        assert 'original' in r
        assert 'deobfuscated' in r
        assert 'layers' in r
        assert 'techniques_found' in r

    def test_hex_concat(self, js_deob):
        code = r"'\x61\x6c' + '\x65\x72\x74'"
        r = js_deob.deobfuscate(code)
        assert 'alert' in r['deobfuscated']
