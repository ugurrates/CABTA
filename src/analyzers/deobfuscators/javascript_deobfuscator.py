"""
Author: Ugur Ates
JavaScript Deobfuscation Engine.

Handles common obfuscation techniques:
- eval() unwrapping
- unescape() / decodeURIComponent() decoding
- String.fromCharCode() array reconstruction
- Hex escape sequences (\\x41)
- Unicode escape sequences (\\u0041)
- Octal escape sequences (\\101)
- parseInt() radix tricks
- Array-based string building
"""

import base64
import logging
import re
from typing import Dict, List

logger = logging.getLogger(__name__)


class JavaScriptDeobfuscator:
    """Multi-layer JavaScript deobfuscation engine.

    Usage::

        deob = JavaScriptDeobfuscator()
        result = deob.deobfuscate(obfuscated_code)
        print(result['deobfuscated'])
    """

    MAX_ITERATIONS = 10

    def deobfuscate(self, code: str) -> Dict:
        """Apply all deobfuscation passes iteratively.

        Returns:
            Dict with 'original', 'deobfuscated', 'layers', 'techniques_found'.
        """
        result: Dict = {
            'original': code,
            'deobfuscated': code,
            'layers': [],
            'techniques_found': [],
        }

        current = code
        for iteration in range(self.MAX_ITERATIONS):
            previous = current

            transforms = [
                ('hex_escape', self._decode_hex_escapes),
                ('unicode_escape', self._decode_unicode_escapes),
                ('octal_escape', self._decode_octal_escapes),
                ('fromcharcode', self._resolve_fromcharcode),
                ('unescape', self._resolve_unescape),
                ('atob', self._resolve_atob),
                ('parseint_tricks', self._resolve_parseint),
                ('string_concat', self._resolve_string_concat),
                ('eval_unwrap', self._unwrap_eval),
            ]

            for name, transform in transforms:
                try:
                    new_code = transform(current)
                    if new_code != current:
                        result['layers'].append({
                            'technique': name,
                            'iteration': iteration,
                        })
                        if name not in result['techniques_found']:
                            result['techniques_found'].append(name)
                        current = new_code
                except Exception as exc:
                    logger.debug(f"[JS-DEOB] {name} error: {exc}")

            if current == previous:
                break

        result['deobfuscated'] = current
        return result

    # ------------------------------------------------------------------
    # Transforms
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_hex_escapes(code: str) -> str:
        r"""Decode hex escape sequences.

        ``\x49\x45\x58`` -> ``IEX``
        """
        # Match sequences of \xNN
        pattern = r'(?:\\x[0-9a-fA-F]{2})+'

        def replacer(m):
            hex_str = m.group(0)
            chars = re.findall(r'\\x([0-9a-fA-F]{2})', hex_str)
            try:
                return ''.join(chr(int(h, 16)) for h in chars)
            except (ValueError, OverflowError):
                return hex_str

        return re.sub(pattern, replacer, code)

    @staticmethod
    def _decode_unicode_escapes(code: str) -> str:
        r"""Decode unicode escape sequences.

        ``\u0049\u0045\u0058`` -> ``IEX``
        """
        pattern = r'(?:\\u[0-9a-fA-F]{4})+'

        def replacer(m):
            uni_str = m.group(0)
            codes = re.findall(r'\\u([0-9a-fA-F]{4})', uni_str)
            try:
                return ''.join(chr(int(c, 16)) for c in codes)
            except (ValueError, OverflowError):
                return uni_str

        return re.sub(pattern, replacer, code)

    @staticmethod
    def _decode_octal_escapes(code: str) -> str:
        r"""Decode octal escape sequences inside strings.

        ``'\111\105\130'`` -> ``'IEX'``
        Only applies within quoted strings to avoid false positives.
        """
        def decode_in_string(m):
            s = m.group(1)
            delim = m.group(0)[0]
            # Only decode if there are octal escapes
            if '\\' not in s:
                return m.group(0)

            def octal_replacer(om):
                try:
                    return chr(int(om.group(1), 8))
                except (ValueError, OverflowError):
                    return om.group(0)

            result = re.sub(r'\\([0-7]{1,3})', octal_replacer, s)
            return f'{delim}{result}{delim}'

        # Single-quoted strings
        code = re.sub(r"'((?:[^'\\]|\\.)*)'", decode_in_string, code)
        # Double-quoted strings
        code = re.sub(r'"((?:[^"\\]|\\.)*)"', decode_in_string, code)
        return code

    @staticmethod
    def _resolve_fromcharcode(code: str) -> str:
        """Resolve String.fromCharCode() calls.

        ``String.fromCharCode(73,69,88)`` -> ``IEX``
        """
        pattern = r'String\.fromCharCode\s*\(\s*([\d\s,]+)\s*\)'

        def replacer(m):
            try:
                nums = [int(n.strip()) for n in m.group(1).split(',') if n.strip()]
                return repr(''.join(chr(n) for n in nums))
            except (ValueError, OverflowError):
                return m.group(0)

        return re.sub(pattern, replacer, code, flags=re.IGNORECASE)

    @staticmethod
    def _resolve_unescape(code: str) -> str:
        """Resolve unescape() and decodeURIComponent() calls.

        ``unescape('%49%45%58')`` -> ``'IEX'``
        """
        pattern = r'(?:unescape|decodeURIComponent)\s*\(\s*["\']([^"\']+)["\']\s*\)'

        def replacer(m):
            try:
                from urllib.parse import unquote
                decoded = unquote(m.group(1))
                return repr(decoded)
            except Exception:
                return m.group(0)

        return re.sub(pattern, replacer, code)

    @staticmethod
    def _resolve_atob(code: str) -> str:
        """Resolve atob() base64 decoding.

        ``atob('SUVY')`` -> ``'IEX'``
        """
        pattern = r'atob\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']\s*\)'

        def replacer(m):
            try:
                decoded = base64.b64decode(m.group(1)).decode('utf-8', errors='replace')
                return repr(decoded)
            except Exception:
                return m.group(0)

        return re.sub(pattern, replacer, code)

    @staticmethod
    def _resolve_parseint(code: str) -> str:
        """Resolve parseInt() with non-decimal radix used as string building.

        ``parseInt('1a',16)`` -> ``26``
        """
        pattern = r'parseInt\s*\(\s*["\']([^"\']+)["\']\s*,\s*(\d+)\s*\)'

        def replacer(m):
            try:
                return str(int(m.group(1), int(m.group(2))))
            except (ValueError, OverflowError):
                return m.group(0)

        return re.sub(pattern, replacer, code)

    @staticmethod
    def _resolve_string_concat(code: str) -> str:
        """Resolve JavaScript string concatenation.

        ``'Inv'+'oke'+'-Exp'`` -> ``'Invoke-Exp'``
        """
        # Single-quoted
        pattern = r"'([^']*)'\s*\+\s*'([^']*)'"
        while re.search(pattern, code):
            code = re.sub(pattern, r"'\1\2'", code)

        # Double-quoted
        pattern = r'"([^"]*)"\s*\+\s*"([^"]*)"'
        while re.search(pattern, code):
            code = re.sub(pattern, r'"\1\2"', code)

        return code

    @staticmethod
    def _unwrap_eval(code: str) -> str:
        """Remove eval() / Function() wrappers.

        ``eval('alert(1)')`` -> ``alert(1)``
        Only unwraps when the argument is a simple string literal.
        """
        patterns = [
            r'eval\s*\(\s*["\'](.+?)["\']\s*\)',
            r'(?:new\s+)?Function\s*\(\s*["\'](.+?)["\']\s*\)',
        ]
        for pattern in patterns:
            m = re.search(pattern, code, re.DOTALL)
            if m:
                return m.group(1)
        return code
