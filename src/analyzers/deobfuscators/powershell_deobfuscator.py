"""
Author: Ugur Ates
PowerShell Deobfuscation Engine.

Handles common obfuscation techniques:
- String concatenation ('A'+'msi')
- Backtick/tick-mark obfuscation (I`EX, Ne`w-Ob`ject)
- [char] array reconstruction ([char]73+[char]69+...)
- Environment variable concatenation ($env:x)
- Replace() chains (.Replace('x','y'))
- Format operator (-f)
- Nested base64 / SecureString
- Invoke-Expression / IEX wrapper removal
- Reverse string reconstruction
"""

import base64
import logging
import re
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


class PowerShellDeobfuscator:
    """Multi-layer PowerShell deobfuscation engine.

    Usage::

        deob = PowerShellDeobfuscator()
        result = deob.deobfuscate(obfuscated_code)
        print(result['deobfuscated'])
    """

    MAX_ITERATIONS = 10  # Prevent infinite loops

    def deobfuscate(self, code: str) -> Dict:
        """Apply all deobfuscation passes iteratively.

        Returns:
            Dict with 'original', 'deobfuscated', 'layers', 'techniques_found'.
        """
        result = {
            'original': code,
            'deobfuscated': code,
            'layers': [],
            'techniques_found': [],
        }

        current = code
        for iteration in range(self.MAX_ITERATIONS):
            previous = current

            # Apply each transform
            transforms = [
                ('backtick_removal', self._remove_backticks),
                ('caret_removal', self._remove_carets),
                ('string_concat', self._resolve_string_concat),
                ('char_array', self._resolve_char_array),
                ('format_operator', self._resolve_format_operator),
                ('replace_chain', self._resolve_replace_chains),
                ('base64_decode', self._decode_base64),
                ('reverse_string', self._resolve_reverse_string),
                ('iex_unwrap', self._unwrap_iex),
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
                    logger.debug(f"[PS-DEOB] {name} error: {exc}")

            if current == previous:
                break  # No more changes

        result['deobfuscated'] = current
        return result

    # ------------------------------------------------------------------
    # Transforms
    # ------------------------------------------------------------------

    @staticmethod
    def _remove_backticks(code: str) -> str:
        """Remove PowerShell backtick escape chars used for obfuscation.

        ``I`EX`` -> ``IEX``, ``Ne`w-Ob`ject`` -> ``New-Object``
        Preserves meaningful escapes like `n, `t, `r.
        """
        # Remove backticks NOT followed by n, t, r, 0, a, b, f, v
        return re.sub(r'`([^ntr0abfv])', r'\1', code)

    @staticmethod
    def _remove_carets(code: str) -> str:
        """Remove cmd-style caret escapes: c^m^d -> cmd."""
        return code.replace('^', '')

    @staticmethod
    def _resolve_string_concat(code: str) -> str:
        """Resolve PowerShell string concatenation.

        ``'Inv'+'oke'+'-Exp'+'ression'`` -> ``'Invoke-Expression'``
        """
        # Match adjacent quoted strings with + between them
        pattern = r"'([^']*)'\s*\+\s*'([^']*)'"
        while re.search(pattern, code):
            code = re.sub(pattern, r"'\1\2'", code)

        # Double-quoted
        pattern = r'"([^"]*)"\s*\+\s*"([^"]*)"'
        while re.search(pattern, code):
            code = re.sub(pattern, r'"\1\2"', code)

        return code

    @staticmethod
    def _resolve_char_array(code: str) -> str:
        """Resolve [char]XX+[char]YY patterns.

        ``[char]73+[char]69+[char]88`` -> ``IEX``
        """
        # Find sequences of [char]NN joined by +
        pattern = r'\[char\]\s*(\d+)(?:\s*\+\s*\[char\]\s*(\d+))+'

        def replacer(m):
            # Re-extract all numbers from the full match (case-insensitive!)
            nums = re.findall(r'\[char\]\s*(\d+)', m.group(0), re.IGNORECASE)
            try:
                return ''.join(chr(int(n)) for n in nums)
            except (ValueError, OverflowError):
                return m.group(0)

        return re.sub(pattern, replacer, code, flags=re.IGNORECASE)

    @staticmethod
    def _resolve_format_operator(code: str) -> str:
        """Resolve PowerShell -f format operator.

        ``'{0}{1}'-f 'IE','X'`` -> ``'IEX'``
        """
        pattern = r"'([^']+)'\s*-f\s*'([^']+)'(?:\s*,\s*'([^']+)')*"

        def replacer(m):
            fmt = m.group(0)
            # Extract template and arguments
            template_m = re.match(r"'([^']+)'\s*-f\s*(.+)", fmt)
            if not template_m:
                return fmt
            template = template_m.group(1)
            args_str = template_m.group(2)
            args = re.findall(r"'([^']*)'", args_str)
            try:
                result = template
                for i, arg in enumerate(args):
                    result = result.replace(f'{{{i}}}', arg)
                return f"'{result}'"
            except Exception:
                return fmt

        return re.sub(pattern, replacer, code, flags=re.IGNORECASE)

    @staticmethod
    def _resolve_replace_chains(code: str) -> str:
        """Resolve .Replace() chains.

        ``'xEy'.Replace('x','I').Replace('y','X')`` -> ``'IEX'``
        """
        # Find string followed by .Replace() calls
        pattern = r"'([^']*)'\s*((?:\.Replace\s*\([^)]+\)\s*)+)"

        def replacer(m):
            s = m.group(1)
            replacements = re.findall(
                r"\.Replace\s*\(\s*'([^']*)'\s*,\s*'([^']*)'\s*\)",
                m.group(2)
            )
            for old, new in replacements:
                s = s.replace(old, new)
            return f"'{s}'"

        return re.sub(pattern, replacer, code, flags=re.IGNORECASE)

    @staticmethod
    def _decode_base64(code: str) -> str:
        """Decode -EncodedCommand or inline base64 strings.

        Handles:
        - ``-EncodedCommand <base64>``
        - ``[Convert]::FromBase64String('...')``
        - ``[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('...'))``
        """
        # -EncodedCommand / -enc / -ec
        enc_pattern = r'-(?:EncodedCommand|enc|ec)\s+([A-Za-z0-9+/=]{20,})'

        def decode_b64(m):
            b64 = m.group(1)
            try:
                decoded = base64.b64decode(b64)
                # Try UTF-16LE (PowerShell default for -EncodedCommand)
                try:
                    text = decoded.decode('utf-16-le')
                except UnicodeDecodeError:
                    text = decoded.decode('utf-8', errors='replace')
                return text
            except Exception:
                return m.group(0)

        code = re.sub(enc_pattern, decode_b64, code)

        # [Convert]::FromBase64String('...')
        convert_pattern = r"\[(?:System\.)?Convert\]::FromBase64String\(\s*'([A-Za-z0-9+/=]+)'\s*\)"

        def decode_convert(m):
            try:
                decoded = base64.b64decode(m.group(1))
                text = decoded.decode('utf-8', errors='replace')
                return f"'{text}'"
            except Exception:
                return m.group(0)

        code = re.sub(convert_pattern, decode_convert, code, flags=re.IGNORECASE)

        return code

    @staticmethod
    def _resolve_reverse_string(code: str) -> str:
        """Resolve reversed string patterns.

        ``-join ('X','E','I')[-1..-3]`` or ``'XEI'[-1..-3] -join ''``
        """
        # Simple: 'string'[-1..-N]
        pattern = r"'([^']+)'\s*\[\s*-1\s*\.\.\s*-\d+\s*\]"

        def replacer(m):
            return f"'{m.group(1)[::-1]}'"

        return re.sub(pattern, replacer, code)

    @staticmethod
    def _unwrap_iex(code: str) -> str:
        """Remove IEX / Invoke-Expression wrappers.

        ``IEX('actual-code')`` -> ``actual-code``
        """
        patterns = [
            r'(?:IEX|Invoke-Expression)\s*\(\s*(.+?)\s*\)\s*$',
            r'(?:IEX|Invoke-Expression)\s+(.+)$',
            r'\.\s*\(\s*(.+?)\s*\)\s*$',  # .('code')
        ]
        for pattern in patterns:
            m = re.match(pattern, code.strip(), re.IGNORECASE | re.DOTALL)
            if m:
                inner = m.group(1).strip()
                # Remove outer quotes if present
                if (inner.startswith("'") and inner.endswith("'")) or \
                   (inner.startswith('"') and inner.endswith('"')):
                    inner = inner[1:-1]
                return inner

        return code
