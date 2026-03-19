"""
Author: Ugur Ates
VBScript / VBA Deobfuscation Engine.

Handles common obfuscation techniques:
- Chr() / ChrW() decode (decimal and hex)
- String concatenation with &
- Execute() / ExecuteGlobal() extraction
- Eval() extraction
- Replace() chains
- StrReverse()
"""

import logging
import re
from typing import Dict, List

logger = logging.getLogger(__name__)


class VBScriptDeobfuscator:
    """Multi-layer VBScript / VBA deobfuscation engine.

    Usage::

        deob = VBScriptDeobfuscator()
        result = deob.deobfuscate(obfuscated_code)
        print(result['deobfuscated'])
    """

    MAX_ITERATIONS = 10

    def deobfuscate(self, code: str) -> Dict:
        """Apply all deobfuscation passes iteratively."""
        result = {
            'original': code,
            'deobfuscated': code,
            'layers': [],
            'techniques_found': [],
        }

        current = code
        for iteration in range(self.MAX_ITERATIONS):
            previous = current

            transforms = [
                ('chr_decode', self._resolve_chr),
                ('string_concat', self._resolve_concat),
                ('replace_chain', self._resolve_replace),
                ('str_reverse', self._resolve_strreverse),
                ('execute_unwrap', self._unwrap_execute),
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
                    logger.debug(f"[VBS-DEOB] {name} error: {exc}")

            if current == previous:
                break

        result['deobfuscated'] = current
        return result

    # ------------------------------------------------------------------
    # Transforms
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_chr(code: str) -> str:
        """Resolve Chr(), ChrW(), ChrB() calls.

        ``Chr(73) & Chr(69) & Chr(88)`` -> ``"IEX"``
        Also handles hex: ``Chr(&H49)``.
        """
        def chr_replacer(m):
            val_str = m.group(1).strip()
            try:
                if val_str.upper().startswith('&H'):
                    val = int(val_str[2:], 16)
                else:
                    val = int(val_str)
                return f'"{chr(val)}"'
            except (ValueError, OverflowError):
                return m.group(0)

        # Chr(N), ChrW(N), ChrB(N)
        return re.sub(
            r'(?:Chr|ChrW|ChrB)\s*\(\s*([^)]+)\s*\)',
            chr_replacer,
            code,
            flags=re.IGNORECASE,
        )

    @staticmethod
    def _resolve_concat(code: str) -> str:
        """Resolve VB string concatenation with & operator.

        ``"A" & "B" & "C"`` -> ``"ABC"``
        """
        pattern = r'"([^"]*)"\s*&\s*"([^"]*)"'
        while re.search(pattern, code):
            code = re.sub(pattern, r'"\1\2"', code)
        return code

    @staticmethod
    def _resolve_replace(code: str) -> str:
        """Resolve Replace() function calls.

        ``Replace("xEy", "x", "I")`` -> ``"IEy"``
        """
        pattern = r'Replace\s*\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)'

        def replacer(m):
            s = m.group(1)
            old = m.group(2)
            new = m.group(3)
            return f'"{s.replace(old, new)}"'

        return re.sub(pattern, replacer, code, flags=re.IGNORECASE)

    @staticmethod
    def _resolve_strreverse(code: str) -> str:
        """Resolve StrReverse() calls.

        ``StrReverse("XEI")`` -> ``"IEX"``
        """
        pattern = r'StrReverse\s*\(\s*"([^"]*)"\s*\)'

        def replacer(m):
            return f'"{m.group(1)[::-1]}"'

        return re.sub(pattern, replacer, code, flags=re.IGNORECASE)

    @staticmethod
    def _unwrap_execute(code: str) -> str:
        """Extract content from Execute() / ExecuteGlobal() / Eval() wrappers.

        ``Execute("actual-code")`` -> ``actual-code``
        """
        patterns = [
            r'(?:Execute|ExecuteGlobal|Eval)\s*\(\s*"([^"]*)"\s*\)',
            r"(?:Execute|ExecuteGlobal|Eval)\s*\(\s*'([^']*)'\s*\)",
        ]
        for pattern in patterns:
            m = re.search(pattern, code, re.IGNORECASE)
            if m:
                return m.group(1)
        return code
