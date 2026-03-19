"""
Author: Ugur Ates
Batch/CMD Deobfuscation Engine.

Handles common obfuscation techniques:
- Caret escape removal (c^m^d -> cmd)
- Variable expansion (%ComSpec%, %APPDATA%, etc.)
- SET variable building (set a=pow & set b=ershell & %a%%b%)
- Substring extraction (%var:~start,length%)
- Delayed expansion (!var!)
- Double percent signs (%% -> %)
- CALL obfuscation
- Environment variable abuse
"""

import logging
import re
from typing import Dict, List

logger = logging.getLogger(__name__)

# Common Windows environment variables with typical values
ENV_VARS = {
    '%comspec%': 'C:\\Windows\\system32\\cmd.exe',
    '%systemroot%': 'C:\\Windows',
    '%windir%': 'C:\\Windows',
    '%temp%': 'C:\\Users\\User\\AppData\\Local\\Temp',
    '%tmp%': 'C:\\Users\\User\\AppData\\Local\\Temp',
    '%appdata%': 'C:\\Users\\User\\AppData\\Roaming',
    '%localappdata%': 'C:\\Users\\User\\AppData\\Local',
    '%programfiles%': 'C:\\Program Files',
    '%programfiles(x86)%': 'C:\\Program Files (x86)',
    '%programdata%': 'C:\\ProgramData',
    '%userprofile%': 'C:\\Users\\User',
    '%homedrive%': 'C:',
    '%homepath%': '\\Users\\User',
    '%systemdrive%': 'C:',
    '%pathext%': '.COM;.EXE;.BAT;.CMD;.VBS;.JS;.WSH;.MSC',
    '%os%': 'Windows_NT',
    '%public%': 'C:\\Users\\Public',
    '%allusersprofile%': 'C:\\ProgramData',
}


class BatchDeobfuscator:
    """Multi-layer Batch/CMD deobfuscation engine.

    Usage::

        deob = BatchDeobfuscator()
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
                ('caret_removal', self._remove_carets),
                ('set_variable_building', self._resolve_set_variables),
                ('env_var_expansion', self._expand_env_vars),
                ('substring_extraction', self._resolve_substrings),
                ('double_percent', self._resolve_double_percent),
                ('call_obfuscation', self._resolve_call),
                ('echo_off_removal', self._remove_echo_off),
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
                    logger.debug(f"[BAT-DEOB] {name} error: {exc}")

            if current == previous:
                break

        result['deobfuscated'] = current
        return result

    # ------------------------------------------------------------------
    # Transforms
    # ------------------------------------------------------------------

    @staticmethod
    def _remove_carets(code: str) -> str:
        """Remove caret escape characters.

        ``c^m^d /c who^ami`` -> ``cmd /c whoami``
        Carets before newlines (line continuation) are preserved.
        """
        # Remove carets NOT before newlines
        return re.sub(r'\^([^\r\n])', r'\1', code)

    @staticmethod
    def _resolve_double_percent(code: str) -> str:
        """Resolve double percent signs in batch files.

        ``%%A`` -> ``%A`` (within FOR loops and batch files)
        """
        return code.replace('%%', '%')

    @staticmethod
    def _resolve_set_variables(code: str) -> str:
        """Resolve SET variable building and expand them.

        Handles::
            set a=pow
            set b=ershell
            %a%%b%  -> powershell
        """
        # Extract all SET assignments
        variables: Dict[str, str] = {}
        set_pattern = re.compile(
            r'set\s+/a\s+(\w+)\s*=\s*(.+?)$|'  # set /a var=expr
            r'set\s+"(\w+)=([^"]*)"$|'           # set "var=value"
            r'set\s+(\w+)\s*=\s*(.*)$',          # set var=value
            re.MULTILINE | re.IGNORECASE,
        )

        for m in set_pattern.finditer(code):
            if m.group(1):
                variables[m.group(1).lower()] = m.group(2).strip()
            elif m.group(3):
                variables[m.group(3).lower()] = m.group(4).strip()
            elif m.group(5):
                variables[m.group(5).lower()] = m.group(6).strip()

        if not variables:
            return code

        # Expand %var% references
        result = code
        max_passes = 5
        for _ in range(max_passes):
            prev = result
            for var, val in variables.items():
                # Case-insensitive variable replacement
                result = re.sub(
                    r'%' + re.escape(var) + r'%',
                    val,
                    result,
                    flags=re.IGNORECASE,
                )
            if result == prev:
                break

        # Also expand !var! (delayed expansion)
        for _ in range(max_passes):
            prev = result
            for var, val in variables.items():
                result = re.sub(
                    r'!' + re.escape(var) + r'!',
                    val,
                    result,
                    flags=re.IGNORECASE,
                )
            if result == prev:
                break

        return result

    @staticmethod
    def _expand_env_vars(code: str) -> str:
        """Expand known environment variables.

        ``%ComSpec%`` -> ``C:\\Windows\\system32\\cmd.exe``
        """
        result = code
        for var, val in ENV_VARS.items():
            result = re.sub(
                re.escape(var),
                val.replace('\\', '\\\\'),  # Escape backslashes for re.sub
                result,
                flags=re.IGNORECASE,
            )
        return result

    @staticmethod
    def _resolve_substrings(code: str) -> str:
        """Resolve variable substring extraction.

        ``%var:~0,3%`` extracts characters 0 to 2 from var's value.
        This is a common obfuscation technique.
        """
        # Pattern: %varname:~start,length%
        # We can only resolve this if the variable is a known env var
        pattern = r'%(\w+):~(-?\d+),(-?\d+)%'

        def replacer(m):
            var_name = m.group(1).lower()
            start = int(m.group(2))
            length = int(m.group(3))

            # Check known env vars
            full_var = f'%{var_name}%'
            value = ENV_VARS.get(full_var)
            if value is None:
                return m.group(0)

            try:
                if start < 0:
                    start = max(0, len(value) + start)
                if length < 0:
                    return value[start:length]
                return value[start:start + length]
            except (IndexError, ValueError):
                return m.group(0)

        return re.sub(pattern, replacer, code, flags=re.IGNORECASE)

    @staticmethod
    def _resolve_call(code: str) -> str:
        """Resolve CALL obfuscation.

        ``call cmd /c whoami`` -> ``cmd /c whoami``
        CALL is used to bypass certain detections.
        """
        # Remove leading CALL from command invocations
        # Be careful to only remove it when it's used for obfuscation
        return re.sub(
            r'^call\s+(?=cmd|powershell|wscript|cscript|mshta|certutil|bitsadmin)',
            '',
            code,
            flags=re.MULTILINE | re.IGNORECASE,
        )

    @staticmethod
    def _remove_echo_off(code: str) -> str:
        """Remove @echo off and other noise for cleaner output.

        ``@echo off`` at the start of batch files is noise for analysis.
        """
        return re.sub(r'^@?\s*echo\s+off\s*$', '', code,
                       flags=re.MULTILINE | re.IGNORECASE).strip()
