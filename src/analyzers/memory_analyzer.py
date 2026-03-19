"""
Author: Ugur Ates
Memory Forensics Module - Volatility 3 CLI Wrapper.

Provides automated memory dump analysis through Volatility 3 with
built-in heuristics for detecting suspicious activity.

Detection capabilities:
- Auto-detect OS type (Windows / Linux)
- Process listing and hidden process detection (pslist vs psscan)
- Code injection detection via malfind (RWX memory regions)
- Network connection enumeration via netscan
- Command line extraction with suspicious pattern flagging
- Misspelled system process detection (process masquerading)

Best Practice: Used by SOC analysts for incident response triage of
memory dumps (.dmp, .raw, .vmem, .mem).
"""

import logging
import subprocess
import shutil
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)


class MemoryAnalyzer:
    """
    Wrapper around Volatility 3 CLI for automated memory dump analysis.

    Usage::

        analyzer = MemoryAnalyzer()
        result = analyzer.analyze('/path/to/memory.dmp')
        if result.get('success'):
            for proc in result['hidden_processes']:
                print(f"Hidden PID: {proc['pid']}")
    """

    # Suspicious command-line patterns (case-insensitive matching)
    SUSPICIOUS_CMDLINE_PATTERNS = [
        '-enc',
        '-encodedcommand',
        'certutil -urlcache',
        '-ExecutionPolicy Bypass',
        'IEX',
        'Invoke-Expression',
        'DownloadString',
        'DownloadFile',
        'Start-BitsTransfer',
        'bitsadmin /transfer',
    ]

    # Known process name misspellings used for masquerading
    MISSPELLED_PROCESSES = {
        'scvhost.exe': 'svchost.exe',
        'svch0st.exe': 'svchost.exe',
        'lssas.exe': 'lsass.exe',
        'lsas.exe': 'lsass.exe',
        'csrs.exe': 'csrss.exe',
        'cssrs.exe': 'csrss.exe',
        'svhost.exe': 'svchost.exe',
        'iexplor.exe': 'iexplore.exe',
        'exploer.exe': 'explorer.exe',
        'explore.exe': 'explorer.exe',
    }

    # Processes that should only have one instance
    SINGLETON_PROCESSES = {
        'lsass.exe', 'services.exe', 'wininit.exe', 'csrss.exe',
        'smss.exe', 'explorer.exe',
    }

    def __init__(self):
        self._vol3_available = None  # Lazy check

    def analyze(self, dump_path: str) -> Dict[str, Any]:
        """
        Run full memory forensics analysis on a dump file.

        Args:
            dump_path: Path to the memory dump file.

        Returns:
            Dict with analysis results including processes, hidden processes,
            injections, network connections, and suspicious findings.
        """
        result: Dict[str, Any] = {
            'success': False,
            'dump_path': dump_path,
            'os_type': None,
            'processes': [],
            'hidden_processes': [],
            'injections': [],
            'network_connections': [],
            'cmdlines': [],
            'suspicious_cmdlines': [],
            'suspicious_processes': [],
            'errors': [],
        }

        if not self._check_volatility_installed():
            result['errors'].append(
                'Volatility 3 is not installed or not found in PATH. '
                'Install with: pip install volatility3'
            )
            logger.warning("[MEMORY] Volatility 3 not available")
            return result

        # Detect OS type
        os_type = self._detect_os(dump_path)
        result['os_type'] = os_type
        if os_type == 'unknown':
            result['errors'].append('Could not determine OS type from memory dump')
            return result

        logger.info(f"[MEMORY] Detected OS: {os_type}")

        # Process listing
        processes = self._get_process_list(dump_path, os_type)
        result['processes'] = processes
        pslist_pids = {p['pid'] for p in processes if p.get('pid')}

        # Hidden process detection
        hidden = self._scan_hidden_processes(dump_path, os_type, pslist_pids)
        result['hidden_processes'] = hidden

        # Code injection detection
        injections = self._detect_injection(dump_path, os_type)
        result['injections'] = injections

        # Network connections
        connections = self._get_network_connections(dump_path, os_type)
        result['network_connections'] = connections

        # Command lines
        cmdlines = self._get_cmdlines(dump_path, os_type)
        result['cmdlines'] = cmdlines

        # Flag suspicious command lines
        suspicious_cmds = []
        for cmd_entry in cmdlines:
            cmd_text = cmd_entry.get('cmdline', '')
            if not cmd_text:
                continue
            cmd_lower = cmd_text.lower()
            for pattern in self.SUSPICIOUS_CMDLINE_PATTERNS:
                if pattern.lower() in cmd_lower:
                    suspicious_cmds.append({
                        'pid': cmd_entry.get('pid'),
                        'process': cmd_entry.get('process', ''),
                        'cmdline': cmd_text,
                        'matched_pattern': pattern,
                    })
                    break
        result['suspicious_cmdlines'] = suspicious_cmds

        # Suspicious process heuristics
        suspicious_procs = self._check_suspicious_processes(processes)
        result['suspicious_processes'] = suspicious_procs

        result['success'] = True

        # Summary statistics
        result['summary'] = {
            'total_processes': len(processes),
            'hidden_processes': len(hidden),
            'injections_detected': len(injections),
            'network_connections': len(connections),
            'suspicious_cmdlines': len(suspicious_cmds),
            'suspicious_processes': len(suspicious_procs),
        }

        logger.info(
            f"[MEMORY] Analysis complete: {len(processes)} procs, "
            f"{len(hidden)} hidden, {len(injections)} injections, "
            f"{len(suspicious_cmds)} suspicious cmds"
        )

        return result

    # ------------------------------------------------------------------
    # Volatility 3 interaction
    # ------------------------------------------------------------------

    def _check_volatility_installed(self) -> bool:
        """Check if Volatility 3 CLI (vol or vol3) is available."""
        if self._vol3_available is not None:
            return self._vol3_available

        # Try common command names
        for cmd in ('vol', 'vol3', 'volatility3'):
            if shutil.which(cmd) is not None:
                self._vol3_available = True
                logger.info(f"[MEMORY] Found Volatility 3 as '{cmd}'")
                return True

        # Try as a Python module
        try:
            rc, stdout, _ = self._run_vol3('', 'windows.info', test_mode=True)
            # Even if it fails with bad args, the import worked
            self._vol3_available = True
            return True
        except Exception:
            pass

        self._vol3_available = False
        return False

    def _run_vol3(self, dump_path: str, plugin: str,
                  extra_args: str = '', test_mode: bool = False) -> Tuple[int, str, str]:
        """
        Execute a Volatility 3 plugin via CLI.

        Args:
            dump_path: Path to memory dump.
            plugin: Plugin name (e.g., 'windows.pslist').
            extra_args: Additional CLI arguments.
            test_mode: If True, skip dump_path requirement.

        Returns:
            (return_code, stdout, stderr)
        """
        # Determine command
        vol_cmd = None
        for cmd in ('vol', 'vol3', 'volatility3'):
            if shutil.which(cmd) is not None:
                vol_cmd = cmd
                break

        if vol_cmd is None:
            # Fallback: try python -m volatility3.cli
            vol_cmd = 'python'
            base_args = [vol_cmd, '-m', 'volatility3.cli']
        else:
            base_args = [vol_cmd]

        if not test_mode:
            base_args.extend(['-f', dump_path])

        base_args.append(plugin)

        if extra_args:
            base_args.extend(extra_args.split())

        logger.debug(f"[MEMORY] Running: {' '.join(base_args)}")

        try:
            proc = subprocess.run(
                base_args,
                capture_output=True,
                text=True,
                timeout=300,
            )
            return (proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired:
            logger.warning(f"[MEMORY] Plugin {plugin} timed out")
            return (-1, '', 'Timeout after 300 seconds')
        except FileNotFoundError:
            return (-1, '', 'Volatility 3 command not found')
        except Exception as exc:
            return (-1, '', str(exc))

    def _detect_os(self, dump_path: str) -> str:
        """
        Detect the OS of the memory dump by trying info plugins.

        Returns:
            'windows', 'linux', or 'unknown'.
        """
        # Try Windows first (more common in forensics)
        rc, stdout, _ = self._run_vol3(dump_path, 'windows.info')
        if rc == 0 and stdout.strip():
            return 'windows'

        rc, stdout, _ = self._run_vol3(dump_path, 'linux.info')
        if rc == 0 and stdout.strip():
            return 'linux'

        return 'unknown'

    def _get_process_list(self, dump_path: str, os_type: str) -> List[Dict]:
        """Get running process list via pslist."""
        plugin = 'windows.pslist' if os_type == 'windows' else 'linux.pslist'
        rc, stdout, stderr = self._run_vol3(dump_path, plugin)

        if rc != 0:
            logger.warning(f"[MEMORY] pslist failed: {stderr[:200]}")
            return []

        return self._parse_table_output(stdout)

    def _scan_hidden_processes(self, dump_path: str, os_type: str,
                               pslist_pids: set) -> List[Dict]:
        """
        Detect hidden processes by comparing psscan with pslist.

        Processes found by psscan but not pslist (with PID > 4) are
        potentially hidden by rootkits.
        """
        plugin = 'windows.psscan' if os_type == 'windows' else 'linux.psscan'
        rc, stdout, stderr = self._run_vol3(dump_path, plugin)

        if rc != 0:
            logger.warning(f"[MEMORY] psscan failed: {stderr[:200]}")
            return []

        scan_results = self._parse_table_output(stdout)
        hidden = []

        for proc in scan_results:
            pid = proc.get('pid')
            if pid is None:
                continue
            try:
                pid_int = int(pid)
            except (ValueError, TypeError):
                continue

            # PID 0 and 4 (System) are expected to differ
            if pid_int <= 4:
                continue

            if pid_int not in pslist_pids:
                proc['reason'] = 'Found in psscan but not in pslist (potentially hidden)'
                hidden.append(proc)

        return hidden

    def _detect_injection(self, dump_path: str, os_type: str) -> List[Dict]:
        """Detect code injection via malfind (RWX memory regions)."""
        plugin = 'windows.malfind' if os_type == 'windows' else 'linux.malfind'
        rc, stdout, stderr = self._run_vol3(dump_path, plugin)

        if rc != 0:
            logger.warning(f"[MEMORY] malfind failed: {stderr[:200]}")
            return []

        return self._parse_table_output(stdout)

    def _get_network_connections(self, dump_path: str, os_type: str) -> List[Dict]:
        """Get network connections via netscan."""
        plugin = 'windows.netscan' if os_type == 'windows' else 'linux.netscan'
        rc, stdout, stderr = self._run_vol3(dump_path, plugin)

        if rc != 0:
            logger.warning(f"[MEMORY] netscan failed: {stderr[:200]}")
            return []

        return self._parse_table_output(stdout)

    def _get_cmdlines(self, dump_path: str, os_type: str) -> List[Dict]:
        """Extract process command lines."""
        plugin = 'windows.cmdline' if os_type == 'windows' else 'linux.cmdline'
        rc, stdout, stderr = self._run_vol3(dump_path, plugin)

        if rc != 0:
            logger.warning(f"[MEMORY] cmdline failed: {stderr[:200]}")
            return []

        return self._parse_table_output(stdout)

    # ------------------------------------------------------------------
    # Heuristic checks
    # ------------------------------------------------------------------

    def _check_suspicious_processes(self, processes: List[Dict]) -> List[Dict]:
        """
        Apply heuristics to detect suspicious processes.

        Checks:
        - Misspelled system process names (masquerading)
        - Multiple instances of singleton processes (e.g., lsass.exe)
        """
        findings: List[Dict] = []

        # Track process name occurrences
        name_counts: Dict[str, int] = {}
        for proc in processes:
            name = proc.get('name', proc.get('ImageFileName', '')).strip().lower()
            if not name:
                continue
            name_counts[name] = name_counts.get(name, 0) + 1

        for proc in processes:
            name = proc.get('name', proc.get('ImageFileName', '')).strip()
            name_lower = name.lower()
            pid = proc.get('pid', proc.get('PID', 'N/A'))

            # Check for misspelled process names
            if name_lower in self.MISSPELLED_PROCESSES:
                real_name = self.MISSPELLED_PROCESSES[name_lower]
                findings.append({
                    'pid': pid,
                    'process': name,
                    'finding': 'process_masquerading',
                    'description': (
                        f'Process "{name}" appears to impersonate "{real_name}" '
                        f'(possible masquerading / T1036.004)'
                    ),
                    'severity': 'CRITICAL',
                })

        # Check for multiple singleton processes
        for singleton in self.SINGLETON_PROCESSES:
            count = name_counts.get(singleton, 0)
            if count > 1:
                findings.append({
                    'process': singleton,
                    'finding': 'multiple_singleton',
                    'description': (
                        f'Found {count} instances of "{singleton}" '
                        f'(expected 1 - possible process hollowing / T1055.012)'
                    ),
                    'severity': 'HIGH',
                    'count': count,
                })

        return findings

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_table_output(output: str) -> List[Dict]:
        """
        Parse Volatility 3 tabular text output into list of dicts.

        Vol3 outputs tab-separated or column-aligned tables with a header row.
        """
        if not output or not output.strip():
            return []

        lines = output.strip().splitlines()

        # Skip any preamble lines (lines before the header)
        header_idx = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            # Header line typically contains column names like PID, PPID, etc.
            if stripped and not stripped.startswith('*') and not stripped.startswith('Volatility'):
                header_idx = i
                break

        if header_idx >= len(lines):
            return []

        header_line = lines[header_idx]
        # Try tab separation first, then whitespace
        if '\t' in header_line:
            headers = [h.strip().lower().replace(' ', '_') for h in header_line.split('\t')]
            sep = '\t'
        else:
            headers = [h.strip().lower().replace(' ', '_') for h in header_line.split()]
            sep = None  # whitespace split

        results = []
        for line in lines[header_idx + 1:]:
            line = line.strip()
            if not line or line.startswith('-'):
                continue

            if sep == '\t':
                values = [v.strip() for v in line.split('\t')]
            else:
                values = line.split()

            row = {}
            for j, header in enumerate(headers):
                if j < len(values):
                    val = values[j]
                    # Try to convert numeric values
                    try:
                        val = int(val)
                    except (ValueError, TypeError):
                        pass
                    row[header] = val
                else:
                    row[header] = None

            # Normalize common field names
            if 'pid' not in row:
                for key in ('PID', 'Pid', 'process_id'):
                    if key.lower() in row:
                        row['pid'] = row[key.lower()]
                        break

            if 'name' not in row:
                for key in ('imagefilename', 'image_file_name', 'process'):
                    if key in row:
                        row['name'] = row[key]
                        break

            if 'cmdline' not in row:
                for key in ('args', 'command_line', 'commandline'):
                    if key in row:
                        row['cmdline'] = row[key]
                        break

            results.append(row)

        return results
