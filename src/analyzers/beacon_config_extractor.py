"""
Author: Ugur Ates
Cobalt Strike Beacon Config Extraction Module.

Extract Cobalt Strike beacon configuration from PE binaries using XOR
decryption and TLV (Type-Length-Value) parsing.

Detection capabilities:
- XOR brute-force with known CS keys (0x69 for CS 3.x, 0x2E for CS 4.x)
- Fallback XOR scan (0x00-0xFF) on first 1024 bytes when magic header found
- TLV parser for beacon configuration blocks
- Extraction of C2 servers, ports, user agents, watermarks, public keys
- Known JA3S / JARM fingerprint matching
- IOC extraction from decoded configuration

Best Practice: Called from shellcode_detector.py when Cobalt Strike signatures
are detected, or from malware_analyzer.py to enrich analysis output.
"""

import logging
import struct
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class BeaconConfigExtractor:
    """
    Extract and parse Cobalt Strike beacon configuration from binary data.

    Usage::

        extractor = BeaconConfigExtractor()
        config = extractor.extract_config(file_data)
        if config.get('success'):
            print(config['c2_server'])
    """

    # XOR keys used by Cobalt Strike versions
    CS3_XOR_KEY = 0x69
    CS4_XOR_KEY = 0x2E

    # Beacon type enum
    BEACON_TYPES = {
        0: 'HTTP',
        1: 'Hybrid HTTP/DNS',
        2: 'SMB',
        4: 'TCP',
        8: 'HTTPS',
        16: 'DNS-over-HTTPS',
    }

    # TLV Field IDs
    FIELD_BEACON_TYPE = 1
    FIELD_PORT = 2
    FIELD_SLEEP_TIME = 3
    FIELD_JITTER = 5
    FIELD_PUBLIC_KEY = 7
    FIELD_C2_SERVER = 8
    FIELD_USER_AGENT = 9
    FIELD_POST_URI = 10
    FIELD_SPAWN_TO_X86 = 13
    FIELD_SPAWN_TO_X64 = 14
    FIELD_WATERMARK = 37
    FIELD_LICENSE_ID = 38
    FIELD_PIPE_NAME = 54

    # Field type hints: 1 = short (2 bytes), 2 = int (4 bytes), 3 = blob/string
    FIELD_TYPES = {
        FIELD_BEACON_TYPE: 1,
        FIELD_PORT: 1,
        FIELD_SLEEP_TIME: 2,
        FIELD_JITTER: 1,
        FIELD_PUBLIC_KEY: 3,
        FIELD_C2_SERVER: 3,
        FIELD_USER_AGENT: 3,
        FIELD_POST_URI: 3,
        FIELD_SPAWN_TO_X86: 3,
        FIELD_SPAWN_TO_X64: 3,
        FIELD_WATERMARK: 2,
        FIELD_LICENSE_ID: 2,
        FIELD_PIPE_NAME: 3,
    }

    # Known JA3S hashes associated with Cobalt Strike
    KNOWN_JA3S = [
        'ae4edc6faf64d08308082ad26be60767',
        'a0e9f5d64349fb13191bc781f81f42e1',
    ]

    # Known JARM hash for Cobalt Strike
    KNOWN_JARM = '07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1'

    # Magic header bytes that indicate a potential config block
    # CS uses 0x0000BEEF (big-endian) or 0x0000FACE as config markers
    CONFIG_MAGIC_MARKERS = [
        b'\x00\x00\xBE\xEF',
        b'\x00\x00\xFA\xCE',
    ]

    # Minimum config block size (bytes)
    MIN_CONFIG_SIZE = 128

    def extract_config(self, file_data: bytes) -> Dict[str, Any]:
        """
        Attempt to extract Cobalt Strike beacon configuration.

        Args:
            file_data: Raw binary content of the PE file.

        Returns:
            Dict with extracted config fields or error information.
        """
        if not file_data or len(file_data) < self.MIN_CONFIG_SIZE:
            return {'success': False, 'error': 'Data too small for beacon config'}

        result: Dict[str, Any] = {
            'success': False,
            'xor_key': None,
            'cs_version': None,
            'config': {},
            'iocs': [],
        }

        # Try to find and decrypt the config block
        config_block = self._find_config_block(file_data)
        if config_block is None:
            logger.debug("[BEACON] No config block found in data")
            return result

        decrypted_data, xor_key = config_block
        result['xor_key'] = f'0x{xor_key:02x}'

        if xor_key == self.CS3_XOR_KEY:
            result['cs_version'] = '3.x'
        elif xor_key == self.CS4_XOR_KEY:
            result['cs_version'] = '4.x'
        else:
            result['cs_version'] = 'unknown'

        # Parse TLV fields from decrypted config
        try:
            parsed = self._parse_tlv(decrypted_data)
        except Exception as exc:
            logger.warning(f"[BEACON] TLV parsing failed: {exc}")
            return result

        if not parsed:
            return result

        # Extract known fields
        config = {}

        # Beacon type
        beacon_type_raw = self._get_field_value(parsed, self.FIELD_BEACON_TYPE)
        if beacon_type_raw is not None:
            config['beacon_type'] = self.BEACON_TYPES.get(beacon_type_raw, f'Unknown({beacon_type_raw})')
            config['beacon_type_raw'] = beacon_type_raw

        # Port
        port = self._get_field_value(parsed, self.FIELD_PORT)
        if port is not None:
            config['port'] = port

        # Sleep time (milliseconds)
        sleep_time = self._get_field_value(parsed, self.FIELD_SLEEP_TIME)
        if sleep_time is not None:
            config['sleep_time_ms'] = sleep_time
            config['sleep_time_human'] = f'{sleep_time / 1000:.1f}s'

        # Jitter percentage
        jitter = self._get_field_value(parsed, self.FIELD_JITTER)
        if jitter is not None:
            config['jitter_percent'] = jitter

        # Public key
        pubkey = self._get_field_value(parsed, self.FIELD_PUBLIC_KEY)
        if pubkey is not None:
            if isinstance(pubkey, bytes):
                config['public_key'] = pubkey.hex()
                config['public_key_len'] = len(pubkey)
            else:
                config['public_key'] = str(pubkey)

        # C2 Server
        c2 = self._get_field_value(parsed, self.FIELD_C2_SERVER)
        if c2 is not None:
            c2_str = c2.decode('utf-8', errors='ignore').rstrip('\x00') if isinstance(c2, bytes) else str(c2)
            config['c2_server'] = c2_str
            # Parse individual C2 addresses as IOCs
            for addr in c2_str.split(','):
                addr = addr.strip()
                if addr:
                    result['iocs'].append({
                        'type': 'c2_address',
                        'value': addr,
                        'source': 'beacon_config',
                    })

        # User-Agent
        ua = self._get_field_value(parsed, self.FIELD_USER_AGENT)
        if ua is not None:
            config['user_agent'] = ua.decode('utf-8', errors='ignore').rstrip('\x00') if isinstance(ua, bytes) else str(ua)

        # Post URI
        post_uri = self._get_field_value(parsed, self.FIELD_POST_URI)
        if post_uri is not None:
            config['post_uri'] = post_uri.decode('utf-8', errors='ignore').rstrip('\x00') if isinstance(post_uri, bytes) else str(post_uri)

        # Watermark
        watermark = self._get_field_value(parsed, self.FIELD_WATERMARK)
        if watermark is not None:
            config['watermark'] = watermark

        # License ID
        license_id = self._get_field_value(parsed, self.FIELD_LICENSE_ID)
        if license_id is not None:
            config['license_id'] = license_id

        # Pipe name (SMB beacons)
        pipe = self._get_field_value(parsed, self.FIELD_PIPE_NAME)
        if pipe is not None:
            config['pipe_name'] = pipe.decode('utf-8', errors='ignore').rstrip('\x00') if isinstance(pipe, bytes) else str(pipe)

        # SpawnTo
        spawn_x86 = self._get_field_value(parsed, self.FIELD_SPAWN_TO_X86)
        if spawn_x86 is not None:
            config['spawn_to_x86'] = spawn_x86.decode('utf-8', errors='ignore').rstrip('\x00') if isinstance(spawn_x86, bytes) else str(spawn_x86)

        spawn_x64 = self._get_field_value(parsed, self.FIELD_SPAWN_TO_X64)
        if spawn_x64 is not None:
            config['spawn_to_x64'] = spawn_x64.decode('utf-8', errors='ignore').rstrip('\x00') if isinstance(spawn_x64, bytes) else str(spawn_x64)

        # Add known threat intel fingerprints
        config['known_ja3s_hashes'] = self.KNOWN_JA3S
        config['known_jarm_hash'] = self.KNOWN_JARM

        result['config'] = config
        result['success'] = bool(config)

        if result['success']:
            logger.info(
                f"[BEACON] Extracted config: CS {result['cs_version']}, "
                f"key=0x{xor_key:02x}, "
                f"C2={config.get('c2_server', 'N/A')}, "
                f"port={config.get('port', 'N/A')}"
            )

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _xor_decrypt(self, data: bytes, key: int) -> bytes:
        """XOR decrypt a byte sequence with a single-byte key."""
        return bytes(b ^ key for b in data)

    def _find_config_block(self, data: bytes) -> Optional[Tuple[bytes, int]]:
        """
        Locate and decrypt the beacon config block.

        Strategy:
        1. Try known CS keys (0x69 for 3.x, 0x2E for 4.x) on the entire file.
        2. Fallback: brute-force 0x00-0xFF on the first 1024 bytes if magic found.

        Returns:
            (decrypted_config_bytes, xor_key) or None.
        """
        # Phase 1: try known keys across the full data
        for key in (self.CS4_XOR_KEY, self.CS3_XOR_KEY):
            decrypted = self._xor_decrypt(data, key)
            for marker in self.CONFIG_MAGIC_MARKERS:
                offset = decrypted.find(marker)
                if offset != -1:
                    # Config block starts after the 4-byte marker
                    config_start = offset + 4
                    config_data = decrypted[config_start:]
                    if len(config_data) >= self.MIN_CONFIG_SIZE:
                        logger.debug(
                            f"[BEACON] Config found at offset 0x{offset:x} with key 0x{key:02x}"
                        )
                        return (config_data, key)

        # Phase 2: brute-force on first 1024 bytes
        scan_region = data[:1024]
        for key in range(0x00, 0x100):
            if key in (self.CS3_XOR_KEY, self.CS4_XOR_KEY):
                continue  # Already tried
            decrypted = self._xor_decrypt(scan_region, key)
            for marker in self.CONFIG_MAGIC_MARKERS:
                offset = decrypted.find(marker)
                if offset != -1:
                    # Re-decrypt the full data with this key
                    full_decrypted = self._xor_decrypt(data, key)
                    config_start = offset + 4
                    config_data = full_decrypted[config_start:]
                    if len(config_data) >= self.MIN_CONFIG_SIZE:
                        logger.debug(
                            f"[BEACON] Config found via brute-force at 0x{offset:x} "
                            f"with key 0x{key:02x}"
                        )
                        return (config_data, key)

        return None

    def _parse_tlv(self, config_data: bytes) -> Dict[int, Any]:
        """
        Parse TLV (Type-Length-Value) encoded beacon configuration.

        CS beacon config uses a simple TLV format:
        - Type:   2 bytes (big-endian unsigned short)
        - Length:  2 bytes (big-endian unsigned short)
        - Value:   `Length` bytes

        Returns:
            Dict mapping field_id -> raw value.
        """
        parsed: Dict[int, Any] = {}
        offset = 0

        while offset + 4 <= len(config_data):
            try:
                field_type = struct.unpack_from('>H', config_data, offset)[0]
                field_length = struct.unpack_from('>H', config_data, offset + 2)[0]
            except struct.error:
                break

            offset += 4

            # Sanity checks
            if field_type == 0 and field_length == 0:
                break  # End of config
            if field_length > 4096:
                break  # Implausible field length
            if offset + field_length > len(config_data):
                break  # Truncated data

            raw_value = config_data[offset:offset + field_length]
            offset += field_length

            # Decode based on known field type hints
            expected_type = self.FIELD_TYPES.get(field_type)
            if expected_type == 1 and field_length >= 2:
                # Short value
                parsed[field_type] = struct.unpack_from('>H', raw_value)[0]
            elif expected_type == 2 and field_length >= 4:
                # Integer value
                parsed[field_type] = struct.unpack_from('>I', raw_value)[0]
            elif expected_type == 3:
                # Blob / string
                parsed[field_type] = raw_value
            else:
                # Store raw bytes for unknown fields
                parsed[field_type] = raw_value

        return parsed

    def _get_field_value(self, parsed: dict, field_id: int) -> Any:
        """Retrieve a parsed field value, returning None if absent."""
        return parsed.get(field_id)
