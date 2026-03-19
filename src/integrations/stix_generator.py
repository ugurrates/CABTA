"""
Author: Ugur Ates
STIX 2.1 Indicator Generation Module.

Generate STIX 2.1 compliant indicators, malware objects, and bundles
from analysis results. Uses plain Python dicts (no stix2 library dependency).

Features:
- Convert IOCs to STIX 2.1 indicators (ipv4-addr, domain-name, file hashes, url, email-addr)
- TLP marking definitions (RED, AMBER, GREEN, CLEAR)
- Create STIX bundles from full analysis results
- JSON export for sharing with STIX-compatible platforms (TAXII, OpenCTI, MISP)
- Identity object for CABTA attribution

Reference: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
"""

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class STIXGenerator:
    """
    Generate STIX 2.1 JSON objects from analysis results.

    Usage::

        gen = STIXGenerator(organization_name="CABTA")
        indicator = gen.ioc_to_indicator('ipv4-addr', '192.168.1.1',
                                         name='Suspicious IP', tlp='AMBER')
        bundle = gen.analysis_to_bundle(analysis_result)
        gen.export_json(bundle, '/tmp/stix_bundle.json')
    """

    # Standard TLP Marking Definition IDs (STIX 2.1)
    TLP_CLEAR = 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9'
    TLP_GREEN = 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da'
    TLP_AMBER = 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'
    TLP_RED = 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed'

    TLP_MAP = {
        'CLEAR': TLP_CLEAR,
        'WHITE': TLP_CLEAR,  # Legacy alias
        'GREEN': TLP_GREEN,
        'AMBER': TLP_AMBER,
        'RED': TLP_RED,
    }

    # STIX spec version
    SPEC_VERSION = '2.1'

    # IOC type to STIX pattern mapping
    IOC_PATTERN_MAP = {
        'ipv4-addr': "ipv4-addr:value = '{value}'",
        'ipv6-addr': "ipv6-addr:value = '{value}'",
        'domain-name': "domain-name:value = '{value}'",
        'url': "url:value = '{value}'",
        'email-addr': "email-addr:value = '{value}'",
        'md5': "file:hashes.MD5 = '{value}'",
        'sha1': "file:hashes.'SHA-1' = '{value}'",
        'sha256': "file:hashes.'SHA-256' = '{value}'",
        'sha512': "file:hashes.'SHA-512' = '{value}'",
        'file-hash': "file:hashes.'SHA-256' = '{value}'",
    }

    # Regex patterns for IOC type auto-detection
    IOC_DETECT_PATTERNS = {
        'ipv4-addr': re.compile(
            r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
        ),
        'ipv6-addr': re.compile(r'^[0-9a-fA-F:]+$'),
        'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
        'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
        'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
        'sha512': re.compile(r'^[a-fA-F0-9]{128}$'),
        'email-addr': re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$'),
        'url': re.compile(r'^https?://', re.IGNORECASE),
        'domain-name': re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'),
    }

    def __init__(self, organization_name: str = "CABTA"):
        self.organization_name = organization_name
        self._identity_id = f'identity--{uuid.uuid4()}'

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_identity(self) -> dict:
        """Create a STIX Identity object for the generating organization."""
        now = self._timestamp()
        return {
            'type': 'identity',
            'spec_version': self.SPEC_VERSION,
            'id': self._identity_id,
            'created': now,
            'modified': now,
            'name': self.organization_name,
            'description': f'{self.organization_name} - Cyber Blue Team Assistant',
            'identity_class': 'organization',
        }

    def ioc_to_indicator(
        self,
        ioc_type: str,
        ioc_value: str,
        name: str = "",
        description: str = "",
        confidence: int = 50,
        tlp: str = "GREEN",
    ) -> dict:
        """
        Convert a single IOC to a STIX 2.1 Indicator object.

        Args:
            ioc_type: IOC type (e.g. 'ipv4-addr', 'domain-name', 'sha256', 'url').
            ioc_value: The IOC value.
            name: Human-readable indicator name.
            description: Optional description.
            confidence: Confidence score 0-100.
            tlp: TLP marking level (CLEAR, GREEN, AMBER, RED).

        Returns:
            STIX Indicator dict.
        """
        pattern = self._create_indicator_pattern(ioc_type, ioc_value)
        if not pattern:
            logger.warning(f"[STIX] Unsupported IOC type: {ioc_type}")
            return {}

        now = self._timestamp()
        indicator_id = f'indicator--{uuid.uuid4()}'

        indicator = {
            'type': 'indicator',
            'spec_version': self.SPEC_VERSION,
            'id': indicator_id,
            'created': now,
            'modified': now,
            'name': name or f'{ioc_type}: {ioc_value}',
            'description': description or f'IOC extracted by {self.organization_name}',
            'indicator_types': [self._ioc_type_to_indicator_type(ioc_type)],
            'pattern': f'[{pattern}]',
            'pattern_type': 'stix',
            'pattern_version': '2.1',
            'valid_from': now,
            'confidence': max(0, min(100, confidence)),
            'created_by_ref': self._identity_id,
        }

        # Apply TLP marking
        tlp_id = self.TLP_MAP.get(tlp.upper())
        if tlp_id:
            indicator['object_marking_refs'] = [tlp_id]

        return indicator

    def analysis_to_bundle(self, analysis_result: dict, tlp: str = "GREEN") -> dict:
        """
        Create a STIX 2.1 Bundle from a full analysis result dict.

        Extracts IOCs from the analysis and converts them to STIX indicators.
        Optionally creates a malware object if a verdict is available.

        Args:
            analysis_result: The output dict from MalwareAnalyzer.analyze().
            tlp: Default TLP marking for all objects.

        Returns:
            STIX Bundle dict.
        """
        objects: List[dict] = []

        # Identity
        identity = self.create_identity()
        objects.append(identity)

        # TLP marking definition object
        tlp_marking = self._create_tlp_marking(tlp)
        if tlp_marking:
            objects.append(tlp_marking)

        # Extract IOCs from analysis result
        iocs = self._extract_iocs_from_analysis(analysis_result)

        # Determine confidence based on score
        base_confidence = 50
        composite_score = analysis_result.get('composite_score', 0)
        if composite_score >= 80:
            base_confidence = 85
        elif composite_score >= 60:
            base_confidence = 70
        elif composite_score >= 40:
            base_confidence = 55

        # Create indicators for each IOC
        relationship_targets = []
        for ioc_type, ioc_value in iocs:
            indicator = self.ioc_to_indicator(
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                confidence=base_confidence,
                tlp=tlp,
            )
            if indicator:
                objects.append(indicator)
                relationship_targets.append(indicator['id'])

        # File hash indicators
        hashes = analysis_result.get('hashes', {})
        for hash_type in ('md5', 'sha1', 'sha256'):
            hash_val = hashes.get(hash_type)
            if hash_val:
                indicator = self.ioc_to_indicator(
                    ioc_type=hash_type,
                    ioc_value=hash_val,
                    name=f'File hash ({hash_type})',
                    description=f'File hash from analyzed sample',
                    confidence=base_confidence,
                    tlp=tlp,
                )
                if indicator:
                    objects.append(indicator)
                    relationship_targets.append(indicator['id'])

        # Malware object if verdict is malicious/suspicious
        verdict = analysis_result.get('verdict', '')
        if verdict and verdict.upper() in ('MALICIOUS', 'SUSPICIOUS', 'HIGH_RISK'):
            malware_name = analysis_result.get('file_info', {}).get('name', 'Unknown sample')
            llm = analysis_result.get('llm_analysis', {})
            mal_description = llm.get('summary', f'Analyzed by {self.organization_name}')

            malware_types = ['unknown']
            if isinstance(llm.get('classification'), str):
                malware_types = [llm['classification'].lower()]

            malware_obj = self._create_malware_object(
                name=malware_name,
                description=mal_description if isinstance(mal_description, str) else str(mal_description),
                malware_types=malware_types,
            )
            tlp_id = self.TLP_MAP.get(tlp.upper())
            if tlp_id:
                malware_obj['object_marking_refs'] = [tlp_id]
            objects.append(malware_obj)

            # Relationships: indicator -> indicates -> malware
            for ind_id in relationship_targets:
                rel = self._create_relationship(ind_id, 'indicates', malware_obj['id'])
                objects.append(rel)

        # Build the bundle
        bundle = {
            'type': 'bundle',
            'id': f'bundle--{uuid.uuid4()}',
            'objects': objects,
        }

        logger.info(f"[STIX] Created bundle with {len(objects)} objects")
        return bundle

    def export_json(self, bundle: dict, output_path: str) -> str:
        """
        Export a STIX bundle to a JSON file.

        Args:
            bundle: STIX bundle dict.
            output_path: File path for JSON output.

        Returns:
            The output file path.
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(bundle, f, indent=2, ensure_ascii=False, default=str)
            logger.info(f"[STIX] Bundle exported to {output_path}")
            return output_path
        except Exception as exc:
            logger.error(f"[STIX] Export failed: {exc}")
            raise

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _create_indicator_pattern(self, ioc_type: str, value: str) -> str:
        """Create a STIX pattern string for the given IOC type and value."""
        # Normalize type
        ioc_type_lower = ioc_type.lower().replace('_', '-')

        # Auto-detect type if generic
        if ioc_type_lower in ('auto', 'unknown', 'ioc', 'hash'):
            ioc_type_lower = self._detect_ioc_type(value)

        template = self.IOC_PATTERN_MAP.get(ioc_type_lower)
        if not template:
            return ''

        # Escape single quotes in value
        safe_value = value.replace("'", "\\'")
        return template.format(value=safe_value)

    def _create_malware_object(self, name: str, description: str,
                                malware_types: list) -> dict:
        """Create a STIX 2.1 Malware object."""
        now = self._timestamp()
        return {
            'type': 'malware',
            'spec_version': self.SPEC_VERSION,
            'id': f'malware--{uuid.uuid4()}',
            'created': now,
            'modified': now,
            'name': name,
            'description': description,
            'malware_types': malware_types or ['unknown'],
            'is_family': False,
            'created_by_ref': self._identity_id,
        }

    def _create_relationship(self, source_ref: str, relationship_type: str,
                              target_ref: str) -> dict:
        """Create a STIX 2.1 Relationship object."""
        now = self._timestamp()
        return {
            'type': 'relationship',
            'spec_version': self.SPEC_VERSION,
            'id': f'relationship--{uuid.uuid4()}',
            'created': now,
            'modified': now,
            'relationship_type': relationship_type,
            'source_ref': source_ref,
            'target_ref': target_ref,
            'created_by_ref': self._identity_id,
        }

    def _create_tlp_marking(self, tlp: str) -> Optional[dict]:
        """Create a TLP marking-definition object."""
        tlp_upper = tlp.upper()
        tlp_id = self.TLP_MAP.get(tlp_upper)
        if not tlp_id:
            return None

        # Use the canonical name from STIX spec
        tlp_name_map = {
            'CLEAR': 'TLP:CLEAR',
            'WHITE': 'TLP:CLEAR',
            'GREEN': 'TLP:GREEN',
            'AMBER': 'TLP:AMBER',
            'RED': 'TLP:RED',
        }

        return {
            'type': 'marking-definition',
            'spec_version': self.SPEC_VERSION,
            'id': tlp_id,
            'created': '2017-01-20T00:00:00.000Z',
            'definition_type': 'tlp',
            'name': tlp_name_map.get(tlp_upper, f'TLP:{tlp_upper}'),
            'definition': {
                'tlp': tlp_upper.lower() if tlp_upper != 'WHITE' else 'clear',
            },
        }

    def _detect_ioc_type(self, value: str) -> str:
        """Auto-detect the IOC type from its value."""
        for ioc_type, pattern in self.IOC_DETECT_PATTERNS.items():
            if pattern.match(value):
                return ioc_type
        return 'domain-name'  # Default fallback

    def _extract_iocs_from_analysis(self, analysis_result: dict) -> List[tuple]:
        """
        Extract (ioc_type, ioc_value) pairs from an analysis result dict.
        """
        iocs: List[tuple] = []
        seen = set()

        def _add(ioc_type: str, value: str):
            if value and value not in seen:
                seen.add(value)
                iocs.append((ioc_type, value))

        # IOC analysis section
        ioc_analysis = analysis_result.get('ioc_analysis', {})
        for ioc_result in ioc_analysis.get('results', []):
            ioc_val = ioc_result.get('ioc', ioc_result.get('value', ''))
            if ioc_val:
                detected_type = self._detect_ioc_type(ioc_val)
                _add(detected_type, ioc_val)

        # String analysis IOCs
        string_analysis = analysis_result.get('string_analysis', {})
        for url in string_analysis.get('user_agents', []):
            pass  # User agents are not IOCs

        # Static analysis IOCs
        static = analysis_result.get('static_analysis', {})
        static_iocs = static.get('iocs', {})
        if isinstance(static_iocs, dict):
            for url in static_iocs.get('urls', []):
                _add('url', url)
            for ip in static_iocs.get('ipv4', []):
                _add('ipv4-addr', ip)
            for domain in static_iocs.get('domains', []):
                _add('domain-name', domain)

        # Beacon config C2 addresses
        beacon = analysis_result.get('beacon_config', {})
        if beacon.get('success'):
            for ioc_entry in beacon.get('iocs', []):
                c2_val = ioc_entry.get('value', '')
                if c2_val:
                    detected = self._detect_ioc_type(c2_val)
                    _add(detected, c2_val)

        return iocs

    @staticmethod
    def _ioc_type_to_indicator_type(ioc_type: str) -> str:
        """Map IOC type to STIX indicator_types vocabulary."""
        mapping = {
            'ipv4-addr': 'malicious-activity',
            'ipv6-addr': 'malicious-activity',
            'domain-name': 'malicious-activity',
            'url': 'malicious-activity',
            'email-addr': 'attribution',
            'md5': 'malicious-activity',
            'sha1': 'malicious-activity',
            'sha256': 'malicious-activity',
            'sha512': 'malicious-activity',
            'file-hash': 'malicious-activity',
        }
        return mapping.get(ioc_type.lower(), 'anomalous-activity')

    @staticmethod
    def _timestamp() -> str:
        """Return current UTC timestamp in STIX format."""
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')
