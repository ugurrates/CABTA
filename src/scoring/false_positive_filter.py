"""
Author: Ugur AtesFalse positive filtering and trusted vendor database."""

from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)
class FalsePositiveFilter:
    """
    Filter false positives using trusted vendor database.
    
    Features:
    - Trusted vendor whitelist
    - Common tool signatures
    - Aviation industry whitelists
    """
    
    # Trusted software vendors
    TRUSTED_VENDORS = {
        'Microsoft Corporation',
        'Microsoft Windows',
        'Apple Inc.',
        'Google LLC',
        'Mozilla Corporation',
        'Adobe Systems',
        'Oracle Corporation',
        'SAP SE',
        'Cisco Systems',
        'VMware, Inc.',
        'Intel Corporation',
        'NVIDIA Corporation',
        'IBM Corporation',
        'Red Hat, Inc.',
        'Canonical Ltd.',
        'Amazon.com, Inc.',
        'Valve Corporation',
        'Electronic Arts',
        'Rockstar Games',
        'Ubisoft'
    }
    
    # Trusted filenames (system files, common tools)
    TRUSTED_FILENAMES = {
        'explorer.exe',
        'svchost.exe',
        'chrome.exe',
        'firefox.exe',
        'msedge.exe',
        'outlook.exe',
        'winword.exe',
        'excel.exe',
        'powerpnt.exe',
        'teams.exe',
        'zoom.exe',
        'slack.exe'
    }
    
    # Known hashes of legitimate software (example - would be much larger in production)
    KNOWN_GOOD_HASHES = set()
    
    @staticmethod
    def is_false_positive(file_data: Dict, threat_score: int) -> tuple[bool, str]:
        """
        Check if detection is likely a false positive.
        
        Args:
            file_data: File analysis data
            threat_score: Current threat score
        
        Returns:
            Tuple of (is_false_positive, reason)
        """
        # Check trusted vendor
        signer = file_data.get('signature', {}).get('signer', '')
        if FalsePositiveFilter.is_trusted_vendor(signer):
            return True, f'Signed by trusted vendor: {signer}'
        
        # Check filename
        filename = file_data.get('filename', '').lower()
        if filename in FalsePositiveFilter.TRUSTED_FILENAMES:
            # Only if signed
            if file_data.get('signature', {}).get('signed'):
                return True, f'Trusted system file: {filename}'
        
        # Check hash whitelist
        sha256 = file_data.get('sha256', '')
        if sha256 in FalsePositiveFilter.KNOWN_GOOD_HASHES:
            return True, 'Hash in known-good database'
        
        # Low detection rate with signature
        vt_detections = file_data.get('vt_detections', '0/0')
        if '/' in vt_detections:
            detected, total = vt_detections.split('/')
            if int(detected) <= 2 and int(total) > 50:
                if file_data.get('signature', {}).get('signed'):
                    return True, 'Low VT detection rate with valid signature'
        
        return False, ''
    
    @staticmethod
    def is_trusted_vendor(vendor: str) -> bool:
        """Check if vendor is trusted."""
        return any(trusted in vendor for trusted in FalsePositiveFilter.TRUSTED_VENDORS)
    
    @staticmethod
    def adjust_score_for_context(base_score: int, file_data: Dict) -> int:
        """
        Adjust threat score based on context.
        
        Args:
            base_score: Original threat score
            file_data: File analysis data
        
        Returns:
            Adjusted score
        """
        adjusted = base_score
        
        # Reduce score for signed files
        if file_data.get('signature', {}).get('signed'):
            adjusted = int(adjusted * 0.7)
        
        # Reduce score for low VT detections
        vt_detections = file_data.get('vt_detections', '0/0')
        if '/' in vt_detections:
            detected, total = vt_detections.split('/')
            if int(detected) <= 3 and int(total) > 50:
                adjusted = int(adjusted * 0.8)
        
        return max(0, min(100, adjusted))
    
    @staticmethod
    def add_to_whitelist(identifier: str, identifier_type: str):
        """
        Add identifier to whitelist.
        
        Args:
            identifier: Hash, filename, or vendor name
            identifier_type: 'hash', 'filename', 'vendor'
        """
        if identifier_type == 'hash':
            FalsePositiveFilter.KNOWN_GOOD_HASHES.add(identifier)
        elif identifier_type == 'filename':
            FalsePositiveFilter.TRUSTED_FILENAMES.add(identifier.lower())
        elif identifier_type == 'vendor':
            FalsePositiveFilter.TRUSTED_VENDORS.add(identifier)
        
        logger.info(f"[WHITELIST] Added {identifier_type}: {identifier}")

    # ------------------------------------------------------------------ #
    # Analyst Feedback
    # ------------------------------------------------------------------ #

    # In-memory feedback store (would be persisted to DB in production)
    _analyst_feedback: Dict[str, bool] = {}

    @classmethod
    def record_analyst_feedback(cls, sha256: str, is_false_positive: bool) -> None:
        """Record analyst feedback for a given file hash.

        When an analyst marks a file as false positive, its hash is
        automatically added to the known-good set for future analyses.

        Args:
            sha256: SHA-256 hash of the file.
            is_false_positive: True if the analyst determined this is an FP.
        """
        cls._analyst_feedback[sha256] = is_false_positive
        if is_false_positive:
            cls.KNOWN_GOOD_HASHES.add(sha256)
            logger.info(f"[FP-FEEDBACK] Marked {sha256[:16]}... as false positive")
        else:
            # If previously whitelisted, remove it
            cls.KNOWN_GOOD_HASHES.discard(sha256)
            logger.info(f"[FP-FEEDBACK] Confirmed {sha256[:16]}... as true positive")

    @classmethod
    def get_feedback(cls, sha256: str) -> Optional[bool]:
        """Return analyst feedback for a hash, or None if not reviewed."""
        return cls._analyst_feedback.get(sha256)

    @classmethod
    def get_all_feedback(cls) -> Dict[str, bool]:
        """Return all recorded analyst feedback."""
        return dict(cls._analyst_feedback)
