"""
Author: Ugur Ates
APK Analyzer - Android Package Analizi.

Entegre Araçlar:
- apktool: APK decompilation
- aapt: Manifest/resource extraction
- unzip: APK extraction
- strings: String extraction
"""

import logging
import re
import zipfile
import tempfile
import os
from typing import Dict, List, Tuple
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class APKAnalysisResult:
    """APK analiz sonucu."""
    success: bool = False
    file_path: str = ""
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    native_libraries: List[str] = field(default_factory=list)
    certificate_info: Dict = field(default_factory=dict)
    suspicious_permissions: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    threat_indicators: List[str] = field(default_factory=list)
    threat_score: int = 0
    raw_outputs: Dict[str, str] = field(default_factory=dict)
    # Enhanced risk scoring fields
    risk_score: int = 0
    risk_level: str = ""
    dangerous_permission_details: List[Dict] = field(default_factory=list)
    suspicious_api_details: List[Dict] = field(default_factory=list)
    mitre_mobile_techniques: List[Dict] = field(default_factory=list)
    obfuscation_indicators: List[str] = field(default_factory=list)
    is_obfuscated: bool = False
    dex_count: int = 0
    permission_categories: Dict[str, List[str]] = field(default_factory=dict)

class APKAnalyzer:
    """Android APK analizi."""

    DANGEROUS_PERMISSIONS_LEGACY = [
        'android.permission.READ_SMS',
        'android.permission.SEND_SMS',
        'android.permission.RECEIVE_SMS',
        'android.permission.READ_CONTACTS',
        'android.permission.READ_CALL_LOG',
        'android.permission.RECORD_AUDIO',
        'android.permission.CAMERA',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.WRITE_EXTERNAL_STORAGE',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.READ_PHONE_STATE',
        'android.permission.CALL_PHONE',
        'android.permission.PROCESS_OUTGOING_CALLS',
        'android.permission.RECEIVE_BOOT_COMPLETED',
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.BIND_ACCESSIBILITY_SERVICE',
        'android.permission.BIND_DEVICE_ADMIN',
        'android.permission.REQUEST_INSTALL_PACKAGES',
        'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE',
    ]

    # Enhanced dangerous permission categorization and scoring
    DANGEROUS_PERMISSIONS = {
        'android.permission.SEND_SMS': ('SMS', 8),
        'android.permission.READ_SMS': ('SMS', 8),
        'android.permission.RECEIVE_SMS': ('SMS', 8),
        'android.permission.READ_CONTACTS': ('Contacts', 6),
        'android.permission.READ_CALL_LOG': ('Contacts', 6),
        'android.permission.RECORD_AUDIO': ('Media', 8),
        'android.permission.CAMERA': ('Media', 7),
        'android.permission.ACCESS_FINE_LOCATION': ('Location', 7),
        'android.permission.READ_PHONE_STATE': ('Device', 5),
        'android.permission.CALL_PHONE': ('Device', 7),
        'android.permission.WRITE_EXTERNAL_STORAGE': ('Storage', 5),
        'android.permission.READ_EXTERNAL_STORAGE': ('Storage', 4),
        'android.permission.INSTALL_PACKAGES': ('Admin', 10),
        'android.permission.BIND_DEVICE_ADMIN': ('Admin', 10),
        'android.permission.SYSTEM_ALERT_WINDOW': ('Overlay', 8),
        'android.permission.RECEIVE_BOOT_COMPLETED': ('Boot', 6),
        'android.permission.BIND_ACCESSIBILITY_SERVICE': ('Accessibility', 9),
        'android.permission.REQUEST_INSTALL_PACKAGES': ('Admin', 8),
        'android.permission.WRITE_SETTINGS': ('Settings', 6),
        'android.permission.READ_PHONE_NUMBERS': ('Device', 5),
    }

    # Suspicious API detection patterns with MITRE Mobile ATT&CK mapping
    SUSPICIOUS_APIS = [
        ('Runtime.exec', 'Command Execution', 'T1059'),
        ('ProcessBuilder', 'Process Creation', 'T1059'),
        ('DexClassLoader', 'Dynamic Code Loading', 'T1407'),
        ('Method.invoke', 'Reflection', 'T1620'),
        ('Class.forName', 'Dynamic Class Loading', 'T1407'),
        ('Cipher.getInstance', 'Encryption', 'T1486'),
        ('SmsManager.sendTextMessage', 'SMS Sending', 'T1582'),
        ('DevicePolicyManager', 'Device Admin', 'T1404'),
        ('PackageManager.setComponentEnabledSetting', 'Component Hiding', 'T1628'),
        ('HttpURLConnection', 'Network Connection', 'T1071'),
        ('WebView.loadUrl', 'Web Content Loading', 'T1185'),
        ('Build.SERIAL', 'Device Fingerprinting', 'T1082'),
        ('Settings.Secure.getString', 'Device ID Access', 'T1082'),
        ('TelephonyManager', 'Telephony Access', 'T1082'),
    ]

    SUSPICIOUS_STRINGS = [
        (r'su\s+\-c', 'Root command'),
        (r'/system/bin/su', 'Root binary'),
        (r'Superuser', 'Root check'),
        (r'busybox', 'Busybox'),
        (r'DexClassLoader', 'Dynamic DEX loading'),
        (r'dalvik\.system\.DexClassLoader', 'Dynamic code'),
        (r'Runtime\.getRuntime\(\)\.exec', 'Runtime exec'),
        (r'ProcessBuilder', 'Process execution'),
        (r'android\.app\.admin', 'Device admin'),
        (r'AccessibilityService', 'Accessibility abuse'),
        (r'getInstalledPackages', 'App enumeration'),
        (r'PackageManager', 'Package manipulation'),
    ]

    def __init__(self):
        from ..tools.external_tool_runner import get_tool_runner
        self.tool_runner = get_tool_runner()

    def analyze(self, file_path: str) -> APKAnalysisResult:
        """Kapsamli APK analizi."""
        logger.info(f"[APK] Analyzing: {Path(file_path).name}")
        result = APKAnalysisResult(file_path=file_path)

        # 1. aapt ile manifest analizi
        if self.tool_runner.is_available('aapt'):
            aapt_out = self.tool_runner.run_aapt(file_path)
            if aapt_out.success:
                self._parse_aapt_output(aapt_out.stdout, result)
                result.raw_outputs['aapt'] = aapt_out.stdout
                result.success = True

        # 2. ZIP olarak ac ve analiz et
        try:
            self._analyze_apk_contents(file_path, result)
        except Exception as e:
            logger.warning(f"[APK] Content analysis failed: {e}")

        # 3. Suspicious permission detection
        self._detect_suspicious_permissions(result)

        # 4. Enhanced: Detect suspicious APIs
        self._detect_suspicious_apis(result)

        # 5. Enhanced: Detect obfuscation
        self._detect_obfuscation(result)

        # 6. Enhanced: Map MITRE Mobile ATT&CK techniques
        self._map_mitre_techniques(result)

        # 7. Calculate legacy score (backward compat)
        result.threat_score = self._calculate_score(result)

        # 8. Enhanced: Calculate risk score
        result.risk_score = self._calculate_risk_score(result)
        result.risk_level = self._get_risk_level(result.risk_score)

        return result

    def _parse_aapt_output(self, output: str, result: APKAnalysisResult):
        """aapt dump badging ciktisini parse et."""
        for line in output.split('\n'):
            if line.startswith('package:'):
                # package: name='com.example' versionCode='1' versionName='1.0'
                name_match = re.search(r"name='([^']+)'", line)
                if name_match:
                    result.package_name = name_match.group(1)

                version_code = re.search(r"versionCode='([^']+)'", line)
                if version_code:
                    result.version_code = version_code.group(1)

                version_name = re.search(r"versionName='([^']+)'", line)
                if version_name:
                    result.version_name = version_name.group(1)

            elif line.startswith('sdkVersion:'):
                sdk = re.search(r"'(\d+)'", line)
                if sdk:
                    result.min_sdk = int(sdk.group(1))

            elif line.startswith('targetSdkVersion:'):
                sdk = re.search(r"'(\d+)'", line)
                if sdk:
                    result.target_sdk = int(sdk.group(1))

            elif line.startswith('uses-permission:'):
                perm = re.search(r"name='([^']+)'", line)
                if perm:
                    result.permissions.append(perm.group(1))

            elif 'activity' in line.lower() and "name='" in line:
                name = re.search(r"name='([^']+)'", line)
                if name:
                    result.activities.append(name.group(1))

            elif 'service' in line.lower() and "name='" in line:
                name = re.search(r"name='([^']+)'", line)
                if name:
                    result.services.append(name.group(1))

            elif 'receiver' in line.lower() and "name='" in line:
                name = re.search(r"name='([^']+)'", line)
                if name:
                    result.receivers.append(name.group(1))

    def _analyze_apk_contents(self, file_path: str, result: APKAnalysisResult):
        """APK icerigini analiz et."""
        with zipfile.ZipFile(file_path, 'r') as apk:
            # Native libraries
            for name in apk.namelist():
                if name.startswith('lib/') and name.endswith('.so'):
                    result.native_libraries.append(name)

            # DEX files - extract strings and count
            dex_files = [n for n in apk.namelist() if n.endswith('.dex')]
            result.dex_count = len(dex_files)

            for name in dex_files:
                try:
                    dex_content = apk.read(name)
                    self._analyze_dex_strings(dex_content, result)
                except Exception:
                    pass

    def _analyze_dex_strings(self, content: bytes, result: APKAnalysisResult):
        """DEX dosyasindan string'leri analiz et."""
        try:
            text = content.decode('utf-8', errors='ignore')
        except Exception:
            text = str(content)

        # URLs
        url_pattern = re.compile(r'https?://[^\s<>"\']+')
        for url in url_pattern.findall(text):
            if len(url) > 10 and url not in result.urls:
                result.urls.append(url[:200])

        # IPs
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        for ip in ip_pattern.findall(text):
            if ip not in result.ips and not ip.startswith('0.'):
                result.ips.append(ip)

        # Suspicious patterns
        for pattern, desc in self.SUSPICIOUS_STRINGS:
            if re.search(pattern, text, re.I):
                if desc not in result.suspicious_strings:
                    result.suspicious_strings.append(desc)

        # Store raw text for API and obfuscation detection
        if not hasattr(result, '_dex_text'):
            result._dex_text = text
        else:
            result._dex_text += text

    def _detect_suspicious_permissions(self, result: APKAnalysisResult):
        """Tehlikeli permission'lari tespit et."""
        categories: Dict[str, List[str]] = {}

        for perm in result.permissions:
            # Legacy compatibility: check against old list
            if perm in self.DANGEROUS_PERMISSIONS_LEGACY:
                if perm not in result.suspicious_permissions:
                    result.suspicious_permissions.append(perm)

            # Enhanced: categorized scoring
            if perm in self.DANGEROUS_PERMISSIONS:
                category, score = self.DANGEROUS_PERMISSIONS[perm]
                result.dangerous_permission_details.append({
                    'permission': perm,
                    'category': category,
                    'risk_score': score,
                })
                if category not in categories:
                    categories[category] = []
                categories[category].append(perm)

        result.permission_categories = categories

        # Specific dangerous combinations
        perm_set = set(result.permissions)

        if 'android.permission.SEND_SMS' in perm_set and 'android.permission.RECEIVE_SMS' in perm_set:
            result.threat_indicators.append("SMS interception capability")

        if 'android.permission.BIND_ACCESSIBILITY_SERVICE' in perm_set:
            result.threat_indicators.append("Accessibility service abuse risk")

        if 'android.permission.BIND_DEVICE_ADMIN' in perm_set:
            result.threat_indicators.append("Device admin capability")

        if 'android.permission.REQUEST_INSTALL_PACKAGES' in perm_set:
            result.threat_indicators.append("Can install other apps")

    def _detect_suspicious_apis(self, result: APKAnalysisResult):
        """Detect suspicious API usage in DEX content."""
        dex_text = getattr(result, '_dex_text', '')
        if not dex_text:
            return

        for api_pattern, description, technique_id in self.SUSPICIOUS_APIS:
            if api_pattern in dex_text:
                result.suspicious_api_details.append({
                    'api': api_pattern,
                    'description': description,
                    'mitre_technique': technique_id,
                })

    def _detect_obfuscation(self, result: APKAnalysisResult):
        """Detect signs of code obfuscation."""
        dex_text = getattr(result, '_dex_text', '')

        # Single-letter class names (a.b.c pattern) - obfuscation indicator
        obfuscated_pattern = re.compile(r'L[a-z]/[a-z]/[a-z];')
        if dex_text and obfuscated_pattern.search(dex_text):
            result.obfuscation_indicators.append("Single-letter class names (ProGuard/R8 obfuscation)")

        # Multi-DEX check (many DEX files can indicate packed/obfuscated apps)
        if result.dex_count > 3:
            result.obfuscation_indicators.append(f"Multi-DEX: {result.dex_count} DEX files detected")

        # Native libraries (can be used for code hiding)
        if result.native_libraries:
            native_count = len(result.native_libraries)
            result.obfuscation_indicators.append(
                f"Native libraries: {native_count} .so files (potential native code hiding)"
            )

        # Short/meaningless method names pattern
        short_names_pattern = re.compile(r'\b[a-z]{1,2}\([^)]*\)')
        if dex_text and len(short_names_pattern.findall(dex_text[:50000])) > 50:
            result.obfuscation_indicators.append("High density of short method names")

        result.is_obfuscated = len(result.obfuscation_indicators) >= 2

    def _map_mitre_techniques(self, result: APKAnalysisResult):
        """Map detected capabilities to MITRE Mobile ATT&CK techniques."""
        techniques_seen = set()
        perm_set = set(result.permissions)

        # Permission-based technique mapping
        perm_technique_map = [
            ({'android.permission.SEND_SMS', 'android.permission.READ_SMS', 'android.permission.RECEIVE_SMS'},
             'T1582', 'SMS Control', 'Application can send/read/intercept SMS messages'),
            ({'android.permission.RECORD_AUDIO'},
             'T1429', 'Audio Capture', 'Application can record audio'),
            ({'android.permission.CAMERA'},
             'T1512', 'Video Capture', 'Application can access camera'),
            ({'android.permission.ACCESS_FINE_LOCATION'},
             'T1430', 'Location Tracking', 'Application can track device location'),
            ({'android.permission.READ_CONTACTS', 'android.permission.READ_CALL_LOG'},
             'T1636', 'Contact Discovery', 'Application can access contacts/call log'),
            ({'android.permission.BIND_ACCESSIBILITY_SERVICE'},
             'T1453', 'Accessibility Abuse', 'Application uses accessibility service for control'),
            ({'android.permission.BIND_DEVICE_ADMIN'},
             'T1404', 'Device Admin Exploitation', 'Application requests device admin privileges'),
            ({'android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.INSTALL_PACKAGES'},
             'T1407', 'Download New Code', 'Application can install additional packages'),
            ({'android.permission.SYSTEM_ALERT_WINDOW'},
             'T1411', 'Overlay Attack', 'Application can draw over other apps'),
            ({'android.permission.RECEIVE_BOOT_COMPLETED'},
             'T1398', 'Boot Persistence', 'Application starts at device boot'),
        ]

        for required_perms, technique_id, name, description in perm_technique_map:
            if required_perms & perm_set and technique_id not in techniques_seen:
                techniques_seen.add(technique_id)
                result.mitre_mobile_techniques.append({
                    'technique_id': technique_id,
                    'name': name,
                    'description': description,
                    'source': 'permission',
                })

        # API-based technique mapping (from suspicious API detection)
        for api_detail in result.suspicious_api_details:
            tid = api_detail['mitre_technique']
            if tid not in techniques_seen:
                techniques_seen.add(tid)
                result.mitre_mobile_techniques.append({
                    'technique_id': tid,
                    'name': api_detail['description'],
                    'description': f"Detected API: {api_detail['api']}",
                    'source': 'api',
                })

    def _calculate_risk_score(self, result: APKAnalysisResult) -> int:
        """Calculate enhanced risk score (0-100)."""
        score = 0

        # Dangerous permissions: sum individual scores, max 40
        dangerous_count = len(result.dangerous_permission_details)
        score += min(dangerous_count * 8, 40)

        # Suspicious APIs: max 30
        suspicious_api_count = len(result.suspicious_api_details)
        score += min(suspicious_api_count * 10, 30)

        # External IPs: max 15
        # Filter out common private/internal IPs
        external_ips = [
            ip for ip in result.ips
            if not ip.startswith('10.') and not ip.startswith('192.168.')
            and not ip.startswith('127.') and not ip.startswith('172.')
        ]
        external_ip_count = len(external_ips)
        score += min(external_ip_count * 5, 15)

        # Obfuscation bonus
        if result.is_obfuscated:
            score += 15

        return min(score, 100)

    @staticmethod
    def _get_risk_level(risk_score: int) -> str:
        """Determine risk level from score."""
        if risk_score >= 75:
            return "CRITICAL"
        elif risk_score >= 50:
            return "HIGH"
        elif risk_score >= 25:
            return "MEDIUM"
        elif risk_score > 0:
            return "LOW"
        return "NONE"

    def _calculate_score(self, result: APKAnalysisResult) -> int:
        """Threat score hesapla (legacy)."""
        score = 0

        # Suspicious permissions
        score += min(len(result.suspicious_permissions) * 5, 40)

        # Suspicious strings
        score += min(len(result.suspicious_strings) * 5, 30)

        # Threat indicators
        score += len(result.threat_indicators) * 10

        # URLs/IPs
        score += min(len(result.urls) + len(result.ips), 10)

        # Low target SDK (old API = less security)
        if result.target_sdk > 0 and result.target_sdk < 26:
            score += 10

        return min(score, 100)
