"""
Threat Actor Profiling using MITRE ATT&CK STIX data.
Maps detected techniques to known threat groups.
"""
import json
import os
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple


class ThreatActorProfiler:
    """Maps detected ATT&CK techniques to known threat groups"""

    # Built-in threat actor database (no external download needed)
    # Top 30 most active groups with their commonly used techniques
    THREAT_ACTORS = {
        'APT29': {
            'aliases': ['NOBELIUM', 'Cozy Bear', 'The Dukes', 'Midnight Blizzard'],
            'country': 'Russia',
            'motivation': 'Espionage',
            'techniques': ['T1566.001', 'T1059.001', 'T1053.005', 'T1071.001', 'T1027',
                          'T1055', 'T1083', 'T1082', 'T1057', 'T1021.002', 'T1078',
                          'T1547.001', 'T1543.003', 'T1036', 'T1105', 'T1070.004'],
            'malware': ['Cobalt Strike', 'SUNBURST', 'TEARDROP', 'EnvyScout'],
        },
        'APT28': {
            'aliases': ['Fancy Bear', 'Sofacy', 'Forest Blizzard', 'STRONTIUM'],
            'country': 'Russia',
            'motivation': 'Espionage',
            'techniques': ['T1566.001', 'T1566.002', 'T1059.001', 'T1059.003', 'T1053.005',
                          'T1027', 'T1055.001', 'T1071.001', 'T1003.001', 'T1078',
                          'T1547.001', 'T1036.005', 'T1090', 'T1105'],
            'malware': ['X-Agent', 'Zebrocy', 'Seduploader', 'Komplex'],
        },
        'Lazarus Group': {
            'aliases': ['HIDDEN COBRA', 'Diamond Sleet', 'Zinc'],
            'country': 'North Korea',
            'motivation': 'Financial / Espionage',
            'techniques': ['T1566.001', 'T1059.001', 'T1059.003', 'T1059.005', 'T1053.005',
                          'T1027', 'T1055', 'T1071.001', 'T1003', 'T1486', 'T1490',
                          'T1547.001', 'T1543.003', 'T1105', 'T1497.001'],
            'malware': ['Manuscrypt', 'FALLCHILL', 'HOPLIGHT', 'AppleJeus'],
        },
        'FIN7': {
            'aliases': ['Carbon Spider', 'Sangria Tempest'],
            'country': 'Russia',
            'motivation': 'Financial',
            'techniques': ['T1566.001', 'T1566.002', 'T1059.001', 'T1059.003', 'T1059.005',
                          'T1053.005', 'T1547.001', 'T1055', 'T1027', 'T1071.001',
                          'T1003.001', 'T1021.002', 'T1047', 'T1569.002'],
            'malware': ['Carbanak', 'GRIFFON', 'BOOSTWRITE', 'Cobalt Strike'],
        },
        'APT41': {
            'aliases': ['Winnti', 'Brass Typhoon', 'Wicked Panda', 'Barium'],
            'country': 'China',
            'motivation': 'Espionage / Financial',
            'techniques': ['T1566.001', 'T1059.001', 'T1059.003', 'T1053.005', 'T1547.001',
                          'T1055', 'T1027', 'T1071.001', 'T1003', 'T1021.002',
                          'T1190', 'T1505.003', 'T1036', 'T1105'],
            'malware': ['ShadowPad', 'Winnti', 'POISONPLUG', 'Cobalt Strike'],
        },
        'APT1': {
            'aliases': ['Comment Crew', 'Comment Panda'],
            'country': 'China',
            'motivation': 'Espionage',
            'techniques': ['T1566.001', 'T1059.001', 'T1053.005', 'T1547.001', 'T1071.001',
                          'T1003', 'T1005', 'T1074.001', 'T1041'],
            'malware': ['WEBC2', 'BISCUIT', 'AURIGA'],
        },
        'Turla': {
            'aliases': ['Venomous Bear', 'Secret Blizzard', 'Snake', 'Uroburos'],
            'country': 'Russia',
            'motivation': 'Espionage',
            'techniques': ['T1566.001', 'T1059.001', 'T1059.003', 'T1053.005', 'T1547.001',
                          'T1055', 'T1027', 'T1071.001', 'T1071.004', 'T1090.003',
                          'T1003', 'T1036', 'T1497'],
            'malware': ['Snake', 'Carbon', 'Kazuar', 'LightNeuron'],
        },
        'Sandworm': {
            'aliases': ['Voodoo Bear', 'Seashell Blizzard', 'IRIDIUM'],
            'country': 'Russia',
            'motivation': 'Sabotage / Espionage',
            'techniques': ['T1566.001', 'T1059.001', 'T1059.003', 'T1053.005', 'T1547.001',
                          'T1486', 'T1490', 'T1561.002', 'T1071.001', 'T1190',
                          'T1021.002', 'T1003', 'T1070'],
            'malware': ['NotPetya', 'Industroyer', 'Olympic Destroyer', 'CaddyWiper'],
        },
        'LockBit': {
            'aliases': ['LockBit Gang', 'LockBit 3.0'],
            'country': 'Unknown',
            'motivation': 'Financial (Ransomware)',
            'techniques': ['T1486', 'T1490', 'T1059.001', 'T1059.003', 'T1053.005',
                          'T1547.001', 'T1003.001', 'T1021.002', 'T1048', 'T1027',
                          'T1562.001', 'T1070', 'T1047', 'T1569.002'],
            'malware': ['LockBit', 'StealBit'],
        },
        'BlackCat': {
            'aliases': ['ALPHV', 'Noberus'],
            'country': 'Unknown',
            'motivation': 'Financial (Ransomware)',
            'techniques': ['T1486', 'T1490', 'T1059.001', 'T1059.003', 'T1053.005',
                          'T1547.001', 'T1003', 'T1021.002', 'T1048', 'T1562.001',
                          'T1027', 'T1036', 'T1070'],
            'malware': ['BlackCat/ALPHV', 'ExMatter'],
        },
        'Cl0p': {
            'aliases': ['TA505', 'Clop'],
            'country': 'Unknown',
            'motivation': 'Financial (Ransomware)',
            'techniques': ['T1486', 'T1490', 'T1190', 'T1059.001', 'T1059.003',
                          'T1048', 'T1003', 'T1021.002', 'T1027'],
            'malware': ['Cl0p', 'FlawedAmmyy', 'SDBot'],
        },
        'Conti': {
            'aliases': ['Wizard Spider (Conti Team)'],
            'country': 'Russia',
            'motivation': 'Financial (Ransomware)',
            'techniques': ['T1486', 'T1490', 'T1059.001', 'T1059.003', 'T1053.005',
                          'T1547.001', 'T1003.001', 'T1021.002', 'T1048', 'T1055',
                          'T1027', 'T1562.001', 'T1047', 'T1569.002'],
            'malware': ['Conti', 'BazarLoader', 'Cobalt Strike', 'TrickBot'],
        },
        'REvil': {
            'aliases': ['Sodinokibi', 'Gold Southfield'],
            'country': 'Russia',
            'motivation': 'Financial (Ransomware)',
            'techniques': ['T1486', 'T1490', 'T1059.001', 'T1059.003', 'T1053.005',
                          'T1003', 'T1021.002', 'T1048', 'T1027', 'T1190'],
            'malware': ['REvil/Sodinokibi', 'Cobalt Strike'],
        },
        'APT32': {
            'aliases': ['OceanLotus', 'Canvas Cyclone'],
            'country': 'Vietnam',
            'motivation': 'Espionage',
            'techniques': ['T1566.001', 'T1566.002', 'T1059.001', 'T1059.005', 'T1053.005',
                          'T1547.001', 'T1055', 'T1027', 'T1071.001', 'T1003',
                          'T1036', 'T1105'],
            'malware': ['METALJACK', 'Denis', 'Cobalt Strike'],
        },
        'Kimsuky': {
            'aliases': ['Velvet Chollima', 'Emerald Sleet', 'Thallium'],
            'country': 'North Korea',
            'motivation': 'Espionage',
            'techniques': ['T1566.001', 'T1566.002', 'T1059.001', 'T1059.005', 'T1053.005',
                          'T1547.001', 'T1027', 'T1071.001', 'T1003', 'T1056.001',
                          'T1113', 'T1005'],
            'malware': ['BabyShark', 'KGH_SPY', 'GREASE'],
        },
        'MuddyWater': {
            'aliases': ['Mercury', 'Mango Sandstorm', 'Static Kitten'],
            'country': 'Iran',
            'motivation': 'Espionage',
            'techniques': ['T1566.001', 'T1059.001', 'T1059.005', 'T1053.005', 'T1547.001',
                          'T1027', 'T1071.001', 'T1003', 'T1105', 'T1219'],
            'malware': ['POWERSTATS', 'MuddyC2Go', 'PhonyC2'],
        },
        'APT33': {
            'aliases': ['Elfin', 'Peach Sandstorm', 'Refined Kitten'],
            'country': 'Iran',
            'motivation': 'Espionage / Sabotage',
            'techniques': ['T1566.001', 'T1566.002', 'T1059.001', 'T1053.005', 'T1547.001',
                          'T1027', 'T1071.001', 'T1003', 'T1078', 'T1110'],
            'malware': ['Shamoon', 'DROPSHOT', 'SHAPESHIFT'],
        },
        'Volt Typhoon': {
            'aliases': ['Vanguard Panda', 'Bronze Silhouette'],
            'country': 'China',
            'motivation': 'Pre-positioning / Espionage',
            'techniques': ['T1059.001', 'T1059.003', 'T1078', 'T1021.001', 'T1021.002',
                          'T1003', 'T1087', 'T1018', 'T1049', 'T1016', 'T1033',
                          'T1007', 'T1047', 'T1218.011'],
            'malware': ['Living-off-the-land (LOLBins)'],
        },
        'Scattered Spider': {
            'aliases': ['Octo Tempest', 'UNC3944', '0ktapus'],
            'country': 'Unknown (English-speaking)',
            'motivation': 'Financial / Extortion',
            'techniques': ['T1566.001', 'T1566.004', 'T1078', 'T1110', 'T1621',
                          'T1059.001', 'T1021.001', 'T1003', 'T1486', 'T1048',
                          'T1199', 'T1556'],
            'malware': ['BlackCat/ALPHV', 'Cobalt Strike'],
        },
        'Play Ransomware': {
            'aliases': ['PlayCrypt', 'Balloonfly'],
            'country': 'Unknown',
            'motivation': 'Financial (Ransomware)',
            'techniques': ['T1486', 'T1490', 'T1059.001', 'T1059.003', 'T1003.001',
                          'T1021.002', 'T1048', 'T1190', 'T1505.003'],
            'malware': ['Play', 'Cobalt Strike', 'SystemBC'],
        },
    }

    def match_techniques(self, detected_techniques: List[str]) -> Dict[str, Any]:
        """Match detected techniques to known threat actors"""
        if not detected_techniques:
            return {'matches': [], 'top_match': None, 'technique_count': 0}

        detected_set = set(detected_techniques)
        matches = []

        for group_name, group_data in self.THREAT_ACTORS.items():
            group_techniques = set(group_data['techniques'])
            overlap = detected_set & group_techniques

            if not overlap:
                continue

            # Calculate match score
            coverage = len(overlap) / len(group_techniques) * 100
            relevance = len(overlap) / max(len(detected_set), 1) * 100
            score = (coverage * 0.6 + relevance * 0.4)

            if len(overlap) >= 2:  # At least 2 technique overlap
                matches.append({
                    'group': group_name,
                    'aliases': group_data['aliases'],
                    'country': group_data['country'],
                    'motivation': group_data['motivation'],
                    'match_score': round(score, 1),
                    'matched_techniques': sorted(list(overlap)),
                    'matched_count': len(overlap),
                    'total_group_techniques': len(group_techniques),
                    'coverage_pct': round(coverage, 1),
                    'known_malware': group_data['malware'],
                    'confidence': 'HIGH' if score > 40 else ('MEDIUM' if score > 20 else 'LOW')
                })

        # Sort by match score
        matches.sort(key=lambda x: x['match_score'], reverse=True)

        return {
            'matches': matches[:10],  # Top 10
            'top_match': matches[0] if matches else None,
            'technique_count': len(detected_techniques),
            'total_groups_checked': len(self.THREAT_ACTORS),
            'groups_matched': len(matches)
        }

    def get_group_profile(self, group_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed profile for a specific group"""
        for name, data in self.THREAT_ACTORS.items():
            if name.lower() == group_name.lower() or group_name.lower() in [a.lower() for a in data['aliases']]:
                return {
                    'name': name,
                    'aliases': data['aliases'],
                    'country': data['country'],
                    'motivation': data['motivation'],
                    'technique_count': len(data['techniques']),
                    'techniques': data['techniques'],
                    'known_malware': data['malware']
                }
        return None

    def compare_groups(self, group1: str, group2: str) -> Optional[Dict[str, Any]]:
        """Compare two threat groups"""
        p1 = self.get_group_profile(group1)
        p2 = self.get_group_profile(group2)
        if not p1 or not p2:
            return None

        t1 = set(p1['techniques'])
        t2 = set(p2['techniques'])
        common = t1 & t2

        return {
            'group1': p1['name'],
            'group2': p2['name'],
            'common_techniques': sorted(list(common)),
            'common_count': len(common),
            'only_group1': sorted(list(t1 - t2)),
            'only_group2': sorted(list(t2 - t1)),
            'similarity_pct': round(len(common) / max(len(t1 | t2), 1) * 100, 1)
        }
