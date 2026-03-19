"""
Author: Ugur Ates
Fuzzy Hash Analyzer - SSDEEP & TLSH Integration for Behavioral Similarity.

v1.0.0 Features:
- SSDEEP (Context Triggered Piecewise Hashing) - File content similarity
- TLSH (Trend Micro Locality Sensitive Hash) - Better for malware variants
- IMPHASH (Import Hash) - PE import table fingerprinting
- Combined similarity scoring
- Malware family clustering
- Hash database search

Best Practice: Used by CrowdStrike, VirusTotal, MISP for malware clustering
"""

import json
import logging
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# Availability checks
SSDEEP_AVAILABLE = False
TLSH_AVAILABLE = False
PEFILE_AVAILABLE = False

try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    logger.debug("[FUZZY-HASH] ssdeep not available - pip install ssdeep")

try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    logger.debug("[FUZZY-HASH] tlsh not available - pip install py-tlsh")

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    logger.debug("[FUZZY-HASH] pefile not available for imphash")
@dataclass
class SimilarityResult:
    """Result of similarity comparison."""
    ssdeep_score: int = 0
    tlsh_score: int = 0
    imphash_match: bool = False
    combined_score: int = 0
    verdict: str = "UNKNOWN"
    is_similar: bool = False
    family_match: Optional[str] = None
@dataclass  
class HashBundle:
    """Collection of all hash types for a file."""
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    ssdeep: str = ""
    tlsh: str = ""
    imphash: str = ""
    file_size: int = 0
class FuzzyHashAnalyzer:
    """
    Advanced Fuzzy Hash Analysis for malware similarity detection.
    
    Algorithms:
    - SSDEEP: Context Triggered Piecewise Hashing (Kornblum, 2006)
      Good for: General file similarity, modified documents
      Threshold: >50 = likely same family
      
    - TLSH: Trend Locality Sensitive Hash
      Good for: Malware variants, polymorphic code, better than ssdeep
      Threshold: <100 = likely similar (lower = more similar)
      
    - IMPHASH: PE Import table hash
      Good for: Identifying malware families by API usage
      Exact match = same toolchain/family
    
    Best Practice: VirusTotal/MISP/CrowdStrike use combined approach
    """
    
    # Default DB path relative to project root
    _DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / 'data' / 'fuzzy_hash_db.json'

    # Populated by load_database(); kept as class-level fallback
    KNOWN_FAMILIES: Dict = {}

    def __init__(self, db_path: str = None):
        """Initialize analyzer, load hash database, and check available algorithms.

        Args:
            db_path: Path to fuzzy hash database JSON. Uses the bundled
                     ``data/fuzzy_hash_db.json`` when *None*.
        """
        self.algorithms: List[str] = []
        if SSDEEP_AVAILABLE:
            self.algorithms.append('ssdeep')
        if TLSH_AVAILABLE:
            self.algorithms.append('tlsh')
        if PEFILE_AVAILABLE:
            self.algorithms.append('imphash')

        # Load hash database
        self.db_path = Path(db_path) if db_path else self._DEFAULT_DB_PATH
        self.load_database(self.db_path)

        logger.info(
            f"[FUZZY-HASH] Available algorithms: {self.algorithms}, "
            f"families loaded: {len(self.KNOWN_FAMILIES)}"
        )

    # ------------------------------------------------------------------
    # Database management
    # ------------------------------------------------------------------

    def load_database(self, db_path: Path = None) -> int:
        """Load malware family hash signatures from a JSON file.

        Args:
            db_path: Path to JSON database (defaults to ``self.db_path``)

        Returns:
            Number of families loaded
        """
        path = Path(db_path) if db_path else self.db_path
        if not path.exists():
            logger.warning(f"[FUZZY-HASH] Database not found: {path}")
            return 0

        try:
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)

            families = data.get('families', {})
            loaded = 0
            for name, info in families.items():
                self.KNOWN_FAMILIES[name] = {
                    'imphashes': info.get('imphashes', []),
                    'ssdeep_patterns': info.get('ssdeep_patterns', []),
                    'tlsh_patterns': info.get('tlsh_patterns', []),
                    'aliases': info.get('aliases', []),
                    'description': info.get('description', ''),
                    'mitre_techniques': info.get('mitre_techniques', []),
                }
                loaded += 1

            logger.info(f"[FUZZY-HASH] Loaded {loaded} families from {path.name}")
            return loaded

        except Exception as exc:
            logger.error(f"[FUZZY-HASH] Failed to load database: {exc}")
            return 0

    def update_database(self, family_name: str, *,
                        imphashes: List[str] = None,
                        ssdeep_patterns: List[str] = None,
                        tlsh_patterns: List[str] = None,
                        aliases: List[str] = None,
                        description: str = None,
                        mitre_techniques: List[str] = None,
                        persist: bool = True) -> None:
        """Add or update a malware family entry in the database.

        Args:
            family_name: Canonical lowercase family name
            imphashes: Import hash values to add
            ssdeep_patterns: SSDEEP patterns to add
            tlsh_patterns: TLSH patterns to add
            aliases: Family aliases
            description: Family description
            mitre_techniques: MITRE ATT&CK technique IDs
            persist: Write changes to disk immediately
        """
        entry = self.KNOWN_FAMILIES.setdefault(family_name, {
            'imphashes': [],
            'ssdeep_patterns': [],
            'tlsh_patterns': [],
            'aliases': [],
            'description': '',
            'mitre_techniques': [],
        })

        for key, values in [
            ('imphashes', imphashes),
            ('ssdeep_patterns', ssdeep_patterns),
            ('tlsh_patterns', tlsh_patterns),
            ('aliases', aliases),
            ('mitre_techniques', mitre_techniques),
        ]:
            if values:
                existing = set(entry.get(key, []))
                existing.update(values)
                entry[key] = sorted(existing)

        if description:
            entry['description'] = description

        if persist:
            self._save_database()

    def _save_database(self) -> None:
        """Persist current KNOWN_FAMILIES to disk."""
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                '_metadata': {
                    'version': '1.0.0',
                    'description': 'Known malware family hash signatures',
                    'total_families': len(self.KNOWN_FAMILIES),
                },
                'families': self.KNOWN_FAMILIES,
            }
            with open(self.db_path, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            logger.info(f"[FUZZY-HASH] Database saved ({len(self.KNOWN_FAMILIES)} families)")
        except Exception as exc:
            logger.error(f"[FUZZY-HASH] Failed to save database: {exc}")
    
    def analyze_file(self, file_path: str) -> Dict:
        """
        Generate all hash types for a file.
        
        Args:
            file_path: Path to file
        
        Returns:
            Dict with all hash types and metadata
        """
        result = {
            'file_path': file_path,
            'file_name': Path(file_path).name,
            'hashes': {
                'md5': '',
                'sha1': '',
                'sha256': '',
                'ssdeep': '',
                'tlsh': '',
                'imphash': ''
            },
            'file_size': 0,
            'algorithms_used': [],
            'family_matches': [],
            'similarity_ready': False
        }
        
        try:
            # Read file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            result['file_size'] = len(file_data)
            
            # Traditional hashes
            result['hashes']['md5'] = hashlib.md5(file_data).hexdigest()
            result['hashes']['sha1'] = hashlib.sha1(file_data).hexdigest()
            result['hashes']['sha256'] = hashlib.sha256(file_data).hexdigest()
            
            # SSDEEP fuzzy hash
            if SSDEEP_AVAILABLE:
                try:
                    result['hashes']['ssdeep'] = ssdeep.hash(file_data)
                    result['algorithms_used'].append('ssdeep')
                    logger.debug(f"[SSDEEP] {result['hashes']['ssdeep'][:40]}...")
                except Exception as e:
                    logger.warning(f"[SSDEEP] Failed: {e}")
            
            # TLSH fuzzy hash
            if TLSH_AVAILABLE:
                try:
                    # TLSH requires minimum 50 bytes
                    if len(file_data) >= 50:
                        tlsh_hash = tlsh.hash(file_data)
                        if tlsh_hash:
                            result['hashes']['tlsh'] = tlsh_hash
                            result['algorithms_used'].append('tlsh')
                            logger.debug(f"[TLSH] {tlsh_hash[:40]}...")
                except Exception as e:
                    logger.warning(f"[TLSH] Failed: {e}")
            
            # IMPHASH for PE files
            if PEFILE_AVAILABLE:
                try:
                    pe = pefile.PE(data=file_data, fast_load=True)
                    pe.parse_data_directories(directories=[
                        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
                    ])
                    imphash = pe.get_imphash()
                    if imphash:
                        result['hashes']['imphash'] = imphash
                        result['algorithms_used'].append('imphash')
                        logger.debug(f"[IMPHASH] {imphash}")
                except Exception:
                    pass  # Not a PE file
            
            # Check against known families
            result['family_matches'] = self._check_known_families(result['hashes'])
            
            # Ready for similarity comparison if we have fuzzy hashes
            result['similarity_ready'] = bool(
                result['hashes']['ssdeep'] or result['hashes']['tlsh']
            )
            
            logger.info(f"[FUZZY-HASH] Analyzed {Path(file_path).name}: {result['algorithms_used']}")
            
        except Exception as e:
            logger.error(f"[FUZZY-HASH] Analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    def compare_files(self, file1_path: str, file2_path: str) -> SimilarityResult:
        """
        Compare two files using all available fuzzy hash algorithms.
        
        Args:
            file1_path: First file
            file2_path: Second file
        
        Returns:
            SimilarityResult with scores from each algorithm
        """
        result = SimilarityResult()
        
        # Analyze both files
        hash1 = self.analyze_file(file1_path)
        hash2 = self.analyze_file(file2_path)
        
        if 'error' in hash1 or 'error' in hash2:
            result.verdict = "ERROR"
            return result
        
        # SSDEEP comparison (0-100, higher = more similar)
        if hash1['hashes']['ssdeep'] and hash2['hashes']['ssdeep']:
            try:
                result.ssdeep_score = ssdeep.compare(
                    hash1['hashes']['ssdeep'],
                    hash2['hashes']['ssdeep']
                )
            except:
                pass
        
        # TLSH comparison (0-400+, lower = more similar)
        if hash1['hashes']['tlsh'] and hash2['hashes']['tlsh']:
            try:
                tlsh_diff = tlsh.diff(
                    hash1['hashes']['tlsh'],
                    hash2['hashes']['tlsh']
                )
                # Convert to 0-100 scale (inverse)
                result.tlsh_score = max(0, 100 - (tlsh_diff // 4))
            except:
                pass
        
        # IMPHASH exact match
        if hash1['hashes']['imphash'] and hash2['hashes']['imphash']:
            result.imphash_match = (
                hash1['hashes']['imphash'] == hash2['hashes']['imphash']
            )
        
        # Calculate combined score
        scores = []
        if result.ssdeep_score > 0:
            scores.append(result.ssdeep_score)
        if result.tlsh_score > 0:
            scores.append(result.tlsh_score)
        if result.imphash_match:
            scores.append(100)  # Exact match = 100
        
        if scores:
            result.combined_score = int(sum(scores) / len(scores))
        
        # Determine verdict
        if result.combined_score >= 80 or result.imphash_match:
            result.verdict = "HIGHLY_SIMILAR"
            result.is_similar = True
        elif result.combined_score >= 50:
            result.verdict = "SIMILAR"
            result.is_similar = True
        elif result.combined_score >= 30:
            result.verdict = "POSSIBLY_RELATED"
            result.is_similar = False
        else:
            result.verdict = "DIFFERENT"
            result.is_similar = False
        
        logger.info(
            f"[FUZZY-HASH] Comparison: SSDEEP={result.ssdeep_score}, "
            f"TLSH={result.tlsh_score}, IMPHASH={'✓' if result.imphash_match else '✗'} "
            f"→ {result.verdict} ({result.combined_score}%)"
        )
        
        return result
    
    def compare_hashes(self, hash1: Dict, hash2: Dict) -> SimilarityResult:
        """
        Compare pre-computed hash bundles.
        
        Args:
            hash1: First hash dict with ssdeep/tlsh/imphash keys
            hash2: Second hash dict
        
        Returns:
            SimilarityResult
        """
        result = SimilarityResult()
        
        # SSDEEP
        ssdeep1 = hash1.get('ssdeep', '')
        ssdeep2 = hash2.get('ssdeep', '')
        if ssdeep1 and ssdeep2 and SSDEEP_AVAILABLE:
            try:
                result.ssdeep_score = ssdeep.compare(ssdeep1, ssdeep2)
            except:
                pass
        
        # TLSH
        tlsh1 = hash1.get('tlsh', '')
        tlsh2 = hash2.get('tlsh', '')
        if tlsh1 and tlsh2 and TLSH_AVAILABLE:
            try:
                tlsh_diff = tlsh.diff(tlsh1, tlsh2)
                result.tlsh_score = max(0, 100 - (tlsh_diff // 4))
            except:
                pass
        
        # IMPHASH
        imphash1 = hash1.get('imphash', '')
        imphash2 = hash2.get('imphash', '')
        if imphash1 and imphash2:
            result.imphash_match = imphash1 == imphash2
        
        # Combined score
        scores = []
        if result.ssdeep_score > 0:
            scores.append(result.ssdeep_score)
        if result.tlsh_score > 0:
            scores.append(result.tlsh_score)
        if result.imphash_match:
            scores.append(100)
        
        if scores:
            result.combined_score = int(sum(scores) / len(scores))
        
        # Verdict
        if result.combined_score >= 80 or result.imphash_match:
            result.verdict = "HIGHLY_SIMILAR"
            result.is_similar = True
        elif result.combined_score >= 50:
            result.verdict = "SIMILAR"
            result.is_similar = True
        elif result.combined_score >= 30:
            result.verdict = "POSSIBLY_RELATED"
        else:
            result.verdict = "DIFFERENT"
        
        return result
    
    def search_database(self, file_hashes: Dict, 
                        database: List[Dict],
                        threshold: int = 30) -> List[Dict]:
        """
        Search for similar samples in a hash database.
        
        Args:
            file_hashes: Dict with ssdeep/tlsh/imphash keys
            database: List of hash dicts with 'name', 'ssdeep', 'tlsh', 'imphash'
            threshold: Minimum similarity score to report
        
        Returns:
            List of similar samples with scores
        """
        similar_samples = []
        
        for entry in database:
            similarity = self.compare_hashes(file_hashes, entry)
            
            if similarity.combined_score >= threshold:
                similar_samples.append({
                    'name': entry.get('name', 'Unknown'),
                    'family': entry.get('family', 'Unknown'),
                    'ssdeep_score': similarity.ssdeep_score,
                    'tlsh_score': similarity.tlsh_score,
                    'imphash_match': similarity.imphash_match,
                    'combined_score': similarity.combined_score,
                    'verdict': similarity.verdict,
                    'entry': entry
                })
        
        # Sort by score (highest first)
        similar_samples.sort(key=lambda x: x['combined_score'], reverse=True)
        
        logger.info(f"[FUZZY-HASH] Database search: {len(similar_samples)} matches above {threshold}%")
        
        return similar_samples
    
    def _check_known_families(self, hashes: Dict) -> List[Dict]:
        """Check hashes against known malware families."""
        matches = []
        
        imphash = hashes.get('imphash', '')
        
        for family, signatures in self.KNOWN_FAMILIES.items():
            # Check imphash
            if imphash and imphash in signatures.get('imphashes', []):
                matches.append({
                    'family': family,
                    'match_type': 'imphash',
                    'confidence': 'HIGH'
                })
            
            # Check TLSH patterns (if we had them populated)
            # This would be extended with real malware hash databases
        
        return matches
    
    def cluster_files(self, file_paths: List[str], 
                      threshold: int = 50) -> Dict[str, List[str]]:
        """
        Cluster files by similarity.
        
        Args:
            file_paths: List of file paths to cluster
            threshold: Similarity threshold for clustering
        
        Returns:
            Dict mapping cluster_id to list of file paths
        """
        clusters = {}
        processed = set()
        
        # Analyze all files first
        file_hashes = {}
        for fp in file_paths:
            file_hashes[fp] = self.analyze_file(fp)
        
        # Cluster by similarity
        cluster_id = 0
        for fp1 in file_paths:
            if fp1 in processed:
                continue
            
            # Start new cluster
            cluster_name = f"cluster_{cluster_id}"
            clusters[cluster_name] = [fp1]
            processed.add(fp1)
            
            # Find similar files
            for fp2 in file_paths:
                if fp2 in processed:
                    continue
                
                similarity = self.compare_hashes(
                    file_hashes[fp1]['hashes'],
                    file_hashes[fp2]['hashes']
                )
                
                if similarity.combined_score >= threshold:
                    clusters[cluster_name].append(fp2)
                    processed.add(fp2)
            
            cluster_id += 1
        
        logger.info(f"[FUZZY-HASH] Clustered {len(file_paths)} files into {len(clusters)} clusters")
        
        return clusters
# ==================== HELPER FUNCTIONS ====================

def generate_fuzzy_hashes(file_path: str) -> Dict:
    """
    Generate all fuzzy hashes for a file.
    
    Args:
        file_path: File to hash
    
    Returns:
        Dict with all hash types
    """
    analyzer = FuzzyHashAnalyzer()
    return analyzer.analyze_file(file_path)
def compare_fuzzy_hashes(hash1: str, hash2: str, algorithm: str = 'ssdeep') -> int:
    """
    Compare two fuzzy hashes.
    
    Args:
        hash1: First hash
        hash2: Second hash
        algorithm: 'ssdeep' or 'tlsh'
    
    Returns:
        Similarity score (0-100, higher = more similar)
    """
    if algorithm == 'ssdeep' and SSDEEP_AVAILABLE:
        try:
            return ssdeep.compare(hash1, hash2)
        except:
            return 0
    
    elif algorithm == 'tlsh' and TLSH_AVAILABLE:
        try:
            diff = tlsh.diff(hash1, hash2)
            return max(0, 100 - (diff // 4))
        except:
            return 0
    
    return 0
def get_available_algorithms() -> List[str]:
    """Get list of available fuzzy hash algorithms."""
    algorithms = []
    if SSDEEP_AVAILABLE:
        algorithms.append('ssdeep')
    if TLSH_AVAILABLE:
        algorithms.append('tlsh')
    if PEFILE_AVAILABLE:
        algorithms.append('imphash')
    return algorithms
