"""
Blue Team Assistant - DGA (Domain Generation Algorithm) Detector

Detects algorithmically generated domain names using multiple statistical
heuristics: Shannon entropy, consonant-to-vowel ratio, bigram frequency,
dictionary word matching, length analysis, digit ratio, and n-gram analysis.

Author: Ugur Ates
"""

import math
import re
import string
import logging
from collections import Counter
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VOWELS = set('aeiou')
CONSONANTS = set('bcdfghjklmnpqrstvwxyz')

# Common English bigrams (top ~60 by frequency in natural language)
# Source: letter pair frequencies from large English corpora
COMMON_BIGRAMS = {
    'th', 'he', 'in', 'er', 'an', 'on', 'en', 're', 'nd', 'at',
    'ed', 'ti', 'es', 'or', 'te', 'of', 'st', 'it', 'al', 'ar',
    'is', 'to', 'nt', 'ng', 'se', 'ha', 'as', 'ou', 'io', 'le',
    'no', 'us', 'co', 'me', 'de', 'hi', 'ri', 'ro', 'ic', 'ne',
    'ea', 'ra', 'ce', 'li', 'ch', 'el', 'si', 'ta', 'ma', 'om',
    'ur', 'ca', 'la', 'ge', 'ho', 'pe', 'ni', 'na', 'po', 'fi',
}

# Common English trigrams
COMMON_TRIGRAMS = {
    'the', 'and', 'tion', 'ing', 'her', 'hat', 'ent', 'ion', 'for',
    'ter', 'was', 'tha', 'ere', 'his', 'est', 'all', 'ith', 'ver',
    'not', 'are', 'rea', 'com', 'int', 'pro', 'str', 'ous', 'tra',
}

# Minimal dictionary of common English words found in legitimate domains
# Kept small for performance; focuses on words commonly used in domain names
_DICTIONARY_WORDS = {
    'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can',
    'had', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has',
    'him', 'his', 'how', 'its', 'may', 'new', 'now', 'old', 'see',
    'way', 'who', 'did', 'let', 'say', 'she', 'too', 'use',
    # Domain-common words
    'web', 'net', 'online', 'shop', 'store', 'cloud', 'tech', 'data',
    'info', 'mail', 'host', 'site', 'page', 'blog', 'news', 'game',
    'play', 'app', 'soft', 'ware', 'code', 'dev', 'api', 'free',
    'best', 'top', 'pro', 'plus', 'max', 'hub', 'lab', 'box',
    'link', 'file', 'fast', 'smart', 'safe', 'secure', 'global',
    'world', 'home', 'work', 'market', 'bank', 'pay', 'buy', 'sell',
    'trade', 'real', 'live', 'media', 'social', 'search', 'find',
    'auto', 'car', 'health', 'care', 'travel', 'learn', 'book',
    'read', 'sport', 'food', 'green', 'blue', 'red', 'black', 'white',
    'gold', 'star', 'sun', 'moon', 'fire', 'water', 'air', 'earth',
    'server', 'service', 'digital', 'crypto', 'bit', 'coin', 'chain',
    'login', 'admin', 'user', 'account', 'support', 'help', 'group',
    'team', 'open', 'source', 'power', 'energy', 'space', 'time',
}

# Known DGA family patterns (domain length, entropy ranges, typical TLDs)
_DGA_FAMILY_SIGNATURES = {
    'conficker': {
        'length_range': (8, 15),
        'entropy_min': 3.0,
        'tlds': ['.com', '.net', '.org', '.info', '.biz'],
        'description': 'Conficker-style DGA (random consonant/vowel mix)',
    },
    'cryptolocker': {
        'length_range': (12, 24),
        'entropy_min': 3.5,
        'tlds': ['.com', '.net', '.org', '.ru', '.co.uk'],
        'description': 'CryptoLocker-style DGA (long random strings)',
    },
    'necurs': {
        'length_range': (15, 25),
        'entropy_min': 3.8,
        'tlds': ['.com', '.net', '.org', '.tk', '.pw'],
        'description': 'Necurs-style DGA (very long random domains)',
    },
    'suppobox': {
        'length_range': (8, 20),
        'entropy_min': 2.8,
        'tlds': ['.com', '.net'],
        'description': 'Suppobox-style DGA (dictionary-word concatenation)',
    },
    'generic_random': {
        'length_range': (6, 30),
        'entropy_min': 3.5,
        'tlds': [],
        'description': 'Generic random-character DGA',
    },
}


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def _extract_sld(domain: str) -> str:
    """Extract second-level domain label (strip TLD and subdomains).

    Example: 'evil.sub.example.co.uk' -> 'example'
             'xyzabc123.com' -> 'xyzabc123'
    """
    domain = domain.lower().strip().rstrip('.')

    # Remove known multi-part TLDs first
    multi_tlds = ['.co.uk', '.co.jp', '.com.br', '.com.au', '.org.uk', '.co.in']
    for mt in multi_tlds:
        if domain.endswith(mt):
            domain = domain[:-len(mt)]
            parts = domain.split('.')
            return parts[-1] if parts else domain

    parts = domain.split('.')
    if len(parts) >= 2:
        return parts[-2]  # second-level domain
    return parts[0]


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Higher entropy indicates more randomness (DGA-like).
    Legitimate domains typically have entropy < 3.5.

    Args:
        text: Input string

    Returns:
        Shannon entropy value (0.0 to ~4.7 for lowercase alpha)
    """
    if not text:
        return 0.0

    length = len(text)
    freq = Counter(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_consonant_ratio(text: str) -> float:
    """
    Calculate consonant-to-total-alpha ratio.

    DGA domains tend to have higher consonant ratios because random
    character selection produces more consonants than vowels (21 vs 5).

    Args:
        text: Domain label (alpha characters only considered)

    Returns:
        Ratio 0.0 - 1.0 (consonant count / total alpha count)
    """
    alpha_chars = [c for c in text.lower() if c in VOWELS or c in CONSONANTS]
    if not alpha_chars:
        return 0.0
    consonant_count = sum(1 for c in alpha_chars if c in CONSONANTS)
    return round(consonant_count / len(alpha_chars), 4)


def calculate_bigram_score(text: str) -> float:
    """
    Score based on how many bigrams in the text are common English bigrams.

    Legitimate domains use common letter pairs; DGA domains do not.

    Args:
        text: Domain label

    Returns:
        Score 0.0 - 1.0 (1.0 = all bigrams are common English pairs)
    """
    text = text.lower()
    alpha_text = ''.join(c for c in text if c.isalpha())

    if len(alpha_text) < 2:
        return 0.0

    bigrams = [alpha_text[i:i+2] for i in range(len(alpha_text) - 1)]
    if not bigrams:
        return 0.0

    common_count = sum(1 for bg in bigrams if bg in COMMON_BIGRAMS)
    return round(common_count / len(bigrams), 4)


def calculate_trigram_score(text: str) -> float:
    """
    Score based on common English trigram frequency.

    Args:
        text: Domain label

    Returns:
        Score 0.0 - 1.0
    """
    text = text.lower()
    alpha_text = ''.join(c for c in text if c.isalpha())

    if len(alpha_text) < 3:
        return 0.0

    trigrams = [alpha_text[i:i+3] for i in range(len(alpha_text) - 2)]
    if not trigrams:
        return 0.0

    common_count = sum(1 for tg in trigrams if tg in COMMON_TRIGRAMS)
    return round(common_count / len(trigrams), 4)


def check_dictionary_words(text: str) -> Dict:
    """
    Check if the domain label contains recognizable English words.

    Legitimate domains often contain real words; pure DGA domains do not.

    Args:
        text: Domain label

    Returns:
        Dict with word match details
    """
    text_lower = text.lower()
    found_words: List[str] = []
    covered_chars = 0

    # Sort dictionary by word length descending (greedy match)
    sorted_words = sorted(_DICTIONARY_WORDS, key=len, reverse=True)

    remaining = text_lower
    for word in sorted_words:
        if len(word) >= 3 and word in remaining:
            found_words.append(word)
            covered_chars += len(word)
            remaining = remaining.replace(word, '', 1)

    coverage = covered_chars / len(text_lower) if text_lower else 0.0

    return {
        'words_found': found_words,
        'word_count': len(found_words),
        'coverage': round(min(1.0, coverage), 4),
    }


def calculate_digit_ratio(text: str) -> float:
    """
    Calculate ratio of digits in the domain label.

    High digit content is unusual in legitimate domains.

    Args:
        text: Domain label

    Returns:
        Ratio 0.0 - 1.0
    """
    if not text:
        return 0.0
    digit_count = sum(1 for c in text if c.isdigit())
    return round(digit_count / len(text), 4)


def calculate_ngram_score(text: str, n: int = 2) -> float:
    """
    Calculate statistical likelihood of character sequences.

    Uses character-pair transition probability approximation.
    Lower scores indicate more random (DGA-like) character sequences.

    Args:
        text: Domain label
        n: N-gram size (default 2)

    Returns:
        Score 0.0 - 1.0 (higher = more natural)
    """
    text = text.lower()
    alpha_text = ''.join(c for c in text if c.isalpha())

    if len(alpha_text) < n + 1:
        return 0.5  # Not enough data

    # Build expected frequency from English letter pair statistics
    # (simplified: use bigram presence as proxy)
    if n == 2:
        return calculate_bigram_score(text)
    elif n == 3:
        return calculate_trigram_score(text)

    return 0.5


def _guess_dga_family(sld: str, entropy: float, consonant_ratio: float) -> Optional[str]:
    """Attempt to guess which DGA family a domain might belong to."""
    sld_len = len(sld)

    best_match = None
    best_score = 0

    for family, sig in _DGA_FAMILY_SIGNATURES.items():
        score = 0
        min_len, max_len = sig['length_range']

        if min_len <= sld_len <= max_len:
            score += 1
        if entropy >= sig['entropy_min']:
            score += 1

        # Suppobox uses dictionary concatenation (lower entropy, lower consonant ratio)
        if family == 'suppobox' and consonant_ratio < 0.7 and entropy < 3.5:
            score += 1
        elif family != 'suppobox' and consonant_ratio >= 0.7:
            score += 1

        if score > best_score:
            best_score = score
            best_match = family

    return best_match if best_score >= 2 else None


# ---------------------------------------------------------------------------
# Confidence calculation
# ---------------------------------------------------------------------------

def _calculate_confidence(
    entropy: float,
    consonant_ratio: float,
    bigram_score: float,
    trigram_score: float,
    digit_ratio: float,
    dict_coverage: float,
    sld_length: int,
) -> int:
    """
    Calculate overall DGA confidence score (0-100).

    Combines all heuristic signals with weighted scoring.
    """
    score = 0.0

    # Entropy: high entropy -> more likely DGA (weight: 25)
    if entropy >= 4.0:
        score += 25
    elif entropy >= 3.7:
        score += 20
    elif entropy >= 3.5:
        score += 15
    elif entropy >= 3.2:
        score += 8

    # Consonant ratio: high ratio -> more likely DGA (weight: 15)
    if consonant_ratio >= 0.85:
        score += 15
    elif consonant_ratio >= 0.75:
        score += 10
    elif consonant_ratio >= 0.65:
        score += 5

    # Bigram score: low common bigram freq -> more likely DGA (weight: 20)
    if bigram_score <= 0.1:
        score += 20
    elif bigram_score <= 0.2:
        score += 15
    elif bigram_score <= 0.3:
        score += 10
    elif bigram_score <= 0.4:
        score += 5

    # Trigram score: low trigram freq -> more likely DGA (weight: 10)
    if trigram_score <= 0.05:
        score += 10
    elif trigram_score <= 0.1:
        score += 7
    elif trigram_score <= 0.2:
        score += 3

    # Digit ratio: high digits -> more likely DGA (weight: 10)
    if digit_ratio >= 0.5:
        score += 10
    elif digit_ratio >= 0.3:
        score += 7
    elif digit_ratio >= 0.15:
        score += 4

    # Dictionary word coverage: low coverage -> more likely DGA (weight: 15)
    if dict_coverage <= 0.1:
        score += 15
    elif dict_coverage <= 0.3:
        score += 10
    elif dict_coverage <= 0.5:
        score += 5

    # Length analysis: unusual lengths more suspicious (weight: 5)
    if sld_length >= 20:
        score += 5
    elif sld_length >= 15:
        score += 3
    elif sld_length <= 4:
        score += 2  # Very short can also be DGA

    return max(0, min(100, int(score)))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_dga(domain: str) -> Dict:
    """
    Analyze a domain name for DGA (Domain Generation Algorithm) characteristics.

    Combines multiple statistical heuristics to determine if a domain was
    algorithmically generated.

    Args:
        domain: Full domain name (e.g., 'xjkq8rlm3.evil.com')

    Returns:
        Structured result::

            {
                'domain': str,
                'sld': str,                   # second-level domain label analyzed
                'entropy': float,             # Shannon entropy of SLD
                'consonant_ratio': float,     # consonant / alpha ratio
                'bigram_score': float,        # common bigram frequency
                'trigram_score': float,       # common trigram frequency
                'digit_ratio': float,         # digit / total ratio
                'ngram_score': float,         # overall n-gram naturalness
                'dictionary_match': dict,     # word match details
                'is_dga': bool,               # True if classified as DGA
                'confidence': int,            # 0-100 confidence
                'dga_family_guess': str|None, # suspected DGA family
            }
    """
    domain = domain.lower().strip().rstrip('.')
    sld = _extract_sld(domain)

    if not sld:
        return {
            'domain': domain,
            'sld': '',
            'entropy': 0.0,
            'consonant_ratio': 0.0,
            'bigram_score': 0.0,
            'trigram_score': 0.0,
            'digit_ratio': 0.0,
            'ngram_score': 0.0,
            'dictionary_match': {'words_found': [], 'word_count': 0, 'coverage': 0.0},
            'is_dga': False,
            'confidence': 0,
            'dga_family_guess': None,
        }

    # Run all analyses
    entropy = calculate_entropy(sld)
    consonant_ratio = calculate_consonant_ratio(sld)
    bigram_score = calculate_bigram_score(sld)
    trigram_score = calculate_trigram_score(sld)
    digit_ratio = calculate_digit_ratio(sld)
    ngram_score = calculate_ngram_score(sld, n=2)
    dict_match = check_dictionary_words(sld)

    # Calculate confidence
    confidence = _calculate_confidence(
        entropy=entropy,
        consonant_ratio=consonant_ratio,
        bigram_score=bigram_score,
        trigram_score=trigram_score,
        digit_ratio=digit_ratio,
        dict_coverage=dict_match['coverage'],
        sld_length=len(sld),
    )

    # Classification threshold
    is_dga = confidence >= 50

    # Guess DGA family if classified as DGA
    dga_family = None
    if is_dga:
        dga_family = _guess_dga_family(sld, entropy, consonant_ratio)

    result = {
        'domain': domain,
        'sld': sld,
        'entropy': entropy,
        'consonant_ratio': consonant_ratio,
        'bigram_score': bigram_score,
        'trigram_score': trigram_score,
        'digit_ratio': digit_ratio,
        'ngram_score': ngram_score,
        'dictionary_match': dict_match,
        'is_dga': is_dga,
        'confidence': confidence,
        'dga_family_guess': dga_family,
    }

    logger.info(
        f"[DGA] {domain} (sld={sld}): entropy={entropy:.2f} "
        f"consonant_ratio={consonant_ratio:.2f} bigram={bigram_score:.2f} "
        f"confidence={confidence} is_dga={is_dga}"
    )

    return result
