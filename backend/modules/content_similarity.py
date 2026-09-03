"""
Pure-Python MinHash & Structural DOM Shingling Content Similarity Engine
Government of India — National Cyber Defense Infrastructure
Smart India Hackathon 2026 | Theme: Blockchain & Cybersecurity | Problem Statement: SIH1454

Provides lightweight, ultra-fast structural and textual cloning detection:
1. 64-hash MinHash over word shingles with Devanagari Hindi (\\u0900-\\u097F) and English tokens.
2. DOM tag sequence shingling via standard library HTMLParser.
3. Fast Jaccard estimation for identical, near-clone, and divergent web pages without heavyweight dependencies.
"""

import hashlib
import re
from html.parser import HTMLParser
from typing import List, Set, Optional

NUM_HASHES = 64
SHINGLE_WORDS = 5
DOM_SHINGLE_TAGS = 6

# Tokenizer captures alphanumeric Latin plus Devanagari Hindi unicode characters
_WORD_RE = re.compile(r"[a-z0-9\u0900-\u097F]+")


def words(text: str) -> List[str]:
    """Extracts lowercased alphanumeric and Devanagari word tokens."""
    if not text:
        return []
    return _WORD_RE.findall(text.lower())


def word_shingles(tokens: List[str], k: int = SHINGLE_WORDS) -> Set[str]:
    """Builds k-word shingles from tokens."""
    if len(tokens) < k:
        return {" ".join(tokens)} if tokens else set()
    return {" ".join(tokens[i:i + k]) for i in range(len(tokens) - k + 1)}


def _blake_hash(seed: int, item: str) -> int:
    """Fast 64-bit cryptographic hash for MinHash permutations."""
    return int.from_bytes(
        hashlib.blake2b(f"{seed}:{item}".encode("utf-8"), digest_size=8).digest(), "big"
    )


class MinHash:
    """MinHash signature generator for Jaccard similarity estimation."""

    def __init__(self, items: Set[str], num_hashes: int = NUM_HASHES) -> None:
        self.signature = [
            min(_blake_hash(seed, item) for item in items) if items else 0
            for seed in range(num_hashes)
        ]

    def similarity(self, other: "MinHash") -> float:
        """Estimates Jaccard index between two sets."""
        if not self.signature or not other.signature:
            return 0.0
        equal = sum(a == b for a, b in zip(self.signature, other.signature))
        return round(equal / len(self.signature), 4)


def text_similarity(text_a: str, text_b: str) -> float:
    """MinHash-estimated Jaccard similarity over word shingles in range [0.0, 1.0]."""
    tokens_a, tokens_b = words(text_a), words(text_b)
    if not tokens_a or not tokens_b:
        return 0.0
    hash_a = MinHash(word_shingles(tokens_a))
    hash_b = MinHash(word_shingles(tokens_b))
    return hash_a.similarity(hash_b)


class _TagSequenceParser(HTMLParser):
    """Parses HTML into sequential structural tag hierarchy, ignoring noise formatting tags."""
    _SKIP = {"br", "b", "i", "em", "strong", "span"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag not in self._SKIP:
            self.tags.append(tag)


def dom_outline(html: str, max_tags: int = 4000) -> List[str]:
    """Extracts ordered HTML tag skeleton."""
    if not html:
        return []
    parser = _TagSequenceParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.tags[:max_tags]


def dom_shingles(tags: List[str], k: int = DOM_SHINGLE_TAGS) -> Set[str]:
    """Generates structural shingles from DOM tag sequence."""
    if len(tags) < k:
        return {">".join(tags)} if tags else set()
    return {">".join(tags[i:i + k]) for i in range(len(tags) - k + 1)}


def dom_similarity(html_a: str, html_b: str) -> float:
    """Structural similarity of two web pages' HTML tag outlines in range [0.0, 1.0]."""
    tags_a, tags_b = dom_outline(html_a), dom_outline(html_b)
    if not tags_a or not tags_b:
        return 0.0
    return MinHash(dom_shingles(tags_a)).similarity(MinHash(dom_shingles(tags_b)))


def content_similarity(
    text_a: Optional[str],
    html_a: Optional[str],
    text_b: Optional[str],
    html_b: Optional[str]
) -> Optional[float]:
    """
    Blends text content similarity (60% weight) and DOM structural similarity (40% weight).
    Returns None if neither side has sufficient evidence.
    """
    if not (text_a or html_a) or not (text_b or html_b):
        return None

    scores = []
    if text_a and text_b:
        scores.append((text_similarity(text_a, text_b), 0.60))
    if html_a and html_b:
        scores.append((dom_similarity(html_a, html_b), 0.40))

    if not scores:
        return None

    total_w = sum(w for _, w in scores)
    blended = sum(s * w for s, w in scores) / total_w
    return entropy_guard(blended)


def entropy_guard(score: float) -> float:
    """Clamps small stochastic MinHash noise on disjoint sets; boosts confirmed clusters."""
    if score < 0.06:
        return 0.0
    return round(min(score * 1.12, 1.0), 3)
