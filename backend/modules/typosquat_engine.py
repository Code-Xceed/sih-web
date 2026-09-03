"""
GovShield Sentinel Grid — Typosquatting & Permutation Detection Engine.
Incorporates best-of-breed algorithms from openSquat (Levenshtein, bit-squatting,
omission, repetition, transposition, and subdomain brand masquerading) 
specialized for the Government of India Sovereign Digital Ecosystem.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .homoglyph_analyzer import HomoglyphAnalyzer
from .reference_database import GENUINE_PORTALS

# High-Value Sovereign Indian Brands and Schemes
SOVEREIGN_TARGETS = {
    "pmkisan": {"name": "PM-Kisan Samman Nidhi", "official_domain": "pmkisan.gov.in"},
    "uidai": {"name": "Unique Identification Authority of India (Aadhaar)", "official_domain": "uidai.gov.in"},
    "aadhaar": {"name": "Aadhaar Identity Portal", "official_domain": "myaadhaar.uidai.gov.in"},
    "incometax": {"name": "Income Tax e-Filing Portal", "official_domain": "incometax.gov.in"},
    "gst": {"name": "Goods and Services Tax Portal", "official_domain": "gst.gov.in"},
    "parivahan": {"name": "Ministry of Road Transport & Highways (Parivahan)", "official_domain": "parivahan.gov.in"},
    "epfindia": {"name": "Employees' Provident Fund Organisation (EPFO)", "official_domain": "epfindia.gov.in"},
    "passportindia": {"name": "Passport Seva Portal", "official_domain": "passportindia.gov.in"},
    "digilocker": {"name": "DigiLocker National Cloud", "official_domain": "digilocker.gov.in"},
    "cybercrime": {"name": "National Cyber Crime Reporting Portal", "official_domain": "cybercrime.gov.in"},
    "scholarships": {"name": "National Scholarship Portal", "official_domain": "scholarships.gov.in"},
    "cbse": {"name": "Central Board of Secondary Education", "official_domain": "cbse.gov.in"},
    "irctc": {"name": "Indian Railway Catering and Tourism Corporation", "official_domain": "irctc.co.in"},
    "echallan": {"name": "e-Challan Parivahan System", "official_domain": "echallan.parivahan.gov.in"},
    "eshram": {"name": "e-Shram National Database of Unorganised Workers", "official_domain": "eshram.gov.in"},
    "samagra": {"name": "Samagra Shiksha Abhiyan", "official_domain": "samagra.education.gov.in"},
    "shikshaabhiyan": {"name": "Samagra Shiksha Abhiyan", "official_domain": "samagra.education.gov.in"},
    "sarvashiksha": {"name": "Sarva Shiksha Abhiyan", "official_domain": "samagra.education.gov.in"},
    "pmvbry": {"name": "Pradhan Mantri Viksit Bharat Rozgar Yojana", "official_domain": "pmvbry.epfindia.gov.in"},
    "pmjay": {"name": "Ayushman Bharat (PM-JAY)", "official_domain": "pmjay.gov.in"},
    "sbi": {"name": "State Bank of India (OnlineSBI)", "official_domain": "onlinesbi.sbi"},
    "onlinesbi": {"name": "State Bank of India", "official_domain": "onlinesbi.sbi"},
    "gov": {"name": "Government of India Sovereign TLD (.gov.in)", "official_domain": "india.gov.in"},
    "nic": {"name": "National Informatics Centre (.nic.in)", "official_domain": "nic.in"},
    "india": {"name": "National Portal of India", "official_domain": "india.gov.in"}
}


def damerau_levenshtein(s1: str, s2: str) -> int:
    """Calculates Damerau-Levenshtein distance with adjacent transpositions."""
    d: Dict[Tuple[int, int], int] = {}
    len1, len2 = len(s1), len(s2)
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,        # deletion
                d[(i, j - 1)] + 1,        # insertion
                d[(i - 1, j - 1)] + cost  # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + cost)  # transposition

    return d[(len1 - 1, len2 - 1)]


def is_bitsquat_match(target: str, candidate: str) -> bool:
    """Checks for bit-squatting (single-bit difference in ASCII encoding)."""
    if len(target) != len(candidate):
        return False
    diff_count = 0
    for c1, c2 in zip(target, candidate):
        xor = ord(c1) ^ ord(c2)
        if xor != 0:
            # Check if xor is a power of 2 (single bit flip)
            if (xor & (xor - 1)) == 0:
                diff_count += 1
            else:
                return False
    return diff_count == 1


class TyposquatEngine:
    """Detects typosquatting, permutations, and subdomain brand masquerading."""

    def __init__(self):
        self.homoglyph_analyzer = HomoglyphAnalyzer()

    def analyze(self, domain_or_url: str) -> Dict[str, Any]:
        """Analyzes a domain for typosquatting targeting sovereign brands."""
        url_clean = domain_or_url.strip().lower()
        if not url_clean.startswith(("http://", "https://")):
            url_clean = "https://" + url_clean

        parsed = urlparse(url_clean)
        hostname = (parsed.netloc or "").split(":")[0].lower()

        # If already official .gov.in or .nic.in, it's not a typosquat
        is_gov_tld = hostname.endswith(".gov.in") or hostname.endswith(".nic.in")
        if is_gov_tld:
            return {
                "is_typosquat": False,
                "squat_type": "NONE",
                "target_brand": None,
                "official_domain": None,
                "edit_distance": 0,
                "confidence": 0.0,
                "details": "Authenticated sovereign domain (.gov.in / .nic.in)."
            }

        domain_parts = hostname.split(".")
        main_part = domain_parts[0]
        full_domain_stem = ".".join(domain_parts[:-1]) if len(domain_parts) > 1 else hostname

        # 1. Check Subdomain Brand Masquerading (e.g. pmkisan.gov.in.fraud-site.com)
        for brand_key, meta in SOVEREIGN_TARGETS.items():
            pattern = rf"(^|\.){re.escape(brand_key)}(\.gov\.in|\.nic\.in)?\."
            if re.search(pattern, hostname):
                return {
                    "is_typosquat": True,
                    "squat_type": "SUBDOMAIN_MASQUERADING",
                    "target_brand": meta["name"],
                    "official_domain": meta["official_domain"],
                    "edit_distance": 0,
                    "confidence": 0.98,
                    "details": f"Subdomain brand masquerading: Deceptively embeds official brand '{brand_key}' in subdomain."
                }

        # 2. Check Homoglyphs / Confusables
        homoglyph_res = self.homoglyph_analyzer.inspect(hostname)
        if homoglyph_res.get("is_spoof"):
            skel_name = homoglyph_res.get("skeleton", "")
            for brand_key, meta in SOVEREIGN_TARGETS.items():
                if brand_key in skel_name:
                    return {
                        "is_typosquat": True,
                        "squat_type": "HOMOGLYPH_SPOOF",
                        "target_brand": meta["name"],
                        "official_domain": meta["official_domain"],
                        "edit_distance": 1,
                        "confidence": 0.99,
                        "details": f"Confusable homoglyph: Uses Cyrillic/Greek lookalikes to mimic '{brand_key}'."
                    }

        # 3. Check Exact Token Infix with Deceptive Hyphens (e.g., pmkisan-kyc, uidai-update)
        for brand_key, meta in SOVEREIGN_TARGETS.items():
            if brand_key in hostname and not is_gov_tld:
                return {
                    "is_typosquat": True,
                    "squat_type": "BRAND_TOKEN_COMBINATOR",
                    "target_brand": meta["name"],
                    "official_domain": meta["official_domain"],
                    "edit_distance": 0,
                    "confidence": 0.95,
                    "details": f"Unauthorized commercial domain embeds sovereign brand token '{brand_key}'."
                }

        # 4. Check Levenshtein / Damerau-Levenshtein Edit Distance (openSquat core)
        best_match = None
        min_dist = 999
        match_type = "NONE"

        # Check against the first domain label (SLD) and tokens split by hyphen
        tokens_to_test = [main_part] + main_part.split("-")
        for token in tokens_to_test:
            token_clean = token.strip()
            if len(token_clean) < 3:
                continue

            for brand_key, meta in SOVEREIGN_TARGETS.items():
                # Test Bitsquatting
                if is_bitsquat_match(brand_key, token_clean):
                    return {
                        "is_typosquat": True,
                        "squat_type": "BITSQUATTING",
                        "target_brand": meta["name"],
                        "official_domain": meta["official_domain"],
                        "edit_distance": 1,
                        "confidence": 0.92,
                        "details": f"Bit-squatting single-bit anomaly: '{token_clean}' mimics '{brand_key}'."
                    }

                dist = damerau_levenshtein(brand_key, token_clean)
                if dist < min_dist:
                    min_dist = dist
                    best_match = (brand_key, meta)
                    if dist == 1:
                        if len(token_clean) < len(brand_key):
                            match_type = "OMISSION"
                        elif len(token_clean) > len(brand_key):
                            match_type = "INSERTION_OR_REPETITION"
                        else:
                            match_type = "SUBSTITUTION_OR_TRANSPOSITION"
                    elif dist == 2:
                        match_type = "MULTI_EDIT_PERMUTATION"

        # Thresholds: distance 1 on length >= 4, distance 2 on length >= 6
        if best_match and (min_dist == 1 or (min_dist == 2 and len(best_match[0]) >= 6)):
            brand_key, meta = best_match
            conf = 0.90 if min_dist == 1 else 0.75
            return {
                "is_typosquat": True,
                "squat_type": match_type,
                "target_brand": meta["name"],
                "official_domain": meta["official_domain"],
                "edit_distance": min_dist,
                "confidence": conf,
                "details": f"Levenshtein distance {min_dist} ({match_type}): Deceptive typosquat targeting {meta['name']}."
            }

        return {
            "is_typosquat": False,
            "squat_type": "NONE",
            "target_brand": None,
            "official_domain": None,
            "edit_distance": min_dist if min_dist != 999 else 0,
            "confidence": 0.0,
            "details": "No sovereign typosquatting or permutation patterns identified."
        }
