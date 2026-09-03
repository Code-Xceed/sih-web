"""
Homoglyph, IDN Confusable, and Multi-Script Normalization Engine
Government of India — National Cyber Defense Infrastructure
Smart India Hackathon 2026 | Theme: Blockchain & Cybersecurity | Problem Statement: SIH1454

Detects deceptive character spoofing techniques where attackers substitute lookalike
characters from Cyrillic, Greek, or special unicode scripts to impersonate official
government, banking, or citizen portal domains (e.g. Cyrillic 'а' in "pаypal" or "gοv.in").
"""

import unicodedata
from typing import Dict, List, Tuple, Set, Optional

# Latin look-alikes from Cyrillic, Greek, and common unicode symbol confusables
CONFUSABLES: Dict[str, str] = {
    # Cyrillic look-alikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "һ": "h", "ԁ": "d", "ѕ": "s", "ӏ": "l", "ɡ": "g",
    "ƅ": "b", "ɱ": "m", "ҹ": "ch", "А": "A", "В": "B", "Е": "E", "К": "K",
    "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    # Greek look-alikes
    "α": "a", "β": "b", "γ": "g", "δ": "d", "ε": "e", "ζ": "z", "η": "h",
    "θ": "th", "ι": "i", "κ": "k", "λ": "l", "μ": "m", "ν": "n", "ξ": "x",
    "ο": "o", "π": "p", "ρ": "r", "σ": "s", "τ": "t", "υ": "u", "φ": "f",
    "χ": "ch", "ψ": "ps", "ω": "w", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z",
    "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Υ": "Y", "Χ": "X",
    # Symbol / dash / number confusables
    "ǀ": "l", "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "−": "-",
    "٠": "0", "١": "1", "٢": "2", "٣": "3", "٤": "4", "٥": "5", "٦": "6",
    "٧": "7", "٨": "8", "٩": "9", "०": "0", "१": "1", "२": "2", "३": "3",
    "४": "4", "५": "5", "६": "6", "७": "7", "८": "8", "९": "9",
    "。": ".", "．": ".",
}

SCRIPT_RANGES: Dict[str, List[Tuple[int, int]]] = {
    "latin": [(0x41, 0x5A), (0x61, 0x7A)],
    "cyrillic": [(0x0400, 0x04FF)],
    "greek": [(0x0370, 0x03FF)],
    "devanagari": [(0x0900, 0x097F)],
    "han": [(0x4E00, 0x9FFF)],
    "hangul": [(0xAC00, 0xD7AF)],
}


class HomoglyphAnalyzer:
    """Analyzes domains and hostnames for internationalized confusable spoofing."""

    @staticmethod
    def char_script(ch: str) -> Optional[str]:
        """Identifies unicode script family of a character."""
        cp = ord(ch)
        for script, ranges in SCRIPT_RANGES.items():
            if any(lo <= cp <= hi for lo, hi in ranges):
                return script
        return None

    @staticmethod
    def mixed_script(text: str) -> bool:
        """
        Returns True if the string deceptively mixes scripts that do not naturally occur together
        (e.g., Latin mixed with Cyrillic or Greek inside the same domain label).
        """
        scripts: Set[str] = {
            HomoglyphAnalyzer.char_script(ch) for ch in text
        } - {None}
        # Latin combined with Cyrillic or Greek is almost universally malicious
        dangerous = (scripts & {"latin"}) and (scripts & {"cyrillic", "greek"})
        return bool(dangerous)

    @staticmethod
    def has_homoglyph(text: str) -> bool:
        """Returns True if any known confusable character is present in the text."""
        return any(ch in CONFUSABLES for ch in text)

    @staticmethod
    def skeleton(text: str) -> str:
        """
        Normalizes confusables into a plain canonical ASCII skeleton.
        Example: "pаypal" (with Cyrillic 'а') -> "paypal".
        """
        normalized = unicodedata.normalize("NFKC", text)
        return "".join(CONFUSABLES.get(ch, ch) for ch in normalized).lower()

    @staticmethod
    def is_punycode(host: str) -> bool:
        """Returns True if host contains IDNA punycode labels (xn--)."""
        return any(label.startswith("xn--") for label in host.lower().split("."))

    @staticmethod
    def decode_punycode(host: str) -> str:
        """Decodes punycode hostname to unicode; returns original host on failure."""
        try:
            return host.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            return host

    def inspect(self, host: str) -> Dict[str, any]:
        """Performs full homoglyph inspection on a target hostname."""
        host_clean = host.lower().strip()
        is_puny = self.is_punycode(host_clean)
        decoded = self.decode_punycode(host_clean) if is_puny else host_clean
        has_hg = self.has_homoglyph(decoded)
        is_mixed = self.mixed_script(decoded)
        skel = self.skeleton(decoded)

        risk = 0.0
        reasons = []

        if is_mixed:
            risk += 0.85
            reasons.append("Dangerous mixed-script detected (Latin mixed with Cyrillic/Greek confusables)")
        elif has_hg:
            risk += 0.65
            reasons.append("Character homoglyph substitution detected")

        if is_puny:
            risk += 0.40
            reasons.append("Punycode IDN domain representation (xn--)")

        return {
            "is_punycode": is_puny,
            "has_homoglyphs": has_hg,
            "mixed_script": is_mixed,
            "decoded_unicode": decoded,
            "skeleton": skel,
            "homoglyph_risk": round(min(risk, 1.0), 2),
            "reasons": reasons
        }
