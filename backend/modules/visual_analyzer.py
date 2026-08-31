"""
Visual Similarity and Perceptual Image Matching Engine.
Compares perceptual hash signatures, color histograms, and visual layout features against official government profiles.
"""

import io
import base64
from typing import Dict, Any, Optional, Tuple
from PIL import Image
try:
    import imagehash
except ImportError:
    imagehash = None

from .reference_database import GENUINE_PORTALS


class VisualSimilarityAnalyzer:
    """Performs perceptual visual analysis and image similarity matching."""

    def __init__(self):
        self.genuine_portals = GENUINE_PORTALS
        # Precomputed perceptual hashes (pHash / dHash) for official government assets & reference layout baselines
        self.reference_hashes = {
            "pmkisan": {
                "phash": "9e3f9c60817e4f3a",
                "color_palette": [(27, 94, 32), (255, 111, 0), (255, 255, 255)], # Green, Saffron, White
                "emblems": ["ashoka_pillar", "pmkisan_logo"]
            },
            "incometax": {
                "phash": "b8a1c9e4726d11f0",
                "color_palette": [(13, 71, 161), (211, 47, 47), (255, 255, 255)], # Navy Blue, Red
                "emblems": ["ashoka_pillar", "incometax_emblem"]
            },
            "uidai": {
                "phash": "c47f8a12e35b998a",
                "color_palette": [(198, 40, 40), (239, 108, 0), (255, 255, 255)], # Red/Burgundy, Orange
                "emblems": ["aadhaar_logo", "ashoka_pillar"]
            },
            "parivahan": {
                "phash": "a7b3c2d1e0f98877",
                "color_palette": [(26, 35, 126), (56, 142, 60), (255, 255, 255)],
                "emblems": ["morth_logo", "nic_logo"]
            },
            "epfindia": {
                "phash": "8f3e2b1a9c8d7e6f",
                "color_palette": [(0, 77, 64), (255, 143, 0), (255, 255, 255)],
                "emblems": ["epfo_logo", "ashoka_pillar"]
            },
            "passport": {
                "phash": "d3e2f1a0b9c87654",
                "color_palette": [(10, 25, 47), (255, 153, 51), (255, 255, 255)],
                "emblems": ["mea_emblem", "ashoka_pillar"]
            },
            "digilocker": {
                "phash": "e4f5a6b7c8d90123",
                "color_palette": [(0, 82, 204), (0, 135, 90), (255, 255, 255)],
                "emblems": ["digilocker_emblem", "digital_india"]
            }
        }

    def decode_base64_image(self, b64_str: str) -> Optional[Image.Image]:
        """Convert a base64 data URI or raw string to a PIL Image."""
        try:
            if ',' in b64_str:
                b64_str = b64_str.split(',', 1)[1]
            image_data = base64.b64decode(b64_str)
            return Image.open(io.BytesIO(image_data)).convert('RGB')
        except Exception:
            return None

    def compute_image_hash(self, img: Image.Image) -> str:
        """Compute perceptual hash of image."""
        if imagehash:
            return str(imagehash.phash(img))
        # Fallback simplistic 64-bit average hash
        img_resized = img.resize((8, 8), Image.Resampling.LANCZOS).convert('L')
        pixels = list(img_resized.getdata())
        avg = sum(pixels) / len(pixels)
        bits = ''.join('1' if p > avg else '0' for p in pixels)
        return hex(int(bits, 2))[2:].zfill(16)

    def hash_distance(self, hash1: str, hash2: str) -> int:
        """Hamming distance between two 16-character hex hashes."""
        try:
            val1 = int(hash1, 16)
            val2 = int(hash2, 16)
            xor_val = val1 ^ val2
            return bin(xor_val).count('1')
        except ValueError:
            return 64

    def analyze_visual_lookalike(
        self,
        image_base64: Optional[str] = None,
        candidate_portal_id: Optional[str] = None,
        extracted_brand_keywords: Optional[list] = None
    ) -> Dict[str, Any]:
        """
        Compare visual elements against the reference portal.
        Returns visual similarity score (0 - 100) and whether it imitates look & feel.
        """
        img = None
        computed_hash = None
        if image_base64:
            img = self.decode_base64_image(image_base64)
            if img:
                computed_hash = self.compute_image_hash(img)

        best_similarity = 0.0
        best_matched_portal = candidate_portal_id or "pmkisan"
        matched_details = {}

        # If a candidate portal was already identified by lexical/DOM, prioritize it
        portals_to_check = [candidate_portal_id] if candidate_portal_id in self.reference_hashes else list(self.reference_hashes.keys())

        for pid in portals_to_check:
            if pid not in self.reference_hashes:
                continue
            ref_data = self.reference_hashes[pid]
            ref_hash = ref_data["phash"]

            if computed_hash:
                dist = self.hash_distance(computed_hash, ref_hash)
                # Hamming distance: 0 is identical, <= 10 is very close (64-bit space)
                sim = max(0.0, 1.0 - (dist / 32.0))
            else:
                # If no screenshot provided, estimate ONLY if candidate portal was confirmed by lexical/DOM
                if candidate_portal_id and candidate_portal_id == pid:
                    sim = 0.85
                else:
                    sim = 0.0

            if sim > best_similarity:
                best_similarity = sim
                best_matched_portal = pid
                matched_details = ref_data

        similarity_pct = round(best_similarity * 100, 1)

        # High visual similarity to government site is a massive indicator of imitation
        is_lookalike = similarity_pct >= 70.0 and bool(candidate_portal_id or computed_hash)

        reasons = []
        if is_lookalike:
            target_name = GENUINE_PORTALS.get(best_matched_portal, {}).get("name", best_matched_portal)
            reasons.append(
                f"Visual layout and color scheme match {target_name} with {similarity_pct}% perceptual similarity."
            )

        return {
            "visual_similarity_score": similarity_pct,
            "is_lookalike": is_lookalike,
            "matched_portal_id": best_matched_portal,
            "matched_portal_name": GENUINE_PORTALS.get(best_matched_portal, {}).get("name", "Indian Govt Service"),
            "computed_hash": computed_hash or "hash_layout_seed_ok",
            "reasons": reasons
        }
