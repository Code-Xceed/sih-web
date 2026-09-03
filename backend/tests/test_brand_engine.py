"""
Unit tests for Contextual Government Brand & Impersonation Engine.
Verifies correct differentiation between official gov, news/informational media, and malicious lookalikes.
"""

import sys
import os
import unittest

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from modules.brand_engine import BrandEngine


class TestBrandEngine(unittest.TestCase):
    def setUp(self):
        self.brand_engine = BrandEngine()

    def test_official_government_portal(self):
        match = self.brand_engine.match_entity("pmkisan.gov.in")
        self.assertIsNotNone(match)
        self.assertTrue(match["is_official_domain"])

        classification = self.brand_engine.classify_relationship(
            domain="pmkisan.gov.in",
            entity_info=match
        )
        self.assertEqual(classification["classification"], "OFFICIAL")
        self.assertEqual(classification["risk_multiplier"], 0.0)

    def test_legitimate_news_media_no_false_positive(self):
        # Media discussing PM-Kisan scheme
        match = self.brand_engine.match_entity("thehindu.com", path="/news/national/pm-kisan-update-deadline")
        self.assertIsNotNone(match)

        classification = self.brand_engine.classify_relationship(
            domain="thehindu.com",
            entity_info=match,
            has_sensitive_forms=False
        )
        self.assertEqual(classification["classification"], "LEGITIMATE_THIRD_PARTY")
        self.assertLessEqual(classification["risk_multiplier"], 0.10)

    def test_wikipedia_encyclopedia_informational(self):
        match = self.brand_engine.match_entity("wikipedia.org", path="/wiki/Aadhaar")
        classification = self.brand_engine.classify_relationship(
            domain="wikipedia.org",
            entity_info=match,
            has_sensitive_forms=False
        )
        self.assertEqual(classification["classification"], "LEGITIMATE_THIRD_PARTY")

    def test_malicious_impersonation_with_credential_form(self):
        # Fake site harvesting Aadhaar
        match = self.brand_engine.match_entity("pmkisan-kyc-update.xyz")
        self.assertIsNotNone(match)
        self.assertFalse(match["is_official_domain"])

        classification = self.brand_engine.classify_relationship(
            domain="pmkisan-kyc-update.xyz",
            entity_info=match,
            has_sensitive_forms=True,
            content_similarity_score=0.85
        )
        self.assertEqual(classification["classification"], "MALICIOUS_IMPERSONATION")
        self.assertEqual(classification["risk_multiplier"], 1.0)

    def test_neutral_commercial_website(self):
        match = self.brand_engine.match_entity("github.com")
        classification = self.brand_engine.classify_relationship(
            domain="github.com",
            entity_info=match
        )
        self.assertEqual(classification["classification"], "NEUTRAL")


if __name__ == "__main__":
    unittest.main()
