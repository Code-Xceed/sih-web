"""
Unit tests for RFC 3986 URL Normalizer & Security Pre-Flight Engine.
"""

import sys
import os
import unittest

# Ensure backend directory is in path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from modules.url_normalizer import URLNormalizer


class TestURLNormalizer(unittest.TestCase):
    def setUp(self):
        self.normalizer = URLNormalizer()

    def test_standard_url_normalization(self):
        res = self.normalizer.normalize("http://PMKISAN.GOV.IN///path/to//page?ref=home")
        self.assertTrue(res["valid"])
        self.assertEqual(res["hostname"], "pmkisan.gov.in")
        self.assertEqual(res["registered_domain"], "pmkisan.gov.in")
        self.assertEqual(res["tld"], "gov.in")
        self.assertEqual(res["path"], "/path/to/page")

    def test_deceptive_userinfo_masquerade(self):
        # Attacker tries: http://pmkisan.gov.in@evil.com/
        res = self.normalizer.normalize("http://pmkisan.gov.in:secret@attacker-server.com/login")
        self.assertTrue(res["has_userinfo"])
        self.assertEqual(res["hostname"], "attacker-server.com")
        self.assertTrue(any("userinfo" in ind.lower() for ind in res["indicators"]))

    def test_obfuscated_decimal_ip(self):
        # 2130706433 is 127.0.0.1
        res = self.normalizer.normalize("http://2130706433/admin")
        self.assertTrue(res["is_ip_address"])
        self.assertEqual(res["hostname"], "127.0.0.1")

    def test_unusual_ports(self):
        res = self.normalizer.normalize("https://example.com:8443/login")
        self.assertTrue(res["has_unusual_port"])
        self.assertEqual(res["port"], 8443)

    def test_punycode_decoding(self):
        # xn--p1ai is .rf (Russian Cyrillic TLD)
        res = self.normalizer.normalize("http://xn--e1afmkfd.xn--p1ai")
        self.assertTrue(res["is_punycode"])
        self.assertIn("IDN", " ".join(res["indicators"]))

    def test_homoglyph_confusable_skeleton(self):
        # Cyrillic 'а' (U+0430) instead of Latin 'a'
        cyrillic_fake = "http://pmkis\u0430n-portal.xyz"
        res = self.normalizer.normalize(cyrillic_fake)
        self.assertTrue(res["has_homoglyphs"])
        self.assertEqual(res["canonical_skeleton"], "pmkisan-portal.xyz")

    def test_double_percent_encoding(self):
        res = self.normalizer.normalize("http://example.com/%252e%252e/secret")
        self.assertTrue(res["has_double_encoding"])

    def test_disallowed_schemes(self):
        res = self.normalizer.normalize("javascript:alert(1)")
        self.assertFalse(res["valid"])
        self.assertIn("javascript", res["scheme"])


if __name__ == "__main__":
    unittest.main()
