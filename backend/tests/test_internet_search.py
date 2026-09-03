"""
Unit tests for Live Internet OSINT Search Engine & PIB Fact Check Scam Registry.
"""

import sys
import os
import unittest

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from modules.internet_search_engine import InternetSearchEngine
from modules.threat_intel.pib_factcheck_provider import PIBFactCheckProvider


class TestInternetSearchAndPIB(unittest.TestCase):
    def setUp(self):
        self.pib_provider = PIBFactCheckProvider()
        self.search_engine = InternetSearchEngine()

    def test_pib_factcheck_provider_detects_samagra_scam(self):
        # samagra.shikshaabhiyan.co.in
        ev = self.pib_provider.check_url("http://samagra.shikshaabhiyan.co.in")
        self.assertTrue(ev.match)
        self.assertEqual(ev.threat_type, "FAKE_GOVERNMENT_RECRUITMENT_FEE")
        self.assertGreaterEqual(ev.confidence, 0.95)
        self.assertIn("PIB", ev.raw_reference)

    def test_pib_factcheck_provider_detects_sarvashiksha_scam(self):
        ev = self.pib_provider.check_url("https://www.sarvashiksha.online")
        self.assertTrue(ev.match)
        self.assertEqual(ev.threat_type, "FAKE_GOVERNMENT_RECRUITMENT_FEE")

    def test_pib_factcheck_provider_whitelists_genuine_domain(self):
        ev = self.pib_provider.check_url("https://samagra.education.gov.in")
        self.assertFalse(ev.match)

    def test_internet_search_engine_cache_and_structure(self):
        res = self.search_engine.investigate_domain_osint("shikshaabhiyan.co.in", entity_name="Samagra Shiksha")
        self.assertTrue(res["searched"])
        self.assertEqual(res["domain"], "shikshaabhiyan.co.in")
        self.assertIn("advisory_findings", res)


if __name__ == "__main__":
    unittest.main()
