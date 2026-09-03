"""
Unit tests for Pluggable Threat Intelligence Layer.
Verifies ThreatEvidence models, URLhaus local/offline caching, and Hub aggregation resilience.
"""

import sys
import os
import unittest

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from modules.threat_intel.base import ThreatEvidence, BaseThreatProvider
from modules.threat_intel.hub import ThreatIntelHub
from modules.threat_intel.urlhaus_provider import URLhausProvider
from modules.threat_intel.local_ledger_provider import LocalLedgerProvider


class MockFailingProvider(BaseThreatProvider):
    @property
    def provider_name(self) -> str:
        return "mock/failing-provider"

    def check_url(self, normalized_url: str) -> ThreatEvidence:
        return ThreatEvidence(
            provider=self.provider_name,
            match=False,
            confidence=0.0,
            error="Connection timed out (mocked network outage)"
        )


class TestThreatIntelLayer(unittest.TestCase):
    def test_threat_evidence_dataclass_hashing(self):
        ev = ThreatEvidence(
            provider="test-feed",
            match=True,
            threat_type="phishing",
            confidence=0.95,
            raw_reference="Active zero-day campaign"
        )
        self.assertTrue(len(ev.evidence_hash) == 64)
        self.assertTrue(ev.match)

    def test_urlhaus_offline_dataset_match(self):
        provider = URLhausProvider()
        ev = provider.check_url("http://pmkisan-kyc-update.xyz/login")
        self.assertTrue(ev.match)
        self.assertEqual(ev.threat_type, "phishing")
        self.assertGreaterEqual(ev.confidence, 0.90)

    def test_hub_aggregation_with_provider_outage(self):
        # Even if a provider fails, Hub MUST NOT crash or claim URL is safe
        hub = ThreatIntelHub(providers=[MockFailingProvider(), URLhausProvider()])
        result = hub.evaluate_url("http://pmkisan-kyc-update.xyz")

        self.assertTrue(result["is_known_malicious"])
        self.assertGreaterEqual(result["highest_confidence"], 0.90)
        self.assertEqual(result["provider_count"], 2)
        # Verify failure was recorded in reasons
        self.assertTrue(any("mock/failing-provider" in r for r in result["reasons"]))


if __name__ == "__main__":
    unittest.main()
