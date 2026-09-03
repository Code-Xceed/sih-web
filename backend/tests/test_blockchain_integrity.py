"""
Unit tests for Sovereign Blockchain Ledger & RFC 8785 Canonical Evidence Integrity.
"""

import sys
import os
import unittest
import json

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from modules.blockchain_ledger import (
    blockchain_ledger,
    canonical_json,
    sha256_hash,
    compute_merkle_root
)


class TestBlockchainIntegrity(unittest.TestCase):
    def test_canonical_json_rfc8785_determinism(self):
        # Dicts with differing key insertion orders must yield identical canonical strings
        dict_a = {"z_field": 100, "a_field": "test", "m_nested": {"beta": 2, "alpha": 1}}
        dict_b = {"a_field": "test", "m_nested": {"alpha": 1, "beta": 2}, "z_field": 100}

        canon_a = canonical_json(dict_a)
        canon_b = canonical_json(dict_b)

        self.assertEqual(canon_a, canon_b)
        self.assertEqual(sha256_hash(canon_a), sha256_hash(canon_b))
        # Ensure no extraneous whitespace
        self.assertNotIn(": ", canon_a)
        self.assertNotIn(", ", canon_a)

    def test_merkle_tree_root_calculation(self):
        txs = [
            {"id": "1", "val": "A"},
            {"id": "2", "val": "B"},
            {"id": "3", "val": "C"}
        ]
        root1 = compute_merkle_root(txs)
        root2 = compute_merkle_root(txs)
        self.assertEqual(root1, root2)
        self.assertEqual(len(root1), 64)

    def test_log_threat_incident_anchoring(self):
        incident_id = "TEST-INC-VERIFY-001"
        proof = blockchain_ledger.log_threat_incident(
            incident_id=incident_id,
            malicious_url="http://sbi-instant-kyc-update.xyz",
            target_entity="State Bank of India",
            risk_score=92,
            verdict="PHISHING_CLONE",
            forensic_evidence={"lexical": 95.0, "sensitive_fields": ["pan_number", "otp_code"]}
        )

        self.assertTrue(proof["chain_valid"])
        self.assertTrue(blockchain_ledger.is_chain_valid())
        self.assertEqual(len(proof["evidence_hash"]), 64)

        # Generate Section 65B court certificate
        cert = blockchain_ledger.generate_section65b_certificate(incident_id)
        self.assertIsNotNone(cert)
        self.assertIn("Section 65B of the Indian Evidence Act", cert["legal_certificate_text"])
        self.assertIn(incident_id, cert["legal_certificate_text"])


if __name__ == "__main__":
    unittest.main()
