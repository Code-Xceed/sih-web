"""
GovShield Sovereign Blockchain Threat Intelligence Ledger — Test Suite
Tests:
- Genesis Block Structure & Sovereign TLD Accredited Transactions
- Merkle Root Tree Computation
- Proof-of-Authority (PoA) Mining & Block Chaining
- Chain Cryptographic Tamper-Evident Validation
- Threat Incident Logging & SHA-256 DOM Fingerprinting
- Section 65B Indian Evidence Act Certificate Generation
- REST API Endpoints (/api/blockchain/chain, /api/blockchain/stats, /api/blockchain/section65b)
"""

import sys
import os

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.modules.blockchain_ledger import BlockchainLedger, Block, compute_merkle_root, sha256_hash
from fastapi.testclient import TestClient
from backend.main import app


def test_genesis_block():
    print("Test 1: Genesis Block Initialized...")
    ledger = BlockchainLedger()
    assert len(ledger.chain) == 1, "Chain should start with exactly 1 block"
    genesis = ledger.chain[0]
    assert genesis.index == 0, "Genesis index must be 0"
    assert genesis.previous_hash == "0" * 64, "Genesis previous hash must be 64 zeros"
    assert len(genesis.transactions) == 4, "Genesis should contain 4 sovereign ground-truth portals"
    assert genesis.validator_node == "NIC-DELHI-SOVEREIGN-NODE-01"
    print("  --> PASS: Genesis block conforms to sovereign ground-truth spec.")


def test_merkle_root():
    print("Test 2: Merkle Root Computation...")
    txs = [
        {"id": "tx1", "data": "threat_1"},
        {"id": "tx2", "data": "threat_2"},
        {"id": "tx3", "data": "threat_3"}
    ]
    root = compute_merkle_root(txs)
    assert isinstance(root, str) and len(root) == 64, "Merkle root must be a 64-char SHA-256 hex string"
    # Merkle root should be deterministic
    assert compute_merkle_root(txs) == root, "Merkle root must be deterministic"
    print(f"  --> PASS: Merkle Root = {root[:16]}...")


def test_threat_logging_and_mining():
    print("Test 3: Threat Incident Logging & Auto-Mining...")
    ledger = BlockchainLedger()
    tx_res = ledger.log_threat_incident(
        incident_id="INC-SIH-9999",
        malicious_url="http://fake-epfo-claim.xyz",
        target_entity="Employees Provident Fund Organisation (EPFO)",
        risk_score=92,
        verdict="PHISHING_CLONE",
        forensic_evidence={"lexical_score": 95, "dom_score": 80},
        html_dom_sample="<html><form action='stealer.php'><input name='uan'></form></html>"
    )

    assert tx_res["block_index"] == 1, "First mined block must have index 1"
    assert len(ledger.chain) == 2, "Chain length must be 2 after logging"
    assert ledger.is_chain_valid(), "Chain must be cryptographically valid"
    print(f"  --> PASS: Block #1 mined successfully. Hash: {tx_res['block_hash'][:16]}...")


def test_tamper_detection():
    print("Test 4: Tamper Detection & Cryptographic Integrity...")
    ledger = BlockchainLedger()
    ledger.log_threat_incident(
        incident_id="INC-SIH-8888",
        malicious_url="http://pmkisan-fake.online",
        target_entity="PM-Kisan",
        risk_score=90,
        verdict="PHISHING_CLONE",
        forensic_evidence={}
    )
    assert ledger.is_chain_valid(), "Chain should be valid before tampering"

    # Simulate an attacker trying to alter a block's transaction
    ledger.chain[1].transactions[0]["threat_risk_score"] = 10  # malicious modification
    assert not ledger.is_chain_valid(), "Tamper audit must detect modified transaction via Merkle or self-hash failure"
    print("  --> PASS: Cryptographic integrity audit successfully flagged tampered block!")


def test_section_65b_certificate():
    print("Test 5: Section 65B Indian Evidence Act Certificate Generation...")
    ledger = BlockchainLedger()
    inc_id = "INC-COURT-TEST-01"
    ledger.log_threat_incident(
        incident_id=inc_id,
        malicious_url="http://incometax-refund-fraud.in",
        target_entity="Income Tax e-Filing Portal",
        risk_score=96,
        verdict="PHISHING_CLONE",
        forensic_evidence={"pan_harvested": True}
    )

    cert = ledger.generate_section_65b_certificate(inc_id)
    assert cert["status"] == "SUCCESS", "Certificate generation must succeed"
    assert "SECTION 65B OF THE INDIAN EVIDENCE ACT" in cert["legal_certificate_text"]
    assert cert["certificate_id"].startswith("CERT-65B-")
    assert inc_id in cert["legal_certificate_text"]
    assert "DOM Cryptographic SHA-256" in cert["legal_certificate_text"]
    print(f"  --> PASS: Section 65B Court Certificate generated: {cert['certificate_id']}")


def test_blockchain_api_routes():
    print("Test 6: Blockchain REST API Routes...")
    client = TestClient(app)

    # 1. /api/blockchain/stats
    resp = client.get("/api/blockchain/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "blockchain_metrics" in data
    assert data["blockchain_metrics"]["chain_integrity"] == "SECURE_VALID"

    # 2. /api/blockchain/chain
    resp_chain = client.get("/api/blockchain/chain")
    assert resp_chain.status_code == 200
    chain_data = resp_chain.json()
    assert chain_data["chain_length"] >= 1
    assert len(chain_data["blocks"]) >= 1

    # 3. /api/scan commits to blockchain
    scan_resp = client.post("/api/scan", json={"url": "http://ayushman-card-free.xyz"})
    assert scan_resp.status_code == 200
    scan_json = scan_resp.json()
    assert "blockchain_proof" in scan_json
    inc_id = scan_json["incident_id"]

    # 4. /api/blockchain/verify-evidence/{incident_id}
    verify_resp = client.get(f"/api/blockchain/verify-evidence/{inc_id}")
    assert verify_resp.status_code == 200
    assert verify_resp.json()["status"] == "VERIFIED_ON_BLOCKCHAIN"

    # 5. /api/blockchain/section65b/{incident_id}
    sec65b_resp = client.get(f"/api/blockchain/section65b/{inc_id}")
    assert sec65b_resp.status_code == 200
    assert sec65b_resp.json()["status"] == "SUCCESS"
    print("  --> PASS: All 5 Blockchain REST API routes verified (200 OK)!")


if __name__ == "__main__":
    print("==================================================================")
    print("   GOVSHIELD SOVEREIGN BLOCKCHAIN THREAT LEDGER TEST SUITE       ")
    print("==================================================================")
    test_genesis_block()
    test_merkle_root()
    test_threat_logging_and_mining()
    test_tamper_detection()
    test_section_65b_certificate()
    test_blockchain_api_routes()
    print("==================================================================")
    print("   ALL 6 BLOCKCHAIN & LEGAL EVIDENCE TESTS PASSED (100%)         ")
    print("==================================================================")
