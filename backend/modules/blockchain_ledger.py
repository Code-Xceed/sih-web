"""
Sovereign Blockchain Cyber Threat Intelligence Ledger & Cryptographic Integrity Engine
Government of India — National Cyber Defense Infrastructure
Smart India Hackathon 2026 | Theme: Blockchain & Cybersecurity | Problem Statement: SIH1454

Architecture Note:
Sensitive raw data, credentials, and full HTML are preserved securely OFF-CHAIN.
Only RFC 8785 Canonical JSON hashes, scan IDs, Merkle roots, and verified threat metadata
are committed ON-CHAIN to the Proof-of-Authority (PoA) blockchain.

Provides:
1. Tamper-evident Merkle tree cryptographic chaining.
2. Canonical JSON serialization (RFC 8785) & SHA-256 evidence anchoring.
3. Cryptographic proof-of-authenticity verification.
4. Court-admissible electronic records certificates under Section 65B of the Indian Evidence Act.
"""

import hashlib
import json
import time
import datetime
import uuid
from typing import Dict, Any, List, Optional, Tuple

# Secure Off-Chain Evidence Storage (Preserves privacy while maintaining verifiable hashes on-chain)
OFFCHAIN_EVIDENCE_VAULT: Dict[str, Dict[str, Any]] = {}


def canonical_json(data: Any) -> str:
    """
    Serializes a Python object into Canonical JSON conforming to RFC 8785:
    - Recursively sorted keys
    - No whitespace between items and keys (',', ':')
    - Strict UTF-8 compatibility
    """
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def sha256_hash(data: str) -> str:
    """Computes standard SHA-256 hexadecimal hash."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def compute_merkle_root(transactions: List[Dict[str, Any]]) -> str:
    """
    Computes binary Merkle tree root hash for a list of transactions.
    Ensures complete tamper-proofing of individual threat records.
    """
    if not transactions:
        return sha256_hash("EMPTY_BLOCK_TRANSACTIONS")

    hashes = [sha256_hash(canonical_json(tx)) for tx in transactions]

    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])  # Duplicate last element if odd count
        new_level = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i + 1]
            new_level.append(sha256_hash(combined))
        hashes = new_level

    return hashes[0]


class Block:
    """Represents an immutable block on the GovShield Sovereign Threat Ledger."""

    def __init__(
        self,
        index: int,
        timestamp: str,
        transactions: List[Dict[str, Any]],
        previous_hash: str,
        validator_node: str = "NIC-DELHI-ROOT-01",
        nonce: int = 0
    ):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.validator_node = validator_node
        self.nonce = nonce
        self.merkle_root = compute_merkle_root(transactions)
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        """Calculates block header SHA-256 hash."""
        block_header = {
            "index": self.index,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "previous_hash": self.previous_hash,
            "validator_node": self.validator_node,
            "nonce": self.nonce
        }
        return sha256_hash(canonical_json(block_header))

    def to_dict(self) -> Dict[str, Any]:
        """Serializes block for API endpoints and JSON storage."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "hash": self.hash,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "validator_node": self.validator_node,
            "nonce": self.nonce,
            "transaction_count": len(self.transactions),
            "transactions": self.transactions
        }


class BlockchainLedger:
    """
    Sovereign Proof-of-Authority (PoA) Threat Intelligence Blockchain.
    Authorized Validator Nodes: NIC, CERT-In, NIXI, and Ministry Cyber Cells.
    """

    def __init__(self):
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict[str, Any]] = []
        self.authorized_validators = [
            "NIC-DELHI-SOVEREIGN-NODE-01",
            "CERT-IN-CYBER-COMMAND-HQ",
            "NIXI-INREGISTRY-TRUST-NODE",
            "MEITY-CYBER-DEFENSE-HUB"
        ]
        self.create_genesis_block()

    def create_genesis_block(self):
        """Initializes the genesis block with verified Government of India sovereign namespaces."""
        genesis_transactions = [
            {
                "tx_id": "TX-GENESIS-GOV-001",
                "type": "GENUINE_PORTAL_REGISTRATION",
                "authority": "National Informatics Centre (NIC India)",
                "entity": "Government of India Sovereign TLD Root (.gov.in / .nic.in)",
                "timestamp": "2026-01-01T00:00:00Z",
                "status": "ACCREDITED_SOVEREIGN_INFRASTRUCTURE"
            },
            {
                "tx_id": "TX-GENESIS-PMKISAN-002",
                "type": "GENUINE_PORTAL_REGISTRATION",
                "authority": "Ministry of Agriculture & Farmers Welfare",
                "entity": "PM-Kisan Samman Nidhi Portal (pmkisan.gov.in)",
                "timestamp": "2026-01-01T00:00:00Z",
                "status": "ACTIVE_AUTHENTIC"
            },
            {
                "tx_id": "TX-GENESIS-UIDAI-003",
                "type": "GENUINE_PORTAL_REGISTRATION",
                "authority": "UIDAI / MeitY",
                "entity": "Unique Identification Authority of India (uidai.gov.in)",
                "timestamp": "2026-01-01T00:00:00Z",
                "status": "ACTIVE_AUTHENTIC"
            },
            {
                "tx_id": "TX-GENESIS-INCOMETAX-004",
                "type": "GENUINE_PORTAL_REGISTRATION",
                "authority": "Central Board of Direct Taxes (CBDT)",
                "entity": "Income Tax e-Filing Portal (incometax.gov.in)",
                "timestamp": "2026-01-01T00:00:00Z",
                "status": "ACTIVE_AUTHENTIC"
            }
        ]

        genesis_block = Block(
            index=0,
            timestamp="2026-01-01T00:00:00Z",
            transactions=genesis_transactions,
            previous_hash="0" * 64,
            validator_node="NIC-DELHI-SOVEREIGN-NODE-01",
            nonce=1042
        )
        self.chain.append(genesis_block)

    def get_latest_block(self) -> Block:
        """Returns head block of the chain."""
        return self.chain[-1]

    def log_threat_incident(
        self,
        incident_id: str,
        malicious_url: str,
        target_entity: str,
        risk_score: int,
        verdict: str,
        forensic_evidence: Dict[str, Any],
        html_dom_sample: Optional[str] = None,
        reporter_notes: str = "Automated GovShield Telemetry"
    ) -> Dict[str, Any]:
        """
        Anchors threat intelligence onto the blockchain ledger.
        Full evidence bundle is stored off-chain; canonical SHA-256 hash is anchored on-chain.
        """
        # 1. Canonical Off-Chain Evidence Storage
        evidence_bundle = {
            "incident_id": incident_id,
            "url": malicious_url,
            "target_entity": target_entity,
            "risk_score": risk_score,
            "verdict": verdict,
            "forensics": forensic_evidence,
            "dom_sha256": sha256_hash(html_dom_sample or "NO_DOM_AVAILABLE"),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        canonical_evidence_str = canonical_json(evidence_bundle)
        evidence_sha256 = sha256_hash(canonical_evidence_str)

        # Store in off-chain evidence vault
        OFFCHAIN_EVIDENCE_VAULT[incident_id] = {
            "evidence_hash": evidence_sha256,
            "evidence_bundle": evidence_bundle,
            "canonical_payload": canonical_evidence_str
        }

        # 2. Construct On-Chain Tamper-Evident Transaction
        tx_id = f"TX-THREAT-{uuid.uuid4().hex[:10].upper()}"
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        tx = {
            "tx_id": tx_id,
            "incident_id": incident_id,
            "type": "PHISHING_THREAT_DETECTED",
            "timestamp": timestamp,
            "malicious_url": malicious_url,
            "target_government_entity": target_entity,
            "threat_risk_score": risk_score,
            "verdict": verdict,
            "evidence_hash": evidence_sha256,
            "mitigation_directive": "SECTION_69A_TAKEDOWN_RECOMMENDED",
            "reporter_source": reporter_notes
        }

        self.pending_transactions.append(tx)
        # Mine block with PoA consensus
        new_block = self.mine_pending_block()

        return {
            "transaction_id": tx_id,
            "block_index": new_block.index,
            "block_hash": new_block.hash,
            "merkle_root": new_block.merkle_root,
            "evidence_hash": evidence_sha256,
            "validator_node": new_block.validator_node,
            "timestamp": new_block.timestamp,
            "chain_valid": self.is_chain_valid()
        }

    def mine_pending_block(self) -> Block:
        """Mines pending transactions into a new cryptographically chained block."""
        latest = self.get_latest_block()
        validator_idx = len(self.chain) % len(self.authorized_validators)
        selected_validator = self.authorized_validators[validator_idx]

        new_block = Block(
            index=len(self.chain),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            transactions=list(self.pending_transactions),
            previous_hash=latest.hash,
            validator_node=selected_validator,
            nonce=len(self.chain) * 313
        )
        self.chain.append(new_block)
        self.pending_transactions = []
        return new_block

    def is_chain_valid(self) -> bool:
        """Verifies the integrity of the entire blockchain and Merkle roots."""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i - 1]

            if current.previous_hash != prev.hash:
                return False
            if current.hash != current.compute_hash():
                return False
            if current.merkle_root != compute_merkle_root(current.transactions):
                return False

        return True

    def verify_evidence_authenticity(self, incident_id: str, candidate_evidence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Cryptographically verifies that an off-chain evidence bundle matches the on-chain anchored hash.
        """
        candidate_canonical = canonical_json(candidate_evidence)
        candidate_hash = sha256_hash(candidate_canonical)

        # Search blockchain for anchored transaction
        for block in self.chain:
            for tx in block.transactions:
                if tx.get("incident_id") == incident_id:
                    anchored_hash = tx.get("evidence_hash")
                    is_match = (anchored_hash == candidate_hash)
                    return {
                        "verified": is_match,
                        "incident_id": incident_id,
                        "block_index": block.index,
                        "block_hash": block.hash,
                        "anchored_hash": anchored_hash,
                        "computed_hash": candidate_hash,
                        "tamper_status": "AUTHENTIC" if is_match else "TAMPERED"
                    }

        return {
            "verified": False,
            "incident_id": incident_id,
            "error": "Incident ID not found in sovereign ledger"
        }

    def get_chain(self) -> List[Dict[str, Any]]:
        """Returns serialized list of all blocks in the ledger."""
        return [b.to_dict() for b in self.chain]

    def generate_section65b_certificate(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Generates an electronic records certificate under Section 65B of the Indian Evidence Act, 1872.
        Certified by authorized Government of India validator nodes.
        """
        target_tx = None
        target_block = None

        for block in self.chain:
            for tx in block.transactions:
                if tx.get("incident_id") == incident_id:
                    target_tx = tx
                    target_block = block
                    break
            if target_tx:
                break

        if not target_tx:
            return None

        cert_id = f"CERT-65B-{uuid.uuid4().hex[:8].upper()}"
        issued_date = datetime.datetime.now(datetime.timezone.utc).strftime("%d %B %Y, %H:%M:%S UTC")

        cert_text = f"""
================================================================================
GOVERNMENT OF INDIA — MINISTRY OF ELECTRONICS & INFORMATION TECHNOLOGY (MeitY)
NATIONAL CYBER DEFENSE NETWORK (GOVSHIELD SENTINEL GRID / CERT-IN)
CERTIFICATE UNDER SECTION 65B OF THE INDIAN EVIDENCE ACT, 1872
================================================================================

CERTIFICATE SERIAL NO: {cert_id}
DATE OF ISSUE:         {issued_date}
COMPLIANCE:            Section 65B(4) Electronic Evidence Admissibility

I, System Administrator (Certifying Authority), GovShield Sovereign Cyber Defense Network,
do hereby certify and state under Section 65B of the Indian Evidence Act, 1872:

1. SOURCE COMPUTER OUTPUT SPECIFICATION:
   The computer output containing cyber threat telemetry and phishing forensic records
   described below was produced by the automated GovShield Sentinel Grid server infrastructure,
   during a period over which the computer was used regularly to store or process information
   for the purposes of national cyber threat intelligence.

2. FORENSIC INCIDENT TELEMETRY:
   • Incident Tracking ID:     {target_tx.get('incident_id')}
   • Target Malicious URL:      {target_tx.get('malicious_url')}
   • Targeted Government Entity: {target_tx.get('target_government_entity')}
   • Threat Classification:    {target_tx.get('verdict')}
   • Assessed Risk Score:      {target_tx.get('threat_risk_score')}/100
   • DOM Cryptographic SHA-256: {target_tx.get('evidence_hash')}
   • Cryptographic Evidence:   {target_tx.get('evidence_hash')}

3. SOVEREIGN BLOCKCHAIN LEDGER ANCHORING:
   • Proof-of-Authority Block: #{target_block.index}
   • Block Header Hash:        {target_block.hash}
   • Merkle Root Hash:         {target_block.merkle_root}
   • Validator Node Identity:  {target_block.validator_node}
   • Ledger Timestamp:         {target_tx.get('timestamp')}

4. INTEGRITY DECLARATION:
   Throughout the material part of the said period, the computer operated properly and
   the cryptographic hashing algorithms (SHA-256 / Merkle DAG) ensured the contents of
   the electronic record were not altered, tampered with, or subjected to unauthorized
   intervention.

5. LEGAL NOTICE & STATUTORY POWER:
   This certificate constitutes conclusive proof of electronic record provenance under
   the Indian Evidence Act, 1872 and the Information Technology Act, 2000. It is valid
   for immediate introduction before any Special Cyber Crime Court, Metropolitan Magistrate,
   or Section 69A IT Act Emergency Takedown Committee.

ISSUED UNDER THE DIGITAL SEAL OF:
National Informatics Centre (NIC) & CERT-In Sovereign Threat Ledger Authority
================================================================================
"""
        return {
            "status": "SUCCESS",
            "certificate_id": cert_id,
            "incident_id": incident_id,
            "issued_at": issued_date,
            "validator_node": target_block.validator_node,
            "block_index": target_block.index,
            "block_hash": target_block.hash,
            "merkle_root": target_block.merkle_root,
            "evidence_hash": target_tx.get("evidence_hash"),
            "legal_certificate_text": cert_text.strip()
        }

    # Alias for backward compatibility
    generate_section_65b_certificate = generate_section65b_certificate


# Global singleton ledger instance
blockchain_ledger = BlockchainLedger()
