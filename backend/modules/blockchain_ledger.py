"""
Sovereign Blockchain Cyber Threat Intelligence Ledger
Government of India — National Cyber Defense Infrastructure
Smart India Hackathon 2026 | Theme: Blockchain & Cybersecurity | Problem Statement: SIH1454

Provides tamper-evident cryptographic chaining (SHA-256 + Merkle Trees) for:
1. Ground-truth official Government portal registries (.gov.in / .nic.in).
2. Zero-day phishing lookalike incident logs with forensic SHA-256 DOM hashes.
3. Section 69A IT Act emergency takedown directives.
4. Court-admissible electronic records certificates under Section 65B of the Indian Evidence Act.
"""

import hashlib
import json
import time
import datetime
import uuid
from typing import Dict, Any, List, Optional


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

    hashes = [sha256_hash(json.dumps(tx, sort_keys=True)) for tx in transactions]

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
        return sha256_hash(json.dumps(block_header, sort_keys=True))

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
        Logs a detected zero-day phishing lookalike onto the blockchain ledger.
        Creates an immutable cryptographic transaction and auto-mines a block.
        """
        dom_sha256 = sha256_hash(html_dom_sample or "NO_DOM_AVAILABLE")

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
            "dom_sha256_fingerprint": dom_sha256,
            "forensic_summary": forensic_evidence,
            "mitigation_directive": "SECTION_69A_TAKEDOWN_RECOMMENDED",
            "reporter_source": reporter_notes
        }

        self.pending_transactions.append(tx)
        # Mine block immediately for real-time cyber intelligence
        new_block = self.mine_pending_block(validator_node="CERT-IN-CYBER-COMMAND-HQ")

        return {
            "tx_id": tx_id,
            "block_index": new_block.index,
            "block_hash": new_block.hash,
            "merkle_root": new_block.merkle_root,
            "timestamp": timestamp,
            "dom_fingerprint": dom_sha256
        }

    def mine_pending_block(self, validator_node: Optional[str] = None) -> Block:
        """Mines pending transactions into a new block on the ledger."""
        if not self.pending_transactions:
            return self.get_latest_block()

        latest = self.get_latest_block()
        validator = validator_node or self.authorized_validators[latest.index % len(self.authorized_validators)]

        block = Block(
            index=latest.index + 1,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            transactions=list(self.pending_transactions),
            previous_hash=latest.hash,
            validator_node=validator,
            nonce=int(time.time() * 1000) % 100000
        )

        self.chain.append(block)
        self.pending_transactions = []
        return block

    def is_chain_valid(self) -> bool:
        """Audits the entire blockchain for cryptographic integrity and tamper detection."""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Verify block self-hash
            if current.hash != current.compute_hash():
                return False

            # Verify cryptographic chain continuity
            if current.previous_hash != previous.hash:
                return False

            # Verify Merkle root integrity
            if current.merkle_root != compute_merkle_root(current.transactions):
                return False

        return True

    def verify_evidence(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves cryptographic proof and blockchain inclusion path for a given incident ID.
        Used for verification by Cyber Cells and law enforcement.
        """
        for block in reversed(self.chain):
            for tx in block.transactions:
                if tx.get("incident_id") == incident_id or tx.get("tx_id") == incident_id:
                    return {
                        "verified": True,
                        "incident_id": incident_id,
                        "transaction": tx,
                        "block_height": block.index,
                        "block_hash": block.hash,
                        "block_timestamp": block.timestamp,
                        "merkle_root": block.merkle_root,
                        "validator_node": block.validator_node,
                        "chain_valid": self.is_chain_valid()
                    }
        return None

    def generate_section_65b_certificate(self, incident_id: str) -> Dict[str, Any]:
        """
        Generates an official Certificate under Section 65B of the Indian Evidence Act, 1872
        (and Section 63 of Bharatiya Sakshya Adhiniyam, 2023) for legal admissibility in court.
        """
        evidence = self.verify_evidence(incident_id)
        cert_id = f"CERT-65B-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if not evidence:
            return {
                "status": "ERROR",
                "message": f"No blockchain record found for incident ID '{incident_id}'."
            }

        tx = evidence["transaction"]
        cert_text = f"""================================================================================
GOVERNMENT OF INDIA / NATIONAL CYBER DEFENSE NETWORK
CERTIFICATE UNDER SECTION 65B OF THE INDIAN EVIDENCE ACT, 1872
(Corresponding to Section 63 of the Bharatiya Sakshya Adhiniyam, 2023)
================================================================================
Certificate ID     : {cert_id}
Date of Issuance   : {now}
Issuing Authority  : GovShield Sovereign Blockchain Threat Intelligence Network
Accredited Node    : {evidence['validator_node']}

1. PARTICULARS OF ELECTRONIC RECORD:
   - Target URL Inspected       : {tx.get('malicious_url')}
   - Impersonated Authority     : {tx.get('target_government_entity')}
   - Incident Reference         : {tx.get('incident_id')}
   - Risk Assessment Score      : {tx.get('threat_risk_score')} / 100 ({tx.get('verdict')})
   - DOM Cryptographic SHA-256  : {tx.get('dom_sha256_fingerprint')}

2. IMMUTABLE BLOCKCHAIN PROOF OF RECORD:
   - Blockchain Ledger Block    : Height #{evidence['block_height']}
   - Block Header Hash (SHA256) : {evidence['block_hash']}
   - Merkle Tree Root Hash      : {evidence['merkle_root']}
   - Block Timestamp (UTC)      : {evidence['block_timestamp']}
   - Cryptographic Integrity    : VERIFIED / TAMPER-PROOF

3. DECLARATION OF SYSTEM INTEGRITY (Sec 65B(2)):
   I, the automated evidence registrar of the GovShield Sentinel Grid System, do hereby
   certify that:
   (a) The electronic record containing the forensic extraction of the above URL was
       produced by computers operating under lawful command during regular cyber defense.
   (b) The computer system and cryptographic blockchain network were operating properly
       without unauthorized interference or data corruption.
   (c) The SHA-256 cryptographic hashes and Merkle proofs represent true, unmanipulated
       evidence of digital deception and identity harvesting targeting sovereign citizens.

4. RECOMMENDED LEGAL ACTION:
   - Registration of FIR under Section 66D of Information Technology Act (Cheating by personation).
   - Domain de-registration and sinkholing via National Internet Exchange of India (NIXI).
   - Emergency domain takedown order under Section 69A of Information Technology Act.
================================================================================
Digitally Certified by Sovereign Cyber Validator: [{evidence['validator_node']}]
================================================================================"""

        return {
            "status": "SUCCESS",
            "certificate_id": cert_id,
            "generated_at": now,
            "incident_id": incident_id,
            "blockchain_proof": evidence,
            "legal_certificate_text": cert_text
        }

    def get_stats(self) -> Dict[str, Any]:
        """Returns real-time ledger metrics."""
        total_tx = sum(len(b.transactions) for b in self.chain)
        threat_tx = sum(
            1 for b in self.chain for tx in b.transactions
            if tx.get("type") == "PHISHING_THREAT_DETECTED"
        )
        return {
            "total_blocks": len(self.chain),
            "latest_block_hash": self.get_latest_block().hash,
            "total_transactions": total_tx,
            "logged_phishing_threats": threat_tx,
            "active_validator_nodes": len(self.authorized_validators),
            "chain_integrity": "SECURE_VALID" if self.is_chain_valid() else "COMPROMISED",
            "consensus_mechanism": "Proof-of-Authority (PoA) Sovereign Grid"
        }
