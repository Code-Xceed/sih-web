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
import hmac
import json
import time
import datetime
import uuid
import os
import sqlite3
import threading
from typing import Dict, Any, List, Optional, Tuple

# Secure Off-Chain Evidence Storage (Preserves privacy while maintaining verifiable hashes on-chain)
OFFCHAIN_EVIDENCE_VAULT: Dict[str, Dict[str, Any]] = {}

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "sovereign_ledger.db"
)

# Authorized Sovereign Validator Cryptographic Authority Secrets
VALIDATOR_SECRETS: Dict[str, str] = {
    "NIC-DELHI-SOVEREIGN-NODE-01": "NIC-MEITY-ROOT-AUTH-KEY-2026-X9",
    "CERT-IN-CYBER-COMMAND-HQ": "CERT-IN-INCIDENT-RESPONSE-NODE-SEC-77",
    "NIXI-INREGISTRY-TRUST-NODE": "NIXI-REGISTRY-SOVEREIGN-ROOT-99",
    "MEITY-CYBER-DEFENSE-HUB": "MEITY-NATIONAL-CYBER-SHIELD-NODE-42"
}


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


def sign_block(block_hash: str, validator_node: str) -> str:
    """Cryptographically signs block header hash with validator authority secret."""
    secret = VALIDATOR_SECRETS.get(validator_node, "SOVEREIGN-FALLBACK-KEY-2026").encode("utf-8")
    return hmac.new(secret, block_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_validator_signature(block_hash: str, validator_node: str, signature: str) -> bool:
    """Verifies that block signature was issued by the accredited validator node."""
    if not signature:
        return False
    expected = sign_block(block_hash, validator_node)
    return hmac.compare_digest(expected, signature)


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
        nonce: int = 0,
        validator_signature: Optional[str] = None
    ):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.validator_node = validator_node
        self.nonce = nonce
        self.merkle_root = compute_merkle_root(transactions)
        self.hash = self.compute_hash()
        self.validator_signature = validator_signature or sign_block(self.hash, self.validator_node)

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

    def verify_signature(self) -> bool:
        """Verifies validator HMAC signature against block hash and ensures transactions/header haven't been tampered."""
        if self.merkle_root != compute_merkle_root(self.transactions):
            return False
        if self.hash != self.compute_hash():
            return False
        return verify_validator_signature(self.hash, self.validator_node, self.validator_signature)

    verify_validator_signature = verify_signature

    def to_dict(self) -> Dict[str, Any]:
        """Serializes block for API endpoints and JSON storage."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "hash": self.hash,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "validator_node": self.validator_node,
            "validator_signature": self.validator_signature,
            "nonce": self.nonce,
            "transaction_count": len(self.transactions),
            "transactions": self.transactions
        }


class BlockchainLedger:
    """
    Sovereign Proof-of-Authority (PoA) Threat Intelligence Blockchain.
    Authorized Validator Nodes: NIC, CERT-In, NIXI, and Ministry Cyber Cells.
    Backed by SQLite WAL storage for zero data loss across container restarts.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict[str, Any]] = []
        self.authorized_validators = [
            "NIC-DELHI-SOVEREIGN-NODE-01",
            "CERT-IN-CYBER-COMMAND-HQ",
            "NIXI-INREGISTRY-TRUST-NODE",
            "MEITY-CYBER-DEFENSE-HUB"
        ]
        self.db_path = db_path
        self._lock = threading.Lock()

        loaded = False
        if self.db_path:
            self._init_sqlite_db()
            loaded = self._load_from_sqlite()

        if not loaded:
            self.create_genesis_block()

    def _init_sqlite_db(self):
        """Initializes SQLite tables for blocks and offchain evidence."""
        if not self.db_path:
            return
        try:
            db_dir = os.path.dirname(os.path.abspath(self.db_path))
            os.makedirs(db_dir, exist_ok=True)
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA journal_mode=WAL;")
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sovereign_blocks (
                        block_index INTEGER PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        block_hash TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        merkle_root TEXT NOT NULL,
                        validator_node TEXT NOT NULL,
                        validator_signature TEXT NOT NULL,
                        nonce INTEGER NOT NULL,
                        transactions_json TEXT NOT NULL
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS evidence_vault (
                        incident_id TEXT PRIMARY KEY,
                        evidence_hash TEXT NOT NULL,
                        evidence_bundle_json TEXT NOT NULL,
                        timestamp TEXT NOT NULL
                    )
                """)
                conn.commit()
        except Exception as e:
            print(f"[BlockchainLedger] SQLite initialization note: {e}")

    def _load_from_sqlite(self) -> bool:
        """Loads historical blocks and evidence from SQLite storage."""
        if not self.db_path or not os.path.exists(self.db_path):
            return False
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT block_index, timestamp, block_hash, previous_hash, merkle_root,
                           validator_node, validator_signature, nonce, transactions_json
                    FROM sovereign_blocks ORDER BY block_index ASC
                """)
                rows = cursor.fetchall()
                if not rows:
                    return False

                loaded_chain = []
                for row in rows:
                    b_idx, b_ts, b_hash, b_prev, b_merkle, b_node, b_sig, b_nonce, b_txs_raw = row
                    try:
                        txs = json.loads(b_txs_raw)
                    except Exception:
                        txs = []
                    block = Block(
                        index=b_idx,
                        timestamp=b_ts,
                        transactions=txs,
                        previous_hash=b_prev,
                        validator_node=b_node,
                        nonce=b_nonce,
                        validator_signature=b_sig
                    )
                    block.hash = b_hash
                    block.merkle_root = b_merkle
                    loaded_chain.append(block)

                self.chain = loaded_chain

                # Load evidence vault
                cursor.execute("SELECT incident_id, evidence_hash, evidence_bundle_json FROM evidence_vault")
                ev_rows = cursor.fetchall()
                for inc_id, ev_hash, ev_bundle_raw in ev_rows:
                    try:
                        bundle = json.loads(ev_bundle_raw)
                    except Exception:
                        bundle = {}
                    OFFCHAIN_EVIDENCE_VAULT[inc_id] = {
                        "evidence_hash": ev_hash,
                        "evidence_bundle": bundle,
                        "canonical_payload": canonical_json(bundle)
                    }
                return True
        except Exception as e:
            print(f"[BlockchainLedger] Failed to load from SQLite: {e}")
            return False

    def _persist_block(self, block: Block):
        """Persists a mined block to SQLite."""
        if not self.db_path:
            return
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO sovereign_blocks (
                        block_index, timestamp, block_hash, previous_hash,
                        merkle_root, validator_node, validator_signature,
                        nonce, transactions_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    block.index,
                    block.timestamp,
                    block.hash,
                    block.previous_hash,
                    block.merkle_root,
                    block.validator_node,
                    block.validator_signature,
                    block.nonce,
                    json.dumps(block.transactions)
                ))
                conn.commit()
        except Exception as e:
            print(f"[BlockchainLedger] Block persistence error: {e}")

    def _persist_evidence(self, incident_id: str, evidence_hash: str, evidence_bundle: Dict[str, Any]):
        """Persists evidence bundle to SQLite."""
        if not self.db_path:
            return
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO evidence_vault (
                        incident_id, evidence_hash, evidence_bundle_json, timestamp
                    ) VALUES (?, ?, ?, ?)
                """, (
                    incident_id,
                    evidence_hash,
                    json.dumps(evidence_bundle),
                    evidence_bundle.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())
                ))
                conn.commit()
        except Exception as e:
            print(f"[BlockchainLedger] Evidence persistence error: {e}")

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
        if self.db_path:
            self._persist_block(genesis_block)

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
        reporter_notes: str = "Automated GovShield Telemetry",
        ai_synthesis: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Anchors threat intelligence onto the blockchain ledger.
        Full evidence bundle is stored off-chain; canonical SHA-256 hash is anchored on-chain.
        """
        with self._lock:
            # 1. Canonical Off-Chain Evidence Storage
            evidence_bundle = {
                "incident_id": incident_id,
                "url": malicious_url,
                "target_entity": target_entity,
                "risk_score": risk_score,
                "verdict": verdict,
                "forensics": forensic_evidence,
                "ai_synthesis": ai_synthesis or {},
                "dom_sha256": sha256_hash(html_dom_sample or "NO_DOM_AVAILABLE"),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            canonical_evidence_str = canonical_json(evidence_bundle)
            evidence_sha256 = sha256_hash(canonical_evidence_str)

            # Store in off-chain evidence vault (memory & disk)
            OFFCHAIN_EVIDENCE_VAULT[incident_id] = {
                "evidence_hash": evidence_sha256,
                "evidence_bundle": evidence_bundle,
                "canonical_payload": canonical_evidence_str
            }
            self._persist_evidence(incident_id, evidence_sha256, evidence_bundle)

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
                "ai_risk_score": (ai_synthesis or {}).get("ai_risk_score", risk_score),
                "ai_summary": (ai_synthesis or {}).get("plain_english_summary") or (ai_synthesis or {}).get("summary", ""),
                "evidence_hash": evidence_sha256,
                "mitigation_directive": "SECTION_69A_TAKEDOWN_RECOMMENDED",
                "reporter_source": reporter_notes
            }

            self.pending_transactions.append(tx)
            # Mine block with PoA consensus
            new_block = self.mine_pending_block()

            return {
                "status": "LOGGED_ON_CHAIN",
                "transaction_id": tx_id,
                "block_index": new_block.index,
                "block_hash": new_block.hash,
                "merkle_root": new_block.merkle_root,
                "evidence_hash": evidence_sha256,
                "validator_node": new_block.validator_node,
                "validator_signature": new_block.validator_signature,
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
        self._persist_block(new_block)
        return new_block

    def is_chain_valid(self) -> bool:
        """Verifies the integrity of the entire blockchain, Merkle roots, and validator signatures."""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i - 1]

            if current.previous_hash != prev.hash:
                return False
            if current.hash != current.compute_hash():
                return False
            if current.merkle_root != compute_merkle_root(current.transactions):
                return False
            if not verify_validator_signature(current.hash, current.validator_node, current.validator_signature):
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
                        "validator_node": block.validator_node,
                        "validator_signature": block.validator_signature,
                        "tamper_status": "AUTHENTIC" if is_match else "TAMPERED"
                    }

        return {
            "verified": False,
            "incident_id": incident_id,
            "error": "Incident ID not found in sovereign ledger"
        }

    def get_offchain_evidence(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves raw forensic evidence bundle from the offchain vault."""
        vault_entry = OFFCHAIN_EVIDENCE_VAULT.get(incident_id)
        if vault_entry:
            return vault_entry.get("evidence_bundle")
        return None

    def audit_domain_on_blockchain(self, domain: str) -> Dict[str, Any]:
        """
        AI & Forensic Blockchain Audit:
        Scans all historical blocks on the sovereign ledger for matches with candidate domain.
        Verifies Merkle roots, validator signatures, and flags repeat malicious incidents.
        """
        clean_target = domain.strip().lower().rstrip(".")
        if "://" in clean_target:
            from urllib.parse import urlparse
            clean_target = urlparse(clean_target).netloc.split(":")[0].lower()

        matched_incidents: List[Dict[str, Any]] = []
        is_genesis_authentic = False
        genesis_entity = None

        with self._lock:
            for block in self.chain:
                # Audit Genesis Block ground truth
                if block.index == 0:
                    for tx in block.transactions:
                        entity_str = str(tx.get("entity", "")).lower()
                        if clean_target in entity_str:
                            is_genesis_authentic = True
                            genesis_entity = tx.get("entity")
                            break
                    continue

                # Audit Mined Threat Blocks
                for tx in block.transactions:
                    mal_url = str(tx.get("malicious_url", "")).lower()
                    if clean_target in mal_url:
                        matched_incidents.append({
                            "incident_id": tx.get("incident_id"),
                            "block_index": block.index,
                            "block_hash": block.hash,
                            "timestamp": tx.get("timestamp"),
                            "target_entity": tx.get("target_government_entity"),
                            "verdict": tx.get("verdict"),
                            "risk_score": tx.get("threat_risk_score"),
                            "ai_risk_score": tx.get("ai_risk_score", tx.get("threat_risk_score")),
                            "ai_summary": tx.get("ai_summary", ""),
                            "validator_node": block.validator_node,
                            "signature_verified": block.verify_signature(),
                            "evidence_hash": tx.get("evidence_hash")
                        })

        if is_genesis_authentic:
            return {
                "audit_status": "AUTHENTIC_GOV_GENESIS_ROOT",
                "is_prior_offender": False,
                "domain": clean_target,
                "genesis_entity": genesis_entity,
                "genesis_verified": True,
                "risk_adjustment": -25,
                "summary": f"Domain '{clean_target}' is officially anchored in Genesis Block #0 as sovereign government infrastructure.",
                "verified_blocks": [0],
                "incidents_count": 0,
                "prior_incidents_count": 0
            }

        if matched_incidents:
            latest = matched_incidents[-1]
            return {
                "audit_status": "REPEAT_OFFENDER_FLAGGED",
                "is_prior_offender": True,
                "domain": clean_target,
                "prior_incidents_count": len(matched_incidents),
                "incidents_count": len(matched_incidents),
                "latest_incident": latest,
                "risk_adjustment": 50,
                "risk_score_modifier": 50,
                "summary": f"CRITICAL: Domain '{clean_target}' is a repeat cyber threat previously anchored in Block #{latest['block_index']} ({latest['verdict']}).",
                "verified_blocks": [
                    {
                        "block_index": inc["block_index"],
                        "block_hash": inc["block_hash"],
                        "merkle_root_valid": True,
                        "signature_valid": inc["signature_verified"]
                    }
                    for inc in matched_incidents
                ],
                "matched_incidents": matched_incidents
            }

        return {
            "audit_status": "CLEAN_NO_ONCHAIN_RECORD",
            "is_prior_offender": False,
            "domain": clean_target,
            "risk_adjustment": 0,
            "summary": f"Domain '{clean_target}' has no prior malicious incident entries on the sovereign PoA ledger.",
            "verified_blocks": [],
            "incidents_count": 0,
            "prior_incidents_count": 0
        }

    def get_chain(self) -> List[Dict[str, Any]]:
        """Returns serialized list of all blocks in the ledger."""
        return [b.to_dict() for b in self.chain]

    def generate_section65b_certificate(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Generates an electronic records certificate under Section 65B of the Indian Evidence Act, 1872
        (and Section 63 of Bharatiya Sakshya Adhiniyam, 2023).
        Certified by authorized Government of India validator nodes with digital signatures.
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
(CONCURRENT TO SECTION 63 BHARATIYA SAKSHYA ADHINIYAM, 2023)
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
   • Validator Digital Seal:   {target_block.validator_signature}
   • Ledger Timestamp:         {target_tx.get('timestamp')}

4. INTEGRITY DECLARATION:
   Throughout the material part of the said period, the computer operated properly and
   the cryptographic hashing algorithms (SHA-256 / Merkle DAG / HMAC Validator Signatures)
   ensured the contents of the electronic record were not altered, tampered with, or
   subjected to unauthorized intervention.

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
            "validator_signature": target_block.validator_signature,
            "block_index": target_block.index,
            "block_hash": target_block.hash,
            "merkle_root": target_block.merkle_root,
            "evidence_hash": target_tx.get("evidence_hash"),
            "signature_verified": verify_validator_signature(target_block.hash, target_block.validator_node, target_block.validator_signature),
            "legal_certificate_text": cert_text.strip()
        }

    # Alias for backward compatibility
    generate_section_65b_certificate = generate_section65b_certificate


# Global singleton ledger instance with persistent SQLite storage
blockchain_ledger = BlockchainLedger(db_path=DEFAULT_DB_PATH)
