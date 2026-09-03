"""
Local Sovereign Threat Ledger Intelligence Provider.
Queries local historical incidents and cryptographic threat clusters.
"""

from typing import Optional
from .base import BaseThreatProvider, ThreatEvidence


class LocalLedgerProvider(BaseThreatProvider):
    """Integrates with GovShield internal incident memory & historical campaign database."""

    def __init__(self, ledger_instance=None):
        self.ledger = ledger_instance

    @property
    def provider_name(self) -> str:
        return "govshield/sovereign-ledger"

    def check_url(self, normalized_url: str) -> ThreatEvidence:
        if not self.ledger:
            from ..blockchain_ledger import blockchain_ledger
            self.ledger = blockchain_ledger

        # Query blockchain history for prior malicious registrations
        try:
            chain = self.ledger.get_chain()
            for block in chain:
                for tx in block.get("transactions", []):
                    tx_url = tx.get("malicious_url", "")
                    if tx_url and (tx_url == normalized_url or normalized_url.startswith(tx_url)):
                        return ThreatEvidence(
                            provider=self.provider_name,
                            match=True,
                            threat_type="repeat_phishing_campaign",
                            confidence=0.99,
                            raw_reference=f"Immutable PoA Ledger Match: Block #{block['index']} | Incident {tx.get('incident_id')}"
                        )
        except Exception as e:
            return ThreatEvidence(
                provider=self.provider_name,
                match=False,
                error=f"Ledger provider query error: {str(e)}"
            )

        return ThreatEvidence(
            provider=self.provider_name,
            match=False,
            confidence=0.0,
            raw_reference="No prior incident records in sovereign threat ledger"
        )
