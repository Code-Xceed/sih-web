"""
GovShield Sentinel Grid — PIB Fact Check & Indian Cyber Fraud Threat Provider
SIH 2026 Problem Statement SIH1454

Architecture Note:
Directly checks candidate URLs against verified Press Information Bureau (PIB)
Fact Check Unit, CERT-In, and I4C (MHA) blacklists of fraudulent government
scheme and fake recruitment portals.
"""

import os
import json
from typing import Dict, Any, List, Optional
from urllib.parse import urlsplit

from .base import BaseThreatProvider, ThreatEvidence


class PIBFactCheckProvider(BaseThreatProvider):
    """
    Threat intelligence provider ingesting official PIB Fact Check alerts,
    CERT-In notices, and fake government recruitment scam registries.
    """

    def __init__(self, dataset_path: Optional[str] = None):
        if not dataset_path:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            dataset_path = os.path.join(base_dir, "data", "indian_phishing_dataset.json")

        self.dataset_path = dataset_path
        self.scam_registry: List[Dict[str, Any]] = []
        self._load_dataset()

    def _load_dataset(self):
        """Loads and indexes verified scam domains."""
        if os.path.exists(self.dataset_path):
            try:
                with open(self.dataset_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.scam_registry = data.get("confirmed_scam_domains", [])
            except Exception as e:
                print(f"[PIBFactCheckProvider] Warning loading dataset: {e}")
                self.scam_registry = []

    @property
    def provider_name(self) -> str:
        return "pib/factcheck-india"

    def check_url(self, normalized_url: str) -> ThreatEvidence:
        """
        Checks if candidate URL or its domain/subdomain matches verified fake portals.
        """
        parsed = urlsplit(normalized_url if "://" in normalized_url else f"https://{normalized_url}")
        host = (parsed.hostname or "").lower()

        for entry in self.scam_registry:
            root_domain = entry["domain"].lower()
            subdomains = [s.lower() for s in entry.get("subdomains", [])]

            # Direct host match or subdomain match
            if host == root_domain or host.endswith(f".{root_domain}") or host in subdomains:
                raw_ref = f"{entry['flagged_by']} Advisory: {entry['details']} (Genuine: {entry.get('genuine_counterpart')})"
                return ThreatEvidence(
                    provider=self.provider_name,
                    match=True,
                    threat_type=entry.get("scam_type", "FAKE_GOVERNMENT_SCHEME"),
                    confidence=entry.get("confidence", 0.99),
                    raw_reference=raw_ref
                )

        return ThreatEvidence(
            provider=self.provider_name,
            match=False,
            confidence=0.0
        )
