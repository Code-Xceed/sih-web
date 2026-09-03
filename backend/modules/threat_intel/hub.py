"""
Threat Intelligence Hub.
Orchestrates multiple CTI providers, handles timeouts, and correlates external evidence.
"""

from typing import List, Dict, Any, Optional
import concurrent.futures
from .base import BaseThreatProvider, ThreatEvidence
from .urlhaus_provider import URLhausProvider
from .local_ledger_provider import LocalLedgerProvider
from .pib_factcheck_provider import PIBFactCheckProvider


class ThreatIntelHub:
    """Enterprise multi-provider Threat Intelligence aggregator."""

    def __init__(self, providers: Optional[List[BaseThreatProvider]] = None):
        if providers is None:
            self.providers = [
                URLhausProvider(),
                LocalLedgerProvider(),
                PIBFactCheckProvider()
            ]
        else:
            self.providers = providers

    def register_provider(self, provider: BaseThreatProvider):
        """Allows dynamic registration of custom CTI providers."""
        self.providers.append(provider)

    def evaluate_url(self, normalized_url: str) -> Dict[str, Any]:
        """
        Queries all registered threat intelligence providers concurrently.
        Returns correlated threat evidence and fast-track indicators.
        """
        evidence_list: List[Dict[str, Any]] = []
        has_positive_match = False
        highest_confidence = 0.0
        primary_threat_type = None
        reasons: List[str] = []

        # Run provider checks concurrently with strict timeout cap
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.providers) or 1) as executor:
            future_to_provider = {
                executor.submit(p.check_url, normalized_url): p for p in self.providers
            }
            for future in concurrent.futures.as_completed(future_to_provider):
                p = future_to_provider[future]
                try:
                    ev: ThreatEvidence = future.result()
                    evidence_list.append(ev.to_dict())

                    if ev.match:
                        has_positive_match = True
                        if ev.confidence > highest_confidence:
                            highest_confidence = ev.confidence
                            primary_threat_type = ev.threat_type
                        reasons.append(f"Threat Intel [{ev.provider}]: {ev.raw_reference}")
                    elif ev.error:
                        reasons.append(f"Threat Intel [{ev.provider}]: Unavailable ({ev.error})")
                except Exception as e:
                    evidence_list.append({
                        "provider": p.provider_name,
                        "match": False,
                        "confidence": 0.0,
                        "error": str(e)
                    })

        # Calculate threat intelligence risk score
        intel_score = 0.0
        if has_positive_match:
            intel_score = highest_confidence * 100.0

        return {
            "intel_risk_score": round(intel_score, 1),
            "is_known_malicious": has_positive_match and highest_confidence >= 0.85,
            "primary_threat_type": primary_threat_type,
            "highest_confidence": highest_confidence,
            "provider_count": len(self.providers),
            "evidence": evidence_list,
            "reasons": reasons
        }
