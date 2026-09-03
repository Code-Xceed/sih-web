"""
Base interfaces and structured data models for Threat Intelligence Providers.
Conforms to enterprise CTI exchange standards.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import hashlib
import json
import datetime


@dataclass
class ThreatEvidence:
    """Normalized structured threat intelligence evidence artifact."""
    provider: str
    match: bool
    threat_type: Optional[str] = None
    confidence: float = 0.0
    timestamp: str = ""
    raw_reference: Optional[str] = None
    evidence_hash: str = ""
    error: Optional[str] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if not self.evidence_hash:
            payload = f"{self.provider}|{self.match}|{self.threat_type}|{self.confidence}|{self.raw_reference}"
            self.evidence_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BaseThreatProvider(ABC):
    """Abstract interface for threat intelligence feeds."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique identifier for this threat provider."""
        pass

    @abstractmethod
    def check_url(self, normalized_url: str) -> ThreatEvidence:
        """
        Queries threat intelligence provider for a candidate URL.
        Must never raise uncaught exceptions; return ThreatEvidence with error field on failure.
        """
        pass
