"""
CERT-In (Indian Computer Emergency Response Team) Incident Reporter.
Packages multi-modal forensic evidence into standardized cyber incident reports for automated takedown requests.
"""

import uuid
import datetime
from typing import Dict, Any


class CertInReporter:
    """Formats and dispatches forensic dossiers to CERT-In / Cyber Crime portal."""

    def create_incident_report(self, scan_result: Dict[str, Any], reporter_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create a standardized CERT-In cyber threat dossier."""
        incident_id = f"CERTIN-INC-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        target_entity = scan_result.get("target_entity", "Government of India Service")
        risk_score = scan_result.get("risk_score", 0)
        verdict = scan_result.get("verdict", "SUSPICIOUS")
        url = scan_result.get("url", "unknown")
        signals = scan_result.get("signal_breakdown", {})

        report = {
            "incident_id": incident_id,
            "report_timestamp_utc": timestamp,
            "threat_category": "Phishing & Brand Impersonation (National Portal Clones)",
            "classification": verdict,
            "risk_score": risk_score,
            "target_government_entity": target_entity,
            "malicious_url": url,
            "forensic_evidence": {
                "lexical_typosquatting_score": signals.get("lexical_score", 0),
                "dom_credential_harvesting_score": signals.get("dom_score", 0),
                "visual_perceptual_similarity_percentage": signals.get("visual_similarity", 0),
                "domain_age_days": signals.get("domain_age_days", 0),
                "harvested_sensitive_fields": signals.get("sensitive_fields_found", []),
                "registrar_identified": signals.get("registrar", "Unknown")
            },
            "detected_anomalies_and_indicators": scan_result.get("reasons", []),
            "mitigation_recommendations": [
                "Issue urgent DNS sinkhole and domain suspension to registrar.",
                "Block malicious IP/domain across national ISP gateway firewalls.",
                "Notify nodal security officer of impersonated department.",
                "Log threat indicators into National Cyber Crime Reporting Portal (NCRP)."
            ],
            "reporter_metadata": reporter_info or {
                "source": "GovShield Sentinel Grid v1.0",
                "client": "GovShield Chrome Extension MV3",
                "verification_mode": "Multi-Modal AI/ML Fusion"
            }
        }
        return report
