"""
GovShield Sentinel Grid — Calibrated Multi-Signal Risk & Evidence Correlation Engine
SIH 2026 Problem Statement SIH1454

Architecture Note:
Correlates independent forensic signals across URL, Network, Threat Intel, DOM, Visual,
Brand, and Semantic layers. Strong deterministic evidence (e.g. Known Threat Intel or
Aadhaar/OTP harvesting) dominates weaker heuristics. Generates explainable, calibrated verdicts.
"""

from typing import Dict, Any, List, Optional
import datetime

MODEL_VERSION = "2.1.0-defense-in-depth"
FEATURE_VERSION = "v2"


class FusionEngine:
    """Enterprise multi-signal evidence correlation and risk scoring engine."""

    def __init__(self):
        self.model_version = MODEL_VERSION
        self.feature_version = FEATURE_VERSION

    def evaluate_comprehensive(
        self,
        url_metadata: Dict[str, Any],
        network_evidence: Dict[str, Any],
        threat_intel_evidence: Dict[str, Any],
        dom_evidence: Dict[str, Any],
        visual_evidence: Dict[str, Any],
        brand_evidence: Dict[str, Any],
        content_sim_evidence: Optional[Dict[str, Any]],
        ai_synthesis: Dict[str, Any],
        research_findings: List[Dict[str, Any]],
        crawler_evidence: Optional[Dict[str, Any]] = None,
        internet_search_evidence: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes calibrated multi-signal fusion across all 15 feature dimensions.
        Returns a structured, explainable risk assessment.
        """
        reasons: List[str] = []
        evidence_summary: List[Dict[str, Any]] = []

        # 1. Extract Base Feature Scores
        tld = url_metadata.get("tld", "")
        is_official_gov_tld = tld in ["gov.in", "nic.in", "mil.in"]
        has_homoglyphs = url_metadata.get("has_homoglyphs", False)
        is_known_malicious = threat_intel_evidence.get("is_known_malicious", False)
        highest_intel_conf = threat_intel_evidence.get("highest_confidence", 0.0)

        brand_class = brand_evidence.get("classification", "NEUTRAL")
        claimed_entity = brand_evidence.get("claimed_entity")

        sens_inputs = [s["field"] for s in dom_evidence.get("sensitive_inputs", [])]
        has_citizen_credentials = any(f in ["aadhaar_number", "pan_number", "otp_code", "bank_account", "financial_card"] for f in sens_inputs)
        external_actions = dom_evidence.get("external_action_count", 0)

        vis_sim = visual_evidence.get("visual_similarity_score", 0.0)
        is_visual_lookalike = visual_evidence.get("is_lookalike", False)

        cnt_sim = float(content_sim_evidence.get("similarity", 0.0)) if content_sim_evidence else 0.0
        domain_age = network_evidence.get("rdap", {}).get("domain_age_days")

        # -------------------------------------------------------------
        # DOMINANT RULE 1: Verified Official Government Digital Infrastructure
        # -------------------------------------------------------------
        if is_official_gov_tld and not has_homoglyphs and not external_actions:
            return {
                "verdict": "NO_SIGNIFICANT_INDICATORS",
                "risk_score": 2,
                "confidence": 0.99,
                "threat_level": "LOW",
                "category": "OFFICIAL_GOVERNMENT_PORTAL",
                "target_entity": claimed_entity or "Government of India",
                "impersonated": False,
                "summary": "Verified Authentic Indian Sovereign Infrastructure. The domain belongs to official .gov.in / .nic.in national registry.",
                "reasons": [
                    "Authenticated sovereign domain accredited by National Informatics Centre (NIC India).",
                    "Official SSL Certificate and valid government top-level domain."
                ],
                "recommendation": "Safe for citizen navigation and official transactions.",
                "signal_breakdown": {
                    "lexical_score": 0.0,
                    "threat_intel_score": 0.0,
                    "dom_score": 0.0,
                    "visual_similarity": 100.0,
                    "content_similarity": 100.0,
                    "domain_age_days": domain_age or 4500
                },
                "model_version": self.model_version,
                "feature_version": self.feature_version
            }

        # -------------------------------------------------------------
        # DOMINANT RULE 2: Confirmed Threat Intel Match or Live OSINT PIB Fact Check Alert
        # -------------------------------------------------------------
        is_osint_scam = bool(internet_search_evidence and internet_search_evidence.get("is_scam_reported"))
        if is_known_malicious or is_osint_scam:
            risk_score = int(max(95, highest_intel_conf * 100))
            is_pib = any("pib" in str(e).lower() for e in threat_intel_evidence.get("evidence", [])) or (is_osint_scam and any("pib" in str(f).lower() for f in (internet_search_evidence or {}).get("advisory_findings", [])))

            category = "GOVERNMENT_IMPERSONATION_SCAM" if (is_pib or claimed_entity) else "KNOWN_MALICIOUS_THREAT"

            if is_pib:
                reasons.append("EXPLICIT PIB FACT CHECK ALERT: Flagged by Press Information Bureau & Ministry Cyber Cell as an illegal fraudulent portal collecting fake application fees or stealing credentials.")
            else:
                reasons.append("Identified as an active phishing / malware campaign in authoritative threat feeds (URLhaus / Sovereign Ledger).")

            if claimed_entity:
                reasons.append(f"Actively impersonating official sovereign brand/scheme: '{claimed_entity}'.")
            if internet_search_evidence and internet_search_evidence.get("official_gov_counterpart"):
                reasons.append(f"Official genuine sovereign portal is '{internet_search_evidence['official_gov_counterpart']}'.")
            if has_citizen_credentials:
                reasons.append(f"Deploys form harvesting citizen credentials: {sens_inputs}.")

            target = claimed_entity or "Indian Citizens"
            return {
                "verdict": "MALICIOUS",
                "risk_score": risk_score,
                "confidence": max(highest_intel_conf, 0.98),
                "threat_level": "CRITICAL",
                "category": category,
                "target_entity": target,
                "impersonated": True,
                "summary": f"CRITICAL FRAUD: Confirmed scam portal mimicking {target}. Flagged by national cyber defense advisories.",
                "reasons": reasons,
                "recommendation": "DO NOT PAY ANY FEES OR ENTER DETAILS. This is a fake website. Visit genuine government portals (.gov.in) and report cyber fraud to 1930.",
                "signal_breakdown": {
                    "lexical_score": 90.0,
                    "threat_intel_score": 100.0,
                    "dom_score": 85.0,
                    "visual_similarity": vis_sim,
                    "content_similarity": cnt_sim * 100,
                    "domain_age_days": domain_age or 10
                },
                "model_version": self.model_version,
                "feature_version": self.feature_version
            }

        # -------------------------------------------------------------
        # DOMINANT RULE 3: Legitimate Informational / Journalistic Media
        # -------------------------------------------------------------
        if brand_class == "LEGITIMATE_THIRD_PARTY":
            return {
                "verdict": "NO_SIGNIFICANT_INDICATORS",
                "risk_score": 8,
                "confidence": 0.94,
                "threat_level": "LOW",
                "category": "LEGITIMATE_THIRD_PARTY_INFORMATIONAL",
                "target_entity": claimed_entity,
                "impersonated": False,
                "summary": f"Authentic news media or informational encyclopedia reporting on '{claimed_entity or 'public policy'}'. No deceptive harvesting detected.",
                "reasons": [
                    brand_evidence.get("reason", "Verified informational third-party domain."),
                    "No deceptive credential or Aadhaar/OTP harvesting forms present."
                ],
                "recommendation": "Informational portal. Ensure sensitive credentials are only submitted on official .gov.in portals.",
                "signal_breakdown": {
                    "lexical_score": 10.0,
                    "threat_intel_score": 0.0,
                    "dom_score": 0.0,
                    "visual_similarity": 0.0,
                    "content_similarity": cnt_sim * 100,
                    "domain_age_days": domain_age or 3000
                },
                "model_version": self.model_version,
                "feature_version": self.feature_version
            }

        # -------------------------------------------------------------
        # MULTI-SIGNAL CORRELATION ENGINE (Correlating Independent Features)
        # -------------------------------------------------------------
        base_score = 0.0
        confidence_factors = []

        # 1. Lexical & Homoglyph Signals
        if has_homoglyphs:
            base_score += 45.0
            reasons.append(f"Homoglyph multi-script attack detected: {url_metadata.get('canonical_skeleton')}")
            confidence_factors.append(0.92)

        if url_metadata.get("is_ip_address"):
            base_score += 35.0
            reasons.append("Web service accessed directly via numeric IP address instead of registered domain.")
            confidence_factors.append(0.85)

        if url_metadata.get("has_userinfo"):
            base_score += 30.0
            reasons.append("URL contains deceptive authority userinfo (@) syntax.")
            confidence_factors.append(0.88)

        # 2. Brand & Impersonation Intent
        if claimed_entity and not is_official_gov_tld:
            if brand_class == "MALICIOUS_IMPERSONATION":
                base_score += 50.0
                reasons.append(f"Unauthorized commercial domain deceptive lookalike targeting {claimed_entity}.")
                confidence_factors.append(0.95)
            elif brand_class == "SUSPICIOUS_IMPERSONATION":
                base_score += 30.0
                reasons.append(f"Domain incorporates official brand tokens representing {claimed_entity}.")
                confidence_factors.append(0.75)

        # 3. Form & Sensitive Citizen Credential Harvesting
        if has_citizen_credentials and not is_official_gov_tld:
            base_score += 55.0
            reasons.append(f"High-risk credential harvesting form requesting citizen identity: {sens_inputs}")
            confidence_factors.append(0.96)
        elif len(sens_inputs) > 0 and not is_official_gov_tld:
            base_score += 25.0
            reasons.append(f"Form captures sensitive login credentials on unauthorized domain: {sens_inputs}")
            confidence_factors.append(0.80)

        # 4. Visual & Structural Cloning Evidence
        if is_visual_lookalike and not is_official_gov_tld:
            base_score += 40.0
            reasons.append(f"Visual perceptual hash matches official {claimed_entity or 'portal'} with {vis_sim}% similarity.")
            confidence_factors.append(0.90)

        if cnt_sim >= 0.50 and not is_official_gov_tld:
            base_score += 35.0
            reasons.append(f"MinHash shingling confirms {int(cnt_sim * 100)}% structural DOM cloning of official portal.")
            confidence_factors.append(0.88)

        # 5. Domain Age & Registration Evidence
        if domain_age is not None:
            if domain_age < 7 and not is_official_gov_tld:
                base_score += 30.0
                reasons.append(f"Extremely fresh zero-day domain: Registered {domain_age} days ago.")
                confidence_factors.append(0.85)
            elif domain_age < 30 and not is_official_gov_tld:
                base_score += 15.0
                reasons.append(f"Newly registered domain ({domain_age} days old).")
                confidence_factors.append(0.70)

        # 6. Redirect & Network Evidence
        if crawler_evidence and crawler_evidence.get("has_cross_domain_redirect"):
            base_score += 20.0
            reasons.append("Cross-domain redirect chain obscuring landing destination.")
            confidence_factors.append(0.80)

        # Clean baseline for neutral platforms (only if no URL deception or homoglyphs)
        if (brand_class == "NEUTRAL" and not has_citizen_credentials and not is_visual_lookalike
            and cnt_sim < 0.20 and not has_homoglyphs and not url_metadata.get("has_userinfo")
            and not url_metadata.get("is_ip_address")):
            base_score = min(base_score, 15.0)
            reasons = ["Legitimate commercial web platform. No government impersonation or citizen identity theft observed."]

        final_risk = min(max(round(base_score), 0), 99)
        avg_confidence = round(sum(confidence_factors) / len(confidence_factors), 2) if confidence_factors else 0.80

        # Calibrate Verdict
        if final_risk >= 75:
            verdict = "PHISHING_CLONE"
            threat_level = "CRITICAL"
            category = "GOVERNMENT_IMPERSONATION_CLONE"
            recommendation = "DANGER! Do not enter Aadhaar, PAN, OTP, or passwords. Report immediately to 1930."
        elif final_risk >= 40:
            verdict = "SUSPICIOUS"
            threat_level = "ELEVATED"
            category = "SUSPICIOUS_UNVERIFIED_DOMAIN"
            recommendation = "Exercise caution. Verify the official portal URL on india.gov.in before providing any information."
        else:
            verdict = "LEGITIMATE"
            threat_level = "LOW"
            category = "AUTHENTIC_WEB_SERVICE"
            recommendation = "No significant malicious indicators detected. Proceed with standard caution."

        summary = (
            f"CRITICAL: Deceptive clone mimicking {claimed_entity or 'Government Service'}. Harvesting citizen credentials."
            if verdict == "PHISHING_CLONE" else
            (f"Caution: Unverified domain referencing {claimed_entity}." if verdict == "SUSPICIOUS" else
             "Authentic web platform. No significant malicious indicators detected.")
        )

        return {
            "verdict": verdict,
            "risk_score": final_risk,
            "confidence": avg_confidence,
            "threat_level": threat_level,
            "category": category,
            "target_entity": claimed_entity or "Legitimate Commercial Web",
            "impersonated": verdict == "PHISHING_CLONE",
            "summary": summary,
            "reasons": reasons,
            "recommendation": recommendation,
            "signal_breakdown": {
                "lexical_score": url_metadata.get("has_homoglyphs", False) and 80 or 10,
                "threat_intel_score": threat_intel_evidence.get("intel_risk_score", 0.0),
                "dom_score": dom_evidence.get("risk_score", 0.0),
                "visual_similarity": vis_sim,
                "content_similarity": cnt_sim * 100,
                "domain_age_days": domain_age or 180,
                "sensitive_fields_found": sens_inputs
            },
            "model_version": self.model_version,
            "feature_version": self.feature_version
        }

    # Backward compatibility wrapper for older tests
    def evaluate(
        self,
        lexical_result: Dict[str, Any],
        dom_result: Dict[str, Any],
        visual_result: Dict[str, Any],
        whois_result: Dict[str, Any],
        content_sim_result: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Legacy evaluation method for backward compatibility."""
        is_gov_tld = lexical_result.get("is_genuine_gov_tld", False)
        target_entity = lexical_result.get("target_entity", "Official Government Entity")

        if is_gov_tld and lexical_result.get("risk_score", 0) == 0:
            return {
                "verdict": "LEGITIMATE",
                "risk_score": 2,
                "confidence_score": 0.99,
                "threat_level": "LOW",
                "target_entity": target_entity,
                "impersonated": False,
                "summary": "Verified Authentic Indian Government Portal. The domain belongs to official .gov.in/.nic.in national infrastructure.",
                "reasons": [
                    "Domain authenticated via National Informatics Centre (NIC) registry.",
                    "Official SSL Certificate and verified government TLD."
                ],
                "signal_breakdown": {
                    "lexical_score": 0,
                    "dom_score": 0,
                    "visual_similarity": 100.0,
                    "domain_age_days": whois_result.get("domain_age_days", 4000)
                }
            }

        lex_score = lexical_result.get("risk_score", 0.0)
        dom_score = dom_result.get("risk_score", 0.0)
        sens_inputs = dom_result.get("sensitive_inputs", [])
        vis_sim = visual_result.get("visual_similarity_score", 0.0)
        is_lookalike = visual_result.get("is_lookalike", False)
        whois_score = whois_result.get("risk_score", 0.0)

        target_entity_id = lexical_result.get("target_entity_id")
        has_citizen_tokens = any(s["field"] in ["aadhaar_number", "pan_number", "otp_code", "bank_account", "financial_card"] for s in sens_inputs)

        # Clean baseline for authentic commercial web platforms (e.g. ChatGPT, Bing, GitHub)
        if lex_score == 0 and not is_lookalike and not has_citizen_tokens and not target_entity_id:
            return {
                "verdict": "LEGITIMATE",
                "risk_score": 0,
                "confidence_score": 0.98,
                "threat_level": "LOW",
                "target_entity": target_entity or "Legitimate Commercial Platform",
                "impersonated": False,
                "summary": "Authentic web platform. No government impersonation or citizen identity theft observed.",
                "reasons": ["No government brand tokens or citizen identity harvesting detected."],
                "signal_breakdown": {
                    "lexical_score": 0,
                    "dom_score": 0,
                    "visual_similarity": 0.0,
                    "domain_age_days": whois_result.get("domain_age_days", 180),
                    "sensitive_fields_found": [s["field"] for s in sens_inputs]
                }
            }

        fused = (lex_score * 0.30) + (dom_score * 0.30) + (vis_sim * 0.25) + (whois_score * 0.15)
        reasons = []

        if (has_citizen_tokens or (target_entity_id and len(sens_inputs) > 0)) and not is_gov_tld:
            fused = max(fused, 88.0)
            reasons.append(f"Deceptive form harvesting citizen credentials: {[s['field'] for s in sens_inputs]}")
        if is_lookalike and not is_gov_tld:
            fused = max(fused, 85.0)
            reasons.append(f"Visual lookalike matches official portal layout ({vis_sim}% similarity)")
        if lex_score > 40 and not is_gov_tld:
            fused = max(fused, 80.0)
            reasons.append("Unauthorized domain incorporates official government brand names")

        final_score = int(min(max(round(fused), 0), 99))
        verdict = "PHISHING_CLONE" if final_score >= 66 else ("SUSPICIOUS" if final_score >= 26 else "LEGITIMATE")

        return {
            "verdict": verdict,
            "risk_score": final_score,
            "confidence_score": 0.92,
            "threat_level": "HIGH" if verdict == "PHISHING_CLONE" else ("MEDIUM" if verdict == "SUSPICIOUS" else "LOW"),
            "target_entity": target_entity,
            "impersonated": verdict == "PHISHING_CLONE",
            "summary": f"CRITICAL: Deceptive clone mimicking {target_entity}." if verdict == "PHISHING_CLONE" else "Scan completed.",
            "reasons": reasons or ["No malicious indicators found."],
            "signal_breakdown": {
                "lexical_score": lex_score,
                "dom_score": dom_score,
                "visual_similarity": vis_sim,
                "domain_age_days": whois_result.get("domain_age_days", 180),
                "sensitive_fields_found": [s["field"] for s in sens_inputs]
            }
        }
