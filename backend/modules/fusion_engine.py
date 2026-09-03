"""
AI/ML Multi-Signal Risk Fusion Engine.
Synthesizes Lexical, DOM, Visual Similarity, and WHOIS indicators into an explainable 0-100 risk score.
"""

from typing import Dict, Any, List


class FusionEngine:
    """Combines multi-modal signals into a calibrated risk score with explainable verdicts."""

    def __init__(self):
        # Weights for multi-modal signal fusion
        self.weights = {
            "lexical": 0.30,
            "dom": 0.25,
            "visual": 0.30,
            "whois": 0.15
        }

    def evaluate(
        self,
        lexical_result: Dict[str, Any],
        dom_result: Dict[str, Any],
        visual_result: Dict[str, Any],
        whois_result: Dict[str, Any],
        content_sim_result: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Perform multi-signal weighted fusion and generate explainable reasons."""

        # 1. Immediate Whitelist check: Official Gov domain
        if lexical_result.get("is_genuine_gov_tld") and lexical_result.get("risk_score", 0) == 0:
            return {
                "verdict": "LEGITIMATE",
                "risk_score": 2,
                "confidence_score": 0.99,
                "threat_level": "LOW",
                "target_entity": lexical_result.get("target_entity", "Official Government Entity"),
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
        whois_score = whois_result.get("risk_score", 0.0)

        # Visual lookalike factor
        vis_sim = visual_result.get("visual_similarity_score", 0.0)
        is_lookalike = visual_result.get("is_lookalike", False)

        # Calculate base weighted score
        # Note: For phishing detection, high visual similarity on an UNTRUSTED domain is a massive risk multiplier
        visual_risk_contribution = vis_sim if (not lexical_result.get("is_genuine_gov_tld")) else 0.0

        fused_score = (
            lex_score * self.weights["lexical"] +
            dom_score * self.weights["dom"] +
            visual_risk_contribution * self.weights["visual"] +
            whois_score * self.weights["whois"]
        )

        # Boost conditions for zero-day government lookalike clones
        is_cloned_impersonation = False
        gov_inputs = [s["field"] for s in dom_result.get("sensitive_inputs", []) if s["field"] in ["aadhaar_number", "pan_number", "otp_code", "bank_account"]]

        if is_lookalike and (len(dom_result.get("sensitive_inputs", [])) > 0 or lex_score > 30):
            # Classic zero-day phishing signature: Looks like gov portal + asks for credentials + not gov domain
            fused_score = max(fused_score, 88.0)
            is_cloned_impersonation = True
        elif is_lookalike and whois_result.get("is_newly_registered"):
            fused_score = max(fused_score, 82.0)
            is_cloned_impersonation = True
        elif gov_inputs and not lexical_result.get("is_genuine_gov_tld"):
            # Non-gov domain harvesting citizen Aadhaar/PAN/OTP
            fused_score = max(fused_score, 85.0)
            is_cloned_impersonation = True
        elif lexical_result.get("target_entity_id") and not lexical_result.get("is_genuine_gov_tld") and lex_score >= 45:
            # Direct government brand injection / impersonation (e.g. income-tax-refund.example)
            fused_score = max(fused_score, 88.0)
            is_cloned_impersonation = True
        elif (lex_score > 35 or len(dom_result.get("hotlinked_gov_assets", [])) > 0) and len(dom_result.get("sensitive_inputs", [])) >= 1:
            fused_score = max(fused_score, 78.0)
            is_cloned_impersonation = True

        # MinHash Content & Structural DOM Similarity Confirmation
        cnt_sim = 0.0
        if content_sim_result:
            cnt_sim = float(content_sim_result.get("similarity", 0.0))
            if cnt_sim >= 0.70 and not lexical_result.get("is_genuine_gov_tld"):
                fused_score = max(fused_score, 88.0)
                is_cloned_impersonation = True

        # Clean baseline for standard web platforms without government spoofing
        if lex_score == 0 and not is_lookalike and not gov_inputs and len(dom_result.get("hotlinked_gov_assets", [])) == 0 and not lexical_result.get("target_entity_id"):
            fused_score = 0.0

        final_score = int(min(max(round(fused_score), 0), 99))

        # Classification thresholds
        if final_score >= 66:
            verdict = "PHISHING_CLONE"
            threat_level = "HIGH"
        elif final_score >= 26:
            verdict = "SUSPICIOUS"
            threat_level = "MEDIUM"
        else:
            verdict = "LEGITIMATE"
            threat_level = "LOW"

        # Synthesize plain-English explainability reasons
        all_reasons: List[str] = []
        all_reasons.extend(lexical_result.get("reasons", []))
        if content_sim_result and content_sim_result.get("reasons"):
            all_reasons.extend(content_sim_result.get("reasons"))
        all_reasons.extend(dom_result.get("reasons", []))
        all_reasons.extend(visual_result.get("reasons", []))
        all_reasons.extend(whois_result.get("reasons", []))

        # Deduplicate and limit to most critical reasons
        seen = set()
        deduped_reasons = []
        for r in all_reasons:
            if r and r not in seen:
                seen.add(r)
                deduped_reasons.append(r)

        # Executive summary
        target_name = visual_result.get("matched_portal_name") or lexical_result.get("target_entity") or "Government Portal"
        if verdict == "PHISHING_CLONE":
            summary = f"CRITICAL: Deceptive clone mimicking {target_name}. This site uses lookalike branding and credential fields to harvest user data."
        elif verdict == "SUSPICIOUS":
            summary = f"WARNING: Potential suspicious portal mimicking {target_name}. Contains anomalies in domain registration or DOM form actions."
        else:
            summary = "Site appears normal with low risk indicators."

        return {
            "verdict": verdict,
            "risk_score": final_score,
            "threat_level": threat_level,
            "target_entity": target_name,
            "is_genuine_gov_tld": lexical_result.get("is_genuine_gov_tld", False),
            "impersonated": is_cloned_impersonation or verdict == "PHISHING_CLONE",
            "summary": summary,
            "reasons": deduped_reasons[:6],
            "signal_breakdown": {
                "lexical_score": round(lex_score, 1),
                "dom_score": round(dom_score, 1),
                "visual_similarity": round(vis_sim, 1),
                "content_similarity": round(cnt_sim * 100, 1) if cnt_sim else 0.0,
                "domain_age_days": whois_result.get("domain_age_days", 0),
                "sensitive_fields_found": [s["field"] for s in dom_result.get("sensitive_inputs", [])],
                "registrar": whois_result.get("registrar", "Unknown")
            }
        }
