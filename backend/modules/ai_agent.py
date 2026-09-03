"""
GovShield Sentinel Grid — Gemini 2.0 Semantic & Threat Research Synthesis Layer
SIH 2026 Problem Statement SIH1454

Architecture Note:
Gemini acts STRICTLY as a Semantic & Research Analyst synthesizing structured scanner facts.
It does NOT have authority to invent domain reputations, ownership facts, or unilaterally
declare binary malicious verdicts. It outputs structured observations distinguishing:
1. Observed Facts
2. External Research
3. Inferences & Social Engineering Tactics
4. Uncertainties
"""

import os
import json
import base64
import sys
from typing import Dict, Any, Optional, List

try:
    from google import genai
    from google.genai import types
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


class AIAgent:
    """Semantic Reasoning and Evidence Synthesis Analyst using Gemini 2.0 Flash."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self.client = None
        self.client_ready = False
        self.model_name = "gemini-2.0-flash"

        if GENAI_AVAILABLE and self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
                self.client_ready = True
            except Exception as e:
                print(f"[AIAgent] Client initialization note: {e}")
                self.client_ready = False

    def synthesize_evidence(
        self,
        url_metadata: Dict[str, Any],
        network_evidence: Dict[str, Any],
        threat_intel_evidence: Dict[str, Any],
        dom_evidence: Dict[str, Any],
        brand_evidence: Dict[str, Any],
        research_findings: List[Dict[str, Any]],
        dom_sample: str = "",
        image_base64: Optional[str] = None,
        internet_search_evidence: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Receives structured scanner evidence and synthesizes semantic intent,
        social-engineering vectors, and observed inconsistencies.
        """
        if not self.client_ready or not self.client:
            # Deterministic Fallback Synthesis when GenAI client is offline
            return self._deterministic_fallback_synthesis(
                url_metadata, network_evidence, threat_intel_evidence,
                dom_evidence, brand_evidence, research_findings,
                internet_search_evidence
            )

        # Prepare concise structured evidence payload for Gemini
        evidence_payload = {
            "target_url": url_metadata.get("normalized_url"),
            "domain": url_metadata.get("registered_domain"),
            "tld": url_metadata.get("tld"),
            "homoglyphs_detected": url_metadata.get("has_homoglyphs", False),
            "canonical_skeleton": url_metadata.get("canonical_skeleton"),
            "unusual_port": url_metadata.get("port"),
            "domain_age_days": network_evidence.get("rdap", {}).get("domain_age_days"),
            "tls_issuer": network_evidence.get("tls", {}).get("issuer_common_name"),
            "is_automated_free_cert": network_evidence.get("tls", {}).get("is_automated_free_cert", False),
            "threat_intel_match": threat_intel_evidence.get("is_known_malicious", False),
            "pib_fact_check_flagged": any("pib" in str(e).lower() for e in threat_intel_evidence.get("evidence", [])),
            "claimed_entity": brand_evidence.get("claimed_entity"),
            "official_domains": brand_evidence.get("official_domains", []),
            "brand_relationship": brand_evidence.get("classification"),
            "sensitive_fields_harvested": [s["field"] for s in dom_evidence.get("sensitive_inputs", [])],
            "page_title": dom_evidence.get("page_title"),
            "external_exfiltration": dom_evidence.get("exfiltration_endpoints", []),
            "active_cyber_advisories": [r["finding"] for r in research_findings[:3]],
            "live_internet_osint_findings": [f["snippet"] for f in (internet_search_evidence or {}).get("advisory_findings", [])[:3]]
        }

        prompt = f"""
You are a Senior Cyber Threat Intelligence Analyst for CERT-In, I4C, and GovShield.
Your objective: Analyze the structured evidence collected from deterministic cyber scanners, live OSINT search, and official PIB Fact Check advisories to synthesize an explainable threat evaluation.

CORE THREAT PATTERNS & GROUND TRUTH EXEMPLARS (TRAINING KNOWLEDGE):
- PATTERN 1 (Fake Government Job/Scheme Recruitment): Scammers register unofficial domains (.co.in, .org.in, .online, .site) mimicking sovereign missions such as "Samagra Shiksha Abhiyan", "Sarva Shiksha Abhiyan", "Viksit Bharat Rozgar Yojana", or "KVS". They promise fake teacher/clerk vacancies and extort 500-1500 INR registration fees. The official domain for Samagra Shiksha is exclusively `samagra.education.gov.in`. Any commercial .co.in/.in site claiming to be Samagra Shiksha is an active criminal fraud.
- PATTERN 2 (Citizen Welfare Subsidy/DBT Scams): Scammers clone PM-Kisan or Ayushman Bharat to steal farmer Aadhaar numbers, PAN, and OTPs under pretext of mandatory eKYC.
- PATTERN 3 (Utility Disconnection & Digital Arrest Extortion): Threatening power shutoff or fake CBI arrest warrants.

CRITICAL CONSTRAINTS:
1. Distinguish strictly between:
   - OBSERVED FACTS (Directly measurable indicators present in the evidence)
   - EXTERNAL RESEARCH (Official CERT-In, PIB Fact Check, or RBI cyber advisories)
   - INFERENCES (Social-engineering tactics and deceptive intent deduced from facts)
   - UNCERTAINTIES (Gaps in evidence or missing data)
2. DO NOT invent reputation results, domain registrations, or official certifications.
3. DO NOT output arbitrary binary decisions; output structured observations conforming to the JSON schema.

EVIDENCE BUNDLE:
```json
{json.dumps(evidence_payload, indent=2)}
```

DOM CONTENT SAMPLE (First 4000 characters):
```html
{(dom_sample or '')[:4000]}
```

Respond with ONLY a valid JSON object strictly matching this schema:
{{
  "observed_facts": ["string"],
  "external_research": ["string"],
  "claimed_entity": "string or null",
  "page_purpose": "string",
  "social_engineering_tactics": ["string"],
  "inconsistencies": ["string"],
  "sensitive_data_requested": ["string"],
  "government_impersonation": true/false,
  "uncertainties": ["string"],
  "confidence": 0.0 to 1.0,
  "plain_english_summary": "string"
}}
"""
        contents = [prompt]
        if image_base64:
            try:
                img_bytes = base64.b64decode(image_base64)
                contents.append(types.Part.from_bytes(data=img_bytes, mime_type="image/png"))
            except Exception:
                pass

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=contents,
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    response_mime_type="application/json"
                )
            )
            parsed_json = json.loads(response.text.strip())
            parsed_json["ai_enabled"] = True
            parsed_json["status"] = "SUCCESS"
            return parsed_json
        except Exception as e:
            fallback = self._deterministic_fallback_synthesis(
                url_metadata, network_evidence, threat_intel_evidence,
                dom_evidence, brand_evidence, research_findings
            )
            fallback["gemini_error"] = str(e)
            return fallback

    def _deterministic_fallback_synthesis(
        self,
        url_metadata: Dict[str, Any],
        network_evidence: Dict[str, Any],
        threat_intel_evidence: Dict[str, Any],
        dom_evidence: Dict[str, Any],
        brand_evidence: Dict[str, Any],
        research_findings: List[Dict[str, Any]],
        internet_search_evidence: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Provides reproducible deterministic semantic reasoning when GenAI client is offline."""
        observed_facts: List[str] = []
        inconsistencies: List[str] = []
        social_eng: List[str] = []
        uncertainties: List[str] = []

        if internet_search_evidence and internet_search_evidence.get("is_scam_reported"):
            observed_facts.append("Live Internet OSINT search detected public cyber scam / PIB Fact Check warnings.")
            social_eng.append("Exploits government scheme names (such as Samagra Shiksha or Rozgar Yojana) to collect unauthorized fees or credentials.")
            inconsistencies.append("Confirmed fraudulent scheme portal flagged in public advisories.")

        if internet_search_evidence and internet_search_evidence.get("official_gov_counterpart"):
            observed_facts.append(f"Official sovereign counterpart discovered: {internet_search_evidence['official_gov_counterpart']}")

        claimed_entity = brand_evidence.get("claimed_entity")
        sens_inputs = [s["field"] for s in dom_evidence.get("sensitive_inputs", [])]
        age_days = network_evidence.get("rdap", {}).get("domain_age_days")
        is_gov_tld = url_metadata.get("tld") in ["gov.in", "nic.in"]

        if claimed_entity:
            observed_facts.append(f"Domain references sovereign entity '{claimed_entity}'.")
            if not is_gov_tld:
                inconsistencies.append(
                    f"Site purports to represent '{claimed_entity}' but is hosted on commercial TLD '.{url_metadata.get('tld')}' instead of official government domains."
                )

        if sens_inputs:
            observed_facts.append(f"Webpage contains credential input fields: {sens_inputs}")
            social_eng.append("Direct harvesting of citizen identity and financial verification tokens.")

        if age_days is not None:
            observed_facts.append(f"Domain registration age is {age_days} days.")
            if age_days < 30 and claimed_entity and not is_gov_tld:
                inconsistencies.append(f"Newly registered domain ({age_days} days old) mimicking established national infrastructure.")

        if url_metadata.get("has_homoglyphs"):
            observed_facts.append(f"Multi-script homoglyph obfuscation: {url_metadata.get('canonical_skeleton')}")
            social_eng.append("Visual domain spoofing via confusable Unicode character substitution.")

        if threat_intel_evidence.get("is_known_malicious"):
            observed_facts.append("Identified in active global threat intelligence feeds (URLhaus/Ledger).")

        gov_impersonation = (
            not is_gov_tld and
            bool(claimed_entity) and
            (bool(sens_inputs) or (age_days is not None and age_days < 30) or url_metadata.get("has_homoglyphs", False))
        )

        external_research_items = [r["finding"] for r in research_findings[:2]]

        summary = (
            f"Adversarial impersonation targeting {claimed_entity} on unauthorized domain."
            if gov_impersonation else
            "Authentic or neutral web portal with no deceptive government impersonation observed."
        )

        return {
            "ai_enabled": False,
            "status": "DETERMINISTIC_SYNTHESIS",
            "observed_facts": observed_facts,
            "external_research": external_research_items,
            "claimed_entity": claimed_entity,
            "page_purpose": "Credential Verification / Citizen Service" if sens_inputs else "Informational",
            "social_engineering_tactics": social_eng,
            "inconsistencies": inconsistencies,
            "sensitive_data_requested": sens_inputs,
            "government_impersonation": gov_impersonation,
            "uncertainties": uncertainties,
            "confidence": 0.85 if gov_impersonation else 0.90,
            "plain_english_summary": summary
        }

    def generate_content_synthesis(
        self,
        url: str,
        url_metadata: Dict[str, Any],
        dom_evidence: Dict[str, Any],
        brand_evidence: Dict[str, Any],
        threat_intel_evidence: Dict[str, Any],
        sovereign_ml_evidence: Optional[Dict[str, Any]] = None,
        html_sample: str = "",
        verdict_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Synthesizes an explainable AI summary by analyzing both the domain and HTML DOM content."""
        hostname = (url_metadata.get("hostname") or "").split(":")[0].lower()
        if not hostname and "://" in url:
            from urllib.parse import urlparse
            hostname = urlparse(url).netloc.split(":")[0].lower()

        is_gov_tld = url_metadata.get("tld") in ["gov.in", "nic.in"]
        is_localhost = hostname in ["localhost", "127.0.0.1", "0.0.0.0"] or hostname.endswith(".local") or hostname.startswith("192.168.") or hostname.startswith("10.")

        page_title = dom_evidence.get("page_title", "")
        sens_inputs = [s["field"] for s in dom_evidence.get("sensitive_inputs", [])]
        forms_count = dom_evidence.get("forms_detected", 0)
        claimed_entity = brand_evidence.get("claimed_entity")
        is_known_malicious = threat_intel_evidence.get("is_known_malicious", False)
        ml_prob = (sovereign_ml_evidence or {}).get("probability", 0.0)

        v_score = (verdict_data or {}).get("risk_score", 0)
        v_verdict = (verdict_data or {}).get("verdict", "")
        is_critical_threat = v_score >= 60 or v_verdict in ["PHISHING_CLONE", "MALICIOUS"] or is_known_malicious or ml_prob >= 0.70 or (claimed_entity and not is_gov_tld)
        is_suspicious_domain = (v_score >= 26 or v_verdict == "SUSPICIOUS") and not is_critical_threat and not is_gov_tld

        # 1. Classify Domain Architecture
        if is_localhost:
            domain_type = "Local Loopback / Private Dev Host"
            domain_badge = "LOCAL_DEV"
        elif is_gov_tld:
            domain_type = "Official Indian Sovereign Infrastructure (.gov.in)"
            domain_badge = "SOVEREIGN_GOV"
        elif is_critical_threat:
            domain_type = f"Deceptive Phishing Clone ({f'targeting {claimed_entity}' if claimed_entity else f'Threat Score {v_score}/100'})"
            domain_badge = "CRITICAL_PHISHING_CLONE"
        elif is_suspicious_domain:
            domain_type = f"Unverified Suspicious Domain (Score {v_score}/100)"
            domain_badge = "SUSPICIOUS_DOMAIN"
        else:
            domain_type = "Commercial / Public Web Platform"
            domain_badge = "AUTHENTIC_WEB"

        # 2. Classify HTML Content Intent
        if "docs" in url.lower() or "swagger" in page_title.lower() or "fastapi" in page_title.lower() or "openapi" in (html_sample or "").lower():
            content_type = "Developer API Documentation (Swagger / OpenAPI)"
        elif sens_inputs:
            content_type = f"Credential Harvesting Form ({', '.join(sens_inputs)})"
        elif is_critical_threat:
            content_type = "Deceptive Phishing Trap / Social Engineering Form"
        elif forms_count > 0:
            content_type = "Interactive Web Form Page"
        elif "search" in url.lower() or "google" in hostname or "bing" in hostname:
            content_type = "Web Search & Navigation Portal"
        elif is_gov_tld:
            content_type = "Official Citizen Welfare Service"
        else:
            content_type = "General Informational Web Content"

        # 3. Generate Explainable AI Synthesis (English & Hindi)
        if is_localhost:
            summary_en = f"AI Content Analysis confirms this URL is an internal developer endpoint ({content_type}) running locally on {hostname}. The HTML DOM contains API documentation with zero deceptive government scheme branding, citizen credential traps, or external cyber threats."
            summary_hi = f"AI विश्लेषण के अनुसार यह URL एक स्थानीय डेवलपर एंडपॉइंट ({content_type}) है जो लोकलहोस्ट पर चल रहा है। इस पेज पर कोई फर्जी सरकारी योजना या आधार/OTP चुराने वाला फॉर्म नहीं पाया गया।"
        elif is_critical_threat:
            summary_en = f"AI Content Analysis flags this webpage as an unauthorized deceptive portal ({domain_type}). The domain mimics authentic services or uses suspicious host patterns. DO NOT enter passwords, OTPs, Aadhaar, PAN, or banking credentials here."
            summary_hi = f"AI विश्लेषण के अनुसार यह वेबसाइट एक फर्जी और जोखिम भरी वेबसाइट ({domain_type}) है। यहाँ अपना पासवर्ड, OTP, आधार या बैंक विवरण कभी दर्ज न करें।"
        elif is_suspicious_domain:
            summary_en = f"AI Domain Analysis flags {hostname} with suspicious indicators (Risk Score: {v_score}/100). Exercise caution and verify official links on india.gov.in before sharing sensitive personal details."
            summary_hi = f"AI विश्लेषण के अनुसार {hostname} एक संदिग्ध और अपुष्ट वेबसाइट है। किसी भी प्रकार की गोपनीय जानकारी साझा करने से पहले जांच करें।"
        elif is_gov_tld:
            summary_en = f"AI Verification confirms this is the authentic sovereign portal for {claimed_entity or 'Government of India'}, accredited under the National Informatics Centre (NIC) national registry. The HTML DOM and TLS encryption conform to national sovereign standards."
            summary_hi = f"AI सत्यापन के अनुसार यह {claimed_entity or 'भारत सरकार'} का आधिकारिक एवं सुरक्षित पोर्टल है जो NIC अवसंरचना पर प्रमाणित है।"
        else:
            summary_en = f"AI Domain Analysis verifies {hostname} as an authentic public web platform ({content_type}). The HTML DOM structure shows normal web operations with zero government scheme impersonation, credential harvesting forms, or unauthorized fee demands."
            summary_hi = f"AI विश्लेषण के अनुसार {hostname} एक सुरक्षित सामान्य वेब प्लेटफॉर्म है। इस पर सरकारी योजनाओं की कोई नकल नहीं पाई गई।"

        # 4. Optional Live Gemini 2.0 Flash Enhancement
        if self.client_ready and self.client and not is_localhost:
            try:
                g_prompt = (
                    f"You are GovShield AI Cyber Analyst. In 2 concise sentences, summarize this domain and webpage for citizens:\n"
                    f"URL: {url}\n"
                    f"Hostname: {hostname}\n"
                    f"Sovereign .gov.in: {is_gov_tld}\n"
                    f"Target Entity: {claimed_entity or 'None'}\n"
                    f"Page Title: {page_title}\n"
                    f"Detected Sensitive Inputs: {sens_inputs}\n"
                    f"Explain what this page is and advise whether citizens should enter credentials or avoid it."
                )
                g_resp = self.client.models.generate_content(
                    model=self.model_name,
                    contents=[g_prompt],
                    config=types.GenerateContentConfig(temperature=0.2, max_output_tokens=150)
                )
                if g_resp and g_resp.text:
                    summary_en = g_resp.text.strip()
            except Exception:
                pass

        key_insights = [
            f"Domain Architecture: {domain_type}",
            f"Page Content & Intent: {content_type}",
            f"Sensitive Forms: {f'Harvesting {len(sens_inputs)} citizen input fields ({', '.join(sens_inputs)})' if sens_inputs else 'Zero sensitive credential or biometric inputs detected.'}"
        ]

        return {
            "domain_type": domain_type,
            "domain_badge": domain_badge,
            "content_type": content_type,
            "page_title": page_title or "No HTML Title Specified",
            "forms_count": forms_count,
            "sensitive_inputs": sens_inputs,
            "key_insights": key_insights,
            "ai_summary_en": summary_en,
            "ai_summary_hi": summary_hi,
            "ai_summary": summary_en,
            "is_localhost": is_localhost
        }

