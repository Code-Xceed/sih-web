"""
GovShield Sentinel Grid — Multimodal GenAI Vision & DOM Verification Agent
SIH 2026 Problem Statement SIH1454

Uses the official Google GenAI SDK (`google-genai`) to access the latest
and most powerful multimodal reasoning models (Gemini 2.0 Flash / 1.5 Flash).
"""

import os
import json
import base64
import sys
from typing import Dict, Any, Optional

if sys.platform == 'win32' and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

DEFAULT_API_KEY = ""

try:
    from google import genai
    from google.genai import types
    GENAI_V2_AVAILABLE = True
except ImportError:
    GENAI_V2_AVAILABLE = False


class AIAgent:
    """Multimodal AI Agent for detecting lookalike phishing sites imitating Government portals."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self.client = None
        self.client_ready = False
        self.model_name = "gemini-2.0-flash"
        self.active_model = "gemini-2.0-flash"
        self.models_to_try = ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"]

        if GENAI_V2_AVAILABLE and self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
                self.client_ready = True
            except Exception as e:
                print(f"[AI Agent] Client init note: {e}")
                self.client_ready = False

    def analyze_webpage(
        self,
        url: str,
        html_dom: str = "",
        image_base64: Optional[str] = None,
        candidate_entity: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Runs multimodal evaluation on URL + DOM + Screenshot.
        Returns a structured risk assessment and plain-English explanation.
        """
        if not self.client_ready or not self.client:
            return {
                "ai_enabled": False,
                "status": "AI_OFFLINE_OR_UNAVAILABLE",
                "message": "AI client not active."
            }

        # Truncate DOM sample to keep inference fast (<500ms)
        dom_sample = (html_dom or "")[:8000]

        prompt = f"""
You are the Chief AI Cybersecurity Intelligence Agent for GovShield & CERT-In (National Cyber Defense of India).
Your primary mission: Research, analyze, and detect fraudulent websites that IMITATE or IMPERSONATE Indian Government portals, taxes, and public welfare services (SIH1454).

Candidate Webpage:
- Target URL: {url}
- Reference Candidate: {candidate_entity or "Detect automatically"}
- Extracted DOM Structure (sample):
```html
{dom_sample}
```

DEEP DOMAIN INTELLIGENCE & RESEARCH PROTOCOL:
1. SEMANTIC DECONSTRUCTION OF DOMAIN NAME:
   - Break down the domain into its core tokens (e.g., "gst-refund" -> "gst" + "refund", "pm-kisan-kyc" -> "pm kisan" + "kyc", "e-aadhaar-download" -> "aadhaar" + "download", "challan-pay" -> "challan" + "pay").
   - Identify if ANY token references Indian Public Schemes, Ministries, Taxes, Welfare or Citizen Services:
     * Taxes & Revenue: GST (Goods and Services Tax), Income Tax, ITR, TDS, e-Filing, CBIC, CBDT.
     * Citizen Identity & Civil: Aadhaar, UIDAI, myAadhaar, PAN Card, Passport Seva, Voter ID / NVSP / EPIC, DigiLocker, Ration Card / NFSA.
     * Welfare & DBT Subsidies: PM-Kisan, PM-Awas (PMAY), Ayushman Bharat (PMJAY), e-Shram, LPG Subsidy, Mudra, Kisan Credit.
     * Transport & Law: Parivahan, Vahan, Sarathi, e-Challan, RTO, Fastag, CyberCrime (NCRP/1930), FIR.
     * Labour & Social Security: EPFO, UAN, PF Passbook, ESIC, Jeevan Pramaan, NPS Pension.
     * Education & Exams: CBSE, NTA, NEET, JEE, NSP (National Scholarships), UPSC, SSC.

2. FRAUDULENT GOVERNMENT DECEPTIVE CLONES & LOOKALIKES:
   - If ANY non-governmental domain (e.g., .example, .xyz, .top, .site, .online, .live, .cc, or any commercial TLD) contains government scheme names, acronyms, or combinations with action verbs ("refund", "kyc", "update", "verify", "claim", "download", "apply", "login", "portal", "subsidy", "dbt", "status"):
   - THIS IS AN UNAUTHORIZED ZERO-DAY GOVERNMENT SCHEME IMPERSONATION / PHISHING CLONE!
   - For these malicious lookalikes:
     "is_phishing": true,
     "is_gov_impersonation": true,
     "risk_score": 90 to 98,
     "threat_category": "Zero-Day Government Scheme Phishing Clone",
     "impersonated_portal": "[Exact Name of Impersonated Gov Service, e.g., Goods and Services Tax (GST) Portal / Income Tax e-Filing / PM-Kisan Samman Nidhi]",
     "plain_english_explanation": "Critical zero-day phishing clone. Domain illegally uses official government branding/keywords to deceive citizens."

3. LEGITIMATE COMMERCIAL / TECH PLATFORMS (e.g., ChatGPT / OpenAI, Google, Bing, GitHub, Microsoft, Amazon, YouTube, Wikipedia, LinkedIn, standard SaaS / businesses):
   - These are legitimate authentic services with their own established branding and NO government scheme impersonation.
   - For these authentic commercial platforms:
     "is_phishing": false,
     "is_gov_impersonation": false,
     "risk_score": 0,
     "threat_category": "Legitimate Commercial Platform",
     "impersonated_portal": "None",
     "plain_english_explanation": "Authentic commercial web service. No Indian Government impersonation or citizen identity harvesting detected."

4. OFFICIAL GOVERNMENT PORTALS (.gov.in, .nic.in, verified state portals):
   - "is_phishing": false,
   - "is_gov_impersonation": false,
   - "risk_score": 0,
   - "threat_category": "Official Government Infrastructure",
   - "impersonated_portal": "None",
   - "plain_english_explanation": "Verified official Government of India portal under National Informatics Centre infrastructure."

Return STRICT JSON matching:
{{
    "is_phishing": boolean,
    "is_gov_impersonation": boolean,
    "confidence_score": float (0.0 to 1.0),
    "risk_score": integer (0 to 100),
    "impersonated_portal": string,
    "threat_category": string,
    "visual_clone_similarity_pct": integer (0 to 100),
    "sensitive_harvested_fields": ["list", "of", "fields"],
    "plain_english_explanation": string,
    "certin_mitigation_action": string
}}
"""

        contents = [prompt]

        if image_base64:
            try:
                if ',' in image_base64:
                    image_base64 = image_base64.split(',', 1)[1]
                img_bytes = base64.b64decode(image_base64)
                contents.append(types.Part.from_bytes(data=img_bytes, mime_type="image/png"))
            except Exception as err:
                print(f"[AI Agent] Image decode note: {err}")

        # Attempt inference with model cascade
        for m_name in self.models_to_try:
            try:
                response = self.client.models.generate_content(
                    model=m_name,
                    contents=contents,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.1
                    )
                )
                if response and response.text:
                    raw_text = response.text.strip()
                    if raw_text.startswith("```json"):
                        raw_text = raw_text[7:]
                    elif raw_text.startswith("```"):
                        raw_text = raw_text[3:]
                    if raw_text.endswith("```"):
                        raw_text = raw_text[:-3]
                    raw_text = raw_text.strip()

                    parsed_result = json.loads(raw_text)
                    parsed_result["ai_enabled"] = True
                    parsed_result["model_used"] = m_name
                    parsed_result["status"] = "SUCCESS"
                    self.active_model = m_name
                    self.model_name = m_name
                    return parsed_result
            except Exception as e:
                continue

        return {
            "ai_enabled": True,
            "status": "AI_API_FALLBACK",
            "message": "AI API call deferred to local Multi-Signal Fusion Engine.",
            "fallback_triggered": True
        }
