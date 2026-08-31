"""
DOM Structure and Content Similarity Analyzer.
Extracts form actions, sensitive input types (Aadhaar/PAN/OTP), external hotlinked assets, and keywords.
"""

from typing import Dict, Any, List, Optional
import urllib.parse
from bs4 import BeautifulSoup
from .reference_database import GENUINE_PORTALS, GOVERNMENT_TLDS


class DOMAnalyzer:
    """Analyzes webpage DOM structure, form inputs, external links, and text semantics."""

    def __init__(self):
        self.genuine_portals = GENUINE_PORTALS

    def analyze_html(self, html_content: str, base_url: str, matched_portal_id: Optional[str] = None) -> Dict[str, Any]:
        """Parse raw HTML string and extract forensic features."""
        if not html_content or len(html_content.strip()) == 0:
            return {
                "risk_score": 10.0,
                "forms_detected": 0,
                "sensitive_inputs": [],
                "hotlinked_gov_assets": [],
                "external_action_count": 0,
                "reasons": ["No HTML content provided or unable to fetch live DOM."]
            }

        soup = BeautifulSoup(html_content, 'html.parser')
        parsed_base = urllib.parse.urlparse(base_url)
        current_host = (parsed_base.hostname or "").lower()

        # 1. Page Title & Head
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        meta_desc = ""
        meta_desc_tag = soup.find('meta', attrs={'name': 'description'}) or soup.find('meta', attrs={'property': 'og:description'})
        if meta_desc_tag and meta_desc_tag.get('content'):
            meta_desc = meta_desc_tag['content'].strip()

        # 2. Form & Input Fields Analysis
        forms = soup.find_all('form')
        sensitive_inputs: List[Dict[str, str]] = []
        external_action_count = 0
        insecure_form_count = 0

        for idx, form in enumerate(forms):
            action = form.get('action', '').strip()
            # Check form action destination
            if action:
                action_parsed = urllib.parse.urlparse(action)
                if action_parsed.hostname and action_parsed.hostname.lower() != current_host:
                    external_action_count += 1
                if action.startswith('http://') and base_url.startswith('https://'):
                    insecure_form_count += 1
            elif action in ['#', '', 'about:blank', 'javascript:void(0)']:
                # Common phishing tactic to capture via JS listener
                external_action_count += 1

            # Check input tags
            for inp in form.find_all(['input', 'textarea', 'select']):
                inp_type = (inp.get('type') or 'text').lower()
                inp_name = (inp.get('name') or '').lower()
                inp_id = (inp.get('id') or '').lower()
                inp_placeholder = (inp.get('placeholder') or '').lower()
                combined_ident = f"{inp_name} {inp_id} {inp_placeholder}"

                # Match sensitive keywords
                if inp_type == 'password' or 'password' in combined_ident:
                    sensitive_inputs.append({"field": "password", "type": inp_type, "identifier": inp_name or inp_id})
                elif any(k in combined_ident for k in ['aadhaar', 'uid', 'aadhar', '12-digit']):
                    sensitive_inputs.append({"field": "aadhaar_number", "type": inp_type, "identifier": inp_name or inp_id})
                elif any(k in combined_ident for k in ['pan', 'pan_no', 'pan_card', 'pancard']):
                    sensitive_inputs.append({"field": "pan_number", "type": inp_type, "identifier": inp_name or inp_id})
                elif any(k in combined_ident for k in ['otp', 'one-time-password', 'verification-code']):
                    sensitive_inputs.append({"field": "otp_code", "type": inp_type, "identifier": inp_name or inp_id})
                elif any(k in combined_ident for k in ['cvv', 'card_number', 'credit_card', 'debit_card', 'atm_pin']):
                    sensitive_inputs.append({"field": "financial_card", "type": inp_type, "identifier": inp_name or inp_id})
                elif any(k in combined_ident for k in ['bank_account', 'account_no', 'ifsc', 'acc_no']):
                    sensitive_inputs.append({"field": "bank_account", "type": inp_type, "identifier": inp_name or inp_id})

        # 3. External Government Asset Hotlinking (Images, Stylesheets, Favicons)
        hotlinked_gov_assets: List[str] = []
        all_media_tags = soup.find_all(['img', 'link', 'script'])
        for tag in all_media_tags:
            src = tag.get('src') or tag.get('href') or ''
            if src:
                src_parsed = urllib.parse.urlparse(src)
                src_host = (src_parsed.hostname or "").lower()
                if any(src_host.endswith(tld) for tld in GOVERNMENT_TLDS):
                    if src_host != current_host:
                        hotlinked_gov_assets.append(src)

        # 4. Text & Keyword density
        page_text = soup.get_text(separator=' ').lower()
        matched_keywords: List[str] = []
        target_portal = self.genuine_portals.get(matched_portal_id) if matched_portal_id else None

        if target_portal:
            for kw in target_portal["keywords"]:
                if kw in page_text:
                    matched_keywords.append(kw)

        # Compute DOM Risk Score
        risk_score = 0.0
        reasons: List[str] = []

        is_gov_host = any(current_host.endswith(tld) for tld in GOVERNMENT_TLDS)
        gov_specific_fields = [s["field"] for s in sensitive_inputs if s["field"] in ["aadhaar_number", "pan_number", "otp_code", "bank_account"]]

        # 1. Government-specific identity harvesting on an unauthorized non-gov domain
        if gov_specific_fields and not is_gov_host:
            risk_score += 45
            unique_fields = list(set(gov_specific_fields))
            reasons.append(f"Contains high-value citizen identity fields (Aadhaar/PAN/OTP) on non-governmental domain: {', '.join(unique_fields)}")

        # 2. Standard password field on a non-gov domain ONLY if there's already a portal impersonation context
        elif sensitive_inputs and matched_portal_id and not is_gov_host:
            risk_score += 35
            reasons.append("Requests login credentials while imitating a government portal structure.")

        # 3. Hotlinked government emblems/assets
        if hotlinked_gov_assets and not is_gov_host:
            risk_score += 30
            reasons.append(f"Hotlinks {len(hotlinked_gov_assets)} official assets/logos directly from genuine .gov.in servers to imitate branding.")

        if external_action_count > 0 and not is_gov_host and matched_portal_id:
            risk_score += 20
            reasons.append("Form submission sends sensitive user data to an external/unverified third-party endpoint.")

        if insecure_form_count > 0:
            risk_score += 25
            reasons.append("Form submits data over an unencrypted plain HTTP channel.")

        if matched_keywords and not is_gov_host:
            risk_score += min(len(matched_keywords) * 8, 25)
            reasons.append(f"High density of official terminology matching '{target_portal['name'] if target_portal else 'Gov Portal'}'")

        risk_score = min(round(risk_score, 1), 100.0)

        return {
            "risk_score": risk_score,
            "title": title,
            "meta_description": meta_desc,
            "forms_detected": len(forms),
            "sensitive_inputs": sensitive_inputs,
            "hotlinked_gov_assets": hotlinked_gov_assets[:5], # top 5
            "external_action_count": external_action_count,
            "matched_keywords": matched_keywords,
            "reasons": reasons
        }
