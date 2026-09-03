"""
GovShield Sentinel Grid — DOM, Form & Script Forensics Engine
Performs deep structural analysis of HTML, sensitive credential harvesting forms, and suspicious scripts.

Features Extracted:
- Indian Citizen Identity & Financial Token Forms (Aadhaar, PAN, Bank, UPI, MPIN, OTP)
- Form Action Exfiltration Destinations (Cross-domain, Telegram/Discord webhooks, Formspree)
- Insecure Form Submissions (HTTP action on HTTPS host)
- Script Behavior (eval, obfuscated base64, hidden iframes, anti-tamper)
- External Sovereign Asset Hotlinking (Emblems, Logos, CSS from genuine .gov.in)
"""

from typing import Dict, Any, List, Optional
import urllib.parse
import re
from bs4 import BeautifulSoup
from .reference_database import GENUINE_PORTALS, GOVERNMENT_TLDS

SUSPICIOUS_EXFILTRATION_HOSTS = [
    "api.telegram.org", "discord.com/api/webhooks", "formspree.io",
    "formcarry.com", "getform.io", "formsubmit.co", "formkeep.com",
    "webtolead", "pipedream.net", "ngrok.io", "herokuapp.com"
]


class DOMAnalyzer:
    """Enterprise DOM Structure and Credential Harvesting Forensics."""

    def __init__(self):
        self.genuine_portals = GENUINE_PORTALS

    def analyze_html(self, html_content: str, base_url: str, matched_portal_id: Optional[str] = None) -> Dict[str, Any]:
        """Parse raw HTML string and extract forensic features."""
        if not html_content or len(html_content.strip()) == 0:
            return {
                "risk_score": 5.0,
                "forms_detected": 0,
                "sensitive_inputs": [],
                "hotlinked_gov_assets": [],
                "external_action_count": 0,
                "script_risks": [],
                "reasons": ["No HTML content retrieved (Headless or Empty DOM)."]
            }

        soup = BeautifulSoup(html_content, 'html.parser')
        parsed_base = urllib.parse.urlsplit(base_url)
        current_host = (parsed_base.hostname or "").lower()

        # 1. Page Title & Meta Descriptions
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        meta_desc = ""
        meta_desc_tag = soup.find('meta', attrs={'name': 'description'}) or soup.find('meta', attrs={'property': 'og:description'})
        if meta_desc_tag and meta_desc_tag.get('content'):
            meta_desc = meta_desc_tag['content'].strip()

        # 2. Form & Sensitive Citizen Identity Input Inspection
        forms = soup.find_all('form')
        sensitive_inputs: List[Dict[str, str]] = []
        external_action_count = 0
        insecure_form_count = 0
        exfiltration_endpoints: List[str] = []
        reasons: List[str] = []

        for idx, form in enumerate(forms):
            action = (form.get('action') or '').strip()
            method = (form.get('method') or 'GET').upper()

            # Check form action destination
            if action:
                action_parsed = urllib.parse.urlsplit(action)
                action_host = (action_parsed.hostname or "").lower()

                # Check known exfiltration relays (Telegram, Discord, formspree)
                for exfil in SUSPICIOUS_EXFILTRATION_HOSTS:
                    if exfil in action.lower():
                        exfiltration_endpoints.append(action)
                        reasons.append(f"Form exfiltrates citizen data to external relay: {exfil}")

                if action_host and action_host != current_host:
                    external_action_count += 1
                if action.startswith('http://') and base_url.startswith('https://'):
                    insecure_form_count += 1
            elif action in ['#', '', 'about:blank', 'javascript:void(0)']:
                # Common phishing tactic to capture credentials via client-side JavaScript
                external_action_count += 1

            # Check input tags
            for inp in form.find_all(['input', 'textarea', 'select']):
                inp_type = (inp.get('type') or 'text').lower()
                inp_name = (inp.get('name') or '').lower()
                inp_id = (inp.get('id') or '').lower()
                inp_placeholder = (inp.get('placeholder') or '').lower()
                inp_autocomplete = (inp.get('autocomplete') or '').lower()
                combined_ident = f"{inp_name} {inp_id} {inp_placeholder} {inp_autocomplete}"

                # Match sensitive Indian tokens
                if inp_type == 'password' or 'password' in combined_ident:
                    sensitive_inputs.append({"field": "password", "type": inp_type, "identifier": inp_name or inp_id})
                elif any(k in combined_ident for k in ['aadhaar', 'uid', 'aadhar', '12-digit', 'uidai']):
                    sensitive_inputs.append({"field": "aadhaar_number", "type": inp_type, "identifier": inp_name or inp_id})
                elif any(k in combined_ident for k in ['pan', 'pan_no', 'pan_card', 'pancard', '10-digit']):
                    sensitive_inputs.append({"field": "pan_number", "type": inp_type, "identifier": inp_name or inp_id})
                elif any(k in combined_ident for k in ['otp', 'one-time-password', 'verification-code', 'mpin', 'tpin']):
                    sensitive_inputs.append({"field": "otp_code", "type": inp_type, "identifier": inp_name or inp_id})
                elif any(k in combined_ident for k in ['cvv', 'card_number', 'credit_card', 'debit_card', 'atm_pin']):
                    sensitive_inputs.append({"field": "financial_card", "type": inp_type, "identifier": inp_name or inp_id})
                elif any(k in combined_ident for k in ['bank_account', 'account_no', 'ifsc', 'acc_no']):
                    sensitive_inputs.append({"field": "bank_account", "type": inp_type, "identifier": inp_name or inp_id})
                elif any(k in combined_ident for k in ['upi', 'vpa', 'bhim']):
                    sensitive_inputs.append({"field": "upi_id", "type": inp_type, "identifier": inp_name or inp_id})

        # 3. External Government Asset Hotlinking (Images, Logos, CSS)
        hotlinked_gov_assets: List[str] = []
        all_media_tags = soup.find_all(['img', 'link', 'script'])
        for tag in all_media_tags:
            src = tag.get('src') or tag.get('href') or ''
            if src:
                src_parsed = urllib.parse.urlsplit(src)
                src_host = (src_parsed.hostname or "").lower()
                if any(src_host.endswith(tld) for tld in GOVERNMENT_TLDS):
                    if src_host != current_host:
                        hotlinked_gov_assets.append(src)

        # 4. Script & DOM Obfuscation Forensics
        script_risks: List[str] = []
        scripts = soup.find_all('script')
        for s in scripts:
            content = s.string or ""
            if content:
                # Look for suspicious eval or unescape
                if "eval(" in content or "unescape(" in content or "String.fromCharCode(" in content:
                    script_risks.append("Dynamic script evaluation / de-obfuscation (eval/unescape)")
                if "atob(" in content and len(content) > 500:
                    script_risks.append("Base64 payload execution in script body")
                if "document.write(" in content:
                    script_risks.append("DOM overwriting via document.write")

        # Hidden iframes
        iframes = soup.find_all('iframe')
        for f in iframes:
            style = (f.get('style') or '').lower()
            width = f.get('width')
            height = f.get('height')
            if 'display:none' in style or 'visibility:hidden' in style or width in ['0', '1'] or height in ['0', '1']:
                script_risks.append("Hidden iframe (zero-pixel or invisible) detected")

        # Calculate DOM forensic risk score
        dom_risk = 0.0
        if len(sensitive_inputs) > 0:
            dom_risk += min(len(sensitive_inputs) * 25.0, 75.0)
            reasons.append(f"Sensitive credential/identity harvesting form found: {[s['field'] for s in sensitive_inputs]}")

        if external_action_count > 0:
            dom_risk += 25.0
            reasons.append(f"Form action points to external/suspicious destination ({external_action_count} instances)")

        if insecure_form_count > 0:
            dom_risk += 20.0
            reasons.append("Insecure cleartext HTTP form submission on HTTPS website")

        if len(hotlinked_gov_assets) > 0:
            dom_risk += min(len(hotlinked_gov_assets) * 15.0, 30.0)
            reasons.append(f"Unauthorized hotlinking of official government media ({len(hotlinked_gov_assets)} assets)")

        if script_risks:
            dom_risk += min(len(script_risks) * 10.0, 25.0)
            reasons.extend(script_risks)

        normalized_risk = min(max(round(dom_risk, 1), 0.0), 100.0)

        return {
            "risk_score": normalized_risk,
            "page_title": title,
            "meta_description": meta_desc,
            "forms_detected": len(forms),
            "sensitive_inputs": sensitive_inputs,
            "hotlinked_gov_assets": hotlinked_gov_assets[:10],
            "external_action_count": external_action_count,
            "insecure_form_count": insecure_form_count,
            "exfiltration_endpoints": exfiltration_endpoints,
            "script_risks": script_risks,
            "reasons": reasons
        }
