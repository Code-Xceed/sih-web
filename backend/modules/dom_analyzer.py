"""
GovShield Sentinel Grid — DOM, Form & Script Forensics Engine.
Incorporates best-of-breed algorithms from PhishDetect and url.vet:
- Indian Citizen Identity & Financial Token Forms (Aadhaar, PAN, Bank, UPI, MPIN, OTP)
- Form Action Exfiltration Destinations (Cross-domain, Telegram/Discord webhooks, Formspree)
- Escaped HTML Entity Brand Obfuscation (&#...; decimal/hex entity decoding from PhishDetect)
- Deceptive Government Title & OpenGraph Claim Verification
- Meta-Refresh Client Redirect Detection
- Script Behavior & Anti-Forensics (eval, obfuscated base64, hidden iframes, disabled contextmenu)
- External Sovereign Asset Hotlinking (Emblems, Logos, CSS from genuine .gov.in)
"""

from __future__ import annotations

import html
import re
import urllib.parse
from typing import Any, Dict, List, Optional
from bs4 import BeautifulSoup
from .reference_database import GENUINE_PORTALS, GOVERNMENT_TLDS

SUSPICIOUS_EXFILTRATION_HOSTS = [
    "api.telegram.org", "discord.com/api/webhooks", "formspree.io",
    "formcarry.com", "getform.io", "formsubmit.co", "formkeep.com",
    "webtolead", "pipedream.net", "ngrok.io", "herokuapp.com"
]

SOVEREIGN_TITLE_PATTERNS = [
    r"pm[\s\-]?kisan", r"aadhaar", r"uidai", r"income[\s\-]?tax",
    r"parivahan", r"epfo|epf\sindia", r"passport\sseva", r"digilocker",
    r"cyber[\s\-]?crime", r"samagra\sshiksha", r"sarva\sshiksha",
    r"viksit\sbharat", r"rozgar\syojana", r"ayushman\sbharat", r"e[\s\-]?shram"
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
                "html_deception_signals": {},
                "reasons": ["No HTML content retrieved (Headless or Empty DOM)."]
            }

        soup = BeautifulSoup(html_content, 'html.parser')
        parsed_base = urllib.parse.urlsplit(base_url)
        current_host = (parsed_base.hostname or "").lower()
        is_gov_domain = current_host.endswith(".gov.in") or current_host.endswith(".nic.in")

        # 1. Page Title & Meta Descriptions (PhishDetect check)
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        meta_desc = ""
        meta_desc_tag = soup.find('meta', attrs={'name': 'description'}) or soup.find('meta', attrs={'property': 'og:description'})
        if meta_desc_tag and meta_desc_tag.get('content'):
            meta_desc = meta_desc_tag['content'].strip()

        # Check deceptive sovereign title claim on non-gov domain
        is_deceptive_title = False
        deceptive_title_brand = ""
        if not is_gov_domain and title:
            for pat in SOVEREIGN_TITLE_PATTERNS:
                if re.search(pat, title, re.IGNORECASE):
                    is_deceptive_title = True
                    deceptive_title_brand = title
                    break

        # 2. Escaped HTML Entity Obfuscation (PhishDetect checkEscapedText)
        has_escaped_brand_obfuscation = False
        raw_decoded = html.unescape(html_content)
        if raw_decoded != html_content:
            # If decoding altered entities, check if sovereign keywords were hidden
            for brand_key in ["pmkisan", "aadhaar", "uidai", "incometax", "samagra"]:
                if brand_key in raw_decoded.lower() and brand_key not in html_content.lower():
                    has_escaped_brand_obfuscation = True
                    break

        # 3. Meta-Refresh Client-Side Redirection (url.vet / PhishDetect check)
        meta_refresh = soup.find('meta', attrs={'http-equiv': lambda v: v and v.lower() == 'refresh'})
        has_meta_refresh = False
        meta_refresh_target = ""
        if meta_refresh and meta_refresh.get('content'):
            content = meta_refresh['content']
            has_meta_refresh = True
            url_match = re.search(r"url=([^;]+)", content, re.IGNORECASE)
            if url_match:
                meta_refresh_target = url_match.group(1).strip()

        # 4. Form & Sensitive Citizen Identity Input Inspection
        forms = soup.find_all('form')
        sensitive_inputs: List[Dict[str, str]] = []
        external_action_count = 0
        insecure_form_count = 0
        exfiltration_endpoints: List[str] = []
        reasons: List[str] = []

        for idx, form in enumerate(forms):
            action = (form.get('action') or '').strip()

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

        # 5. External Government Asset Hotlinking (Images, Logos, CSS)
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

        # 6. Script & Anti-Forensics Forensics (PhishDetect / PhishGuard)
        script_risks: List[str] = []
        scripts = soup.find_all('script')
        for s in scripts:
            content = s.string or ""
            if content:
                if "eval(" in content or "unescape(" in content or "String.fromCharCode(" in content:
                    script_risks.append("Dynamic script evaluation / de-obfuscation (eval/unescape)")
                if "atob(" in content and len(content) > 500:
                    script_risks.append("Base64 payload execution in script body")
                if "document.write(" in content:
                    script_risks.append("DOM overwriting via document.write")
                if "debugger" in content:
                    script_risks.append("Anti-debugging instruction detected")

        # Anti-analysis event listeners on body (e.g. disable right click or copy)
        body = soup.find('body')
        if body:
            body_events = [k for k in body.attrs.keys() if k.lower() in ['oncontextmenu', 'onselectstart', 'ondragstart', 'onkeydown']]
            if len(body_events) >= 2:
                script_risks.append("Anti-inspection event blockers detected on DOM body (disabled right-click/keys)")

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

        if is_deceptive_title:
            dom_risk += 35.0
            reasons.append(f"Deceptive page title claims official government authority on non-gov host: '{title}'")

        if has_escaped_brand_obfuscation:
            dom_risk += 30.0
            reasons.append("HTML entity encoding (&#...;) used to obfuscate sovereign brand tokens from filters")

        if has_meta_refresh:
            dom_risk += 20.0
            reasons.append(f"Client-side meta refresh auto-redirection active -> '{meta_refresh_target}'")

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
            "html_deception_signals": {
                "is_deceptive_title": is_deceptive_title,
                "deceptive_title_brand": deceptive_title_brand,
                "has_escaped_brand_obfuscation": has_escaped_brand_obfuscation,
                "has_meta_refresh": has_meta_refresh,
                "meta_refresh_target": meta_refresh_target
            },
            "reasons": reasons
        }
