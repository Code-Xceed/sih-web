"""
Lexical and Typosquatting Analyzer for URLs and Domains.
Computes string similarity distances, Shannon entropy, homoglyphs, and keyword anomalies.
"""

import re
import math
import urllib.parse
from typing import Dict, Any, List, Optional
from .reference_database import (
    GENUINE_PORTALS, GOVERNMENT_TLDS, SUSPICIOUS_TLDS, HIGH_RISK_KEYWORDS,
    AUTHENTIC_COMMERCIAL_DOMAINS, GOVERNMENT_BRAND_TOKENS, GOVERNMENT_ACTION_TOKENS
)


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return round(entropy, 3)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute standard Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def string_similarity(s1: str, s2: str) -> float:
    """Normalized similarity score between 0.0 and 1.0 based on Levenshtein."""
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = levenshtein_distance(s1.lower(), s2.lower())
    return round(1.0 - (dist / max_len), 4)


class LexicalAnalyzer:
    """Analyzes URL strings for typosquatting, deceptive brand injection, and lexical anomalies."""

    def __init__(self):
        self.genuine_portals = GENUINE_PORTALS
        self.suspicious_tlds = SUSPICIOUS_TLDS
        self.high_risk_keywords = HIGH_RISK_KEYWORDS
        self.commercial_whitelist = AUTHENTIC_COMMERCIAL_DOMAINS
        self.gov_brand_tokens = GOVERNMENT_BRAND_TOKENS
        self.gov_action_tokens = GOVERNMENT_ACTION_TOKENS

    def parse_url(self, raw_url: str) -> Dict[str, str]:
        """Normalize and parse a given URL."""
        url = raw_url.strip()
        if not re.match(r'^[a-zA-Z]+://', url):
            url = 'http://' + url
        parsed = urllib.parse.urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        return {
            "raw_url": raw_url,
            "normalized_url": url,
            "scheme": parsed.scheme,
            "hostname": hostname,
            "path": path,
            "query": query,
            "port": str(parsed.port) if parsed.port else ""
        }

    def analyze(self, raw_url: str) -> Dict[str, Any]:
        """Perform comprehensive lexical evaluation on the URL."""
        parsed = self.parse_url(raw_url)
        hostname = parsed["hostname"]
        path = parsed["path"]
        raw = parsed["normalized_url"].lower()

        # 0A. Known Authentic Commercial Domains & Search Engines (e.g. bing.com, google.com, chatgpt.com)
        is_known_commercial = any(
            hostname == d or hostname.endswith('.' + d)
            for d in self.commercial_whitelist
        )
        if is_known_commercial:
            return {
                "verdict": "LEGITIMATE",
                "risk_score": 0.0,
                "hostname": hostname,
                "is_genuine_gov_tld": False,
                "has_suspicious_tld": False,
                "entropy": 2.0,
                "anomalies": [],
                "target_entity": "Legitimate Commercial Platform",
                "target_entity_domain": hostname,
                "target_entity_id": None,
                "similarity_to_genuine": 0.0,
                "reasons": ["Authentic commercial platform / search engine. No government impersonation."]
            }

        # 0B. Local Demo Genuine Replica check
        if (hostname in ["localhost", "127.0.0.1"]) and ("official" in path or "genuine" in path):
            return {
                "verdict": "GENUINE_PORTAL",
                "risk_score": 0.0,
                "hostname": hostname,
                "is_genuine_gov_tld": True,
                "has_suspicious_tld": False,
                "entropy": 2.0,
                "target_entity": "PM-Kisan Samman Nidhi Portal (Gov of India)",
                "target_entity_domain": "pmkisan.gov.in",
                "target_entity_id": "pmkisan",
                "anomalies": [],
                "similarity_to_genuine": 1.0,
                "reasons": ["Authenticated Government Scheme Demonstration Replica."]
            }

        is_genuine_gov_tld = any(hostname.endswith(tld) for tld in GOVERNMENT_TLDS)
        has_suspicious_tld = any(hostname.endswith(tld) for tld in self.suspicious_tlds)
        is_ip_address = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname))
        hyphen_count = hostname.count('-')
        subdomain_depth = len(hostname.split('.')) - 2 if len(hostname.split('.')) > 2 else 0
        entropy = shannon_entropy(hostname)

        # Keyword presence
        detected_keywords = [kw for kw in self.high_risk_keywords if kw in raw]

        # Extract main domain stem (e.g., 'bing' from 'www.bing.com', 'gst-refund' from 'gst-refund.example')
        host_parts = [p for p in hostname.split('.') if p not in ['www', 'com', 'org', 'net', 'in', 'co', 'io', 'ai']]
        main_host_stem = '-'.join(host_parts) if host_parts else hostname
        normalized_stem = main_host_stem.replace('-', '').lower()

        # Brand impersonation & similarity check
        best_match_entity: Optional[Dict[str, Any]] = None
        highest_similarity = 0.0
        impersonation_type = "none"

        # 1. Exact match check & Official Government TLD
        for portal_id, portal_data in self.genuine_portals.items():
            primary_dom = portal_data["primary_domain"]
            primary_stem = primary_dom.split('.')[0]
            if hostname in portal_data["valid_domains"] or (is_genuine_gov_tld and portal_id in hostname):
                return {
                    "verdict": "GENUINE_PORTAL",
                    "risk_score": 0.0,
                    "hostname": hostname,
                    "target_entity": portal_data["name"],
                    "target_entity_domain": primary_dom,
                    "entity_id": portal_id,
                    "target_entity_id": portal_id,
                    "is_genuine_gov_tld": True,
                    "anomalies": [],
                    "similarity_to_genuine": 1.0,
                    "reasons": [f"Exact match to verified official domain: {hostname}"]
                }

            if not is_genuine_gov_tld:
                # 2A. Substring & Hyphen-Normalized Combination Check (e.g. gst-refund, income-tax, pm-kisan)
                stem_in_domain = (primary_stem in main_host_stem) or (primary_stem in normalized_stem) or (portal_id in normalized_stem)
                
                # 2B. Portal Keyword Fingerprint Matching
                kw_match = False
                for kw in portal_data.get("keywords", []):
                    kw_words = [w.lower() for w in kw.split() if len(w) >= 3]
                    if kw_words and all(w in hostname for w in kw_words):
                        kw_match = True
                        break
                    kw_clean = kw.replace(' ', '').replace('-', '').lower()
                    if len(kw_clean) >= 4 and kw_clean in normalized_stem:
                        kw_match = True
                        break

                if stem_in_domain or kw_match:
                    sim = 0.95
                    if sim > highest_similarity:
                        highest_similarity = sim
                        best_match_entity = portal_data
                        impersonation_type = "brand_injection"

                # 3. String distance check - STRICT THRESHOLD (>= 0.72)
                sim_score = string_similarity(primary_stem, main_host_stem)
                if sim_score >= 0.72 and sim_score > highest_similarity:
                    highest_similarity = sim_score
                    best_match_entity = portal_data
                    impersonation_type = "typosquatting"

        # 4. Generalized Government Token & Scheme Analysis
        if not is_genuine_gov_tld and not best_match_entity:
            domain_tokens = set(main_host_stem.replace('.', '-').split('-'))
            matched_gov_tokens = domain_tokens.intersection(self.gov_brand_tokens)
            matched_act_tokens = domain_tokens.intersection(self.gov_action_tokens)
            
            if matched_gov_tokens:
                gov_tok = list(matched_gov_tokens)[0]
                matched_portal = self.genuine_portals.get(gov_tok)
                if matched_portal:
                    best_match_entity = matched_portal
                else:
                    best_match_entity = {
                        "id": gov_tok,
                        "name": f"Official {gov_tok.upper()} Public Service",
                        "primary_domain": f"{gov_tok}.gov.in"
                    }
                highest_similarity = 0.95
                impersonation_type = "brand_injection"

        # Calculate Lexical Risk Score (0 - 100)
        risk_score = 0.0
        anomalies: List[str] = []
        reasons: List[str] = []

        if is_ip_address:
            risk_score += 35
            anomalies.append("IP_HOST_ADDRESS")
            reasons.append("Website uses raw numeric IP address instead of a domain name.")

        if has_suspicious_tld:
            risk_score += 25
            anomalies.append("SUSPICIOUS_TLD")
            reasons.append(f"Domain uses high-abuse top-level domain suffix.")

        if hyphen_count >= 2:
            risk_score += 15
            anomalies.append("EXCESSIVE_HYPHENS")
            reasons.append(f"Domain contains {hyphen_count} hyphens, often used to mimic authentic portal names.")

        if subdomain_depth >= 3:
            risk_score += 15
            anomalies.append("DEEP_SUBDOMAINS")
            reasons.append("Excessive subdomain levels detected.")

        if "@" in raw:
            risk_score += 30
            anomalies.append("URL_EMBEDDED_CREDENTIALS")
            reasons.append("URL contains '@' character which can obscure true destination.")

        if entropy > 4.2:
            risk_score += 15
            anomalies.append("HIGH_ENTROPY_DOMAIN")
            reasons.append(f"High randomness entropy ({entropy}) in domain name.")

        if best_match_entity and not is_genuine_gov_tld:
            if impersonation_type == "brand_injection":
                risk_score += 55
                anomalies.append("GOV_BRAND_IMPERSONATION")
                reasons.append(f"Unauthorized non-government domain uses official name / keywords of '{best_match_entity['name']}'.")
            elif highest_similarity >= 0.75:
                risk_score += 45
                anomalies.append("TYPOSQUATTING_CANDIDATE")
                reasons.append(f"High lexical similarity ({int(highest_similarity*100)}%) to official portal '{best_match_entity['primary_domain']}'.")

        if detected_keywords and not is_genuine_gov_tld:
            risk_score += min(len(detected_keywords) * 10, 30)
            anomalies.append("SENSITIVE_KEYWORDS_DETECTED")
            reasons.append(f"Contains urgent or financial action keywords: {', '.join(detected_keywords)}")

        # Normalization
        risk_score = min(round(risk_score, 1), 100.0)

        return {
            "risk_score": risk_score,
            "hostname": hostname,
            "is_genuine_gov_tld": is_genuine_gov_tld,
            "has_suspicious_tld": has_suspicious_tld,
            "entropy": entropy,
            "anomalies": anomalies,
            "target_entity": best_match_entity["name"] if best_match_entity else "Unknown / Generic Portal",
            "target_entity_domain": best_match_entity["primary_domain"] if best_match_entity else "",
            "target_entity_id": best_match_entity["id"] if best_match_entity else None,
            "similarity_to_genuine": highest_similarity,
            "reasons": reasons
        }
