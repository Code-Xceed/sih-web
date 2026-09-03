"""
GovShield Sentinel Grid — Contextual Government & Brand Impersonation Engine
Maintains an authoritative Knowledge Base of Indian Sovereign Portals, Banking, and Payment Systems.

Distinguishes between:
- OFFICIAL (Government of India / Authenticated PSU Infrastructure)
- LEGITIMATE_THIRD_PARTY (News media, encyclopedias, tax consultation)
- SUSPICIOUS_IMPERSONATION (Lookalike domains claiming authority)
- MALICIOUS_IMPERSONATION (Adversarial phishing clones harvesting citizen credentials)
- NEUTRAL (Legitimate commercial platforms with no deceptive claims)
"""

from typing import Dict, Any, List, Optional, Tuple
from .reference_database import GENUINE_PORTALS, GOVERNMENT_TLDS

# Known legitimate third-party informational and journalistic domains
LEGITIMATE_INFORMATIONAL_DOMAINS = {
    # Reputable Indian News & Media
    "thehindu.com", "timesofindia.indiatimes.com", "indianexpress.com",
    "hindustantimes.com", "ndtv.com", "livemint.com", "moneycontrol.com",
    "financialexpress.com", "economictimes.indiatimes.com", "thewire.in",
    "theprint.in", "scroll.in", "firstpost.com", "business-standard.com",
    "deccanherald.com", "tribuneindia.com", "abplive.com", "amarujala.com",
    "aajtak.in", "dainikbhaskar.com", "jagran.com", "news18.com",
    
    # Encyclopedias & Reference
    "wikipedia.org", "wikimedia.org", "britannica.com",
    
    # Established Tax & Fintech Informational Portals
    "cleartax.in", "taxmann.com", "taxguru.in", "indiafilings.com", "policybazaar.com",
    
    # Education & Career Guidance
    "jagranjosh.com", "shiksha.com", "careers360.com", "sarkariresult.com"
}

# Scam / Fraud Action Verbs indicating deceptive phishing lures
DECEPTIVE_ACTION_TOKENS = {
    "kyc", "e-kyc", "update", "verify", "verification", "refund", "claim",
    "disburse", "subsidy", "dbt", "download", "login", "portal", "status",
    "apply", "winner", "lottery", "instant-loan", "bill-payment", "bijli",
    "electricity-disconnection", "digital-arrest", "customs-clearance"
}


class BrandEngine:
    """Contextual Brand and Sovereign Impersonation Intelligence."""

    def __init__(self):
        self.knowledge_base = GENUINE_PORTALS

    def match_entity(self, domain: str, path: str = "", page_title: str = "") -> Optional[Dict[str, Any]]:
        """
        Identifies which sovereign brand or government entity is being referenced or targeted.
        """
        domain_clean = domain.lower()
        search_blob = f"{domain_clean} {path.lower()} {page_title.lower()}"

        # 1. Exact official domain match
        for entity_id, data in self.knowledge_base.items():
            if domain_clean == data["primary_domain"] or domain_clean in data.get("valid_domains", []):
                return {
                    "entity_id": entity_id,
                    "organization": data["name"],
                    "department": data["department"],
                    "primary_domain": data["primary_domain"],
                    "is_official_domain": True,
                    "match_type": "OFFICIAL_DOMAIN"
                }

        # 2. Token and alias matching
        best_match = None
        highest_score = 0

        for entity_id, data in self.knowledge_base.items():
            score = 0
            # Construct comprehensive alias set
            aliases = set(data.get("aliases", []))
            aliases.add(entity_id)
            aliases.add(data["primary_domain"].split(".")[0])
            if "-" in entity_id:
                aliases.add(entity_id.replace("-", ""))
            else:
                if entity_id.startswith("pm") and len(entity_id) > 2:
                    aliases.add(f"pm-{entity_id[2:]}")

            # Check domain name & search blob for aliases
            for alias in aliases:
                alias_clean = alias.lower()
                if alias_clean in domain_clean:
                    score += 40
                elif alias_clean in search_blob:
                    score += 20

            # Check entity keywords
            for kw in data.get("keywords", []):
                kw_clean = kw.lower()
                if kw_clean in domain_clean:
                    score += 30
                elif kw_clean in search_blob:
                    score += 15

            if score > highest_score and score >= 15:
                highest_score = score
                best_match = {
                    "entity_id": entity_id,
                    "organization": data["name"],
                    "department": data["department"],
                    "primary_domain": data["primary_domain"],
                    "is_official_domain": False,
                    "match_type": "BRAND_TOKEN_MATCH",
                    "match_confidence": min(highest_score / 65.0, 1.0)
                }

        return best_match

    def classify_relationship(
        self,
        domain: str,
        entity_info: Optional[Dict[str, Any]],
        has_sensitive_forms: bool = False,
        content_similarity_score: float = 0.0,
        lexical_risk_score: float = 0.0
    ) -> Dict[str, Any]:
        """
        Classifies the relationship between the target website and the government organization:
        - OFFICIAL
        - LEGITIMATE_THIRD_PARTY
        - SUSPICIOUS_IMPERSONATION
        - MALICIOUS_IMPERSONATION
        - NEUTRAL
        """
        domain_clean = domain.lower()

        # Check official government TLD
        is_gov_tld = any(domain_clean.endswith(tld) for tld in GOVERNMENT_TLDS)

        # 1. Official National Infrastructure
        if entity_info and entity_info.get("is_official_domain"):
            return {
                "classification": "OFFICIAL",
                "risk_multiplier": 0.0,
                "claimed_entity": entity_info["organization"],
                "reason": "Authenticated official Indian Government / PSU digital infrastructure."
            }
        if is_gov_tld and lexical_risk_score < 20:
            return {
                "classification": "OFFICIAL",
                "risk_multiplier": 0.0,
                "claimed_entity": entity_info["organization"] if entity_info else "Government of India",
                "reason": "Verified domain ending in authoritative sovereign TLD (.gov.in / .nic.in)."
            }

        # 2. Check if host is a known legitimate informational third party (News, Wikipedia)
        for legit_domain in LEGITIMATE_INFORMATIONAL_DOMAINS:
            if domain_clean == legit_domain or domain_clean.endswith("." + legit_domain):
                # If news site mentions gov schemes, it's informational unless compromised with harvesting forms
                if not has_sensitive_forms:
                    return {
                        "classification": "LEGITIMATE_THIRD_PARTY",
                        "risk_multiplier": 0.05,
                        "claimed_entity": entity_info["organization"] if entity_info else None,
                        "reason": f"Legitimate news or informational publication ({legit_domain}) discussing public policy or schemes."
                    }

        # 3. If no government entity was matched
        if not entity_info:
            return {
                "classification": "NEUTRAL",
                "risk_multiplier": 0.1,
                "claimed_entity": None,
                "reason": "No Indian government brand or welfare scheme tokens detected."
            }

        # 4. Check for Deceptive Action Tokens in Domain
        has_deceptive_action = any(act in domain_clean for act in DECEPTIVE_ACTION_TOKENS)

        # 5. Malicious Impersonation vs Suspicious Lookalike
        if has_sensitive_forms or content_similarity_score >= 0.70 or (has_deceptive_action and lexical_risk_score >= 40):
            return {
                "classification": "MALICIOUS_IMPERSONATION",
                "risk_multiplier": 1.0,
                "claimed_entity": entity_info["organization"],
                "reason": f"High-confidence adversarial impersonation targeting {entity_info['organization']}. Combines unauthorized domain with action lures or credential harvesting."
            }
        else:
            return {
                "classification": "SUSPICIOUS_IMPERSONATION",
                "risk_multiplier": 0.65,
                "claimed_entity": entity_info["organization"],
                "reason": f"Unauthorized domain utilizes official branding tokens for {entity_info['organization']}. Requires caution."
            }
