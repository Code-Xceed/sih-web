import sys
import os
import json

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from fastapi.testclient import TestClient

from backend.main import app, blockchain_ledger
from backend.modules.homoglyph_analyzer import HomoglyphAnalyzer
from backend.modules.content_similarity import (
    words, word_shingles, text_similarity, dom_outline, dom_similarity, content_similarity
)
from backend.modules.lexical_analyzer import LexicalAnalyzer, jaro_winkler, levenshtein_distance
from backend.modules.reference_database import GENUINE_PORTALS


client = TestClient(app)


def test_homoglyph_confusable_normalization():
    """Verify Cyrillic and Greek confusables are properly detected and normalized to ASCII skeletons."""
    h = HomoglyphAnalyzer()

    # Cyrillic 'а' (U+0430) vs Latin 'a'
    cyrillic_paypal = "p\u0430ypal"
    assert h.has_homoglyph(cyrillic_paypal) is True
    assert h.mixed_script(cyrillic_paypal) is True
    assert h.skeleton(cyrillic_paypal) == "paypal"

    # Greek 'ο' (U+03BF) vs Latin 'o'
    greek_gov = "g\u03bfv.in"
    assert h.has_homoglyph(greek_gov) is True
    assert h.skeleton(greek_gov) == "gov.in"

    # Clean Latin string
    clean = "pmkisan.gov.in"
    assert h.has_homoglyph(clean) is False
    assert h.mixed_script(clean) is False

    # Punycode
    puny = "xn--80ak6aa92e.com"
    assert h.is_punycode(puny) is True


def test_pure_python_minhash_and_dom_similarity():
    """Verify MinHash Jaccard estimation for text and DOM tag structures including Devanagari."""
    # Text similarity with Hindi and English
    text_en_hi_1 = "पीएम किसान सम्मान निधि PM-Kisan Samman Nidhi eKYC aadhaar update portal"
    text_en_hi_2 = "पीएम किसान सम्मान निधि PM-Kisan Samman Nidhi eKYC aadhaar status portal"
    text_unrelated = "Fresh garden flowers and organic roses delivery shop"

    sim_related = text_similarity(text_en_hi_1, text_en_hi_2)
    sim_unrelated = text_similarity(text_en_hi_1, text_unrelated)

    assert sim_related > 0.40
    assert sim_unrelated < 0.10

    # DOM structural outline similarity
    dom1 = "<html><body><div><header></header><form><input><input><button></button></form></div></body></html>"
    dom2 = "<html><body><div><header></header><form><input><input><input><button></button></form></div></body></html>"
    dom_unrelated = "<html><body><table><tr><td><img></td></tr></table></body></html>"

    dom_sim_related = dom_similarity(dom1, dom2)
    dom_sim_unrelated = dom_similarity(dom1, dom_unrelated)

    assert dom_sim_related > dom_sim_unrelated
    assert dom_sim_related >= 0.35

    # Blended content similarity
    blended = content_similarity(text_en_hi_1, dom1, text_en_hi_2, dom2)
    assert blended is not None
    assert blended > 0.40


def test_jaro_winkler_and_lexical_analysis():
    """Verify Jaro-Winkler prefix-weighted distance and typosquatting detection."""
    assert jaro_winkler("sbi", "sbi") == 1.0
    assert jaro_winkler("martha", "marhta") > 0.90
    assert jaro_winkler("pmkisan", "pmkissan") > 0.90

    lex = LexicalAnalyzer()

    # Homoglyph targeting PM-Kisan
    res_hg = lex.analyze("http://pmk\u0456san-portal.xyz/login")
    assert res_hg["risk_score"] >= 80.0
    assert "HOMOGLYPH_CONFUSABLES" in res_hg["anomalies"]
    assert "PM-Kisan" in res_hg["target_entity"]

    # Typosquatting targeting SBI
    res_sbi = lex.analyze("https://onllinesbi-secure.top/netbanking")
    assert res_sbi["risk_score"] >= 75.0
    assert "State Bank of India" in res_sbi["target_entity"]

    # Official SBI domain must never be flagged
    res_official = lex.analyze("https://onlinesbi.sbi/portal")
    assert res_official["risk_score"] == 0.0
    assert res_official["verdict"] == "GENUINE_PORTAL"


def test_expanded_brand_registry():
    """Verify protected registry includes Banking, UPI, and Sovereign portals."""
    expected_brands = ["pmkisan", "incometax", "uidai", "sbi", "npci_upi", "paytm", "hdfc", "icici"]
    for b in expected_brands:
        assert b in GENUINE_PORTALS
        assert "primary_domain" in GENUINE_PORTALS[b]
        assert "keywords" in GENUINE_PORTALS[b]


def test_cloud_native_probes():
    """Test /healthz and /readyz liveness and readiness endpoints."""
    res_h = client.get("/healthz")
    assert res_h.status_code == 200
    assert res_h.json()["status"] == "ok"

    res_r = client.get("/readyz")
    assert res_r.status_code == 200
    assert res_r.json()["ready"] is True
    assert res_r.json()["blockchain_valid"] is True


def test_api_brands_endpoint():
    """Test programmatic brand discovery endpoint /api/brands."""
    res = client.get("/api/brands")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    assert body["count"] >= 10
    brand_names = [b["name"] for b in body["brands"]]
    assert any("State Bank of India" in name for name in brand_names)
    assert any("PM-Kisan" in name for name in brand_names)


def test_api_scan_and_cti_feed():
    """Test synchronous scan, CTI feed (JSON and CSV), and threat logging."""
    # Perform scan of a banking lookalike
    scan_resp = client.post("/api/scan", json={
        "url": "http://sbi-instant-kyc-update.xyz/login",
        "html_content": "<form><input name='account_no'><input name='profile_password'><input name='otp'></form>"
    })
    assert scan_resp.status_code == 200
    data = scan_resp.json()
    assert data["risk_score"] >= 75
    assert data["threat_level"] in ("HIGH", "CRITICAL")
    assert "blockchain_proof" in data

    # Test CTI Feed in JSON format
    feed_json = client.get("/api/feed?format=json")
    assert feed_json.status_code == 200
    j_body = feed_json.json()
    assert j_body["status"] == "success"
    assert j_body["count"] >= 1

    # Test CTI Feed in CSV format
    feed_csv = client.get("/api/feed?format=csv")
    assert feed_csv.status_code == 200
    assert "incident_id,url,target_entity" in feed_csv.text
    assert "sbi-instant-kyc-update.xyz" in feed_csv.text


def test_api_async_scan_mode():
    """Test asynchronous background scan mode with job status polling."""
    # Dispatch async scan
    resp = client.post("/api/scan?mode=async", json={
        "url": "http://pmkisan-yojana-bonus-claim.top/verify",
        "html_content": "<form><input name='aadhaar'><input name='otp'></form>"
    })
    assert resp.status_code == 202
    body = resp.json()
    scan_id = body["scan_id"]
    status_url = body["status_url"]
    assert scan_id.startswith("SCAN-")
    assert status_url == f"/api/scan/{scan_id}"

    # Poll status endpoint
    poll_resp = client.get(status_url)
    assert poll_resp.status_code == 200
    poll_data = poll_resp.json()
    assert poll_data["scan_id"] == scan_id
    assert poll_data["status"] in ("pending", "complete")


if __name__ == "__main__":
    print("=================================================================")
    print("  SENTINEL DOMAIN INHERITANCE TEST SUITE — GOVSHIELD SENTINEL GRID")
    print("=================================================================\n")

    tests = [
        ("1. Homoglyphs & Confusable Skeletons", test_homoglyph_confusable_normalization),
        ("2. Pure-Python MinHash & DOM Similarity", test_pure_python_minhash_and_dom_similarity),
        ("3. Jaro-Winkler & Lexical Typosquatting", test_jaro_winkler_and_lexical_analysis),
        ("4. Expanded Indian Brand Registry (BFSI/UPI/Gov)", test_expanded_brand_registry),
        ("5. Cloud-Native Probes (/healthz & /readyz)", test_cloud_native_probes),
        ("6. Programmatic Brand Discovery (/api/brands)", test_api_brands_endpoint),
        ("7. Synchronous Scan & CTI Feeds (JSON/CSV)", test_api_scan_and_cti_feed),
        ("8. Asynchronous Scan Pipeline (/api/scan?mode=async)", test_api_async_scan_mode),
    ]

    passed = 0
    for name, fn in tests:
        try:
            print(f"Running {name}...")
            fn()
            print(f"  --> [PASS]\n")
            passed += 1
        except Exception as e:
            print(f"  --> [FAIL]: {e}\n")
            import traceback
            traceback.print_exc()

    print("=================================================================")
    print(f"  RESULTS: {passed}/{len(tests)} TESTS PASSED ({int(passed/len(tests)*100)}%)")
    print("=================================================================")
    if passed != len(tests):
        sys.exit(1)
