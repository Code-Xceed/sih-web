"""
GovShield Sentinel Grid - Mock Testing & Simulation Server
SIH 2026 Problem Statement SIH1454

Serves:
- http://localhost:8080/                 -> Demonstration Portal with Test Scenarios
- http://localhost:8080/pmkisan-official -> Genuine Government Service Replica
- http://localhost:8080/pmkisan-kyc-update -> Zero-Day Phishing Lookalike Clone
"""

import os
import http.server
import socketserver

PORT = 8080
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>GovShield Sentinel Grid — Hackathon Live Test Harness</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0a1128;
      color: #f8fafc;
      padding: 40px 20px;
      line-height: 1.5;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
    }
    .header {
      text-align: center;
      margin-bottom: 40px;
      border-bottom: 1px solid rgba(255,255,255,0.1);
      padding-bottom: 20px;
    }
    h1 {
      color: #00d4ff;
      font-size: 28px;
      margin: 0 0 10px 0;
    }
    .subtitle {
      color: #94a3b8;
      font-size: 14px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
      gap: 20px;
    }
    .card {
      background: #121e3a;
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 12px;
      padding: 24px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .card.genuine {
      border-left: 5px solid #10b981;
    }
    .card.phishing {
      border-left: 5px solid #ef4444;
    }
    .card h2 {
      margin-top: 0;
      font-size: 18px;
    }
    .card p {
      color: #cbd5e1;
      font-size: 13px;
      flex-grow: 1;
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
      margin-bottom: 12px;
    }
    .badge-safe { background: rgba(16, 185, 129, 0.2); color: #10b981; }
    .badge-risk { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
    .btn {
      display: block;
      text-align: center;
      text-decoration: none;
      padding: 10px 16px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 13px;
      margin-top: 15px;
      transition: all 0.2s;
    }
    .btn-safe { background: #10b981; color: #fff; }
    .btn-safe:hover { background: #059669; }
    .btn-risk { background: #ef4444; color: #fff; }
    .btn-risk:hover { background: #dc2626; }
    .instruction-box {
      background: #1c2b4e;
      border-radius: 8px;
      padding: 16px;
      margin-top: 30px;
      border: 1px solid rgba(0, 212, 255, 0.2);
    }
    .instruction-box h3 {
      color: #00d4ff;
      margin-top: 0;
      font-size: 15px;
    }
    ol {
      margin-left: 20px;
      font-size: 13px;
      color: #cbd5e1;
    }
    li { margin-bottom: 6px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>GovShield Sentinel Grid Test Harness</h1>
      <div class="subtitle">SIH1454: AI/ML Detection of Lookalike Government Phishing Domains</div>
    </div>

    <div class="grid">
      <!-- Scenario 1: Authentic -->
      <div class="card genuine">
        <div>
          <span class="badge badge-safe">SCENARIO 1: AUTHENTIC REPLICA</span>
          <h2>Genuine PM-Kisan Portal</h2>
          <p>Authentic government structure, valid authorized endpoints, zero credential harvesting form actions. The extension badge should display <strong>SAFE</strong> (🟢 Risk Score 0–5).</p>
        </div>
        <a href="/pmkisan-official" target="_blank" class="btn btn-safe">Launch Genuine Scenario &rarr;</a>
      </div>

      <!-- Scenario 2: Phishing Clone -->
      <div class="card phishing">
        <div>
          <span class="badge badge-risk">SCENARIO 2: ZERO-DAY PHISHING CLONE</span>
          <h2>Deceptive Lookalike Clone</h2>
          <p>Mimics visual colors, Hindi banner, hotlinks official logos, but asks for 12-digit Aadhaar, Mobile & OTP and submits to external server. The extension should trigger <strong>RISK</strong> (🔴 85-95) + in-page alert banner.</p>
        </div>
        <a href="/pmkisan-kyc-update" target="_blank" class="btn btn-risk">Launch Phishing Clone &rarr;</a>
      </div>
    </div>

    <div class="instruction-box">
      <h3>🚀 How to Test with the Chrome Extension</h3>
      <ol>
        <li>Load the <code>extension/</code> folder in Chrome (<code>chrome://extensions</code> &rarr; Developer mode &rarr; Load unpacked).</li>
        <li>Open either test scenario above in a new tab.</li>
        <li>Observe the <strong>automatic GovShield badge change</strong> in the toolbar (<code>SAFE</code> vs <code>RISK</code>).</li>
        <li>Click the GovShield extension icon in the toolbar to inspect the <strong>Forensic AI Breakdown</strong> and generate a one-click <strong>CERT-In Takedown Dossier</strong>.</li>
      </ol>
    </div>
  </div>
</body>
</html>
"""


class MockPhishingHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path in ["/", "/index.html"]:
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(INDEX_HTML.encode("utf-8"))
        elif self.path.startswith("/pmkisan-official"):
            self.serve_file(os.path.join(TEMPLATES_DIR, "pmkisan_genuine.html"))
        elif self.path.startswith("/pmkisan-kyc-update"):
            self.serve_file(os.path.join(TEMPLATES_DIR, "pmkisan_phishing_clone.html"))
        else:
            super().do_GET()

    def serve_file(self, filepath):
        if os.path.exists(filepath):
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            with open(filepath, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, "Page Not Found")


def run_mock_server():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), MockPhishingHandler) as httpd:
        print(f"================================================================")
        print(f"🚀 GovShield Test Harness running on http://localhost:{PORT}")
        print(f"   • Scenario 1 (Genuine): http://localhost:{PORT}/pmkisan-official")
        print(f"   • Scenario 2 (Phishing): http://localhost:{PORT}/pmkisan-kyc-update")
        print(f"================================================================")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down test server.")


if __name__ == "__main__":
    run_mock_server()
