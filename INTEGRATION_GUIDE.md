# 🛡️ GovShield AI — Backend Architecture & Integration Guide
**Smart India Hackathon 2026 (SIH1454)**  
*Multi-Modal AI/ML Sovereign Phishing & Lookalike Clone Defense System*

---

## 📌 1. Overview & Architecture

GovShield is an AI/ML cybersecurity backend engine engineered to detect zero-day phishing lookalikes and fraudulent clones targeting Indian Sovereign Public Services (Income Tax, GST, PM-Kisan, UIDAI Aadhaar, Parivahan, EPFO, etc.).

```
                          ┌────────────────────────┐
                          │ Client / Web / Browser │
                          └───────────┬────────────┘
                                      │ HTTP JSON (POST /api/scan)
                                      ▼
             ┌──────────────────────────────────────────────────┐
             │       FastAPI Multi-Modal AI Fusion Engine       │
             └───────┬────────────┬─────────────┬─────────────┬─┘
                     │            │             │             │
        ┌────────────▼───┐ ┌──────▼──────┐ ┌────▼───────┐ ┌───▼─────────────┐
        │ Tier 1: Lexical│ │ Tier 2: DOM │ │ Tier 3:    │ │ Tier 4: WHOIS &  │
        │ Typosquatting  │ │ Credentials │ │ Visual     │ │ Domain Age NRD   │
        │ & Token Stems  │ │ (Aadhaar/   │ │ Perceptual │ │ (Registrar Risk) │
        │                │ │  PAN/OTP)   │ │ pHash      │ │                  │
        └────────────┬───┘ └──────┬──────┘ └────┬───────┘ └───┬─────────────┘
                     │            │             │             │
                     └────────────┼─────────────┼─────────────┘
                                  ▼
             ┌──────────────────────────────────────────────────┐
             │  Tier 5: Gemini 2.0 Flash Cyber Intel AI Agent   │
             │   (Deep Domain Research & Scheme Impersonation)  │
             └────────────────────┬─────────────────────────────┘
                                  ▼
             ┌──────────────────────────────────────────────────┐
             │       Multi-Signal Bayesian Fusion Engine        │
             │     Risk Score (0-100) & Action Classification   │
             └────────────────────┬─────────────────────────────┘
                                  ▼
             ┌──────────────────────────────────────────────────┐
             │  1-Click CERT-In Automated Takedown Dossier (NCRP)│
             └──────────────────────────────────────────────────┘
```

---

## 🚀 2. Quick Start (Run in 1 Command)

### Prerequisites:
- Python 3.9+ (Python 3.10 / 3.11 / 3.12 recommended)
- Optional: `GEMINI_API_KEY` environment variable (if using Gemini 2.0 Flash multimodal AI)

### Step 1: Install Dependencies
```bash
pip install -r backend/requirements.txt
```

### Step 2: Start Backend Server
```bash
python run_backend.py
```
*The server will start immediately at `http://127.0.0.1:8000`.*  
*Interactive Swagger API documentation is available at `http://127.0.0.1:8000/docs`.*

---

## 📡 3. API Endpoints Reference

### Endpoint 1: Full AI Multi-Modal Scan (`POST /api/scan`)

Performs a 5-tier inspection combining lexical typosquatting, DOM form analysis, visual pHash similarity, WHOIS domain age, and Gemini 2.0 Flash AI reasoning.

#### **Request Body (`application/json`)**:
```json
{
  "url": "https://gst-refund.example",
  "html_content": "<form><input name='aadhaar_number'><input name='otp'></form>",
  "image_base64": ""
}
```

#### **Response (`application/json`)**:
```json
{
  "url": "https://gst-refund.example",
  "verdict": "PHISHING_CLONE",
  "risk_score": 88,
  "threat_level": "HIGH",
  "target_entity": "Goods and Services Tax (GST) Portal",
  "is_genuine_gov_tld": false,
  "impersonated": true,
  "summary": "CRITICAL: Deceptive clone mimicking Goods and Services Tax (GST) Portal.",
  "reasons": [
    "AI Insight: High-confidence zero-day phishing clone impersonating Indian public welfare/tax services.",
    "Unauthorized non-government domain uses official keywords of 'Goods and Services Tax (GST) Portal'.",
    "Contains urgent or financial action keywords: refund",
    "Contains high-value citizen identity fields (Aadhaar/PAN/OTP) on non-governmental domain: aadhaar_number, otp"
  ],
  "signal_breakdown": {
    "lexical_score": 100.0,
    "dom_score": 50.0,
    "visual_similarity": 85.0,
    "domain_age_days": 6,
    "sensitive_fields_found": ["aadhaar_number", "otp"],
    "registrar": "Public Registrar"
  },
  "genai_analysis": {
    "status": "SUCCESS",
    "model_used": "gemini-2.0-flash",
    "threat_category": "Zero-Day Government Scheme Phishing Clone",
    "plain_english_explanation": "Critical zero-day phishing clone. Domain attempts unauthorized brand injection of GST services.",
    "certin_mitigation_action": "Direct ISP/TSP DNS blocking under Section 69A IT Act."
  }
}
```

---

### Endpoint 2: Automated CERT-In Dossier Generation (`POST /api/report-certin`)

Generates a formal forensic cybersecurity incident report ready for transmission to the Indian Computer Emergency Response Team (CERT-In) and NCRP cybercrime cells.

#### **Request Body (`application/json`)**:
```json
{
  "scan_result": {
    "url": "https://gst-refund.example",
    "verdict": "PHISHING_CLONE",
    "risk_score": 88,
    "target_entity": "Goods and Services Tax (GST) Portal"
  },
  "reporter_notes": "Submitted via GovShield Citizen Web Portal"
}
```

#### **Response (`application/json`)**:
```json
{
  "status": "DISPATCHED",
  "message": "Incident dossier logged and forwarded to CERT-In automated ingestion triage.",
  "incident_report": {
    "incident_id": "CERTIN-INC-XXXX",
    "timestamp": "2026-08-31T05:30:00Z",
    "classification": "PHISHING_CLONE",
    "risk_score": 88,
    "target_government_entity": "Goods and Services Tax (GST) Portal",
    "malicious_url": "https://gst-refund.example",
    "forensic_evidence": {
      "lexical_typosquatting": 100.0,
      "credential_harvesting_inputs": ["aadhaar_number", "otp"],
      "domain_age_days": 6
    },
    "mitigation_recommendations": [
      "Issue urgent DNS sinkhole via NIXI / INRegistry.",
      "Direct ISP/TSP DNS blocking under Section 69A IT Act.",
      "Notify CERT-In Incident Response Team (incident@cert-in.org.in)."
    ]
  }
}
```

---

### Endpoint 3: System Health Check (`GET /api/health`)

#### **Response (`application/json`)**:
```json
{
  "status": "online",
  "system": "GovShield Sentinel Grid",
  "models_loaded": {
    "lexical_typosquatting": true,
    "dom_form_inspector": true,
    "visual_phash_matcher": true,
    "whois_age_evaluator": true,
    "fusion_risk_engine": true,
    "multimodal_genai_agent": true
  },
  "ai_model": "gemini-2.0-flash",
  "indexed_reference_portals_count": 16
}
```

---

## 💻 4. Frontend Integration Code (Copy-Paste Ready)

### Vanilla JavaScript / Web Dashboard
```javascript
// Scan any URL
async function inspectWebsite(targetUrl) {
  try {
    const response = await fetch("http://127.0.0.1:8000/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: targetUrl })
    });
    const data = await response.json();
    
    console.log("Risk Score (0-100):", data.risk_score);
    console.log("Verdict:", data.verdict); // "LEGITIMATE", "SUSPICIOUS", "PHISHING_CLONE"
    console.log("Target Entity:", data.target_entity);
    console.log("AI Explanation:", data.genai_analysis?.plain_english_explanation);
    return data;
  } catch (error) {
    console.error("Backend offline:", error);
  }
}

// Generate CERT-In Incident Dossier
async function generateCertInReport(scanData) {
  const resp = await fetch("http://127.0.0.1:8000/api/report-certin", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      scan_result: scanData,
      reporter_notes: "Citizen threat report via Web Portal"
    })
  });
  return await resp.json();
}
```

### React / Next.js Hook Example
```tsx
import { useState } from 'react';

export function useGovShield() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const scan = async (url: string) => {
    setLoading(true);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      const data = await res.json();
      setResult(data);
      return data;
    } finally {
      setLoading(false);
    }
  };

  return { scan, result, loading };
}
```

---

## 🧪 5. Automated Verification Tests

Run the full end-to-end test suite passing all 7 real-world test cases:
```bash
python test_system.py
```

### Test Suite Output:
- `[TEST 1]` Genuine Government Portal (`pmkisan.gov.in`) $\rightarrow$ `Score: 2/100 (Safe Official)`
- `[TEST 2]` Phishing Clone (`pmkisan-kyc-update.xyz`) $\rightarrow$ `Score: 88/100 (PHISHING CLONE)`
- `[TEST 3]` CERT-In Dossier Generation $\rightarrow$ `Dispatched with Incident ID & Evidence`
- `[TEST 4]` Commercial Platform (`chatgpt.com`) $\rightarrow$ `Score: 0/100 (Safe Commercial)`
- `[TEST 5]` Search Engine (`bing.com`) $\rightarrow$ `Score: 0/100 (Safe Search Engine)`
- `[TEST 6]` Lookalike Tax Domain (`income-tax-refund.example`) $\rightarrow$ `Score: 88/100 (PHISHING CLONE)`
- `[TEST 7]` Lookalike GST Domain (`gst-refund.example`) $\rightarrow$ `Score: 88/100 (PHISHING CLONE)`

---

## 📂 6. Directory Structure

```
SIH/
├── backend/
│   ├── main.py                  # FastAPI server & route handlers
│   ├── requirements.txt         # Core Python dependencies
│   ├── modules/
│   │   ├── ai_agent.py          # Gemini 2.0 Flash AI Autonomous Agent
│   │   ├── lexical_analyzer.py  # Typosquatting, Levenshtein & Brand Token Engine
│   │   ├── dom_analyzer.py      # Form & Credential Theft Inspector (Aadhaar/PAN/OTP)
│   │   ├── visual_analyzer.py   # Perceptual pHash & Visual Template Matcher
│   │   ├── whois_analyzer.py    # WHOIS Domain Age & NRD Verification
│   │   ├── fusion_engine.py     # Multi-Signal AI/ML Risk Scoring & Fusion
│   │   ├── reference_database.py# Sovereign Indian Government Portal Registry
│   │   └── certin_reporter.py   # CERT-In Incident Dossier Generator
│   └── tests/
│       └── test_api.py          # FastAPI Integration Test Suite
├── website/                     # Responsive Web Portal (Swiss Brutalist Design)
│   ├── index.html               # Web portal markup
│   ├── style.css                # Cohesive responsive styling
│   └── app.js                   # Live API integration controller
├── extension/                   # Chrome Extension (Manifest V3)
│   ├── popup/                   # Popup matching website 1:1
│   ├── content.js               # In-page real-time warning injection
│   └── background.js            # Tab navigation & live scanning listener
├── run_backend.py               # Standalone 1-click backend runner
├── test_system.py               # System verification test suite
├── start_all.ps1                # PowerShell launcher (Headless)
├── start_all.bat                # Batch launcher (Headless)
├── stop_all.ps1                 # Clean process stopper
└── INTEGRATION_GUIDE.md         # This technical documentation
```
