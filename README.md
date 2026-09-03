# 🛡️ Sentinel Grid (GovShield)
### Multi-Modal AI/ML Verification Layer for Phishing & Government Lookalike Domain Detection
**Smart India Hackathon 2026 | Problem Statement ID: SIH1454**  
**Team:** Unbound | **Theme:** Blockchain & Cybersecurity  

---

## 📌 Problem Overview & Alignment
Phishing kits actively clone Indian Government web portals (PM-Kisan, Income Tax, UIDAI/Aadhaar, Parivahan, EPF, Passport Seva) pixel-for-pixel—mimicking logos, color palettes, form fields, and error messages. Traditional URL-blacklists miss newly registered zero-day domains. 

**Sentinel Grid (GovShield)** provides a real-time, multi-signal verification system combining **lexical typosquatting analysis**, **DOM credential-harvesting inspection**, **visual perceptual hash matching**, and **WHOIS domain freshness verification** to detect and neutralize phishing lookalike sites.

---

## 🏗️ System Architecture

```
[ Citizen Navigates to URL ] 
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│  GovShield Chrome Extension (Manifest V3)                   │
│  • Instant Badge (🟢 SAFE / 🟡 SUSP / 🔴 RISK)              │
│  • Non-intrusive In-Page Warning on High-Risk Sites        │
│  • Edge Heuristic Fallback Engine                           │
└───────────────────────────┬─────────────────────────────────┘
                            │ (POST /api/scan)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  FastAPI AI/ML Multi-Modal Verification Backend             │
│                                                             │
│  1. 🔤 Lexical & Typosquatting Analyzer                     │
│     - Levenshtein distance against authentic portals        │
│     - Shannon entropy & suspicious TLD evaluation           │
│                                                             │
│  2. 🛡️ DOM & Content Structure Analyzer                    │
│     - Aadhaar / PAN / OTP / Password harvester detection    │
│     - External asset hotlinking ratio calculation           │
│                                                             │
│  3. 🖼️ Visual Perceptual Similarity Engine                 │
│     - Perceptual image hashing (pHash / dHash)              │
│     - Emblem & layout profile similarity (0-100%)           │
│                                                             │
│  4. 📅 WHOIS & Domain Age Evaluator                         │
│     - Newly Registered Domain (NRD) risk factor (<30 days)  │
│                                                             │
│  5. 🧠 Multi-Signal Risk Fusion Engine                      │
│     - Calibrated 0–100 risk score + explainable reasons     │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Sovereign Blockchain Threat Intelligence Ledger (PoA)     │
│  • Tamper-evident SHA-256 block chaining & Merkle trees     │
│  • Proof-of-Authority nodes (NIC, CERT-In, NIXI, MeitY)     │
│  • Section 65B Indian Evidence Act court certificates       │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Bharat-First Rural Citizen Defense & Accessibility Hub     │
│  • Bilingual UI: Instant English & हिंदी vernacular toggle  │
│  • Ultra-Lite Bharat Mode: Optimized for budget 2G/3G phones│
│  • 🔊 Web Speech Voice Advisory for semi-literate citizens  │
│  • 📞 1-Tap 1930 National Cyber Financial Fraud Helpline    │
│  • Section 69A IT Act emergency takedown dossiers           │
└─────────────────────────────────────────────────────────────┘
```

---

## 📂 Project Structure

```
SIH/
├── backend/
│   ├── requirements.txt            # Python dependencies
│   ├── main.py                     # FastAPI REST API endpoints
│   └── modules/
│       ├── blockchain_ledger.py    # Sovereign Blockchain Ledger (PoA + Sec 65B)
│       ├── reference_database.py   # Ground-truth Gov portals database
│       ├── lexical_analyzer.py     # URL string & typosquatting analysis
│       ├── dom_analyzer.py         # DOM forms & sensitive inputs inspection
│       ├── visual_analyzer.py      # Perceptual hash & visual clone matching
│       ├── whois_analyzer.py       # Domain registration age & WHOIS
│       ├── fusion_engine.py        # Multi-signal AI/ML risk fusion
│       └── certin_reporter.py      # CERT-In takedown incident exporter
│
├── website/
│   ├── index.html                  # Sovereign Sentinel Grid Web Portal
│   ├── style.css                   # Responsive CSS + Ultra-Lite Bharat Mode
│   └── app.js                      # Bilingual, Voice Advisory & Blockchain Explorer
│
├── extension/
│   ├── manifest.json               # Manifest V3 configuration
│   ├── background.js               # Service worker with tab listeners & edge fallback
│   ├── content.js                  # In-page DOM inspector & Hindi/English alert banner
│   ├── content.css                 # Banner styling
│   └── popup/
│       ├── popup.html              # Government cyber defense UI (1930 & Voice)
│       ├── popup.css               # Minimal dark theme & animated risk gauge
│       └── popup.js                # Bilingual controller & PoA ledger badge
│
├── demo/
│   ├── mock_phishing_server.py     # Local test harness on port 8080
│   └── templates/
│       ├── pmkisan_genuine.html    # Authentic portal replica
│       └── pmkisan_phishing_clone.html # Zero-day credential harvesting clone
│
├── run_backend.py                  # AI Backend runner (port 8000)
├── test_system.py                  # Automated test suite
├── start_all.ps1                   # 1-click startup script (PowerShell)
├── start_all.bat                   # 1-click startup script (Batch)
└── README.md
```

---

## ⚡ Quick Start & Setup

### 1. Install Backend Dependencies
```powershell
pip install -r backend/requirements.txt
```

### 2. Launch the System (1-Click)
Run the automated launcher script:
```powershell
.\start_all.ps1
```
*(Or double-click `start_all.bat`)*

This starts:
- **FastAPI AI Backend**: `http://127.0.0.1:8000` (Docs: `http://127.0.0.1:8000/docs`)
- **Hackathon Test Simulation Hub**: `http://localhost:8080`

### 3. Install the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle on **"Developer mode"** (top-right switch).
3. Click **"Load unpacked"** and select the `c:\Users\DELL\Desktop\SIH\extension` folder.
4. Pin the **GovShield** icon to your Chrome toolbar.

---

## 🧪 Live Demonstration Guide (For Evaluators & Jury)

1. Open `http://localhost:8080` in Chrome to access the test harness.
2. **Scenario 1 (Authentic Portal)**: Click **"Launch Genuine Scenario"** (`/pmkisan-official`).
   - Notice the GovShield badge displays **`SAFE`** (🟢 Green).
   - Click the extension icon to see: **0/100 Risk Score**, *"Verified Official Portal"*.
3. **Scenario 2 (Zero-Day Phishing Clone)**: Click **"Launch Phishing Clone"** (`/pmkisan-kyc-update`).
   - Notice the GovShield badge changes to **`RISK`** (🔴 Red).
   - An in-page **GovShield Cyber Alert Banner** appears at the top.
   - Click the extension popup to view:
     - **85–95 Risk Score**
     - **Target Impersonation:** PM-Kisan Portal
     - **Forensic Breakdown:** 94% Visual Clone similarity, Aadhaar/OTP harvesting forms detected, unverified domain.
4. **Scenario 3 (CERT-In Dossier Generation)**:
   - Click **"Generate CERT-In Dossier"** in the popup.
   - Inspect the compiled forensic incident JSON and click **"Download JSON"** or **"Transmit to Cyber Cell"**.
