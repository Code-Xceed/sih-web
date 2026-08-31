# SatyaGov / CyberRakshak AI
### Indian Sovereign Government Phishing & Fake Website Detection System
**Smart India Hackathon (SIH) Cybersecurity Project**

---

## 🎯 Problem Statement
In India, fraudulent clone websites and phishing SMS (smishing) campaigns impersonating sovereign government portals result in hundreds of crores lost by ordinary citizens annually. Cybercriminals clone official interfaces of:
- **UIDAI (Aadhaar)** — Harvesting biometric & OTP credentials via fake "Urgent KYC" traps.
- **Income Tax Department** — Stealing net banking passwords under the guise of "Instant Tax Refund Claims".
- **PM-Kisan Samman Nidhi** — Tricking farmers with fake ₹6,000 installment links on `.online` / `.site` domains.
- **Parivahan Sewa / State Police** — Sending fake traffic e-Challan SMS alerts offering 50% fake fine discounts.
- **State Electricity Boards** — Threatening power disconnections tonight unless a fake bill payment portal is visited.

Standard anti-phishing filters often fail because scammers use legitimate free SSL certificates (Let's Encrypt / ZeroSSL), subdomains containing `gov.in` (e.g. `uidai.gov.in.attacker-host.top`), and Cyrillic homoglyphs.

---

## 🛡️ Key Innovations & 6-Layer Detection Pipeline

```
[ Input: Website URL / Domain / SMS Text ]
                    │
                    ▼
┌───────────────────────────────────────────────────────────┐
│              6-Layer Sovereign AI Engine                  │
├───────────────────────────────────────────────────────────┤
│ 1. Sovereign Hierarchy & TLD Validator (.gov.in, .nic.in) │
│ 2. Typosquatting & Levenshtein Matrix (70+ Portals)       │
│ 3. Homograph & Unicode / Punycode (IDN) Spoofing Engine   │
│ 4. Shannon Entropy & Lexical DGA / Hyphen Scorer          │
│ 5. Social Engineering NLP Lure Detector (Scam Keywords)   │
│ 6. Explainable AI Threat Scorer (0-100) + CERT-In Dossier │
└───────────────────────────────────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────────────┐
│                    Minimalist Clean UI                    │
├───────────────────────────────────────────────────────────┤
│ • Instant Live Risk Gauge (0-100 Threat Index)            │
│ • Explainable SHAP-style Risk Weight Visual Breakdown     │
│ • SMS / WhatsApp Smishing Parser with Social Lure Badges  │
│ • Verified Indian Government Portals Directory            │
│ • Batch URL Triage Scanner with CSV Export for Cyber Cells│
│ • 1-Click CERT-In (incident@cert-in.org.in) Dossier Export│
└───────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Features

1. **Instant URL Inspector**:
   - Zero false-positives on genuine sovereign domains (`.gov.in`, `.nic.in`, `irctc.co.in`, `onlinesbi.sbi`).
   - Deep inspection against subdomain masquerading (e.g., `incometax.gov.in.xyz-fake.com`).
   - Pre-loaded test cases for fast jury demonstrations.

2. **Smishing (SMS / WhatsApp) Detector**:
   - Analyzes raw SMS notices sent to citizens.
   - Identifies urgency triggers (*"Electricity will be disconnected tonight at 9:30 PM"*, *"PM Kisan 17th Installment credited"*).
   - Extracts embedded URLs and scores the overall scam risk.

3. **Verified Sovereign Portals Directory**:
   - Curated directory of 70+ official Indian government portals across Central, State, Identity, Taxation, Transport, Welfare, and Judicial sectors.

4. **Cyber Cell Batch Scanner**:
   - Analyzes dozens of URLs in one go.
   - Exports CSV triage report for domain blocking requests and NIXI / INRegistry takedowns.

5. **CERT-In Incident Dossier Generator**:
   - Formats a complete legal & technical incident report ready for submission to **CERT-In (`incident@cert-in.org.in`)** and the **National Cyber Crime Reporting Portal (`cybercrime.gov.in`)**.

---

## 💻 Tech Stack
- **Frontend**: Pure Semantic HTML5, Minimalist Cyber-defense CSS3 (with Dark/Light Themes), Modern Vanilla JavaScript (ES6+ Modules).
- **Engine**: Pure algorithmic & heuristic engine with Levenshtein distance calculation, Shannon Entropy math, Unicode homoglyph matrix, and regular expression NLP parsers.
- **Zero External Runtime Dependencies**: Runs standalone in any modern browser without requiring Node.js, Python, or build steps.

---

## 🧪 How to Test / Run

1. Open `index.html` in any web browser (Chrome, Firefox, Safari, Edge, or via Live Server).
2. Click any of the **SIH Test Presets** to test real-world scenarios:
   - **Fake PM Kisan**: `https://pmkisan-gov-in-update.online/claim-6000` (Scored High Risk Phishing)
   - **Fake e-Challan**: `https://echallan-parivahan-gov-in.top/pay-discount` (Scored High Risk Phishing)
   - **Fake Income Tax**: `https://incometaxindia-efiling.in.net/tax-refund-claim` (Scored High Risk Typosquatting)
   - **Genuine UIDAI**: `https://uidai.gov.in` (Scored Safe / Verified Sovereign)
   - **Genuine DigiLocker**: `https://digilocker.gov.in` (Scored Safe / Verified Sovereign)
3. Switch to the **SMS / Smishing Tab** and try the preloaded scam SMS samples.
4. Click **View Dossier / File CERT-In Report** to see the auto-generated takedown submission.

---

## 📜 License
Developed for the **Smart India Hackathon (SIH)**. Free and open-source for public cybersecurity awareness.
