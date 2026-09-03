# 🛡️ GovShield Sentinel Grid 3.0 — Chrome Web Store Submission Guide

This document is your complete copy-paste guide for publishing **GovShield Sentinel Grid 3.0** on the [Chrome Developer Dashboard](https://chrome.google.com/webstore/devconsole).

---

## 1. Store Listing Details

### Extension Name
GovShield Sentinel Grid 3.0 — Sovereign Cyber Defense

### Summary (132 characters max)
Real-time AI detection of fake government portals, typosquats, and citizen credential phishing. UX4G 3.0 Government Standard (SIH1454).

### Category
Productivity / Developer Tools OR Privacy & Security

### Detailed Description
🛡️ Protect yourself against fake government portals, typosquat scams, and credential theft with GovShield Sentinel Grid 3.0.

Developed under the Smart India Hackathon (SIH1454) and built in strict accordance with the Government of India UX4G 3.0 Design System, GovShield delivers real-time sovereign AI protection for 1.4 billion citizens navigating online services.

Key Capabilities:
⚡ Real-Time Zero-Day Detection: Instantly verifies whether the site you visit is an authentic Indian Government infrastructure (.gov.in / .nic.in) or a deceptive lookalike clone.
🤖 AI Webpage & Domain Synthesis: Evaluates form fields, sensitive input elements (Aadhaar, PAN, OTP, Bank details), and page intent with explainable natural language insights.
🚨 Centered Emergency Warning Alerts: High-visibility in-page warning banner displays on fraudulent sites with direct 1-click incident reporting to the National Cyber Crime Reporting Portal (cybercrime.gov.in).
📞 Instant National Helpline Access: One-click calling to the 1930 National Cyber Crime Helpline.
🌐 Multilingual Citizen Support: Full localized support across 12 scheduled languages: English, Hindi, Bengali, Tamil, Telugu, Marathi, Gujarati, Kannada, Malayalam, Punjabi, Odia, and Assamese.
⛓️ Proof-of-Authority (PoA) Blockchain Proofs: Tamper-proof, cryptographically verifiable threat dossiers admissible under Section 65B of the Indian Evidence Act (BSA 2023).

---

## 2. Permissions Justifications (Required by Google Review Team)

| Permission | Purpose / Justification for Review Team |
| :--- | :--- |
| tabs | Required to detect URL changes when the user navigates between browser tabs in order to evaluate domain authenticity and update the toolbar security badge in real time. |
| activeTab | Required to inspect the active webpage DOM when the user opens the extension popup, enabling analysis of sensitive input fields (e.g., forms soliciting Aadhaar or bank credentials). |
| storage | Required to store user language preference and user UI theme preference locally in chrome.storage.local. |
| alarms | Required to schedule periodic cache cleanup routines to manage browser memory and refresh stale threat intelligence entries without keeping the background worker running continuously. |
| Host Permission: <all_urls> | Required because credential harvesting and fake government portal clones can be hosted on any top-level domain (.xyz, .top, .site). The extension must inject defensive alerts and verify domain integrity across any website the citizen visits. |
