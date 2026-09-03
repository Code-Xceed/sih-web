"""
Reference Database for Authentic Indian Government Portals and Services.
Provides ground truth signatures, domain aliases, visual baselines, and keyword fingerprints.
"""

GOVERNMENT_TLDS = {
    "gov.in",
    "nic.in",
    "ac.in",
    "res.in",
    "edu.in",
    "mil.in",
    "police.uk",  # for generic testing
    "org.in"
}

GENUINE_PORTALS = {
    "pmkisan": {
        "id": "pmkisan",
        "name": "PM-Kisan Samman Nidhi Portal",
        "department": "Ministry of Agriculture & Farmers Welfare, Govt of India",
        "primary_domain": "pmkisan.gov.in",
        "valid_domains": ["pmkisan.gov.in", "pmkisan-nic.in", "pmkisan.nic.in"],
        "keywords": [
            "pm kisan", "samman nidhi", "farmer", "ekyc", "aadhaar verification",
            "beneficiary status", "installment", "kisan credit card", "dbt agriculture"
        ],
        "sensitive_fields": ["aadhaar", "mobile", "account_number", "otp"],
        "official_emblems": ["ashoka_pillar", "digital_india", "agriculture_ministry"],
        "visual_signature": {
            "primary_color": "#1B5E20",  # Green banner
            "secondary_color": "#FF6F00", # Saffron/Orange accent
            "layout_type": "govt_portal_standard",
            "has_tricolor_header": True
        }
    },
    "incometax": {
        "id": "incometax",
        "name": "Income Tax e-Filing Portal",
        "department": "Income Tax Department, Ministry of Finance, Govt of India",
        "primary_domain": "incometax.gov.in",
        "valid_domains": ["incometax.gov.in", "incometaxindiaefiling.gov.in", "eportal.incometax.gov.in"],
        "keywords": [
            "income tax", "e-filing", "itr", "tax return", "pan card",
            "tax refund", "tds", "form 26as", "assessment year", "instant e-pan"
        ],
        "sensitive_fields": ["pan", "password", "bank_account", "otp", "aadhaar"],
        "official_emblems": ["ashoka_pillar", "income_tax_emblem"],
        "visual_signature": {
            "primary_color": "#0D47A1",  # Deep Navy Blue
            "secondary_color": "#D32F2F",
            "layout_type": "tax_portal",
            "has_tricolor_header": True
        }
    },
    "uidai": {
        "id": "uidai",
        "name": "UIDAI - Unique Identification Authority of India (Aadhaar)",
        "department": "Ministry of Electronics & Information Technology, Govt of India",
        "primary_domain": "uidai.gov.in",
        "valid_domains": ["uidai.gov.in", "myaadhaar.uidai.gov.in", "resident.uidai.gov.in"],
        "keywords": [
            "uidai", "aadhaar", "myaadhaar", "download aadhaar", "update aadhaar",
            "aadhaar pvc", "verify aadhaar", "enrollment", "biometrics lock", "vid"
        ],
        "sensitive_fields": ["aadhaar_number", "enrolment_id", "mobile_otp", "biometric_data", "captcha"],
        "official_emblems": ["ashoka_pillar", "aadhaar_logo", "meity_logo"],
        "visual_signature": {
            "primary_color": "#C62828",  # Aadhaar Red/Burgundy
            "secondary_color": "#EF6C00",
            "layout_type": "aadhaar_portal",
            "has_tricolor_header": True
        }
    },
    "parivahan": {
        "id": "parivahan",
        "name": "Parivahan Sewa - National Transport Portal",
        "department": "Ministry of Road Transport & Highways, Govt of India",
        "primary_domain": "parivahan.gov.in",
        "valid_domains": ["parivahan.gov.in", "sarathi.parivahan.gov.in", "vahan.parivahan.gov.in"],
        "keywords": [
            "parivahan", "driving licence", "vahan", "sarathi", "vehicle registration",
            "rc status", "challan payment", "e-challan", "dl renewal"
        ],
        "sensitive_fields": ["dl_number", "application_no", "rc_no", "chassis_no", "otp"],
        "official_emblems": ["ashoka_pillar", "morth_logo", "nic_logo"],
        "visual_signature": {
            "primary_color": "#1A237E",  # Indigo/Blue
            "secondary_color": "#388E3C",
            "layout_type": "transport_portal",
            "has_tricolor_header": True
        }
    },
    "epfindia": {
        "id": "epfindia",
        "name": "Employees' Provident Fund Organisation (EPFO)",
        "department": "Ministry of Labour & Employment, Govt of India",
        "primary_domain": "epfindia.gov.in",
        "valid_domains": ["epfindia.gov.in", "unifiedportal-mem.epfindia.gov.in", "passbook.epfindia.gov.in"],
        "keywords": [
            "epfo", "epf india", "uan", "universal account number", "provident fund",
            "epf passbook", "pf claim", "pensioner portal", "pf balance"
        ],
        "sensitive_fields": ["uan", "password", "pan", "aadhaar", "bank_account", "otp"],
        "official_emblems": ["ashoka_pillar", "epfo_logo"],
        "visual_signature": {
            "primary_color": "#004D40",  # Dark Teal
            "secondary_color": "#FF8F00",
            "layout_type": "epfo_member_portal",
            "has_tricolor_header": True
        }
    },
    "passport": {
        "id": "passport",
        "name": "Passport Seva Portal",
        "department": "Ministry of External Affairs, Govt of India",
        "primary_domain": "passportindia.gov.in",
        "valid_domains": ["passportindia.gov.in", "portal2.passportindia.gov.in"],
        "keywords": [
            "passport seva", "apply passport", "tatkaal passport", "appointment availability",
            "track status", "police clearance certificate", "mea"
        ],
        "sensitive_fields": ["user_id", "password", "application_number", "dob"],
        "official_emblems": ["ashoka_pillar", "mea_emblem"],
        "visual_signature": {
            "primary_color": "#0A192F",
            "secondary_color": "#FF9933",
            "layout_type": "passport_portal",
            "has_tricolor_header": True
        }
    },
    "digilocker": {
        "id": "digilocker",
        "name": "DigiLocker - Document Wallet",
        "department": "National e-Governance Division (NeGD), MeitY, Govt of India",
        "primary_domain": "digilocker.gov.in",
        "valid_domains": ["digilocker.gov.in", "accounts.digilocker.gov.in"],
        "keywords": [
            "digilocker", "digital document", "issued documents", "driving licence",
            "aadhaar card", "cbse marksheet", "pin verify", "sign in digilocker"
        ],
        "sensitive_fields": ["mobile_number", "aadhaar", "security_pin", "otp"],
        "official_emblems": ["ashoka_pillar", "digilocker_emblem", "digital_india"],
        "visual_signature": {
            "primary_color": "#0052CC",
            "secondary_color": "#00875A",
            "layout_type": "digilocker_app",
            "has_tricolor_header": False
        }
    },
    "indiagovin": {
        "id": "indiagovin",
        "name": "National Portal of India",
        "department": "National Informatics Centre (NIC), Govt of India",
        "primary_domain": "india.gov.in",
        "valid_domains": ["india.gov.in", "services.india.gov.in"],
        "keywords": [
            "national portal of india", "india.gov.in", "government services",
            "ministries", "acts and rules", "gazette", "schemes"
        ],
        "sensitive_fields": ["search_query"],
        "official_emblems": ["ashoka_pillar", "nic_logo", "digital_india"],
        "visual_signature": {
            "primary_color": "#003366",
            "secondary_color": "#FF9933",
            "layout_type": "national_gateway",
            "has_tricolor_header": True
        }
    },
    "cybercrime": {
        "id": "cybercrime",
        "name": "National Cyber Crime Reporting Portal (NCRP)",
        "department": "Indian Cyber Crime Coordination Centre (I4C), MHA, Govt of India",
        "primary_domain": "cybercrime.gov.in",
        "valid_domains": ["cybercrime.gov.in"],
        "keywords": [
            "cybercrime", "report cyber crime", "ncrp", "financial fraud",
            "helpline 1930", "citizen complaint", "cyber volunteer"
        ],
        "sensitive_fields": ["login_id", "password", "otp", "mobile"],
        "official_emblems": ["ashoka_pillar", "i4c_emblem", "mha_logo"],
        "visual_signature": {
            "primary_color": "#1A365D",
            "secondary_color": "#E53E3E",
            "layout_type": "security_portal",
            "has_tricolor_header": True
        }
    },
    "scholarships": {
        "id": "scholarships",
        "name": "National Scholarship Portal (NSP)",
        "department": "Ministry of Electronics & Information Technology, Govt of India",
        "primary_domain": "scholarships.gov.in",
        "valid_domains": ["scholarships.gov.in"],
        "keywords": [
            "national scholarship portal", "nsp", "student scholarship", "apply scholarship",
            "dbt scholarship", "aadhaar seeding", "bonafide"
        ],
        "sensitive_fields": ["application_id", "password", "aadhaar", "bank_account", "otp"],
        "official_emblems": ["ashoka_pillar", "meity_logo", "digital_india"],
        "visual_signature": {
            "primary_color": "#004D40",
            "secondary_color": "#FF6F00",
            "layout_type": "scholarship_portal",
            "has_tricolor_header": True
        }
    },
    "irctc": {
        "id": "irctc",
        "name": "IRCTC - Indian Railway Catering and Tourism Corporation",
        "department": "Ministry of Railways, Govt of India",
        "primary_domain": "irctc.co.in",
        "valid_domains": ["irctc.co.in", "www.irctc.co.in", "indianrail.gov.in"],
        "keywords": [
            "irctc", "indian railway", "train ticket", "tatkal ticket",
            "pnr status", "railway reservation", "vande bharat"
        ],
        "sensitive_fields": ["user_name", "password", "captcha", "card_number", "upi_pin", "otp"],
        "official_emblems": ["railway_emblem", "irctc_logo", "ashoka_pillar"],
        "visual_signature": {
            "primary_color": "#002B49",
            "secondary_color": "#FB641B",
            "layout_type": "railway_booking",
            "has_tricolor_header": False
        }
    },
    "cbse": {
        "id": "cbse",
        "name": "CBSE - Central Board of Secondary Education",
        "department": "Ministry of Education, Govt of India",
        "primary_domain": "cbse.gov.in",
        "valid_domains": ["cbse.gov.in", "cbseresults.nic.in", "results.cbse.nic.in"],
        "keywords": [
            "cbse", "central board", "board exam", "cbse results",
            "admit card", "roll number", "class 10 result", "class 12 result"
        ],
        "sensitive_fields": ["roll_number", "school_no", "center_no", "admit_card_id"],
        "official_emblems": ["ashoka_pillar", "cbse_emblem"],
        "visual_signature": {
            "primary_color": "#1E3A8A",
            "secondary_color": "#D97706",
            "layout_type": "education_portal",
            "has_tricolor_header": True
        }
    },
    "gst": {
        "id": "gst",
        "name": "Goods and Services Tax (GST) Portal",
        "department": "GST Council, CBIC, Ministry of Finance, Govt of India",
        "primary_domain": "gst.gov.in",
        "valid_domains": ["gst.gov.in", "services.gst.gov.in", "gstn.org.in", "ewaybillgst.gov.in"],
        "keywords": [
            "gst", "goods and services tax", "gst refund", "gst return", "gst registration",
            "gstin", "gstr", "input tax credit", "cbic", "eway bill", "taxpayers login"
        ],
        "sensitive_fields": ["gstin", "username", "password", "bank_account", "otp", "pan"],
        "official_emblems": ["ashoka_pillar", "gst_logo", "cbic_logo"],
        "visual_signature": {
            "primary_color": "#0B3C5D",
            "secondary_color": "#D9B310",
            "layout_type": "tax_gateway",
            "has_tricolor_header": True
        }
    },
    "ayushman": {
        "id": "ayushman",
        "name": "Ayushman Bharat PM-JAY Portal",
        "department": "National Health Authority (NHA), MoHFW, Govt of India",
        "primary_domain": "pmjay.gov.in",
        "valid_domains": ["pmjay.gov.in", "setu.pmjay.gov.in", "nha.gov.in", "beneficiary.nha.gov.in"],
        "keywords": [
            "ayushman", "ayushman bharat", "pmjay", "ayushman card", "health card",
            "free treatment", "golden card", "bis portal", "ekyc"
        ],
        "sensitive_fields": ["aadhaar_number", "mobile_number", "ration_card", "otp"],
        "official_emblems": ["ashoka_pillar", "pmjay_logo", "nha_logo"],
        "visual_signature": {
            "primary_color": "#00838F",
            "secondary_color": "#FF8F00",
            "layout_type": "health_portal",
            "has_tricolor_header": True
        }
    },
    "eshram": {
        "id": "eshram",
        "name": "e-Shram National Database of Unorganised Workers",
        "department": "Ministry of Labour & Employment, Govt of India",
        "primary_domain": "eshram.gov.in",
        "valid_domains": ["eshram.gov.in", "register.eshram.gov.in"],
        "keywords": [
            "eshram", "e-shram", "shramik card", "uan card", "labour card",
            "shramik kyc", "shramik registration", "shramik pension"
        ],
        "sensitive_fields": ["aadhaar_number", "mobile_otp", "bank_account", "nominee_details"],
        "official_emblems": ["ashoka_pillar", "eshram_logo"],
        "visual_signature": {
            "primary_color": "#E65100",
            "secondary_color": "#1B5E20",
            "layout_type": "labour_portal",
            "has_tricolor_header": True
        }
    },
    "voter": {
        "id": "voter",
        "name": "ECI Voters' Services Portal (NVSP)",
        "department": "Election Commission of India (ECI)",
        "primary_domain": "voters.eci.gov.in",
        "valid_domains": ["voters.eci.gov.in", "eci.gov.in", "nvsp.in"],
        "keywords": [
            "voter", "voter id", "epic", "nvsp", "election commission",
            "download epic", "voter registration", "electoral roll"
        ],
        "sensitive_fields": ["epic_number", "mobile_number", "password", "otp"],
        "official_emblems": ["ashoka_pillar", "eci_logo"],
        "visual_signature": {
            "primary_color": "#1565C0",
            "secondary_color": "#FF6D00",
            "layout_type": "voter_portal",
            "has_tricolor_header": True
        }
    },
    "sbi": {
        "id": "sbi",
        "name": "State Bank of India (SBI)",
        "department": "Public Sector Banking & National Financial Infrastructure",
        "primary_domain": "onlinesbi.sbi",
        "valid_domains": ["onlinesbi.sbi", "sbi.co.in", "bank.sbi"],
        "keywords": [
            "state bank of india", "sbi", "onlinesbi", "internet banking", "yono",
            "profile password", "cif number", "account number", "netbanking"
        ],
        "sensitive_fields": ["username", "password", "profile_password", "otp", "atm_pin"],
        "official_emblems": ["sbi_keyhole_logo"],
        "visual_signature": {
            "primary_color": "#280071",
            "secondary_color": "#00A3E0",
            "layout_type": "banking_portal",
            "has_tricolor_header": False
        }
    },
    "npci_upi": {
        "id": "npci_upi",
        "name": "Unified Payments Interface (UPI / NPCI)",
        "department": "National Payments Corporation of India (Reserve Bank of India)",
        "primary_domain": "npci.org.in",
        "valid_domains": ["npci.org.in", "upi.org.in", "bhimupi.org.in"],
        "keywords": [
            "upi", "npci", "bhim", "unified payments interface", "collect request",
            "upi pin", "qr code", "virtual payment address", "vpa"
        ],
        "sensitive_fields": ["upi_pin", "mpin", "otp", "mobile_number", "bank_account"],
        "official_emblems": ["npci_logo", "upi_logo"],
        "visual_signature": {
            "primary_color": "#F37021",
            "secondary_color": "#007A3D",
            "layout_type": "payment_portal",
            "has_tricolor_header": False
        }
    },
    "paytm": {
        "id": "paytm",
        "name": "Paytm Payments Bank & Wallet",
        "department": "Consumer Digital Banking & Payments Infrastructure",
        "primary_domain": "paytm.com",
        "valid_domains": ["paytm.com", "paytmbank.com"],
        "keywords": [
            "paytm", "paytm kyc", "paytm wallet", "passcode", "paytm fastag", "paytm payment"
        ],
        "sensitive_fields": ["mobile_number", "passcode", "password", "otp", "cvv"],
        "official_emblems": ["paytm_logo"],
        "visual_signature": {
            "primary_color": "#002E6E",
            "secondary_color": "#00BAF2",
            "layout_type": "fintech_portal",
            "has_tricolor_header": False
        }
    },
    "hdfc": {
        "id": "hdfc",
        "name": "HDFC Bank NetBanking",
        "department": "Scheduled Commercial Banking Infrastructure",
        "primary_domain": "hdfcbank.com",
        "valid_domains": ["hdfcbank.com", "netbanking.hdfcbank.com"],
        "keywords": [
            "hdfc", "hdfc bank", "netbanking", "customer id", "ipin", "credit card kyc"
        ],
        "sensitive_fields": ["customer_id", "password", "ipin", "otp", "card_number"],
        "official_emblems": ["hdfc_logo"],
        "visual_signature": {
            "primary_color": "#004C8F",
            "secondary_color": "#ED1C24",
            "layout_type": "banking_portal",
            "has_tricolor_header": False
        }
    },
    "icici": {
        "id": "icici",
        "name": "ICICI Bank Internet Banking",
        "department": "Scheduled Commercial Banking Infrastructure",
        "primary_domain": "icicibank.com",
        "valid_domains": ["icicibank.com", "infinity.icicibank.com"],
        "keywords": [
            "icici", "icici bank", "internet banking", "user id", "grid card", "imobile"
        ],
        "sensitive_fields": ["user_id", "password", "grid_values", "otp", "pin"],
        "official_emblems": ["icici_logo"],
        "visual_signature": {
            "primary_color": "#F58220",
            "secondary_color": "#9E1F24",
            "layout_type": "banking_portal",
            "has_tricolor_header": False
        }
    },
    "samagra": {
        "id": "samagra",
        "name": "Samagra Shiksha Abhiyan Portal",
        "department": "Department of School Education & Literacy, Ministry of Education, Govt of India",
        "primary_domain": "samagra.education.gov.in",
        "valid_domains": ["samagra.education.gov.in", "education.gov.in", "dsel.education.gov.in"],
        "keywords": [
            "samagra shiksha", "shiksha abhiyan", "sarva shiksha", "school education",
            "teacher recruitment", "shikshaabhiyan", "samagra", "shiksha mission"
        ],
        "aliases": ["samagra", "shikshaabhiyan", "sarvashiksha", "shiksha-abhiyan"],
        "sensitive_fields": ["registration_fee", "candidate_name", "aadhaar", "mobile"],
        "official_emblems": ["ashoka_pillar", "education_ministry_emblem"],
        "visual_signature": {
            "primary_color": "#003366",
            "secondary_color": "#FF9933",
            "layout_type": "education_portal",
            "has_tricolor_header": True
        }
    },
    "ssc": {
        "id": "ssc",
        "name": "Staff Selection Commission (SSC)",
        "department": "Department of Personnel and Training (DoPT), Govt of India",
        "primary_domain": "ssc.gov.in",
        "valid_domains": ["ssc.gov.in", "ssc.nic.in"],
        "keywords": ["ssc", "cgl", "chsl", "gd constable", "staff selection", "admit card", "recruitment"],
        "aliases": ["ssc", "staffselection"],
        "sensitive_fields": ["registration_no", "password", "captcha"],
        "official_emblems": ["ashoka_pillar", "ssc_logo"],
        "visual_signature": {
            "primary_color": "#1B365D",
            "secondary_color": "#D99B26",
            "layout_type": "recruitment_portal",
            "has_tricolor_header": True
        }
    },
    "pmvbry": {
        "id": "pmvbry",
        "name": "Pradhan Mantri Viksit Bharat Rozgar Yojana",
        "department": "Ministry of Labour & Employment, Govt of India",
        "primary_domain": "pmvbry.epfindia.gov.in",
        "valid_domains": ["pmvbry.epfindia.gov.in", "pmvbry.labour.gov.in"],
        "keywords": ["viksit bharat rozgar", "pmvbry", "rozgar yojana", "epfindia"],
        "aliases": ["pmvbry", "viksitbharat", "viksitbharatrozgar"],
        "sensitive_fields": ["uan", "aadhaar", "bank_account"],
        "official_emblems": ["ashoka_pillar"],
        "visual_signature": {
            "primary_color": "#0B3C5D",
            "secondary_color": "#328CC1",
            "layout_type": "employment_portal",
            "has_tricolor_header": True
        }
    }
}

# Core Sovereign & Public Infrastructure Brand Tokens
GOVERNMENT_BRAND_TOKENS = {
    "gst", "incometax", "income-tax", "pmkisan", "pm-kisan", "aadhaar", "aadhar",
    "uidai", "parivahan", "epfindia", "epfo", "passport", "digilocker", "cybercrime",
    "scholarship", "scholarships", "cbse", "irctc", "challan", "eshram", "e-shram",
    "samagra", "shikshaabhiyan", "sarvashiksha", "shiksha-abhiyan", "ssc", "pmvbry",
    "ayushman", "pmjay", "pmay", "rationcard", "ration-card", "voterid", "voter-id",
    "voter", "nvsp", "fastag", "jeevanpramaan", "swachhbharat", "digitalindia",
    # BFSI & Critical National Payment Systems
    "sbi", "statebank", "onlinesbi", "npci", "upi", "bhim", "paytm", "phonepe",
    "hdfc", "icici", "pnb", "baroda", "canara"
}

GOVERNMENT_ACTION_TOKENS = {
    "refund", "kyc", "update", "verify", "claim", "status", "download", "link",
    "apply", "login", "portal", "subsidy", "yojana", "dbt", "bonus", "instant",
    "form", "check", "registration", "pay", "services",
    # Specific Indian fraud vectors
    "digital-arrest", "arrest", "electricity", "bijli", "customs", "parcel",
    "courier", "lottery", "disconnection", "sanction", "disburse", "billpay"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".live", ".online",
    ".site", ".vip", ".cc", ".icu", ".click", ".link", ".buzz", ".work",
    ".app", ".support", ".fit", ".rest", ".monster", ".fun", ".country", ".pw",
    ".loan", ".cam", ".surf", ".bar", ".kim", ".cyou", ".zip", ".mov",
    ".example", ".test", ".invalid", ".localhost"
}

HIGH_RISK_KEYWORDS = [
    "kyc", "update", "refund", "subsidy", "bonus", "claim", "instant", "login",
    "verify", "portal", "secure", "free-money", "yojana", "account-blocked",
    "urgent", "action-required", "otp", "aadhaar-link", "pan-update",
    "digital-arrest", "bijli", "electricity-disconnection", "instant-loan"
]

AUTHENTIC_COMMERCIAL_DOMAINS = {
    "bing.com", "google.com", "google.co.in", "chatgpt.com", "openai.com",
    "microsoft.com", "github.com", "youtube.com", "wikipedia.org", "amazon.in",
    "amazon.com", "linkedin.com", "twitter.com", "x.com", "yahoo.com",
    "duckduckgo.com", "reddit.com", "stackoverflow.com", "apple.com",
    "netflix.com", "canva.com", "cloudflare.com", "bolt.new", "bolt.diy"
}
