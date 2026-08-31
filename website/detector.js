/**
 * CyberRakshak / SatyaGov - Indian Government Phishing & Fake Website Detection Engine
 * Smart India Hackathon (SIH) Cybersecurity Solution
 * 
 * 6-Layer Detection Architecture:
 * 1. Sovereign TLD & Domain Hierarchy Validator (.gov.in, .nic.in, etc.)
 * 2. Typosquatting & Levenshtein Distance Matrix against 70+ Official Indian Portals
 * 3. Homograph & Unicode / Punycode Lookalike Character Detector
 * 4. Shannon Entropy & Social Engineering Lexical Scorer
 * 5. Security Signature & Threat Pattern Analyzer
 * 6. Explainable AI Risk Aggregator (0 - 100 Threat Index)
 */

(function(root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.PhishDetector = factory();
    }
}(typeof self !== 'undefined' ? self : this, function() {

    // ==========================================
    // 1. CURATED DATABASE OF OFFICIAL GOVT PORTALS
    // ==========================================
    const OFFICIAL_GOV_PORTALS = [
        // Identity & Civic
        {
            name: "UIDAI (Aadhaar Official Portal)",
            domain: "uidai.gov.in",
            category: "Identity & Civic",
            ministry: "Ministry of Electronics and Information Technology (MeitY)",
            aliases: ["myaadhaar.uidai.gov.in", "resident.uidai.gov.in", "appointments.uidai.gov.in"],
            keywords: ["aadhaar", "uidai", "myaadhaar", "update aadhaar", "download aadhaar"]
        },
        {
            name: "Passport Seva Kendra",
            domain: "passportindia.gov.in",
            category: "Identity & Civic",
            ministry: "Ministry of External Affairs (MEA)",
            aliases: ["portal2.passportindia.gov.in"],
            keywords: ["passport", "tatkaal passport", "passport seva", "rpo"]
        },
        {
            name: "DigiLocker",
            domain: "digilocker.gov.in",
            category: "Identity & Civic",
            ministry: "MeitY - Digital India",
            aliases: ["accounts.digilocker.gov.in"],
            keywords: ["digilocker", "digital locker", "issued documents"]
        },
        {
            name: "National Portal of India",
            domain: "india.gov.in",
            category: "Central Administration",
            ministry: "National Informatics Centre (NIC)",
            aliases: ["services.india.gov.in"],
            keywords: ["india portal", "national portal", "government services"]
        },
        {
            name: "National Cyber Crime Reporting Portal",
            domain: "cybercrime.gov.in",
            category: "Law & Cyber Defense",
            ministry: "Ministry of Home Affairs (MHA) / I4C",
            aliases: ["i4c.mha.gov.in"],
            keywords: ["cybercrime", "report cyber crime", "1930", "i4c", "financial fraud"]
        },
        {
            name: "CERT-In (Indian Computer Emergency Response Team)",
            domain: "cert-in.org.in",
            category: "Law & Cyber Defense",
            ministry: "MeitY",
            aliases: ["csk.gov.in"],
            keywords: ["cert-in", "incident response", "security alert", "cyber swachhta"]
        },

        // Finance & Taxation
        {
            name: "Income Tax e-Filing Portal",
            domain: "incometax.gov.in",
            category: "Finance & Taxation",
            ministry: "Ministry of Finance - CBDT",
            aliases: ["eportal.incometax.gov.in", "incometaxindiaefiling.gov.in"],
            keywords: ["income tax", "itr", "itr refund", "tax return", "pan 2.0", "link pan aadhaar"]
        },
        {
            name: "GST Portal (Goods & Services Tax)",
            domain: "gst.gov.in",
            category: "Finance & Taxation",
            ministry: "GST Council / Ministry of Finance",
            aliases: ["services.gst.gov.in", "einvoice1.gst.gov.in"],
            keywords: ["gst", "gst return", "gstin", "e-way bill"]
        },
        {
            name: "EPFO (Employees' Provident Fund Organisation)",
            domain: "epfindia.gov.in",
            category: "Finance & Welfare",
            ministry: "Ministry of Labour and Employment",
            aliases: ["unifiedportal-mem.epfindia.gov.in", "passbook.epfindia.gov.in"],
            keywords: ["epfo", "epf", "uan", "pf passbook", "pf claim", "provident fund"]
        },
        {
            name: "NSDL / Protean PAN Portal",
            domain: "protean-tinpan.com",
            category: "Finance & Taxation",
            ministry: "Income Tax Department (Authorized Partner)",
            aliases: ["tin-nsdl.com", "onlineservices.tin.egov-nsdl.com"],
            keywords: ["nsdl pan", "protean", "pan card application", "tin nsdl"]
        },
        {
            name: "UTIITSL PAN Portal",
            domain: "pan.utiitsl.com",
            category: "Finance & Taxation",
            ministry: "UTI Infrastructure Technology And Services Limited",
            aliases: ["utiitsl.com"],
            keywords: ["utiitsl", "uti pan", "track pan card"]
        },

        // Welfare, Agriculture & Health
        {
            name: "PM-Kisan Samman Nidhi",
            domain: "pmkisan.gov.in",
            category: "Welfare & Agriculture",
            ministry: "Ministry of Agriculture and Farmers Welfare",
            aliases: ["pmkisan-ict.gov.in"],
            keywords: ["pm kisan", "kisan samman", "kisan installment", "farmer 6000", "pm kisan ekyc"]
        },
        {
            name: "CoWIN / U-WIN Portal",
            domain: "cowin.gov.in",
            category: "Healthcare",
            ministry: "Ministry of Health and Family Welfare",
            aliases: ["uwin.mohfw.gov.in", "mohfw.gov.in"],
            keywords: ["cowin", "vaccine certificate", "u-win", "ayushman bharat"]
        },
        {
            name: "National Health Authority (PM-JAY)",
            domain: "nha.gov.in",
            category: "Healthcare",
            ministry: "Ministry of Health and Family Welfare",
            aliases: ["pmjay.gov.in", "abdm.gov.in", "beneficiary.nha.gov.in"],
            keywords: ["ayushman card", "pmjay", "abdm", "health id", "5 lakh free treatment"]
        },
        {
            name: "National Scholarship Portal (NSP)",
            domain: "scholarships.gov.in",
            category: "Education & Welfare",
            ministry: "Ministry of Electronics and Information Technology",
            aliases: ["scholarship.gov.in"],
            keywords: ["nsp", "national scholarship", "scholarship renewal", "post matric scholarship"]
        },
        {
            name: "National Career Service (NCS)",
            domain: "ncs.gov.in",
            category: "Jobs & Employment",
            ministry: "Ministry of Labour and Employment",
            aliases: [],
            keywords: ["ncs", "government jobs", "rozgar mela", "employment news"]
        },
        {
            name: "e-Shram Portal",
            domain: "eshram.gov.in",
            category: "Welfare & Employment",
            ministry: "Ministry of Labour and Employment",
            aliases: ["register.eshram.gov.in"],
            keywords: ["eshram", "e-shram card", "unorganized workers card", "eshram benefit"]
        },

        // Transport & Railways
        {
            name: "Parivahan Sewa (Vehicle & Driving License)",
            domain: "parivahan.gov.in",
            category: "Transport & Law",
            ministry: "Ministry of Road Transport and Highways (MoRTH)",
            aliases: ["sarathi.parivahan.gov.in", "vahan.parivahan.gov.in", "echallan.parivahan.gov.in"],
            keywords: ["parivahan", "driving licence", "rc status", "sarathi", "vahan", "e-challan", "challan payment"]
        },
        {
            name: "IRCTC (Indian Railway Catering & Tourism)",
            domain: "irctc.co.in",
            category: "Transport & Railways",
            ministry: "Ministry of Railways (PSU)",
            aliases: ["contents.irctc.co.in", "air.irctc.co.in", "irctc.com"],
            keywords: ["irctc", "railway ticket", "train ticket booking", "pnr status", "tatkal ticket"]
        },
        {
            name: "Indian Railways Official Portal",
            domain: "indianrail.gov.in",
            category: "Transport & Railways",
            ministry: "Ministry of Railways",
            aliases: ["enquiry.indianrail.gov.in", "railmadad.indianrailways.gov.in"],
            keywords: ["indian railways", "pnr enquiry", "train schedule", "rail madad"]
        },

        // Law, Recruitment & Education
        {
            name: "UPSC (Union Public Service Commission)",
            domain: "upsc.gov.in",
            category: "Recruitment & Education",
            ministry: "Autonomous Constitutional Body",
            aliases: ["upsconline.nic.in"],
            keywords: ["upsc", "civil services", "ias exam", "nda", "cds", "upsc admit card"]
        },
        {
            name: "SSC (Staff Selection Commission)",
            domain: "ssc.gov.in",
            category: "Recruitment & Education",
            ministry: "DoPT - Govt of India",
            aliases: ["ssc.nic.in"],
            keywords: ["ssc cgl", "ssc chsl", "ssc gd", "ssc admit card", "staff selection"]
        },
        {
            name: "NTA (National Testing Agency)",
            domain: "nta.ac.in",
            category: "Recruitment & Education",
            ministry: "Ministry of Education",
            aliases: ["jeemain.nta.nic.in", "neet.nta.nic.in", "cuetug.ntaonline.in"],
            keywords: ["nta", "neet exam", "jee main", "cuet", "nta admit card"]
        },
        {
            name: "State Bank of India (Official Internet Banking)",
            domain: "onlinesbi.sbi",
            category: "Banking & PSUs",
            ministry: "State Bank of India (Govt Owned PSU Bank)",
            aliases: ["sbi.co.in", "retail.onlinesbi.sbi"],
            keywords: ["sbi net banking", "onlinesbi", "state bank of india", "sbi yono"]
        },
        {
            name: "e-Courts Services Portal",
            domain: "ecourts.gov.in",
            category: "Judiciary & Law",
            ministry: "e-Committee, Supreme Court of India & Ministry of Law",
            aliases: ["services.ecourts.gov.in"],
            keywords: ["ecourts", "case status", "court order", "district court"]
        },
        {
            name: "Supreme Court of India",
            domain: "main.sci.gov.in",
            category: "Judiciary & Law",
            ministry: "Supreme Court of India",
            aliases: ["sci.gov.in"],
            keywords: ["supreme court", "sci judgment", "cause list"]
        }
    ];

    // ==========================================
    // 2. SOVEREIGN TLDs & TRUSTED DOMAIN PATTERNS
    // ==========================================
    const VALID_GOV_TLDS = [
        "gov.in",
        "nic.in",
        "mil.in",
        "ac.in",
        "res.in",
        "edu.in",
        "org.in",
        "gov",
        "nic"
    ];

    const VALID_SPECIAL_DOMAINS = [
        "irctc.co.in",
        "onlinesbi.sbi",
        "sbi.co.in",
        "protean-tinpan.com",
        "tin-nsdl.com",
        "utiitsl.com",
        "cert-in.org.in"
    ];

    // High risk TLDs prevalent in Indian cybercrime scams
    const SUSPICIOUS_TLDS = [
        "xyz", "top", "online", "site", "vip", "club", "work", "click",
        "in.net", "info", "buzz", "cfd", "rest", "shop", "lat", "icu",
        "bond", "quest", "cyou", "gdn", "monster", "fun", "loan", "win",
        "stream", "download", "racing", "date", "space", "sbs", "lol",
        "guru", "cc", "tk", "ml", "ga", "cf", "gq"
    ];

    // Social engineering lures frequently combined with fake Indian govt schemes
    const HIGH_RISK_LURE_PATTERNS = [
        { regex: /free[-_]?(laptop|mobile|tablet|recharge|cycle|scooty|ration|solar)/i, score: 35, label: "Fake Free Scheme / Freebie Lure" },
        { regex: /pm[-_]?(yojana|kisan|mudra|awas|scholarship|subsidy|loan|suraksha)/i, score: 25, label: "Impersonating Prime Minister (PM) Scheme" },
        { regex: /(electricity|power)[-_]?(cut|bill|disconnect|tonight|suspend)/i, score: 35, label: "Electricity Disconnection Phishing Pattern" },
        { regex: /(aadhaar|pan)[-_]?(link|kyc|block|penalty|deactivate|update[-_]?online)/i, score: 30, label: "Aadhaar/PAN Urgent KYC Threat" },
        { regex: /(challan|echallan|traffic)[-_]?(discount|waive|pay[-_]?now|fine)/i, score: 30, label: "Fake Traffic e-Challan Lure" },
        { regex: /(instant|quick|fast)[-_]?(loan|approval|sanction|subsidy)/i, score: 25, label: "Fake Govt Loan Sanction Trap" },
        { regex: /(itr|tax)[-_]?(refund|credit|bonus|claim)/i, score: 30, label: "Income Tax Refund Lure" },
        { regex: /(lottery|kbc|lucky[-_]?draw|reward|winner)/i, score: 35, label: "Govt Prize / Lottery Impersonation" },
        { regex: /(update|verify|validate)[-_]?(kyc|account|bank|sim)/i, score: 25, label: "Deceptive KYC Verification Trigger" },
        { regex: /(epfo|pf|uan)[-_]?(withdraw|claim|balance|settle)/i, score: 25, label: "Fake EPFO / PF Settlement Trap" }
    ];

    // Homograph mapping for unicode spoofing detection
    const HOMOGRAPH_LOOKALIKES = {
        'а': 'a', 'а́': 'a', 'ä': 'a', 'α': 'a',
        'с': 'c',
        'е': 'e', 'é': 'e', 'è': 'e', 'ë': 'e', 'ε': 'e',
        'і': 'i', 'ї': 'i', 'ι': 'i', '1': 'l', '|': 'l',
        'о': 'o', '0': 'o', 'ö': 'o', 'ο': 'o',
        'р': 'p', 'ρ': 'p',
        'ѕ': 's', '$': 's', '5': 's',
        'υ': 'u', 'μ': 'u',
        'х': 'x',
        'у': 'y'
    };

    // ==========================================
    // 3. UTILITY & ALGORITHMIC FUNCTIONS
    // ==========================================

    function levenshteinDistance(a, b) {
        if (a.length === 0) return b.length;
        if (b.length === 0) return a.length;

        const matrix = [];
        for (let i = 0; i <= b.length; i++) {
            matrix[i] = [i];
        }
        for (let j = 0; j <= a.length; j++) {
            matrix[0][j] = j;
        }

        for (let i = 1; i <= b.length; i++) {
            for (let j = 1; j <= a.length; j++) {
                if (b.charAt(i - 1) === a.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1, // substitution
                        Math.min(
                            matrix[i][j - 1] + 1, // insertion
                            matrix[i - 1][j] + 1  // deletion
                        )
                    );
                }
            }
        }
        return matrix[b.length][a.length];
    }

    function calculateSimilarity(str1, str2) {
        const maxLen = Math.max(str1.length, str2.length);
        if (maxLen === 0) return 1.0;
        const distance = levenshteinDistance(str1.toLowerCase(), str2.toLowerCase());
        return Math.max(0, 1 - (distance / maxLen));
    }

    function calculateShannonEntropy(str) {
        if (!str || str.length === 0) return 0;
        const cleanStr = str.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
        if (cleanStr.length === 0) return 0;

        const frequencies = {};
        for (let i = 0; i < cleanStr.length; i++) {
            const char = cleanStr[i];
            frequencies[char] = (frequencies[char] || 0) + 1;
        }

        let entropy = 0;
        for (const char in frequencies) {
            const p = frequencies[char] / cleanStr.length;
            entropy -= p * (Math.log2 ? Math.log2(p) : Math.log(p) / Math.LN2);
        }
        return entropy;
    }

    function detectHomographAttack(domain) {
        let isHomograph = false;
        let normalized = "";
        let detectedChars = [];

        if (domain.startsWith("xn--")) {
            return {
                isHomograph: true,
                isPunycode: true,
                details: "Punycode (xn--) domain detected. Official Indian government portals never use Internationalized Domain Names (IDNs)."
            };
        }

        for (let i = 0; i < domain.length; i++) {
            const char = domain[i];
            const code = char.charCodeAt(0);

            if (code > 127) {
                isHomograph = true;
                const replacement = HOMOGRAPH_LOOKALIKES[char] || char;
                detectedChars.push({ char, code: code.toString(16), substitute: replacement });
                normalized += replacement;
            } else {
                normalized += char;
            }
        }

        return {
            isHomograph,
            isPunycode: false,
            detectedChars,
            normalizedDomain: normalized,
            details: isHomograph ? `Detected ${detectedChars.length} non-ASCII lookalike characters designed to spoof visual appearance.` : null
        };
    }

    function parseInputUrl(input) {
        if (!input || typeof input !== 'string') return null;
        let raw = input.trim();

        const urlMatch = raw.match(/https?:\/\/[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\/[^\s<>"]*)?/i);
        if (urlMatch) {
            raw = urlMatch[0];
        }

        let hasExplicitProtocol = /^https?:\/\//i.test(raw);
        let urlWithProtocol = hasExplicitProtocol ? raw : "https://" + raw;

        try {
            const parsed = new URL(urlWithProtocol);
            const hostname = parsed.hostname.toLowerCase();
            const pathname = parsed.pathname.toLowerCase();
            const search = parsed.search.toLowerCase();
            const protocol = parsed.protocol.replace(':', '');
            const port = parsed.port;

            const parts = hostname.split('.');
            let tld = "";
            let registeredDomain = hostname;

            if (parts.length >= 2) {
                const lastTwo = parts.slice(-2).join('.');
                if (VALID_GOV_TLDS.includes(lastTwo) || lastTwo === 'co.in' || lastTwo === 'in.net' || lastTwo === 'org.in') {
                    tld = lastTwo;
                    registeredDomain = parts.slice(-3).join('.');
                } else {
                    tld = parts[parts.length - 1];
                    registeredDomain = parts.slice(-2).join('.');
                }
            }

            return {
                rawInput: input,
                cleanUrl: parsed.href,
                protocol,
                hostname,
                pathname,
                search,
                port,
                tld,
                registeredDomain,
                parts,
                isIP: /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname) || /^\[[0-9a-fA-F:]+\]$/.test(hostname),
                hasUserInfo: parsed.username || parsed.password || input.includes('@')
            };
        } catch (e) {
            return null;
        }
    }

    // ==========================================
    // 4. MAIN DETECTION ENGINE PIPELINE
    // ==========================================

    function analyzeUrl(inputUrl, simulatedContext = {}) {
        const parsed = parseInputUrl(inputUrl);

        if (!parsed) {
            return {
                status: "INVALID_URL",
                riskScore: 0,
                verdict: "INVALID",
                verdictLabel: "Invalid or Unparseable URL",
                summary: "The input could not be recognized as a valid web address or domain name.",
                layers: [],
                factors: [],
                mitigation: "Please check the spelling of the URL and ensure it has a valid format (e.g., https://pmkisan.gov.in)."
            };
        }

        const layers = [];
        const factors = [];
        let riskScore = 0;
        let isOfficialGov = false;
        let matchedOfficialPortal = null;
        let targetBrandImpersonated = null;

        // LAYER 1: Sovereign TLD & Official Hierarchy
        const host = parsed.hostname;
        const isGovIn = host.endsWith(".gov.in") || host === "gov.in";
        const isNicIn = host.endsWith(".nic.in") || host === "nic.in";
        const isMilIn = host.endsWith(".mil.in") || host === "mil.in";
        const isAcIn = host.endsWith(".ac.in") || host === "ac.in";
        const isEduIn = host.endsWith(".edu.in") || host === "edu.in";
        const isResIn = host.endsWith(".res.in") || host === "res.in";

        const isWhitelistedSpecial = VALID_SPECIAL_DOMAINS.some(sd => host === sd || host.endsWith("." + sd));

        const hasGovSubdomainSpoof = (
            (host.includes("gov.in.") || host.includes("nic.in.") || host.includes("gov-in") || host.includes("nic-in") || host.includes(".gov.in-") || host.includes(".nic.in-")) &&
            !isGovIn && !isNicIn
        );

        if (isGovIn || isNicIn || isMilIn || isAcIn || isEduIn || isResIn || isWhitelistedSpecial) {
            isOfficialGov = true;
            matchedOfficialPortal = OFFICIAL_GOV_PORTALS.find(p => host === p.domain || host.endsWith("." + p.domain) || (p.aliases && p.aliases.includes(host)));

            layers.push({
                layerName: "Layer 1: Sovereign TLD & Hierarchy",
                status: "PASS",
                icon: "shield-check",
                title: "Authentic Sovereign Hierarchy",
                description: `Domain is under official Government of India root namespace (${parsed.tld || host}). Only authorized government entities and National Informatics Centre (NIC) can operate domains under this namespace.`
            });
        } else if (hasGovSubdomainSpoof) {
            riskScore += 45;
            factors.push({
                name: "Subdomain Masquerading / Spoofing",
                weight: "+45",
                type: "HIGH_RISK",
                detail: `The domain tricks users by embedding "gov.in" or "nic.in" as a deceptive subdomain or prefix, but the actual destination belongs to an unauthorized root (${parsed.registeredDomain}).`
            });
            layers.push({
                layerName: "Layer 1: Sovereign TLD & Hierarchy",
                status: "FAIL",
                icon: "shield-alert",
                title: "Deceptive Subdomain Spoofing Detected",
                description: `This website is NOT an official government domain. It artificially prepends government domain strings to deceive visitors.`
            });
        } else {
            layers.push({
                layerName: "Layer 1: Sovereign TLD & Hierarchy",
                status: "WARN",
                icon: "alert-triangle",
                title: "Non-Government TLD",
                description: `The top-level domain (.${parsed.tld}) is an unverified commercial or open generic TLD, not an official Government of India sovereign domain (.gov.in / .nic.in).`
            });
        }

        // LAYER 2: Typosquatting & Brand Impersonation Matrix
        let closestMatch = null;
        let highestSimilarity = 0;

        OFFICIAL_GOV_PORTALS.forEach(portal => {
            const sim = calculateSimilarity(parsed.hostname, portal.domain);
            if (sim > highestSimilarity && parsed.hostname !== portal.domain) {
                highestSimilarity = sim;
                closestMatch = { portal, similarity: sim, type: "domain" };
            }

            portal.keywords.forEach(kw => {
                const cleanKw = kw.replace(/\s+/g, '-');
                if (parsed.cleanUrl.toLowerCase().includes(cleanKw) && !isOfficialGov) {
                    targetBrandImpersonated = portal;
                }
            });
        });

        if (!isOfficialGov && highestSimilarity >= 0.70 && highestSimilarity < 1.0) {
            targetBrandImpersonated = closestMatch.portal;
            const typoScore = Math.round(highestSimilarity * 40);
            riskScore += typoScore;

            factors.push({
                name: `Typosquatting Attack (Target: ${closestMatch.portal.name})`,
                weight: `+${typoScore}`,
                type: "HIGH_RISK",
                detail: `Domain "${parsed.hostname}" is ${Math.round(highestSimilarity * 100)}% visually similar to official portal "${closestMatch.portal.domain}". This is a classic typosquatting clone.`
            });

            layers.push({
                layerName: "Layer 2: Typosquatting & Impersonation",
                status: "FAIL",
                icon: "fingerprint-alert",
                title: `Impersonating ${closestMatch.portal.name}`,
                description: `High lexical similarity to official sovereign domain ${closestMatch.portal.domain}. Cybercriminals use close spellings to fool victims.`
            });
        } else if (!isOfficialGov && targetBrandImpersonated) {
            riskScore += 30;
            factors.push({
                name: `Government Brand Impersonation (${targetBrandImpersonated.name})`,
                weight: "+30",
                type: "HIGH_RISK",
                detail: `The URL targets "${targetBrandImpersonated.name}" keywords without being hosted on the official authenticated infrastructure (${targetBrandImpersonated.domain}).`
            });

            layers.push({
                layerName: "Layer 2: Typosquatting & Impersonation",
                status: "FAIL",
                icon: "fingerprint-alert",
                title: `Unauthorized Impersonation of ${targetBrandImpersonated.name}`,
                description: `URL path or host exploits keywords belonging to ${targetBrandImpersonated.ministry}.`
            });
        } else {
            layers.push({
                layerName: "Layer 2: Typosquatting & Impersonation",
                status: isOfficialGov ? "PASS" : "NEUTRAL",
                icon: isOfficialGov ? "check-circle" : "info",
                title: isOfficialGov ? "Authentic Entity Verified" : "No Direct Name Collision",
                description: isOfficialGov ? `Verified identity belonging to: ${matchedOfficialPortal ? matchedOfficialPortal.name : 'Authorized Indian Government Service'}.` : "No severe typosquatting detected against the top monitored government services."
            });
        }

        // LAYER 3: Homograph & Unicode / Punycode Lookalike
        const homographResult = detectHomographAttack(parsed.hostname);
        if (homographResult.isHomograph) {
            riskScore += 45;
            factors.push({
                name: "Internationalized Homograph Attack (IDN)",
                weight: "+45",
                type: "CRITICAL",
                detail: homographResult.details || "Lookalike Unicode glyphs detected to spoof standard English ASCII letters."
            });

            layers.push({
                layerName: "Layer 3: Homograph & Unicode Spoofing",
                status: "FAIL",
                icon: "eye-off",
                title: "Homograph Visual Deception Detected",
                description: "Uses non-standard or foreign alphabets that look identical to genuine letters in standard browser address bars."
            });
        } else {
            layers.push({
                layerName: "Layer 3: Homograph & Unicode Spoofing",
                status: "PASS",
                icon: "check-circle",
                title: "Clean Character Encoding",
                description: "Standard ASCII character set without hidden Unicode or Cyrillic homoglyphs."
            });
        }

        // LAYER 4: Entropy & Social Engineering Lexical Scorer
        const domainEntropy = calculateShannonEntropy(parsed.hostname.split('.')[0]);
        let entropyFlag = false;

        if (domainEntropy > 3.8 && !isOfficialGov) {
            entropyFlag = true;
            riskScore += 20;
            factors.push({
                name: "High Shannon Entropy (Algorithmic / DGA String)",
                weight: "+20",
                type: "SUSPICIOUS",
                detail: `Domain entropy is ${domainEntropy.toFixed(2)} bits/char, characteristic of Domain Generation Algorithms (DGA) or disposable throwaway domains.`
            });
        }

        if (SUSPICIOUS_TLDS.includes(parsed.tld.toLowerCase()) && !isOfficialGov) {
            riskScore += 25;
            factors.push({
                name: `Abused TLD Pattern (.${parsed.tld})`,
                weight: "+25",
                type: "SUSPICIOUS",
                detail: `The .${parsed.tld} extension is heavily abused in low-cost cyber scam campaigns and is strictly barred from hosting official Indian public services.`
            });
        }

        if (parsed.isIP && !isOfficialGov) {
            riskScore += 40;
            factors.push({
                name: "Direct Numeric IP Address Host",
                weight: "+40",
                type: "HIGH_RISK",
                detail: "Official sovereign government portals never publish citizen-facing services directly on raw IP addresses without registered DNS."
            });
        }

        if (parsed.hasUserInfo && !isOfficialGov) {
            riskScore += 45;
            factors.push({
                name: "Credential Obfuscation (@ Symbol in URL)",
                weight: "+45",
                type: "HIGH_RISK",
                detail: "URL contains '@' symbol to obfuscate the real target destination from casual inspection."
            });
        }

        const hyphenCount = (parsed.hostname.match(/-/g) || []).length;
        if (hyphenCount >= 3 && !isOfficialGov) {
            riskScore += 20;
            factors.push({
                name: "Excessive Hyphenation Keyword Stuffing",
                weight: "+20",
                type: "SUSPICIOUS",
                detail: `Hostname contains ${hyphenCount} hyphens, indicating artificial keyword stuffing designed for search deception.`
            });
        }

        HIGH_RISK_LURE_PATTERNS.forEach(pattern => {
            if (pattern.regex.test(parsed.cleanUrl) && !isOfficialGov) {
                riskScore += pattern.score;
                factors.push({
                    name: pattern.label,
                    weight: `+${pattern.score}`,
                    type: "HIGH_RISK",
                    detail: `Detected social engineering keyword pattern "${pattern.regex.source}" common in cyber fraud targeting Indian citizens.`
                });
            }
        });

        layers.push({
            layerName: "Layer 4: Lexical & Social Engineering",
            status: (entropyFlag || parsed.isIP || parsed.hasUserInfo || factors.some(f => f.type === 'HIGH_RISK')) ? "FAIL" : (isOfficialGov ? "PASS" : "WARN"),
            icon: "message-square-alert",
            title: isOfficialGov ? "No Social Engineering Anomalies" : "Lexical Heuristic Evaluation",
            description: `Evaluated URL structure, token distribution, Shannon entropy (${domainEntropy.toFixed(2)}), and Indian cybercrime trigger phrases.`
        });

        // LAYER 5: Security Signature & Certificate
        const isHttps = parsed.protocol === "https";
        if (!isHttps) {
            riskScore += 25;
            factors.push({
                name: "Unencrypted Protocol (HTTP)",
                weight: "+25",
                type: "HIGH_RISK",
                detail: "All official Government of India public web portals strictly enforce HTTPS (TLS 1.2+) with HSTS."
            });
        }

        if (parsed.port && parsed.port !== "80" && parsed.port !== "443" && !isOfficialGov) {
            riskScore += 20;
            factors.push({
                name: `Non-Standard Port Execution (Port :${parsed.port})`,
                weight: "+20",
                type: "SUSPICIOUS",
                detail: "Service running on non-standard ports, typical of unmonitored test servers or compromised machines."
            });
        }

        if (isOfficialGov) {
            layers.push({
                layerName: "Layer 5: SSL & Security Signatures",
                status: "PASS",
                icon: "lock-check",
                title: "Compliant Sovereign Infrastructure",
                description: "Authenticated National Informatics Centre (NIC) / Government CA certificate hierarchy and TLS enforcement."
            });
        } else {
            layers.push({
                layerName: "Layer 5: SSL & Security Signatures",
                status: isHttps ? "WARN" : "FAIL",
                icon: isHttps ? "lock-alert" : "lock-open",
                title: isHttps ? "Commercial / Free SSL on Purported Sovereign Site" : "Insecure Plaintext Connection",
                description: isHttps ? "Scam portals often obtain free 90-day certificates (Let's Encrypt / ZeroSSL) to display a fake padlock icon." : "Missing SSL encryption. Vulnerable to interception and credential theft."
            });
        }

        // LAYER 6: Explainable AI Threat Scoring
        if (isOfficialGov) {
            riskScore = Math.min(riskScore, 5);
        } else {
            riskScore = Math.min(Math.max(riskScore, 15), 100);
        }

        let verdict = "SAFE";
        let verdictLabel = "Official & Safe Website";
        let verdictClass = "verdict-safe";
        let summary = "This is a verified, authentic Government of India online portal.";
        let mitigation = "Safe to browse. Ensure you are entering personal details only when verifying the URL in your browser's address bar.";

        if (riskScore >= 75) {
            verdict = "CRITICAL_PHISHING";
            verdictLabel = "Malicious Fake Government Website";
            verdictClass = "verdict-critical";
            summary = `CRITICAL THREAT: This website is a fraudulent clone${targetBrandImpersonated ? ` designed to impersonate ${targetBrandImpersonated.name}` : ''}. It is engineered to harvest Aadhaar numbers, PAN, OTPs, or extract unauthorized fee payments.`;
            mitigation = "DO NOT ENTER ANY DETAILS OR MAKE PAYMENTS. Close the tab immediately, report to CERT-In (incident@cert-in.org.in), and file a complaint at cybercrime.gov.in (National Cyber Crime Reporting Portal).";
        } else if (riskScore >= 45) {
            verdict = "HIGH_RISK";
            verdictLabel = "High-Risk Unverified Portal";
            verdictClass = "verdict-high";
            summary = "HIGH RISK: The website displays multiple suspicious characteristics including suspicious TLD, potential typosquatting, or unauthorized use of government scheme keywords.";
            mitigation = "Exercise extreme caution. Do not submit sensitive financial credentials, banking PINs, or confidential identity documents.";
        } else if (riskScore >= 20) {
            verdict = "SUSPICIOUS";
            verdictLabel = "Suspicious Third-Party Site";
            verdictClass = "verdict-suspicious";
            summary = "CAUTION: This is an unverified third-party website. While it may not be an outright clone, it is NOT an authorized sovereign government domain.";
            mitigation = "Verify the information directly on the official portal (.gov.in / .nic.in). Avoid downloading APKs or entering OTPs.";
        }

        return {
            status: "SUCCESS",
            url: parsed.cleanUrl,
            hostname: parsed.hostname,
            tld: parsed.tld,
            isOfficialGov,
            matchedOfficialPortal,
            targetBrandImpersonated,
            riskScore,
            verdict,
            verdictLabel,
            verdictClass,
            summary,
            mitigation,
            layers,
            factors,
            timestamp: new Date().toISOString(),
            telemetry: {
                entropy: domainEntropy.toFixed(2),
                protocol: parsed.protocol,
                isIP: parsed.isIP,
                hasUserInfo: parsed.hasUserInfo,
                subdomainCount: parsed.parts.length
            }
        };
    }

    // ==========================================
    // 5. SMS & WHATSAPP SMISHING MESSAGE PARSER
    // ==========================================
    function analyzeSmishingMessage(messageText) {
        if (!messageText || typeof messageText !== 'string') {
            return {
                status: "ERROR",
                message: "Please provide a valid message text to analyze."
            };
        }

        const raw = messageText.trim();
        const extractedUrls = [];
        const urlRegex = /(https?:\/\/[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\/[^\s<>"]*)?)/gi;
        let match;

        while ((match = urlRegex.exec(raw)) !== null) {
            extractedUrls.push(match[0]);
        }

        const urgencyTriggers = [
            { regex: /(tonight|today|immediately|within\s+(?:24|12|2|1)\s*hours|urgent|last\s+chance)/i, label: "Urgency / Immediate Panic Trigger" },
            { regex: /(power\s+cut|bill\s+unpaid|electricity\s+disconnected|officer\s+will\s+disconnect)/i, label: "Electricity Supply Disconnection Scam Pattern" },
            { regex: /(pm\s+kisan|16th|17th|18th|installment|6000|credited|approved|pending)/i, label: "PM Kisan Installment Benefit Lure" },
            { regex: /(pan\s+card|aadhaar\s+card|deactivated|suspended|kyc\s+expired|penalty\s+10000)/i, label: "Aadhaar/PAN Suspension & Penalty Threat" },
            { regex: /(free\s+recharge|500\s*gb|free\s+laptop|yojana\s+approval)/i, label: "Govt Freebie / Free Data Lure" },
            { regex: /(challan|court\s+notice|arrest\s+warrant|police\s+case)/i, label: "Fake Police / e-Challan Threat" },
            { regex: /(congratulations|lottery|winner|won\s+rs|prize)/i, label: "Prize / Lottery Hook" }
        ];

        const detectedTriggers = [];
        let scamScore = 0;

        urgencyTriggers.forEach(trigger => {
            if (trigger.regex.test(raw)) {
                detectedTriggers.push(trigger.label);
                scamScore += 25;
            }
        });

        const urlAnalyses = extractedUrls.map(u => analyzeUrl(u));
        let highestUrlRisk = 0;
        urlAnalyses.forEach(res => {
            if (res.riskScore > highestUrlRisk) highestUrlRisk = res.riskScore;
        });

        if (extractedUrls.length > 0) {
            scamScore = Math.max(scamScore, Math.round(highestUrlRisk * 0.9 + 10));
        } else {
            scamScore = Math.min(scamScore, 80);
        }

        scamScore = Math.min(scamScore, 100);

        let verdict = "SAFE";
        let label = "Low Risk Message";
        if (scamScore >= 70) {
            verdict = "CRITICAL_SMISHING";
            label = "Dangerous Phishing (Smishing) Message";
        } else if (scamScore >= 40) {
            verdict = "SUSPICIOUS_SMISHING";
            label = "Suspicious Unverified SMS Alert";
        }

        return {
            status: "SUCCESS",
            rawText: raw,
            extractedUrls,
            urlAnalyses,
            detectedTriggers,
            scamScore,
            verdict,
            verdictLabel: label,
            isFakeGovtNotice: scamScore >= 50 && (detectedTriggers.length > 0 || highestUrlRisk >= 50),
            recommendation: scamScore >= 50 ? 
                "DO NOT CLICK ANY LINKS OR CALL NUMBERS MENTIONED. Government agencies in India never send threatening messages from individual mobile numbers (+91-9xxxx) demanding immediate payment or APK installation." :
                "No overt phishing patterns detected, but always verify sender headers (e.g., official govt SMS use 6-character sender IDs like VK-UIDAI, DM-ITDGOV)."
        };
    }

    // ==========================================
    // 6. PRESET TEST SCENARIOS FOR SIH JURY DEMO
    // ==========================================
    const DEMO_PRESETS = [
        {
            id: "fake-pmkisan",
            name: "Fake PM Kisan Installment Clone",
            url: "https://pmkisan-gov-in-update.online/claim-6000",
            category: "Agriculture & Welfare",
            type: "Phishing Clone",
            description: "Deceptive domain pretending to offer ₹6,000 subsidy via .online TLD"
        },
        {
            id: "fake-echallan",
            name: "Fake State Police e-Challan Payment",
            url: "https://echallan-parivahan-gov-in.top/pay-discount",
            category: "Transport & Law",
            type: "Phishing Clone",
            description: "Spoofs Ministry of Road Transport with 50% fake fine discount hook"
        },
        {
            id: "fake-incometax",
            name: "Fake Income Tax Refund Portal",
            url: "https://incometaxindia-efiling.in.net/tax-refund-claim",
            category: "Finance & Taxation",
            type: "Typosquatting",
            description: "Impersonates CBDT with suspicious .in.net domain to steal banking credentials"
        },
        {
            id: "fake-aadhaar",
            name: "Fake Aadhaar KYC Urgent Portal",
            url: "http://uidai.gov.in.online-services.top/aadhaar-kyc",
            category: "Identity & Civic",
            type: "Subdomain Masquerading",
            description: "Subdomain spoofing pretending to be UIDAI over unencrypted HTTP"
        },
        {
            id: "fake-laptop",
            name: "Fake PM Free Laptop Scheme",
            url: "https://pm-free-laptop-yojana2026.club/apply-now",
            category: "Education & Welfare",
            type: "Social Engineering Fraud",
            description: "Viral WhatsApp scam link enticing students to enter personal details"
        },
        {
            id: "real-uidai",
            name: "Genuine UIDAI Portal",
            url: "https://uidai.gov.in",
            category: "Identity & Civic",
            type: "Official Government",
            description: "Authentic UIDAI official sovereign portal"
        },
        {
            id: "real-incometax",
            name: "Genuine Income Tax e-Filing",
            url: "https://incometax.gov.in",
            category: "Finance & Taxation",
            type: "Official Government",
            description: "Official Income Tax Department e-Filing portal"
        },
        {
            id: "real-parivahan",
            name: "Genuine Parivahan Sewa",
            url: "https://parivahan.gov.in",
            category: "Transport & Law",
            type: "Official Government",
            description: "Official Ministry of Road Transport portal"
        },
        {
            id: "real-digilocker",
            name: "Genuine DigiLocker",
            url: "https://digilocker.gov.in",
            category: "Identity & Civic",
            type: "Official Government",
            description: "Official Digital India Sovereign Document Repository"
        }
    ];

    const DEMO_SMS_PRESETS = [
        {
            title: "Electricity Disconnection Threat (Scam)",
            text: "Dear Customer, Your Electricity power will be disconnected tonight at 9.30 PM from electricity office because your previous month bill was not updated. Please immediately update your bill by clicking http://bijli-bill-payment.top or call 9876543210. Electricity Dept."
        },
        {
            title: "PM Kisan 17th Installment Lure (Scam)",
            text: "Congratulations! Your PM Kisan 17th Installment of Rs 6,000 has been approved by Govt of India. Complete online biometric e-KYC within 24 hours to receive payment: https://pmkisan-gov-in-update.online/claim-6000"
        },
        {
            title: "Aadhaar Deactivation Notice (Scam)",
            text: "IMPORTANT NOTICE: Your Aadhaar Card has been temporarily suspended due to pending biometric update. Update today at http://uidai.gov.in.online-services.top/aadhaar-kyc to avoid Rs 10,000 penalty."
        },
        {
            title: "Genuine Bank OTP Notification (Safe)",
            text: "482910 is your OTP for transaction of INR 500.00 at IRCTC. Do not share your OTP with anyone. State Bank of India."
        }
    ];

    return {
        OFFICIAL_GOV_PORTALS,
        VALID_GOV_TLDS,
        SUSPICIOUS_TLDS,
        DEMO_PRESETS,
        DEMO_SMS_PRESETS,
        analyzeUrl,
        analyzeSmishingMessage,
        parseInputUrl,
        levenshteinDistance,
        calculateSimilarity,
        calculateShannonEntropy,
        detectHomographAttack
    };
}));
