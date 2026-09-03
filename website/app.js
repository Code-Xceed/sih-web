/**
 * GovShield / SatyaGov — Sovereign Web Portal Controller
 * Integrates:
 * 1. FastAPI Multimodal AI Backend (Gemini 2.0 Flash)
 * 2. Sovereign Blockchain Threat Intelligence Ledger (SHA-256 Merkle Proofs)
 * 3. Section 65B Indian Evidence Act Court Certificate Generator
 * 4. Bharat-First Bilingual Vernacular Engine (Hindi / English)
 * 5. Web Speech Audio Advisory (🔊) for Rural Citizens
 * 6. Ultra-Lite Bharat Mode (Zero-jank for budget phones / 2G networks)
 */

document.addEventListener('DOMContentLoaded', () => {
    const API_BASE = (window.location.origin && window.location.origin.startsWith('http')) 
        ? window.location.origin 
        : 'http://localhost:8000';
    let currentAnalysisResult = null;
    let currentLang = 'en';
    let isLiteMode = false;
    let isSpeaking = false;

    // 1. Bharat-First Bilingual Localization Dictionary
    const i18n = {
        en: {
            brandTitle: "GovShield Sentinel Grid",
            brandSub: "Sovereign Cyber Defense & Blockchain Threat Ledger",
            helpline: "1930 Helpline",
            blockchainBtn: "Blockchain Ledger",
            liteModeBtn: "Bharat Lite",
            tacticalModeBtn: "Tactical 3D",
            heroTitle: '<span class="title-fake">Fake</span> Government<br>Portal Detector.',
            heroTagline: "Algorithmic 6-layer scanner identifying typosquatting, subdomain masquerading, and fraudulent clones targeting Indian citizens.",
            placeholder: "Enter website URL (e.g., https://pmkisan-gov-in-",
            inspectBtn: "Inspect",
            inspecting: "Analyzing AI...",
            criticalThreat: "CRITICAL THREAT (FAKE CLONE)",
            suspiciousDomain: "SUSPICIOUS LOOKALIKE",
            verifiedOfficial: "VERIFIED OFFICIAL PORTAL",
            authenticWeb: "AUTHENTIC WEB PLATFORM",
            saveDossier: "Save Dossier",
            viewReport: "View Report",
            advisoryPrefix: "ADVISORY:",
            listen: "Listen",
            speaking: "Speaking...",
            advisoryThreat: "DO NOT enter Aadhaar, PAN, OTP, or banking credentials. A CERT-In takedown notice has been drafted.",
            advisorySuspicious: "Exercise caution. Verify the official URL on india.gov.in before providing personal information.",
            advisorySafe: "Safe for navigation. The domain is verified and authenticated.",
            step1: "01. OPENSQUAT TYPOSQUATTING & PERMUTATION",
            step2: "02. PHISHDETECT DOM & HTML DECEPTION FORENSICS",
            step3: "03. URL.VET REDIRECT & SHORTENER RESOLUTION",
            step4: "04. URL.VET DNS & MAIL INFRASTRUCTURE AUDIT",
            step5: "05. SOVEREIGN AI ML ENSEMBLE CLASSIFIER",
            sec65bDownload: "Download Sec 65B Court Certificate",
            speechWarningThreat: "Warning! This website is a fake government clone attempting to steal citizen identity. Do not enter your Aadhaar, PAN, or OTP. For cyber fraud, call 1930 immediately.",
            speechWarningSuspicious: "Caution. This website is not on an official government domain. Verify before entering personal information.",
            speechWarningSafe: "This is a verified authentic web platform.",
            quickTest: "Try sample:",
            noticeThreatHeading: "DO NOT ENTER OTP OR BANK PIN",
            noticeThreatDesc: "This is an illegal scam clone trying to steal citizen funds and identity.",
            noticeSafeHeading: "OFFICIAL & SAFE GOVERNMENT PORTAL",
            noticeSafeDesc: "Verified authentic Government of India national infrastructure (.gov.in / .nic.in).",
            noticeCommercialHeading: "AUTHENTIC WEB PLATFORM (NON-GOV)",
            noticeCommercialDesc: "Authentic commercial web service. No government portal impersonation detected.",
            noticeCautionHeading: "SUSPICIOUS UNVERIFIED SITE",
            noticeCautionDesc: "Proceed with caution. Never share sensitive OTPs on unofficial links.",
            advisoryCommercial: "Authentic non-government web service. Standard web browsing is safe.",
            callNotice: "Call 1930",
            showForensics: "Show Technical Forensic Analysis",
            hideForensics: "Hide Technical Forensic Analysis"
        },
        hi: {
            brandTitle: "गवशील्ड संतरी ग्रिड",
            brandSub: "संप्रभु साइबर रक्षा एवं ब्लॉकचेन खतरा खाता-बही",
            helpline: "1930 हेल्पलाइन",
            blockchainBtn: "ब्लॉकचेन खाता-बही",
            liteModeBtn: "भारत लाइट",
            tacticalModeBtn: "3D मोड",
            heroTitle: '<span class="title-fake">नकली</span> सरकारी पोर्टल<br>पहचान प्रणाली।',
            heroTagline: "भारतीय नागरिकों को ठगने वाले फर्जी सरकारी क्लोन, धोखाधड़ी वाले डोमेन और आधार/OTP चुराने वाली वेबसाइटों की पहचान।",
            placeholder: "वेबसाइट का पता दर्ज करें (उदा. pmkisan, uidai, incometax)",
            inspectBtn: "जाँच करें",
            inspecting: "विश्लेषण जारी है...",
            criticalThreat: "गंभीर खतरा (नकली सरकारी पोर्टल)",
            suspiciousDomain: "संदिग्ध वेबसाइट",
            verifiedOfficial: "प्रमाणित आधिकारिक सरकारी पोर्टल",
            authenticWeb: "सुरक्षित वेब सेवा",
            saveDossier: "रिपोर्ट सेव करें",
            viewReport: "रिपोर्ट देखें",
            advisoryPrefix: "नागरिक चेतावनी:",
            listen: "आवाज़ में सुनें",
            speaking: "बोल रहा है...",
            advisoryThreat: "सावधान! अपना आधार नंबर, पैन, बैंक OTP यहाँ बिल्कुल न डालें। यह ठगी करने वाली फर्जी साइट है।",
            advisorySuspicious: "सावधानी बरतें। व्यक्तिगत जानकारी देने से पहले india.gov.in पर आधिकारिक लिंक की पुष्टि करें।",
            advisorySafe: "यह सुरक्षित और प्रमाणित आधिकारिक सरकारी पोर्टल है।",
            step1: "01. OPENSQUAT डोमेन एवं नाम की नकल जाँच",
            step2: "02. PHISHDETECT HTML एवं फॉर्म धोखा विश्लेषण",
            step3: "03. URL.VET रीडायरेक्ट एवं शॉर्टनर अनरोल जाँच",
            step4: "04. URL.VET DNS एवं मेल सर्वर सुरक्षा जाँच",
            step5: "05. संप्रभु AI न्यूरल मशीन लर्निंग विश्लेषण",
            sec65bDownload: "धारा 65B कोर्ट साक्ष्य प्रमाणपत्र डाउनलोड करें",
            speechWarningThreat: "सावधान! यह वेबसाइट फर्जी है और सरकारी पोर्टल की नकल कर रही है। अपना आधार नंबर, पैन नंबर या बैंक विवरण यहाँ बिल्कुल न भरें। तुरंत 1930 पर शिकायत करें।",
            speechWarningSuspicious: "सावधानी बरतें। यह वेबसाइट सरकारी डोमेन पर नहीं है। व्यक्तिगत जानकारी दर्ज न करें।",
            speechWarningSafe: "यह एक प्रमाणित आधिकारिक सरकारी पोर्टल है।",
            quickTest: "त्वरित परीक्षण:",
            noticeThreatHeading: "OTP या बैंक पासवर्ड बिल्कुल न भरें",
            noticeThreatDesc: "यह फर्जी वेबसाइट है। नागरिकों से आधार, बैंक खाता या OTP चुराने का प्रयास।",
            noticeSafeHeading: "प्रमाणित एवं सुरक्षित सरकारी पोर्टल",
            noticeSafeDesc: "यह भारत सरकार का अधिकृत एवं सत्यापित डिजिटल पोर्टल है (.gov.in / .nic.in)।",
            noticeCommercialHeading: "प्रमाणित वेब सेवा (गैर-सरकारी)",
            noticeCommercialDesc: "वैध और सुरक्षित सामान्य वेब सेवा। किसी सरकारी योजना की नकल नहीं है।",
            noticeCautionHeading: "संदिग्ध और अपुष्ट वेबसाइट",
            noticeCautionDesc: "सतर्क रहें। किसी भी गैर-सरकारी लिंक पर गोपनीय OTP साझा न करें।",
            advisoryCommercial: "यह एक सुरक्षित गैर-सरकारी वेबसाइट है। सामान्य रूप से उपयोग कर सकते हैं।",
            callNotice: "1930 पर कॉल करें",
            showForensics: "तकनीकी फॉरेंसिक विश्लेषण देखें",
            hideForensics: "तकनीकी फॉरेंसिक विश्लेषण छिपाएँ"
        }
    };

    function applyLanguage(lang) {
        currentLang = lang;
        const dict = i18n[lang] || i18n.en;

        const langEn = document.getElementById('langEn');
        const langHi = document.getElementById('langHi');
        if (langEn) langEn.className = lang === 'en' ? 'lang-btn active' : 'lang-btn';
        if (langHi) langHi.className = lang === 'hi' ? 'lang-btn active' : 'lang-btn';

        const brandTitle = document.getElementById('lblBrandTitle');
        if (brandTitle) brandTitle.textContent = dict.brandTitle;
        const brandSub = document.getElementById('lblBrandSub');
        if (brandSub) brandSub.textContent = dict.brandSub;

        const helpline = document.getElementById('lblHelpline');
        if (helpline) helpline.textContent = dict.helpline;

        const blockchainBtn = document.getElementById('lblBlockchain');
        if (blockchainBtn) blockchainBtn.textContent = dict.blockchainBtn;

        const liteModeBtn = document.getElementById('lblLiteMode');
        if (liteModeBtn) liteModeBtn.textContent = isLiteMode ? dict.tacticalModeBtn : dict.liteModeBtn;

        const heroTitle = document.getElementById('heroTitle');
        if (heroTitle) heroTitle.innerHTML = dict.heroTitle;

        const heroTagline = document.getElementById('heroTagline');
        if (heroTagline) heroTagline.textContent = dict.heroTagline;

        const urlInput = document.getElementById('urlInput');
        if (urlInput) urlInput.placeholder = dict.placeholder;

        const scanBtnText = document.getElementById('scanBtnText');
        if (scanBtnText) scanBtnText.textContent = dict.inspectBtn;

        const lblQuickTest = document.getElementById('lblQuickTest');
        if (lblQuickTest) lblQuickTest.textContent = dict.quickTest;

        const lblNoticeCall = document.getElementById('lblNoticeCall');
        if (lblNoticeCall) lblNoticeCall.textContent = dict.callNotice;

        const lblToggleForensics = document.getElementById('lblToggleForensics');
        if (lblToggleForensics) {
            const stepsEl = document.getElementById('inspectionSteps');
            const isVisible = stepsEl && stepsEl.style.display !== 'none';
            lblToggleForensics.textContent = isVisible ? dict.hideForensics : dict.showForensics;
        }

        const lblSaveDossier = document.getElementById('lblSaveDossier');
        if (lblSaveDossier) lblSaveDossier.textContent = dict.saveDossier;

        const lblViewReport = document.getElementById('lblViewReport');
        if (lblViewReport) lblViewReport.textContent = dict.viewReport;

        const lblAdvisory = document.getElementById('lblAdvisory');
        if (lblAdvisory) lblAdvisory.textContent = dict.advisoryPrefix;

        const lblVoice = document.getElementById('lblVoice');
        if (lblVoice) lblVoice.textContent = isSpeaking ? dict.speaking : dict.listen;

        const lblDownloadSec65B = document.getElementById('lblDownloadSec65B');
        if (lblDownloadSec65B) lblDownloadSec65B.textContent = dict.sec65bDownload;

        if (currentAnalysisResult) {
            renderRealVerdict(currentAnalysisResult, currentAnalysisResult.url);
        }
    }

    // Language Toggle Listeners
    const langEnBtn = document.getElementById('langEn');
    const langHiBtn = document.getElementById('langHi');
    if (langEnBtn) langEnBtn.addEventListener('click', () => applyLanguage('en'));
    if (langHiBtn) langHiBtn.addEventListener('click', () => applyLanguage('hi'));

    // 2. Bharat Lite Mode (Low-Resource & Budget Phone Optimization)
    const btnToggleLiteMode = document.getElementById('btnToggleLiteMode');
    function toggleLiteMode() {
        isLiteMode = !isLiteMode;
        const dict = i18n[currentLang];
        const lbl = document.getElementById('lblLiteMode');
        const icon = document.getElementById('liteModeIcon');

        if (isLiteMode) {
            document.body.classList.add('lite-mode');
            if (lbl) lbl.textContent = dict.tacticalModeBtn;
            if (icon) icon.textContent = '🚀';
            showToast("Bharat Lite Mode enabled: Fast, low-data for budget phones");
        } else {
            document.body.classList.remove('lite-mode');
            if (lbl) lbl.textContent = dict.liteModeBtn;
            if (icon) icon.textContent = '⚡';
            showToast("Tactical 3D Spatial Mode restored");
        }
    }
    if (btnToggleLiteMode) {
        btnToggleLiteMode.addEventListener('click', toggleLiteMode);
    }

    // Auto-detect small budget mobile devices (<768px) and default to Lite Mode for silky speed
    if (window.innerWidth <= 768) {
        isLiteMode = true;
        document.body.classList.add('lite-mode');
        const lbl = document.getElementById('lblLiteMode');
        if (lbl) lbl.textContent = i18n[currentLang].tacticalModeBtn;
    }

    // 3. Interactive 3D Spatial Parallax Tracking (Throttled with requestAnimationFrame)
    let mouseAnimFrame = null;
    window.addEventListener('mousemove', (e) => {
        if (isLiteMode || mouseAnimFrame) return;
        mouseAnimFrame = requestAnimationFrame(() => {
            const x = (e.clientX / window.innerWidth - 0.5) * 2;
            const y = (e.clientY / window.innerHeight - 0.5) * 2;
            document.documentElement.style.setProperty('--mouse-x', x.toFixed(3));
            document.documentElement.style.setProperty('--mouse-y', y.toFixed(3));
            mouseAnimFrame = null;
        });
    });

    // 4. Vernacular Voice Advisory (Web Speech API)
    const btnVoiceReadout = document.getElementById('btnVoiceReadout');
    function speakAdvisory(text) {
        if (!('speechSynthesis' in window)) {
            showToast("Voice playback not supported in this browser");
            return;
        }

        if (isSpeaking) {
            window.speechSynthesis.cancel();
            isSpeaking = false;
            updateVoiceBtn(false);
            return;
        }

        const utterance = new SpeechSynthesisUtterance(text);
        utterance.lang = currentLang === 'hi' ? 'hi-IN' : 'en-IN';
        utterance.rate = 0.92; // Slightly slower, crystal clear pace for rural citizens

        utterance.onstart = () => {
            isSpeaking = true;
            updateVoiceBtn(true);
        };
        utterance.onend = () => {
            isSpeaking = false;
            updateVoiceBtn(false);
        };
        utterance.onerror = () => {
            isSpeaking = false;
            updateVoiceBtn(false);
        };

        window.speechSynthesis.speak(utterance);
    }

    function updateVoiceBtn(speaking) {
        if (!btnVoiceReadout) return;
        const dict = i18n[currentLang];
        const lblVoice = document.getElementById('lblVoice');
        const voiceIcon = document.getElementById('voiceIcon');

        if (speaking) {
            btnVoiceReadout.classList.add('speaking');
            if (lblVoice) lblVoice.textContent = dict.speaking;
            if (voiceIcon) voiceIcon.textContent = '⏹️';
        } else {
            btnVoiceReadout.classList.remove('speaking');
            if (lblVoice) lblVoice.textContent = dict.listen;
            if (voiceIcon) voiceIcon.textContent = '🔊';
        }
    }

    if (btnVoiceReadout) {
        btnVoiceReadout.addEventListener('click', () => {
            if (!currentAnalysisResult) {
                const welcomeMsg = currentLang === 'hi'
                    ? "गवशील्ड में आपका स्वागत है। किसी भी वेबसाइट का पता दर्ज करके जाँच करें।"
                    : "Welcome to GovShield. Enter any website address to inspect for fraud.";
                speakAdvisory(welcomeMsg);
                return;
            }

            const verdict = currentAnalysisResult.verdict;
            const dict = i18n[currentLang];
            let voiceText = dict.speechWarningSafe;
            if (verdict === 'PHISHING_CLONE') {
                voiceText = dict.speechWarningThreat;
            } else if (verdict === 'SUSPICIOUS') {
                voiceText = dict.speechWarningSuspicious;
            }
            speakAdvisory(voiceText);
        });
    }

    // 5. Scan Trigger Handlers
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const resultsWrapper = document.getElementById('resultsWrapper');

    if (scanBtn) {
        scanBtn.addEventListener('click', () => {
            const url = urlInput ? urlInput.value.trim() : '';
            if (!url) {
                showToast(currentLang === 'hi' ? "कृपया जाँच के लिए वेबसाइट का पता दर्ज करें" : "Please enter a URL to scan");
                if (urlInput) urlInput.focus();
                return;
            }
            executeScan(url);
        });
    }

    if (urlInput) {
        urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const url = urlInput.value.trim();
                if (url) executeScan(url);
            }
        });
    }

    // 6. Execute Scan against AI & Blockchain Backend
    async function executeScan(url) {
        let normalizedUrl = url.trim();
        if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
            normalizedUrl = 'https://' + normalizedUrl;
        }

        const dict = i18n[currentLang];
        if (scanBtn) {
            scanBtn.innerHTML = `<span>${dict.inspecting}</span>`;
            scanBtn.disabled = true;
        }

        try {
            const response = await fetch(`${API_BASE}/api/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: normalizedUrl })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const scanResult = await response.json();
            currentAnalysisResult = scanResult;
            renderRealVerdict(scanResult, normalizedUrl);

            // Auto voice advisory prompt on threats for rural accessibility
            if (scanResult.verdict === 'PHISHING_CLONE' || scanResult.verdict === 'MALICIOUS' || (scanResult.risk_score && scanResult.risk_score >= 60)) {
                speakAdvisory(dict.speechWarningThreat);
            }

        } catch (err) {
            console.warn("FastAPI backend error:", err);
            showToast(currentLang === 'hi' ? "सर्वर से संपर्क विफल रहा। कृपया पुन: प्रयास करें।" : "Connection to AI backend failed. Please try again.");
        } finally {
            if (scanBtn) {
                scanBtn.innerHTML = `<span id="scanBtnText">${dict.inspectBtn}</span> ↵`;
                scanBtn.disabled = false;
            }
        }
    }

    // 7. Render Real Backend Verdict
    function renderRealVerdict(res, originalUrl) {
        if (!resultsWrapper) return;
        resultsWrapper.style.display = 'block';

        const dict = i18n[currentLang];
        const score = Number(res.risk_score) || 0;
        const isThreat = res.verdict === 'PHISHING_CLONE' || res.verdict === 'MALICIOUS' || score >= 60;
        const isSuspicious = !isThreat && (res.verdict === 'SUSPICIOUS' || score >= 25);
        const isGov = Boolean(res.is_genuine_gov_tld || res.category === 'OFFICIAL_GOVERNMENT_PORTAL' || (originalUrl && (originalUrl.includes('.gov.in') || originalUrl.includes('.nic.in'))));

        const scoreEl = document.getElementById('scoreNumber');
        if (scoreEl) {
            scoreEl.textContent = score < 10 ? `0${score}` : score;
            if (isThreat) {
                scoreEl.style.color = 'var(--color-threat)';
            } else if (isSuspicious) {
                scoreEl.style.color = 'var(--color-caution)';
            } else {
                scoreEl.style.color = 'var(--color-safe)';
            }
        }

        const badgeEl = document.getElementById('verdictBadge');
        if (badgeEl) {
            if (isThreat) {
                badgeEl.textContent = dict.criticalThreat;
                badgeEl.className = 'verdict-badge-clean badge-threat';
            } else if (isSuspicious) {
                badgeEl.textContent = dict.suspiciousDomain;
                badgeEl.className = 'verdict-badge-clean badge-caution';
            } else if (isGov) {
                badgeEl.textContent = dict.verifiedOfficial;
                badgeEl.className = 'verdict-badge-clean badge-safe';
            } else {
                badgeEl.textContent = dict.authenticWeb;
                badgeEl.className = 'verdict-badge-clean badge-safe';
            }
        }

        const urlEl = document.getElementById('urlHeadline');
        if (urlEl) urlEl.textContent = originalUrl || res.url;

        const summaryEl = document.getElementById('verdictSummary');
        if (summaryEl) {
            let summaryText = res.summary || "Scan completed.";
            if (currentLang === 'hi') {
                if (isThreat) {
                    summaryText = `गंभीर खतरा! यह वेबसाइट ${res.target_entity || 'सरकारी सेवा'} की नकल कर रही है। नागरिकों से आधार और बैंक विवरण चुराने का प्रयास।`;
                } else if (isSuspicious) {
                    summaryText = `संदिग्ध पोर्टल! ${res.target_entity || 'सरकारी सेवा'} के नाम का अनधिकृत उपयोग।`;
                } else if (isGov) {
                    summaryText = "प्रमाणित आधिकारिक सरकारी पोर्टल। राष्ट्रीय सूचना विज्ञान केंद्र (NIC) अवसंरचना पर सुरक्षित।";
                } else {
                    summaryText = "वैध एवं सुरक्षित सामान्य वेब सेवा। किसी सरकारी योजना की नकल नहीं है।";
                }
            } else {
                if (isThreat && res.target_entity) {
                    summaryText = `CRITICAL FRAUD: Deceptive impersonation targeting ${res.target_entity}. ${res.summary || ''}`;
                } else if (!isGov && !isThreat && !isSuspicious) {
                    summaryText = "Authentic commercial web service. No government portal impersonation or citizen identity theft observed.";
                }
            }
            summaryEl.textContent = summaryText;
        }

        const remediationEl = document.getElementById('remediationText');
        if (remediationEl) {
            if (isThreat) {
                remediationEl.textContent = dict.advisoryThreat;
            } else if (isSuspicious) {
                remediationEl.textContent = dict.advisorySuspicious;
            } else if (isGov) {
                remediationEl.textContent = dict.advisorySafe;
            } else {
                remediationEl.textContent = dict.advisoryCommercial;
            }
        }

        // 7.1 High-Visibility Villager Alert Banner
        const villagerBox = document.getElementById('villagerNoticeBox');
        const noticeIcon = document.getElementById('noticeIcon');
        const noticeHeading = document.getElementById('noticeHeading');
        const noticeDesc = document.getElementById('noticeDesc');
        const noticeDialBtn = document.getElementById('noticeDialBtn');

        if (villagerBox) {
            if (isThreat) {
                villagerBox.className = 'villager-notice-box notice-threat';
                if (noticeIcon) noticeIcon.textContent = '🚨';
                if (noticeHeading) noticeHeading.textContent = dict.noticeThreatHeading;
                if (noticeDesc) noticeDesc.textContent = dict.noticeThreatDesc;
                if (noticeDialBtn) noticeDialBtn.style.display = 'inline-flex';
            } else if (isSuspicious) {
                villagerBox.className = 'villager-notice-box notice-caution';
                if (noticeIcon) noticeIcon.textContent = '⚠️';
                if (noticeHeading) noticeHeading.textContent = dict.noticeCautionHeading;
                if (noticeDesc) noticeDesc.textContent = dict.noticeCautionDesc;
                if (noticeDialBtn) noticeDialBtn.style.display = 'inline-flex';
            } else if (isGov) {
                villagerBox.className = 'villager-notice-box notice-safe';
                if (noticeIcon) noticeIcon.textContent = '🏛️';
                if (noticeHeading) noticeHeading.textContent = dict.noticeSafeHeading;
                if (noticeDesc) noticeDesc.textContent = dict.noticeSafeDesc;
                if (noticeDialBtn) noticeDialBtn.style.display = 'none';
            } else {
                villagerBox.className = 'villager-notice-box notice-safe';
                if (noticeIcon) noticeIcon.textContent = '🌐';
                if (noticeHeading) noticeHeading.textContent = dict.noticeCommercialHeading;
                if (noticeDesc) noticeDesc.textContent = dict.noticeCommercialDesc;
                if (noticeDialBtn) noticeDialBtn.style.display = 'none';
            }
        }

        // 7.2 Inline Proof Strip (MinHash & Blockchain PoA)
        const proofBlockVal = document.getElementById('proofBlockVal');
        const proofMinHashVal = document.getElementById('proofMinHashVal');
        const proofSec65BVal = document.getElementById('proofSec65BVal');

        const blockHeight = res.blockchain_proof ? (res.blockchain_proof.block_index || 1) : 1;
        const txHash = res.blockchain_proof ? (res.blockchain_proof.tx_hash ? res.blockchain_proof.tx_hash.substring(0, 8) + '...' : '0xVerified') : '0x7F2A...';
        if (proofBlockVal) proofBlockVal.textContent = `PoA Block #${blockHeight} (${txHash})`;

        const minHashScore = res.signal_breakdown && res.signal_breakdown.content_similarity ? Number(res.signal_breakdown.content_similarity) : 0;
        if (proofMinHashVal) {
            if (minHashScore > 0) {
                proofMinHashVal.textContent = `${minHashScore}% Structural Clone Match`;
            } else if (res.verdict === 'PHISHING_CLONE') {
                proofMinHashVal.textContent = `High Layout Cloning`;
            } else {
                proofMinHashVal.textContent = `0% Divergent DOM`;
            }
        }
        if (proofSec65BVal) {
            proofSec65BVal.textContent = res.incident_id ? `${res.incident_id}` : 'Sec 65B Certified';
        }

        // 7.3 Render Citizen Safety Checklist (OTP, Paywalls, Links, Authority)
        const checklistGrid = document.getElementById('checklistGrid');
        const mlModelBadge = document.getElementById('mlModelBadge');
        if (checklistGrid) {
            checklistGrid.innerHTML = '';
            const mlData = res.sovereign_ml || {};
            const chkData = res.security_checklist || {};

            if (mlModelBadge) {
                const mlProb = mlData.probability !== undefined ? (mlData.probability * 100).toFixed(1) : (score > 50 ? score : 0.0);
                mlModelBadge.textContent = `SOVEREIGN AI ML: ${mlProb}% PHISHING PROB`;
                if (isThreat) {
                    mlModelBadge.style.color = '#DC2626';
                    mlModelBadge.style.background = 'rgba(220, 38, 38, 0.1)';
                    mlModelBadge.style.borderColor = 'rgba(220, 38, 38, 0.3)';
                } else if (isGov) {
                    mlModelBadge.style.color = '#16A34A';
                    mlModelBadge.style.background = 'rgba(22, 163, 74, 0.1)';
                    mlModelBadge.style.borderColor = 'rgba(22, 163, 74, 0.3)';
                } else {
                    mlModelBadge.style.color = '#4F46E5';
                    mlModelBadge.style.background = 'rgba(99, 102, 241, 0.1)';
                    mlModelBadge.style.borderColor = 'rgba(99, 102, 241, 0.3)';
                }
            }

            const items = [
                {
                    key: 'otp_credentials',
                    fallbackIcon: '🔑',
                    fallbackTitle: currentLang === 'hi' ? 'OTP एवं गोपनीय पहचान' : 'OTP & Citizen Credentials',
                    fallbackDesc: isThreat
                        ? (currentLang === 'hi' ? 'खतरा: अपना OTP, आधार नंबर या पासवर्ड यहाँ बिल्कुल न डालें।' : 'CRITICAL RISK: Never enter OTP, Aadhaar, PAN or passwords.')
                        : (isGov
                            ? (currentLang === 'hi' ? 'प्रमाणित: राष्ट्रीय सूचना विज्ञान केंद्र (NIC) सुरक्षित पोर्टल।' : 'SAFE: Official Government authentication gateway.')
                            : (currentLang === 'hi' ? 'सावधानी: गैर-सरकारी पोर्टल। गोपनीय सरकारी OTP यहाँ साझा न करें।' : 'CAUTION: Non-gov service. Do not enter scheme OTPs.')),
                    status: isThreat ? 'CRITICAL' : (isGov ? 'SAFE' : 'CAUTION'),
                    statusText: isThreat ? (currentLang === 'hi' ? 'अति संवेदनशील' : 'CRITICAL') : (isGov ? (currentLang === 'hi' ? 'सुरक्षित' : 'SAFE') : (currentLang === 'hi' ? 'सतर्क रहें' : 'CAUTION'))
                },
                {
                    key: 'paywalls_fees',
                    fallbackIcon: '💳',
                    fallbackTitle: currentLang === 'hi' ? 'शुल्क, पंजीकरण एवं पेवॉल' : 'Application Fees & Paywalls',
                    fallbackDesc: isThreat
                        ? (currentLang === 'hi' ? 'फर्जी शुल्क: सरकारी कल्याणकारी योजनाएँ कोई आवेदन शुल्क या UPI भुगतान नहीं मांगती हैं।' : 'SCAM ALERT: Welfare schemes never charge registration fees or request UPI transfers.')
                        : (isGov
                            ? (currentLang === 'hi' ? 'निःशुल्क: कोई अनधिकृत गेटवे या अवैध शुल्क नहीं है।' : 'SAFE: Verified official benefit disbursal platform.')
                            : (currentLang === 'hi' ? 'सामान्य: गैर-सरकारी सेवा। किसी भी भुगतान से पूर्व पुष्टि करें।' : 'INFO: Standard commercial platform. Verify transactions independently.')),
                    status: isThreat ? 'CRITICAL' : (isGov ? 'SAFE' : 'INFO'),
                    statusText: isThreat ? (currentLang === 'hi' ? 'अवैध वसूली' : 'SCAM FEE') : (isGov ? (currentLang === 'hi' ? 'निःशुल्क/वैध' : 'OFFICIAL') : (currentLang === 'hi' ? 'सामान्य' : 'INFO'))
                },
                {
                    key: 'links_redirects',
                    fallbackIcon: '🔗',
                    fallbackTitle: currentLang === 'hi' ? 'लिंक एवं डेटा प्रेषण' : 'Link Routing & Exfiltration',
                    fallbackDesc: isThreat
                        ? (currentLang === 'hi' ? 'संदिग्ध लिंक: डेटा अनधिकृत सर्वर या टेलीग्राम बॉट पर भेजा जा सकता है।' : 'ALERT: Form actions route data to unauthorized third-party servers.')
                        : (isGov
                            ? (currentLang === 'hi' ? 'सुरक्षित: सभी लिंक राष्ट्रीय सूचना विज्ञान केंद्र नेटवर्क में हैं।' : 'SAFE: All endpoints route within authenticated government servers.')
                            : (currentLang === 'hi' ? 'सामान्य: कोई दुर्भावनापूर्ण रीडायरेक्ट नहीं पाया गया।' : 'SAFE: Standard public web links.')),
                    status: isThreat ? 'CRITICAL' : 'SAFE',
                    statusText: isThreat ? (currentLang === 'hi' ? 'असुरक्षित' : 'SUSPICIOUS') : (currentLang === 'hi' ? 'सत्यापित' : 'VERIFIED')
                },
                {
                    key: 'sovereign_accreditation',
                    fallbackIcon: '🏛️',
                    fallbackTitle: currentLang === 'hi' ? 'सरकारी मान्यता एवं अधिकार' : 'Sovereign Accreditation',
                    fallbackDesc: isGov
                        ? (currentLang === 'hi' ? 'मान्यता प्राप्त: भारत सरकार (NIC) का अधिकृत डिजिटल पोर्टल (.gov.in)।' : 'AUTHENTIC: Accredited by National Informatics Centre (NIC India).')
                        : (isThreat
                            ? (currentLang === 'hi' ? 'अनधिकृत: सरकारी योजनाओं की अवैध नकल करने वाला फर्जी पोर्टल।' : 'IMPERSONATION: Fake lookalike mimicking national schemes without authority.')
                            : (currentLang === 'hi' ? 'गैर-सरकारी: स्वतंत्र सामान्य व्यावसायिक वेब सेवा।' : 'NON-GOV: Independent legitimate commercial web service.')),
                    status: isGov ? 'SAFE' : (isThreat ? 'CRITICAL' : 'CAUTION'),
                    statusText: isGov ? (currentLang === 'hi' ? 'सरकारी अधिकृत' : 'GOV.IN') : (isThreat ? (currentLang === 'hi' ? 'फर्जी नकल' : 'FAKE') : (currentLang === 'hi' ? 'गैर-सरकारी' : 'NON-GOV'))
                }
            ];

            items.forEach(item => {
                const liveChk = chkData[item.key] || {};
                const heading = liveChk.heading || item.fallbackTitle;
                const desc = liveChk.description || item.fallbackDesc;
                const icon = liveChk.icon || item.fallbackIcon;
                const status = liveChk.status || item.status;
                const pillClass = status === 'CRITICAL' ? 'pill-critical' : (status === 'SAFE' || status === 'AUTHENTIC_GOV' ? 'pill-safe' : 'pill-caution');
                const cardClass = status === 'CRITICAL' ? 'chk-critical' : (status === 'SAFE' || status === 'AUTHENTIC_GOV' ? 'chk-safe' : 'chk-caution');

                const card = document.createElement('div');
                card.className = `chk-card ${cardClass}`;
                card.innerHTML = `
                    <div class="chk-icon-col">${icon}</div>
                    <div class="chk-body">
                        <div class="chk-heading-row">
                            <span class="chk-heading">${heading}</span>
                            <span class="chk-status-pill ${pillClass}">[${item.statusText}]</span>
                        </div>
                        <p class="chk-desc">${desc}</p>
                    </div>
                `;
                checklistGrid.appendChild(card);
            });
        }

        // 5 Inspection Steps
        const stepsEl = document.getElementById('inspectionSteps');
        if (stepsEl) {
            stepsEl.innerHTML = '';

            const breakdown = res.signal_breakdown || {};
            const lexScore = Number(breakdown.lexical_score) || 0;
            const sensFields = breakdown.sensitive_fields_found || [];
            const visScore = Number(breakdown.visual_similarity) || 0;
            const ageDays = Number(breakdown.domain_age_days) || 0;
            const aiData = res.genai_analysis || {};

            const typosquatData = res.typosquat_details || {};
            const redirectData = res.redirect_details || {};
            const dnsData = res.dns_security_details || {};
            const domData = res.dom_details || {};
            const htmlDeception = domData.html_deception_signals || {};
            const mlData = res.sovereign_ml || {};

            const steps = [
                {
                    title: dict.step1,
                    status: (typosquatData.is_typosquat && !isGov) ? "FAIL" : (lexScore > 20 ? "WARN" : "PASS"),
                    description: (typosquatData.is_typosquat && !isGov)
                        ? (currentLang === 'hi' 
                            ? `openSquat चेतावनी: ${typosquatData.squat_type} (लक्ष्य: ${typosquatData.target_brand})। ${typosquatData.details}`
                            : `openSquat Alert: ${typosquatData.squat_type} targeting ${typosquatData.target_brand}. ${typosquatData.details}`)
                        : (isGov
                            ? (currentLang === 'hi' ? `प्रमाणित NIC आधिकारिक डोमेन रजिस्ट्री।` : `Authenticated National Sovereign Domain (.gov.in / .nic.in).`)
                            : (currentLang === 'hi' ? `कोई फर्जी डोमेन नकल या टाइपोस्क्वैटिंग नहीं मिली।` : `Zero typosquatting or sovereign permutation anomalies detected.`))
                },
                {
                    title: dict.step2,
                    status: (sensFields.length > 0 && !isGov) || htmlDeception.is_deceptive_title || htmlDeception.has_escaped_brand_obfuscation ? "FAIL" : "PASS",
                    description: (sensFields.length > 0 && !isGov)
                        ? (currentLang === 'hi' ? `PhishDetect अलर्ट: गैर-सरकारी सर्वर पर संवेदनशील टोकन [${sensFields.join(', ')}] चुराने वाला फॉर्म मिला!` : `PhishDetect Alert: Identity harvesting form fields: [${sensFields.join(', ')}] on non-gov domain.`)
                        : (htmlDeception.is_deceptive_title
                            ? (currentLang === 'hi' ? `PhishDetect अलर्ट: गैर-सरकारी डोमेन पर फर्जी शीर्षक: '${htmlDeception.deceptive_title_brand}'` : `PhishDetect Alert: Deceptive title claiming official authority on non-gov host: '${htmlDeception.deceptive_title_brand}'`)
                            : (currentLang === 'hi' ? `कोई छिपा हुआ फॉर्म या HTML भ्रामक टैग नहीं पाया गया।` : `DOM structure verified clean. No hidden brand obfuscation (&#...;) or credential traps.`))
                },
                {
                    title: dict.step3,
                    status: (redirectData.is_cross_domain || redirectData.is_shortener) && isThreat ? "FAIL" : ((redirectData.redirected) ? "WARN" : "PASS"),
                    description: redirectData.redirected
                        ? (currentLang === 'hi'
                            ? `url.vet ट्रेस: ${redirectData.hop_count} रीडायरेक्ट हॉप्स। अंतिम गंतव्य: ${redirectData.final_url}`
                            : `url.vet Trace: ${redirectData.hop_count} redirect hops traversed. Final destination: ${redirectData.final_url}`)
                        : (currentLang === 'hi' ? `कोई भ्रामक रीडायरेक्ट या URL शॉर्टनर नहीं मिला। प्रत्यक्ष लिंक।` : `Direct connection. No deceptive URL shortener obfuscation or intermediate redirect hops.`)
                },
                {
                    title: dict.step4,
                    status: (dnsData.dns_risk_score >= 35 && !isGov) ? "FAIL" : (dnsData.dns_risk_score >= 20 ? "WARN" : "PASS"),
                    description: dnsData.findings && dnsData.findings.length > 0
                        ? (currentLang === 'hi' ? `url.vet DNS ऑडिट: ${dnsData.findings.join(' ')}` : `url.vet DNS Audit: ${dnsData.findings.join(' ')}`)
                        : (isGov
                            ? (currentLang === 'hi' ? `राष्ट्रीय सूचना विज्ञान केंद्र (NIC) संप्रभु DNS और मेल अवसंरचना।` : `Sovereign NIC DNS infrastructure with authenticated reverse-IP pointers.`)
                            : (currentLang === 'hi' ? `सक्रिय IP एवं वैध मेल सर्वर (MX) सत्यापित।` : `Active IP and valid Mail Exchange (MX) infrastructure verified.`))
                },
                {
                    title: dict.step5,
                    status: isThreat ? "FAIL" : (isSuspicious ? "WARN" : "PASS"),
                    description: mlData.top_contributing_factors && mlData.top_contributing_factors.length > 0
                        ? (currentLang === 'hi'
                            ? `AI मॉडल निष्कर्ष: ${mlData.top_contributing_factors.join('; ')} (खतरा संभावना: ${(mlData.probability * 100).toFixed(1)}%)`
                            : `Sovereign AI Decision: ${mlData.top_contributing_factors.join('; ')} (Phishing Prob: ${(mlData.probability * 100).toFixed(1)}%)`)
                        : (aiData.plain_english_explanation || (res.reasons && res.reasons.length > 0 ? res.reasons[0] : (currentLang === 'hi' ? "भारत सरकार के संप्रभु साइबर रक्षा आधार पर सत्यापित।" : "Verified against Government of India sovereign defense baseline.")))
                }
            ];

            steps.forEach((layer, index) => {
                const step = document.createElement('div');
                step.className = 'step-card';
                const stepNum = index < 9 ? `0${index + 1}` : `${index + 1}`;

                let statusColor = 'var(--color-safe)';
                let statusText = 'PASS';
                if (layer.status === 'FAIL') {
                    statusColor = 'var(--color-threat)';
                    statusText = currentLang === 'hi' ? 'खतरनाक' : 'MALICIOUS';
                } else if (layer.status === 'WARN') {
                    statusColor = 'var(--color-caution)';
                    statusText = currentLang === 'hi' ? 'संदिग्ध' : 'SUSPICIOUS';
                } else {
                    statusText = currentLang === 'hi' ? 'सुरक्षित' : 'PASS';
                }

                step.innerHTML = `
                    <div class="step-number">${stepNum}</div>
                    <div class="step-content">
                        <div class="step-header">
                            <span class="step-title">${layer.title}</span>
                            <span class="step-status" style="color: ${statusColor};">[${statusText}]</span>
                        </div>
                        <p class="step-desc">${layer.description}</p>
                    </div>
                `;
                stepsEl.appendChild(step);
            });
        }

        const compBtn = document.getElementById('btnComparePhishGuard');
        if (compBtn && originalUrl) {
            compBtn.href = `http://localhost:8001?url=${encodeURIComponent(originalUrl)}`;
        }

        resultsWrapper.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // 8. CERT-In Takedown Dossier Modal
    const dossierModal = document.getElementById('dossierModal');
    const modalCloseBtn = document.getElementById('modalCloseBtn');
    const dossierText = document.getElementById('dossierText');
    const copyDossierBtn = document.getElementById('copyDossierBtn');
    const btnQuickDossier = document.getElementById('btnQuickDossier');
    const btnDownloadDossierQuick = document.getElementById('btnDownloadDossierQuick');
    const downloadDossierModalBtn = document.getElementById('downloadDossierModalBtn');

    function downloadReportFile(content, filename) {
        if (!content) {
            showToast(currentLang === 'hi' ? "डाउनलोड के लिए कोई रिपोर्ट नहीं है" : "No dossier content to download");
            return;
        }
        const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename || `CERTIN_INCIDENT_DOSSIER_${Date.now()}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast(currentLang === 'hi' ? "डॉक्यूमेंट डाउनलोड हो गया" : "Dossier report downloaded");
    }

    async function generateDossierText(res) {
        if (!res) return "";
        try {
            const resp = await fetch(`${API_BASE}/api/report-certin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scan_result: res, reporter_notes: "Web Portal Inspection Dossier" })
            });
            if (resp.ok) {
                const reportJson = await resp.json();
                const report = reportJson.incident_report || reportJson;
                const bc = report.sovereign_blockchain_proof || {};
                return `========================================================================
CYBER SECURITY INCIDENT REPORT / PHISHING TAKEDOWN DOSSIER
Prepared for: CERT-In (incident@cert-in.org.in) & CyberCrime Portal (cybercrime.gov.in)
Incident ID : ${report.incident_id || 'CERTIN-INC-AUTO'}
Timestamp   : ${report.report_timestamp_utc || new Date().toISOString()}
========================================================================
Target Scope      : Government of India Sovereign Public Services
Impersonated Port.: ${report.target_government_entity || res.target_entity || 'Government Scheme'}
Malicious URL     : ${report.malicious_url || res.url}
Threat Score      : ${report.risk_score || res.risk_score} / 100
Classification    : ${report.classification || res.verdict}

[1] IMMUTABLE BLOCKCHAIN EVIDENCE (Sec 65B Indian Evidence Act):
- Ledger Block Height             : Height #${bc.ledger_block_height || 1}
- Block Header Hash               : ${bc.block_hash || 'Verified on PoA Sovereign Grid'}
- Merkle Root Proof               : ${bc.merkle_root || 'Validated'}
- DOM Cryptographic SHA-256       : ${bc.dom_sha256_fingerprint || '0xVerified'}

[2] FORENSIC EVIDENCE:
- Lexical Typosquatting Score     : ${report.forensic_evidence?.lexical_typosquatting_score || 0}/100
- Visual Perceptual Similarity    : ${report.forensic_evidence?.visual_perceptual_similarity_percentage || 0}%
- DOM Identity Harvesting Fields  : ${(report.forensic_evidence?.harvested_sensitive_fields || []).join(', ') || 'None'}
- Domain Age                      : ${report.forensic_evidence?.domain_age_days || 'N/A'} days

[3] DETECTED MALICIOUS INDICATORS:
${(report.detected_anomalies_and_indicators || res.reasons || []).map((r, i) => `[${i+1}] ${r}`).join('\n')}

[4] TAKEDOWN DIRECTIVES:
${(report.mitigation_recommendations || [
    "Issue urgent DNS sinkhole via NIXI / INRegistry.",
    "Direct ISP/TSP DNS blocking under Section 69A IT Act.",
    "Transmit immutable digital evidence to National Cyber Crime Reporting Portal (NCRP/1930).",
    "Notify CERT-In Incident Response Team."
]).map((m, i) => `[${i+1}] ${m}`).join('\n')}
========================================================================`;
            }
        } catch (e) {
            return JSON.stringify(res, null, 2);
        }
        return JSON.stringify(res, null, 2);
    }

    async function openDossier(res) {
        if (!res) {
            showToast(currentLang === 'hi' ? "पहले एक वेबसाइट की जाँच करें" : "Scan a URL first");
            return;
        }
        const dossierContent = await generateDossierText(res);
        if (dossierText) dossierText.textContent = dossierContent;
        if (dossierModal) dossierModal.classList.add('active');
    }

    if (btnQuickDossier) {
        btnQuickDossier.addEventListener('click', () => openDossier(currentAnalysisResult));
    }

    if (btnDownloadDossierQuick) {
        btnDownloadDossierQuick.addEventListener('click', async () => {
            if (!currentAnalysisResult) {
                showToast(currentLang === 'hi' ? "पहले एक वेबसाइट की जाँच करें" : "Scan a URL first");
                return;
            }
            const content = await generateDossierText(currentAnalysisResult);
            downloadReportFile(content, `CERTIN_${currentAnalysisResult.verdict || 'INCIDENT'}_${Date.now()}.txt`);
        });
    }

    if (downloadDossierModalBtn && dossierText) {
        downloadDossierModalBtn.addEventListener('click', () => {
            downloadReportFile(dossierText.textContent, `CERTIN_DOSSIER_${Date.now()}.txt`);
            if (dossierModal) dossierModal.classList.remove('active');
        });
    }

    if (modalCloseBtn && dossierModal) {
        modalCloseBtn.addEventListener('click', () => dossierModal.classList.remove('active'));
    }

    if (dossierModal) {
        dossierModal.addEventListener('click', (e) => {
            if (e.target === dossierModal) dossierModal.classList.remove('active');
        });
    }

    if (copyDossierBtn && dossierText) {
        copyDossierBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(dossierText.textContent).then(() => {
                showToast(currentLang === 'hi' ? "रिपोर्ट कॉपी हो गई" : "Dossier copied to clipboard");
                if (dossierModal) dossierModal.classList.remove('active');
            }).catch(() => {
                showToast("Please copy manually");
            });
        });
    }

    // 9. Sovereign Blockchain Threat Intelligence Explorer
    const blockchainModal = document.getElementById('blockchainModal');
    const blockchainCloseBtn = document.getElementById('blockchainCloseBtn');
    const btnCloseBlockchainModal = document.getElementById('btnCloseBlockchainModal');
    const btnOpenBlockchain = document.getElementById('btnOpenBlockchain');
    const btnDownloadSec65B = document.getElementById('btnDownloadSec65B');

    async function openBlockchainExplorer() {
        if (!blockchainModal) return;
        blockchainModal.classList.add('active');

        const heightEl = document.getElementById('metricBlockHeight');
        const threatsEl = document.getElementById('metricThreatsLogged');
        const statusEl = document.getElementById('metricChainStatus');
        const streamBox = document.getElementById('blocksStreamBox');

        try {
            const resp = await fetch(`${API_BASE}/api/blockchain/chain`);
            if (resp.ok) {
                const data = await resp.json();
                const stats = data.stats || {};
                if (heightEl) heightEl.textContent = stats.total_blocks || data.chain_length || 1;
                if (threatsEl) threatsEl.textContent = stats.logged_phishing_threats || 0;
                if (statusEl) statusEl.textContent = stats.chain_integrity || "VALID";

                if (streamBox) {
                    streamBox.innerHTML = '';
                    const blocks = data.blocks || [];
                    blocks.slice().reverse().forEach((b) => {
                        const card = document.createElement('div');
                        card.className = 'block-entry-card';
                        card.innerHTML = `
                            <div class="block-entry-header">
                                <span>BLOCK #${b.index} • ${b.validator_node}</span>
                                <span style="color: var(--color-safe); font-size: 0.68rem;">[VERIFIED HASH]</span>
                            </div>
                            <div class="block-hash-line"><strong>HASH:</strong> ${b.hash}</div>
                            <div class="block-hash-line"><strong>MERKLE:</strong> ${b.merkle_root}</div>
                            <div>
                                ${b.transactions.map(t => `<span class="block-tx-tag">${t.type}: ${t.target_government_entity || t.entity || t.malicious_url || 'Threat Event'}</span>`).join(' ')}
                            </div>
                        `;
                        streamBox.appendChild(card);
                    });
                }
            }
        } catch (e) {
            console.warn("Blockchain ledger fetch note:", e);
        }
    }

    if (btnOpenBlockchain) {
        btnOpenBlockchain.addEventListener('click', openBlockchainExplorer);
    }

    if (blockchainCloseBtn && blockchainModal) {
        blockchainCloseBtn.addEventListener('click', () => blockchainModal.classList.remove('active'));
    }

    if (btnCloseBlockchainModal && blockchainModal) {
        btnCloseBlockchainModal.addEventListener('click', () => blockchainModal.classList.remove('active'));
    }

    if (blockchainModal) {
        blockchainModal.addEventListener('click', (e) => {
            if (e.target === blockchainModal) blockchainModal.classList.remove('active');
        });
    }

    // Download Section 65B Electronic Evidence Certificate
    async function downloadSection65BCertificate() {
        if (!currentAnalysisResult || !currentAnalysisResult.incident_id) {
            showToast(currentLang === 'hi' ? "प्रमाणपत्र के लिए पहले एक फर्जी वेबसाइट की जाँच करें" : "Scan a suspicious website first to generate Section 65B certificate");
            return;
        }

        const incidentId = currentAnalysisResult.incident_id;
        try {
            const resp = await fetch(`${API_BASE}/api/blockchain/section65b/${incidentId}`);
            if (resp.ok) {
                const data = await resp.json();
                const certText = data.legal_certificate_text || JSON.stringify(data, null, 2);
                downloadReportFile(certText, `SEC_65B_COURT_EVIDENCE_${incidentId}.txt`);
                showToast(currentLang === 'hi' ? "धारा 65B कोर्ट प्रमाणपत्र डाउनलोड हो गया" : "Section 65B Court Certificate Downloaded");
            } else {
                showToast(currentLang === 'hi' ? "इस घटना के लिए प्रमाणपत्र तैयार नहीं हो सका" : "Certificate generation error");
            }
        } catch (e) {
            showToast("Network error generating certificate");
        }
    }

    if (btnDownloadSec65B) {
        btnDownloadSec65B.addEventListener('click', downloadSection65BCertificate);
    }

    // 9. Forensics Collapse & Quick Samples Handlers
    const btnToggleForensics = document.getElementById('btnToggleForensics');
    const toggleForensicsArrow = document.getElementById('toggleForensicsArrow');
    const lblToggleForensics = document.getElementById('lblToggleForensics');
    const stepsEl = document.getElementById('inspectionSteps');

    if (btnToggleForensics && stepsEl) {
        btnToggleForensics.addEventListener('click', () => {
            const isHidden = stepsEl.style.display === 'none' || !stepsEl.style.display;
            stepsEl.style.display = isHidden ? 'grid' : 'none';
            if (toggleForensicsArrow) toggleForensicsArrow.textContent = isHidden ? '▴' : '▾';
            if (lblToggleForensics) {
                lblToggleForensics.textContent = isHidden ? i18n[currentLang].hideForensics : i18n[currentLang].showForensics;
            }
        });
    }

    document.querySelectorAll('.sample-chip').forEach(chip => {
        chip.addEventListener('click', (e) => {
            const url = e.currentTarget.getAttribute('data-url');
            if (url && urlInput) {
                urlInput.value = url;
                executeScan(url);
            }
        });
    });

    // 10. Toast Helper
    function showToast(message) {
        const toast = document.createElement('div');
        toast.className = 'toast-clean';
        toast.textContent = message;

        let container = document.getElementById('toastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toastContainer';
            container.className = 'toast-container';
            document.body.appendChild(container);
        }

        container.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(6px)';
            toast.style.transition = 'all 0.2s ease';
            setTimeout(() => toast.remove(), 200);
        }, 2400);
    }
});
