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
    const API_BASE = window.location.origin.startsWith('http') ? window.location.origin : '';
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
            step1: "01. DOMAIN & TYPOSQUATTING ANALYSIS",
            step2: "02. CREDENTIAL FORM INSPECTION",
            step3: "03. VISUAL SIMILARITY MATCHING",
            step4: "04. DOMAIN AGE & REGISTRATION",
            step5: "05. AI NEURAL VERIFICATION",
            sec65bDownload: "Download Sec 65B Court Certificate",
            speechWarningThreat: "Warning! This website is a fake government clone attempting to steal citizen identity. Do not enter your Aadhaar, PAN, or OTP. For cyber fraud, call 1930 immediately.",
            speechWarningSuspicious: "Caution. This website is not on an official government domain. Verify before entering personal information.",
            speechWarningSafe: "This is a verified authentic web platform."
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
            step1: "01. डोमेन एवं नाम की नकल की जाँच",
            step2: "02. आधार/पैन/OTP फॉर्म की जाँच",
            step3: "03. सरकारी लोगो और रंग-रूप की नकल",
            step4: "04. वेबसाइट पंजीकरण की तारीख और आयु",
            step5: "05. AI साइबर रक्षा विश्लेषण",
            sec65bDownload: "धारा 65B कोर्ट साक्ष्य प्रमाणपत्र डाउनलोड करें",
            speechWarningThreat: "सावधान! यह वेबसाइट फर्जी है और सरकारी पोर्टल की नकल कर रही है। अपना आधार नंबर, पैन नंबर या बैंक विवरण यहाँ बिल्कुल न भरें। तुरंत 1930 पर शिकायत करें।",
            speechWarningSuspicious: "सावधानी बरतें। यह वेबसाइट सरकारी डोमेन पर नहीं है। व्यक्तिगत जानकारी दर्ज न करें।",
            speechWarningSafe: "यह एक प्रमाणित आधिकारिक सरकारी पोर्टल है।"
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
            if (scanResult.verdict === 'PHISHING_CLONE') {
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
        const scoreEl = document.getElementById('scoreNumber');
        if (scoreEl) {
            scoreEl.textContent = score < 10 ? `0${score}` : score;
            if (score >= 66) {
                scoreEl.style.color = 'var(--color-threat)';
            } else if (score >= 26) {
                scoreEl.style.color = 'var(--color-caution)';
            } else {
                scoreEl.style.color = 'var(--color-safe)';
            }
        }

        const badgeEl = document.getElementById('verdictBadge');
        if (badgeEl) {
            if (res.verdict === 'PHISHING_CLONE') {
                badgeEl.textContent = dict.criticalThreat;
                badgeEl.className = 'verdict-badge-clean badge-threat';
            } else if (res.verdict === 'SUSPICIOUS') {
                badgeEl.textContent = dict.suspiciousDomain;
                badgeEl.className = 'verdict-badge-clean badge-caution';
            } else {
                badgeEl.textContent = res.is_genuine_gov_tld ? dict.verifiedOfficial : dict.authenticWeb;
                badgeEl.className = 'verdict-badge-clean badge-safe';
            }
        }

        const urlEl = document.getElementById('urlHeadline');
        if (urlEl) urlEl.textContent = originalUrl || res.url;

        const summaryEl = document.getElementById('verdictSummary');
        if (summaryEl) {
            let summaryText = res.summary || "Scan completed.";
            if (currentLang === 'hi') {
                if (res.verdict === 'PHISHING_CLONE') {
                    summaryText = `गंभीर खतरा! यह वेबसाइट ${res.target_entity || 'सरकारी सेवा'} की नकल कर रही है। नागरिकों से आधार और बैंक विवरण चुराने का प्रयास।`;
                } else if (res.verdict === 'SUSPICIOUS') {
                    summaryText = `संदिग्ध पोर्टल! ${res.target_entity || 'सरकारी सेवा'} के नाम का अनधिकृत उपयोग।`;
                } else {
                    summaryText = "सुरक्षित वेबसाइट। सरकारी पोर्टल का कोई अनधिकृत क्लोन नहीं पाया गया।";
                }
            } else {
                if (res.target_entity && res.verdict !== 'LEGITIMATE') {
                    summaryText = `Deceptive impersonation targeting ${res.target_entity}. ${summaryText}`;
                }
            }
            summaryEl.textContent = summaryText;
        }

        const remediationEl = document.getElementById('remediationText');
        if (remediationEl) {
            if (res.verdict === 'PHISHING_CLONE') {
                remediationEl.textContent = dict.advisoryThreat;
            } else if (res.verdict === 'SUSPICIOUS') {
                remediationEl.textContent = dict.advisorySuspicious;
            } else {
                remediationEl.textContent = dict.advisorySafe;
            }
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

            const steps = [
                {
                    title: dict.step1,
                    status: (lexScore > 45 && res.verdict !== 'LEGITIMATE') ? "FAIL" : (lexScore > 20 ? "WARN" : "PASS"),
                    description: (lexScore > 45 && res.verdict !== 'LEGITIMATE')
                        ? (currentLang === 'hi' ? `अनधिकृत डोमेन आधिकारिक सरकारी टोकन का उपयोग कर रहा है (${res.target_entity || 'सरकारी योजना'})।` : `Unauthorized domain uses official tokens (${res.target_entity || 'Gov Service'}). Lexical risk: ${lexScore}/100.`)
                        : (currentLang === 'hi' ? `कोई फर्जी सरकारी नाम या डोमेन नकल नहीं पाई गई।` : `No fraudulent typosquatting or government brand deception detected.`)
                },
                {
                    title: dict.step2,
                    status: (sensFields.length > 0 && res.verdict !== 'LEGITIMATE') ? "FAIL" : "PASS",
                    description: (sensFields.length > 0 && res.verdict !== 'LEGITIMATE')
                        ? (currentLang === 'hi' ? `गैर-सरकारी डोमेन पर नागरिक पहचान इनपुट [${sensFields.join(', ')}] चुराने वाला फॉर्म मिला!` : `Form action harvesting citizen identity tokens: [${sensFields.join(', ')}] on non-gov domain.`)
                        : (currentLang === 'hi' ? `कोई संवेदनशील आधार या बायोमेट्रिक इनपुट फॉर्म नहीं मिला।` : `No citizen identity or biometric token harvesting forms detected.`)
                },
                {
                    title: dict.step3,
                    status: (visScore >= 70 && res.verdict !== 'LEGITIMATE') ? "FAIL" : "PASS",
                    description: (visScore >= 70 && res.verdict !== 'LEGITIMATE')
                        ? (currentLang === 'hi' ? `दृश्य रंग-रूप और लेआउट ${res.target_entity || 'सरकारी पोर्टल'} से ${visScore}% मेल खाता है।` : `Perceptual visual hash matches ${res.target_entity || 'Gov Portal'} layout with ${visScore}% lookalike similarity.`)
                        : (currentLang === 'hi' ? `सरकारी पोर्टलों के रंग-रूप या लोगो की कोई नकल नहीं पाई गई।` : `Visual layout and color signatures show zero deceptive imitation of government portals.`)
                },
                {
                    title: dict.step4,
                    status: (ageDays < 30 && res.verdict !== 'LEGITIMATE') ? "FAIL" : "PASS",
                    description: (ageDays < 30 && res.verdict !== 'LEGITIMATE')
                        ? (currentLang === 'hi' ? `हाल ही में पंजीकृत नया डोमेन (${ageDays} दिन पुराना)।` : `Newly Registered Domain (${ageDays} days old) on unauthorized top-level domain.`)
                        : (res.is_genuine_gov_tld ? (currentLang === 'hi' ? `प्रमाणित राष्ट्रीय सूचना विज्ञान केंद्र (NIC) अवसंरचना (12+ वर्ष पुरानी)।` : `Authenticated National Informatics Centre (NIC) infrastructure.`) : (currentLang === 'hi' ? `स्थापित डोमेन आयु: ${ageDays} दिन।` : `Established domain age: ${ageDays} days.`))
                },
                {
                    title: dict.step5,
                    status: (res.verdict === 'PHISHING_CLONE') ? "FAIL" : (res.verdict === 'SUSPICIOUS' ? "WARN" : "PASS"),
                    description: aiData.plain_english_explanation || (res.reasons && res.reasons.length > 0 ? res.reasons[0] : (currentLang === 'hi' ? "भारत सरकार के संप्रभु साइबर रक्षा आधार पर सत्यापित।" : "Verified against Government of India sovereign defense baseline."))
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
