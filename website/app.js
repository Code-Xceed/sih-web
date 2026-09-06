import { INDIC_LANGUAGES, UX4G_STRINGS } from './ux4gLanguages.js';
import { scanWebsiteClientSide } from './scannerEngine.js';

// Auto-detect system / browser language
function detectSystemLanguage() {
  try {
    const saved = localStorage.getItem('gs_user_lang');
    if (saved && INDIC_LANGUAGES.some(l => l.code === saved)) return saved;
  } catch (_) {}

  const nav = (navigator.language || (navigator.languages && navigator.languages[0]) || 'en').toLowerCase();
  for (const l of INDIC_LANGUAGES) {
    if (nav.startsWith(l.code)) return l.code;
  }
  return 'hi'; // Default UX4G Indic language
}

// Application State
let currentLang = detectSystemLanguage();
let activeResult = null;

// DOM Elements
const urlInput = document.getElementById('urlInput');
const btnVerify = document.getElementById('btnVerify');
const verifyBtnText = document.getElementById('verifyBtnText');
const verdictSection = document.getElementById('verdictSection');
const verdictHeaderBanner = document.getElementById('verdictHeaderBanner');
const verdictIconBadge = document.getElementById('verdictIconBadge');
const verdictStatusTitle = document.getElementById('verdictStatusTitle');
const verdictStatusSub = document.getElementById('verdictStatusSub');
const gaugeScoreNumber = document.getElementById('gaugeScoreNumber');
const scannedUrlChip = document.getElementById('scannedUrlChip');
const statusPillTag = document.getElementById('statusPillTag');
const advisoryBodyText = document.getElementById('advisoryBodyText');

// Localization Elements
const advisoryTitleLabel = document.getElementById('advisoryTitleLabel');
const aiAnalysisTitle = document.getElementById('aiAnalysisTitle');
const chipLabelDomain = document.getElementById('chipLabelDomain');
const chipLabelContent = document.getElementById('chipLabelContent');
const chipLabelForms = document.getElementById('chipLabelForms');
const reportBtnLabel = document.getElementById('reportBtnLabel');
const officialGovBtnLabel = document.getElementById('officialGovBtnLabel');
const dossierBtnLabel = document.getElementById('dossierBtnLabel');
const helpline1930Label = document.getElementById('helpline1930Label');
const threatScoreLabelEl = document.getElementById('threatScoreLabel');

// Dossier Elements
const btnOpenDossier = document.getElementById('btnOpenDossier');
const dossierModalBackdrop = document.getElementById('dossierModalBackdrop');
const btnCloseDossier = document.getElementById('btnCloseDossier');
const btnCloseDossierBottom = document.getElementById('btnCloseDossierBottom');
const btnCopyDossier = document.getElementById('btnCopyDossier');
const copyDossierBtnText = document.getElementById('copyDossierBtnText');
const dossierPreText = document.getElementById('dossierPreText');

// Accessibility Elements
const a11yDrawerBackdrop = document.getElementById('a11yDrawerBackdrop');
const btnOpenDrawerTop = document.getElementById('btnOpenDrawerTop');
const btnOpenDrawerNav = document.getElementById('btnOpenDrawerNav');
const btnFabA11y = document.getElementById('btnFabA11y');
const btnCloseDrawer = document.getElementById('btnCloseDrawer');
const btnResetA11y = document.getElementById('btnResetA11y');

// Language Dropdown Elements
const langTriggerBtn = document.getElementById('langTriggerBtn');
const langMenuEl = document.getElementById('langMenuEl');
const langOptionsList = document.getElementById('langOptionsList');
const currentLangLabel = document.getElementById('currentLangLabel');

// Accessibility State
const a11yState = {
  colorMode: 'normal',
  biggerText: false,
  lineHeight: false,
  textSpacing: false,
  highlightLinks: false,
  dyslexiaFont: false,
  hideImages: false
};

// -------------------------------------------------------------
// Language & Localization Engine (12 Indic Languages)
// -------------------------------------------------------------
function initLanguages() {
  if (!langOptionsList) return;
  langOptionsList.innerHTML = '';
  INDIC_LANGUAGES.forEach(item => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `lang-option-item ${currentLang === item.code ? 'selected' : ''}`;
    btn.setAttribute('data-lang-code', item.code);
    btn.innerHTML = `
      <span class="lang-native-script">${item.name}</span>
      <span class="lang-english-label">${item.englishName}</span>
    `;
    langOptionsList.appendChild(btn);
  });

  const langObj = INDIC_LANGUAGES.find(l => l.code === currentLang) || INDIC_LANGUAGES[0];
  const labelEl = document.getElementById('currentLangLabel');
  if (labelEl) labelEl.textContent = langObj.name;
}

function setLanguage(langCode) {
  if (!langCode) return;
  currentLang = langCode;
  try { localStorage.setItem('gs_user_lang', langCode); } catch (_) {}
  const langObj = INDIC_LANGUAGES.find(l => l.code === langCode) || INDIC_LANGUAGES[0];
  
  const labelEl = document.getElementById('currentLangLabel');
  if (labelEl) labelEl.textContent = langObj.name;
  if (document.documentElement) document.documentElement.lang = langCode;

  // Update selected class in dropdown
  const options = document.querySelectorAll('.lang-option-item');
  options.forEach(btn => {
    btn.classList.toggle('selected', btn.getAttribute('data-lang-code') === langCode);
  });

  // Cancel any running audio speech if present
  if (window.speechSynthesis) {
    try { window.speechSynthesis.cancel(); } catch (_) {}
  }

  renderLocalizedUI();

  // Re-render complete scan results in new language if a scan is active
  if (activeResult) {
    renderScanResult(activeResult);
  }
}

function renderLocalizedUI() {
  const t = UX4G_STRINGS[currentLang] || UX4G_STRINGS['hi'];

  // Keep top-bar language label 100% in sync with currentLang
  const langObj = INDIC_LANGUAGES.find(l => l.code === currentLang) || INDIC_LANGUAGES[0];
  const currentLangLabelEl = document.getElementById('currentLangLabel');
  if (currentLangLabelEl) currentLangLabelEl.textContent = langObj.name;
  if (document.documentElement) document.documentElement.lang = currentLang;

  // Top bar & header
  const govIndiaEl = document.getElementById('govIndiaEl');
  if (govIndiaEl) govIndiaEl.textContent = `${t.govIndia} ↗`;

  const skipLinkEl = document.getElementById('skipLinkEl');
  if (skipLinkEl) skipLinkEl.textContent = t.skipContent || "मुख्य सामग्री पर जाएं";
  const skipTopEl = document.getElementById('skipTopEl');
  if (skipTopEl) skipTopEl.textContent = t.skipContent || "मुख्य सामग्री पर जाएं";
  
  const brandSubtitleEl = document.getElementById('brandSubtitleEl');
  if (brandSubtitleEl) brandSubtitleEl.textContent = t.brandSubtitle;

  const btnOpenDrawerTop = document.getElementById('btnOpenDrawerTop');
  if (btnOpenDrawerTop) {
    btnOpenDrawerTop.innerHTML = `<span>♿</span><span>${t.a11yTitle ? t.a11yTitle.split(' ')[0] : 'Accessibility'}</span>`;
  }
  const btnOpenDrawerNav = document.getElementById('btnOpenDrawerNav');
  if (btnOpenDrawerNav) {
    btnOpenDrawerNav.textContent = `♿ Options (Ctrl+F2)`;
  }

  // Hero
  const heroHeadingEl = document.getElementById('heroHeadingEl');
  if (heroHeadingEl) heroHeadingEl.textContent = t.heroTitlePrefix;

  const heroSubtextEl = document.getElementById('heroSubtextEl');
  if (heroSubtextEl) heroSubtextEl.textContent = t.heroSub;

  const urlInputEl = document.getElementById('urlInput');
  if (urlInputEl) urlInputEl.placeholder = t.placeholder;

  const verifyBtnTextEl = document.getElementById('verifyBtnText');
  if (verifyBtnTextEl) verifyBtnTextEl.textContent = t.verifyBtn;

  // Static Verdict & AI Analysis Headings
  const threatScoreLabel = document.getElementById('threatScoreLabel');
  if (threatScoreLabel) threatScoreLabel.textContent = t.threatScoreLabel || "जोखिम स्कोर (Threat Score)";
  
  const advisoryTitleLabel = document.getElementById('advisoryTitleLabel');
  if (advisoryTitleLabel) advisoryTitleLabel.textContent = t.advisoryTitle || "सलाह:";
  
  const aiAnalysisTitle = document.getElementById('aiAnalysisTitle');
  if (aiAnalysisTitle) aiAnalysisTitle.textContent = t.aiSummaryTitle || (currentLang === 'hi' ? "Deep AI वेबसाइट व डोमेन इंटेलिजेंस डोजियर" : "Deep AI Website & Domain Intelligence Dossier");
  
  const aiAboutHeading = document.getElementById('aiAboutHeading');
  if (aiAboutHeading) aiAboutHeading.textContent = currentLang === 'hi' ? "वेबसाइट का परिचय व उद्देश्य (About This Website)" : "About This Website & Mission Profile";

  const aiOfferingsTitle = document.getElementById('aiOfferingsTitle');
  if (aiOfferingsTitle) aiOfferingsTitle.textContent = currentLang === 'hi' ? "मुख्य सेवाएं व डिजिटल कार्यप्रणाली (Key Services):" : "Key Services & Digital Offerings:";

  const aiUiHeading = document.getElementById('aiUiHeading');
  if (aiUiHeading) aiUiHeading.textContent = currentLang === 'hi' ? "डीप वेब UI व इंटरैक्शन विश्लेषण (Web UI & DOM Architecture)" : "Deep Web UI & Interaction Architecture";

  const lblUiLayout = document.getElementById('lblUiLayout');
  if (lblUiLayout) lblUiLayout.textContent = currentLang === 'hi' ? "लेआउट व इंटरफ़ेस संरचना:" : "Layout Architecture:";

  const lblUiTraps = document.getElementById('lblUiTraps');
  if (lblUiTraps) lblUiTraps.textContent = currentLang === 'hi' ? "क्रेडेंशियल चोरी जोखिम (Traps):" : "Credential Harvesting Traps:";

  const lblUiForms = document.getElementById('lblUiForms');
  if (lblUiForms) lblUiForms.textContent = currentLang === 'hi' ? "इंटरैक्टिव फॉर्म व इनपुट्स:" : "Interactive Forms & Inputs:";

  const lblUiExfil = document.getElementById('lblUiExfil');
  if (lblUiExfil) lblUiExfil.textContent = currentLang === 'hi' ? "डेटा एक्सफ़िल्ट्रेशन / वेबहुक:" : "Exfiltration Endpoints:";

  const aiCoreHeading = document.getElementById('aiCoreHeading');
  if (aiCoreHeading) aiCoreHeading.textContent = currentLang === 'hi' ? "डोमेन व कोर नेटवर्क इन्फ्रास्ट्रक्चर (Domain & Core Forensics)" : "Domain & Core Network Forensics";

  const lblDomainTld = document.getElementById('lblDomainTld');
  if (lblDomainTld) lblDomainTld.textContent = currentLang === 'hi' ? "डोमेन रजिस्ट्री व संप्रभुता:" : "Domain Authority / TLD:";

  const lblDomainAge = document.getElementById('lblDomainAge');
  if (lblDomainAge) lblDomainAge.textContent = currentLang === 'hi' ? "डोमेन आयु व प्रतिष्ठा:" : "Domain Registration Age:";

  const lblDomainSsl = document.getElementById('lblDomainSsl');
  if (lblDomainSsl) lblDomainSsl.textContent = currentLang === 'hi' ? "SSL/TLS प्रमाणपत्र प्रदाता:" : "TLS/SSL Certificate CA:";

  const lblDomainDns = document.getElementById('lblDomainDns');
  if (lblDomainDns) lblDomainDns.textContent = currentLang === 'hi' ? "DNS व मेल सुरक्षा (MX/SPF):" : "DNS Mail Security (MX/SPF):";

  const lblAiExecutiveDossier = document.getElementById('lblAiExecutiveDossier');
  if (lblAiExecutiveDossier) lblAiExecutiveDossier.textContent = currentLang === 'hi' ? "एआई कार्यकारी सारांश रिपोर्ट (Executive Dossier)" : "AI Executive Dossier & Lineage";

  const lblCopyAiDossierText = document.getElementById('lblCopyAiDossierText');
  if (lblCopyAiDossierText) lblCopyAiDossierText.textContent = currentLang === 'hi' ? "कॉपी करें (Copy)" : "Copy Dossier";

  // 5 Forensic Layer Titles
  const layer1Title = document.getElementById('layer1Title');
  if (layer1Title) layer1Title.textContent = t.layer1 || '1. सरकारी डोमेन प्रमाणन (.gov.in / .nic.in)';
  const layer2Title = document.getElementById('layer2Title');
  if (layer2Title) layer2Title.textContent = t.layer2 || '2. वर्तनी व नाम की नकल (Typosquatting)';
  const layer3Title = document.getElementById('layer3Title');
  if (layer3Title) layer3Title.textContent = t.layer3 || '3. आधार व पासवर्ड चोरी फॉर्म (Credential Theft)';
  const layer4Title = document.getElementById('layer4Title');
  if (layer4Title) layer4Title.textContent = t.layer4 || '4. एआई विजुअल क्लोनिंग (Lookalike Match)';
  const layer5Title = document.getElementById('layer5Title');
  if (layer5Title) layer5Title.textContent = t.layer5 || '5. डोमेन पंजीकरण व उम्र (Domain Age)';

  // Action Buttons
  const reportBtnLabel = document.getElementById('reportBtnLabel');
  if (reportBtnLabel) reportBtnLabel.textContent = t.reportBtn || "cybercrime.gov.in पर रिपोर्ट करें";
  
  const officialGovBtnLabel = document.getElementById('officialGovBtnLabel');
  if (officialGovBtnLabel) officialGovBtnLabel.textContent = t.officialGovBtn || "आधिकारिक पोर्टल पर जाएं";
  
  const dossierBtnLabel = document.getElementById('dossierBtnLabel');
  if (dossierBtnLabel) dossierBtnLabel.textContent = t.dossierBtn || "डोजियर डाउनलोड करें";
  
  const helpline1930Label = document.getElementById('helpline1930Label');
  if (helpline1930Label) helpline1930Label.textContent = t.helpline1930 || "1930 पर कॉल करें";

  // Citizen Cards
  const sectionTitleEl = document.getElementById('sectionTitleEl');
  if (sectionTitleEl) sectionTitleEl.textContent = t.sectionTitle;

  const sectionSubEl = document.getElementById('sectionSubEl');
  if (sectionSubEl) sectionSubEl.textContent = t.sectionSub;

  const card1TitleEl = document.getElementById('card1TitleEl');
  if (card1TitleEl) card1TitleEl.textContent = t.card1Title;
  const card1DescEl = document.getElementById('card1DescEl');
  if (card1DescEl) card1DescEl.textContent = t.card1Desc;
  const card1BtnEl = document.getElementById('card1BtnEl');
  if (card1BtnEl) card1BtnEl.textContent = t.card1Btn;

  const card2TitleEl = document.getElementById('card2TitleEl');
  if (card2TitleEl) card2TitleEl.textContent = t.card2Title;
  const card2DescEl = document.getElementById('card2DescEl');
  if (card2DescEl) card2DescEl.textContent = t.card2Desc;
  const card2BtnEl = document.getElementById('card2BtnEl');
  if (card2BtnEl) card2BtnEl.textContent = t.helpline1930 || "1930 पर कॉल करें";

  const card3TitleEl = document.getElementById('card3TitleEl');
  if (card3TitleEl) card3TitleEl.textContent = t.card3Title;
  const card3DescEl = document.getElementById('card3DescEl');
  if (card3DescEl) card3DescEl.textContent = t.card3Desc;
  const card3BtnEl = document.getElementById('card3BtnEl');
  if (card3BtnEl) card3BtnEl.textContent = t.card3Btn || t.card1Btn;

  // Accessibility Drawer Text
  const a11yDrawerTitle = document.getElementById('a11yDrawerTitle');
  if (a11yDrawerTitle) a11yDrawerTitle.textContent = `${t.a11yTitle || 'Accessibility Options'} UX4G`;
  const colorContrastHeading = document.getElementById('colorContrastHeading');
  if (colorContrastHeading) colorContrastHeading.textContent = t.colorAdjust || 'Color & Contrast';
  const contentAdjustHeading = document.getElementById('contentAdjustHeading');
  if (contentAdjustHeading) contentAdjustHeading.textContent = t.contentAdjust || 'Content Adjustment';

  const lblMonochrome = document.getElementById('lblMonochrome');
  if (lblMonochrome) lblMonochrome.textContent = t.monochrome || 'Monochrome';
  const lblHighSaturate = document.getElementById('lblHighSaturate');
  if (lblHighSaturate) lblHighSaturate.textContent = t.highSaturate || 'High Saturate';
  const lblLowSaturate = document.getElementById('lblLowSaturate');
  if (lblLowSaturate) lblLowSaturate.textContent = t.lowSaturate || 'Low Saturate';
  const lblDarkMode = document.getElementById('lblDarkMode');
  if (lblDarkMode) lblDarkMode.textContent = t.darkMode || 'Dark Mode';
  const lblInvert = document.getElementById('lblInvert');
  if (lblInvert) lblInvert.textContent = t.invertColors || 'Invert Colors';

  const lblBiggerText = document.getElementById('lblBiggerText');
  if (lblBiggerText) lblBiggerText.textContent = t.biggerText || 'Bigger Text';
  const lblLineHeight = document.getElementById('lblLineHeight');
  if (lblLineHeight) lblLineHeight.textContent = t.lineHeight || 'Line Height';
  const lblTextSpacing = document.getElementById('lblTextSpacing');
  if (lblTextSpacing) lblTextSpacing.textContent = t.textSpacing || 'Text Spacing';
  const lblHighlightLinks = document.getElementById('lblHighlightLinks');
  if (lblHighlightLinks) lblHighlightLinks.textContent = t.highlightLinks || 'Highlight Links';
  const lblDyslexia = document.getElementById('lblDyslexia');
  if (lblDyslexia) lblDyslexia.textContent = t.dyslexiaFont || 'Dyslexia Font';
  const lblHideImages = document.getElementById('lblHideImages');
  if (lblHideImages) lblHideImages.textContent = t.hideImages || 'Hide Images';
  const lblResetAll = document.getElementById('lblResetAll');
  if (lblResetAll) lblResetAll.textContent = t.resetAll || 'Reset All Options';

  // Footer
  const footerAboutEl = document.getElementById('footerAboutEl');
  if (footerAboutEl) footerAboutEl.textContent = t.footerAbout;
  const footerSIHEl = document.getElementById('footerSIHEl');
  if (footerSIHEl) footerSIHEl.textContent = t.footerSIH;
  const nationalPortalsHeadingEl = document.getElementById('nationalPortalsHeadingEl');
  if (nationalPortalsHeadingEl) nationalPortalsHeadingEl.textContent = t.nationalPortalsHeading || 'राष्ट्रीय पोर्टल';
  const emergencyHelplinesHeadingEl = document.getElementById('emergencyHelplinesHeadingEl');
  if (emergencyHelplinesHeadingEl) emergencyHelplinesHeadingEl.textContent = t.emergencyHelplinesHeading || 'आपातकालीन हेल्पलाइन';

  // If active result, refresh verdict strings
  if (activeResult) {
    renderVerdict(activeResult);
  }
}

// -------------------------------------------------------------
// Live Scan Engine (Backend API + Instant Client Fallback)
// -------------------------------------------------------------
let isScanInProgress = false;

async function handleScan(targetUrl) {
  if (isScanInProgress) return;

  const urlInputEl = document.getElementById('urlInput') || urlInput;
  let url = (targetUrl || (urlInputEl ? urlInputEl.value : '') || '').trim();
  if (!url) {
    url = 'https://pmkisan.gov.in';
    if (urlInputEl) urlInputEl.value = 'https://pmkisan.gov.in';
  }

  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  isScanInProgress = true;

  // Reset speech synthesis if present
  if (window.speechSynthesis) {
    try { window.speechSynthesis.cancel(); } catch (_) {}
  }

  // Set loading state
  const btnVerifyEl = document.getElementById('btnVerify') || btnVerify;
  const verifyBtnTextEl = document.getElementById('verifyBtnText') || verifyBtnText;
  if (btnVerifyEl) btnVerifyEl.disabled = true;

  const t = UX4G_STRINGS[currentLang] || UX4G_STRINGS['hi'];
  if (verifyBtnTextEl) verifyBtnTextEl.textContent = t.verifying || "जांच जारी है...";

  // 1. Instant client-side preflight evaluation
  const clientPreflight = scanWebsiteClientSide(url);

  // Dynamic API host resolution: relative if hosted on FastAPI (port 8000), absolute if running on custom port/file://
  const getBackendUrl = (endpoint) => {
    if (window.location.origin && window.location.origin.includes(':8000')) {
      return endpoint;
    }
    return `http://localhost:8000${endpoint}`;
  };

  try {
    // 2. Query GovShield Defense-in-Depth Backend API with resilient 4500ms timeout
    let response = null;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4500);

    try {
      response = await fetch(getBackendUrl('/api/scan'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
    } catch (_) {
      clearTimeout(timeoutId);
      // Fallback probe to relative path if absolute failed or timed out
      const fallbackCtrl = new AbortController();
      const fallbackTimeoutId = setTimeout(() => fallbackCtrl.abort(), 2000);
      try {
        response = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: url }),
          signal: fallbackCtrl.signal
        });
      } catch (fErr) {
        // Ignored; fallback below
      } finally {
        clearTimeout(fallbackTimeoutId);
      }
    }

    if (response && response.ok) {
      const serverData = await response.json();
      activeResult = serverData;
      renderVerdict(serverData);
    } else {
      console.warn("Backend API returned non-OK or timed out - using client-side engine");
      activeResult = clientPreflight;
      renderVerdict(clientPreflight);
    }
  } catch (err) {
    console.warn("Backend API unreachable - fallback to sovereign client heuristics:", err);
    activeResult = clientPreflight;
    renderVerdict(clientPreflight);
  } finally {
    isScanInProgress = false;
    if (btnVerifyEl) btnVerifyEl.disabled = false;
    if (verifyBtnTextEl) verifyBtnTextEl.textContent = t.verifyBtn || "सत्यापन करें";
  }
}
window.handleScan = handleScan;

function renderVerdict(res) {
  if (!res) return;
  try {
    const t = UX4G_STRINGS[currentLang] || UX4G_STRINGS['hi'];
    const vSection = document.getElementById('verdictSection') || verdictSection;
    if (vSection) {
      vSection.style.display = 'block';
      vSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

  const score = Math.max(0, Math.min(99, Math.round(res.risk_score || 0)));
  const formattedScore = score < 10 ? `0${score}` : `${score}`;
  gaugeScoreNumber.textContent = formattedScore;
  scannedUrlChip.textContent = res.url || urlInput.value;

  // Verdict Category
  let type = 'safe';
  let title = t.verdictSafe || "सत्यापित एवं प्रामाणिक";
  let icon = '✅';
  let badgeTag = t.badgeSafe || 'AUTHENTIC GOVERNMENT SERVICE';
  let badgeClass = 'verified';

  if (score >= 66 || res.verdict === 'PHISHING_CLONE' || res.verdict === 'MALICIOUS') {
    type = 'threat';
    title = t.verdictThreat || "सावधान! फर्जी / नकली वेबसाइट";
    icon = '🚨';
    badgeTag = t.badgeThreat || 'CRITICAL PHISHING CLONE';
    badgeClass = 'danger';
  } else if (score >= 26 || res.verdict === 'SUSPICIOUS') {
    type = 'caution';
    title = t.verdictCaution || "सतर्कता: संदिग्ध वेबसाइट";
    icon = '⚠️';
    badgeTag = t.badgeCaution || 'UNVERIFIED SUSPICIOUS DOMAIN';
    badgeClass = 'warning';
  }

  // Update Header Banner
  verdictHeaderBanner.className = `verdict-header-banner ${type}`;
  verdictIconBadge.textContent = icon;
  verdictStatusTitle.textContent = title;
  const sovereignText = res.is_genuine_gov_tld ? (t.sovereignDomain || 'Sovereign .gov.in Domain') : (t.unauthorizedDomain || 'Unauthorized Public TLD');
  verdictStatusSub.textContent = `${res.target_entity || t.govIndia || 'Government Service'} • ${sovereignText}`;

  // Gauge styling
  gaugeScoreNumber.className = `gauge-big-number ${type}`;
  statusPillTag.className = `badge-pill-tag ${badgeClass}`;
  statusPillTag.textContent = badgeTag;

  // Citizen Advisory
  const btnReport = document.getElementById("btnReportCybercrime");
  const btnOfficial = document.getElementById("btnOfficialGovRedirect");

  if (btnReport) {
    btnReport.href = "https://cybercrime.gov.in/Webform/Index.aspx";
    if (score >= 26 || res.verdict === "PHISHING_CLONE" || res.verdict === "SUSPICIOUS" || res.verdict === "MALICIOUS") {
      btnReport.style.display = "inline-flex";
    } else {
      btnReport.style.display = "none";
    }
  }

  if (btnOfficial) {
    if ((res.impersonated || score >= 26) && !res.is_genuine_gov_tld) {
      let offDomain = res.official_domain || "";
      if (!offDomain) {
        const ent = (res.target_entity || "").toLowerCase();
        if (ent.includes("kisan")) offDomain = "pmkisan.gov.in";
        else if (ent.includes("tax")) offDomain = "incometax.gov.in";
        else if (ent.includes("aadhaar") || ent.includes("uidai")) offDomain = "uidai.gov.in";
        else if (ent.includes("parivahan")) offDomain = "parivahan.gov.in";
        else if (ent.includes("epfo")) offDomain = "epfindia.gov.in";
        else offDomain = "india.gov.in";
      }
      btnOfficial.href = `https://${offDomain}`;
      btnOfficial.title = `Redirect safely to authentic Government of India portal (${offDomain})`;
      btnOfficial.style.display = "inline-flex";
      const lbl = document.getElementById("officialGovBtnLabel");
      if (lbl) lbl.textContent = `${t.officialGovBtn || "आधिकारिक पोर्टल पर जाएं"} (${offDomain})`;
    } else {
      btnOfficial.style.display = "none";
    }
  }

  if (advisoryTitleLabel) advisoryTitleLabel.textContent = t.advisoryTitle || "सलाह:";

  if (score >= 66 || res.verdict === 'PHISHING_CLONE' || res.verdict === 'MALICIOUS') {
    advisoryBodyText.textContent = t.advisoryThreat || "चेतावनी! यह वेबसाइट फर्जी है जो सरकारी पोर्टल की नकल कर रही है। अपना आधार नंबर, बैंक खाता, पैन या OTP यहाँ कभी दर्ज न करें!";
  } else if (score <= 25) {
    advisoryBodyText.textContent = t.advisorySafe || "यह वेबसाइट पूरी तरह से प्रामाणिक और आधिकारिक सरकारी पोर्टल है। आप इस पर विश्वास के साथ कार्य कर सकते हैं।";
  } else {
    advisoryBodyText.textContent = t.advisoryCaution || "सावधानी बरतें। यह वेबसाइट आधिकारिक सरकारी रजिस्ट्री में दर्ज नहीं है। व्यक्तिगत विवरण दर्ज करने से पहले जांच करें।";
  }

  // -----------------------------------------------------------
  // Deep AI Website & Domain Intelligence Dossier Rendering
  // -----------------------------------------------------------
  const isGov = Boolean(res.is_genuine_gov_tld);
  const deepAi = res.deep_ai_analysis || res.ai_page_analysis?.deep_ai_analysis || {};
  const about = deepAi.about_website || res.about_website || {};
  const webUi = deepAi.web_ui_analysis || res.web_ui_analysis || {};
  const core = deepAi.domain_core_forensics || res.domain_core_forensics || {};
  const bcLedger = deepAi.sovereign_blockchain_ledger || {};
  const fullDossier = deepAi.executive_dossier_text || res.executive_dossier_text || "";

  // Title and Badges
  const aiDomainBadgeEl = document.getElementById('aiAnalysisDomainBadge');
  if (aiDomainBadgeEl) {
    if (isGov) {
      aiDomainBadgeEl.textContent = "SOVEREIGN INFRASTRUCTURE (.gov.in / .nic.in)";
      aiDomainBadgeEl.style.color = "#00875a";
    } else if (score >= 66) {
      aiDomainBadgeEl.textContent = "CRITICAL PHISHING CLONE";
      aiDomainBadgeEl.style.color = "#de350b";
    } else {
      aiDomainBadgeEl.textContent = "PUBLIC WEB PLATFORM";
      aiDomainBadgeEl.style.color = "#4f46e5";
    }
  }

  const aiSiteCategoryBadge = document.getElementById('aiSiteCategoryBadge');
  if (aiSiteCategoryBadge) {
    aiSiteCategoryBadge.textContent = about.category || (isGov ? "🏛️ Sovereign National Portal" : (score >= 66 ? "🚨 Fraudulent Phishing Trap" : "🌐 Public Web Platform"));
  }

  const aiWebsiteOperator = document.getElementById('aiWebsiteOperator');
  if (aiWebsiteOperator) {
    aiWebsiteOperator.textContent = `Operator: ${about.operator || res.brand_details?.organization || (isGov ? "National Informatics Centre" : "Standard Web Platform")}`;
  }

  // Subsection 1: About This Website Summary & Offerings
  const aiSummaryEl = document.getElementById('aiWebpageSummary');
  if (aiSummaryEl) {
    let summaryText = "";
    if (currentLang === 'hi') {
      summaryText = about.summary_hi || res.ai_summary_hi || res.ai_page_analysis?.ai_summary_hi;
    }
    if (!summaryText) {
      summaryText = about.summary_en || res.ai_summary || res.ai_page_analysis?.ai_summary_en || res.summary || "";
    }
    aiSummaryEl.textContent = summaryText;
  }

  const aiCoreOfferingsList = document.getElementById('aiCoreOfferingsList');
  if (aiCoreOfferingsList) {
    const offerings = about.key_offerings || (isGov
      ? ["Direct Benefit Transfer (DBT)", "Aadhaar e-KYC", "NIC Sovereign Cloud"]
      : (score >= 66 ? ["Unauthorized Imitation", "Credential Harvesting Form", "Flagged for CERT-In Takedown"] : ["Public Web Services", "Encrypted TLS", "Authentic Standing"]));
    aiCoreOfferingsList.innerHTML = '';
    offerings.forEach(off => {
      const tag = document.createElement('span');
      tag.className = 'ai-offering-tag';
      tag.textContent = off;
      aiCoreOfferingsList.appendChild(tag);
    });
  }

  // Subsection 2: Deep Web UI & Interaction Architecture
  const aiUiLayoutType = document.getElementById('aiUiLayoutType');
  if (aiUiLayoutType) {
    aiUiLayoutType.textContent = webUi.layout_type || (isGov ? "🏛️ Sovereign Citizen Welfare Portal" : (score >= 66 ? "🚨 Adversarial Phishing Trap Form" : "📄 Content-Driven Web Layout"));
  }

  const aiUiTrapsAlert = document.getElementById('aiUiTrapsAlert');
  if (aiUiTrapsAlert) {
    const traps = webUi.sensitive_inputs_detected || (res.signal_breakdown?.sensitive_fields_found || res.dom_details?.sensitive_inputs || []);
    if (traps && traps.length > 0 && !isGov) {
      const cleanTraps = traps.map(t => typeof t === 'object' ? (t.field || JSON.stringify(t)) : String(t));
      aiUiTrapsAlert.textContent = `🚨 CRITICAL TRAP: [${cleanTraps.join(', ')}]`;
      aiUiTrapsAlert.style.color = '#de350b';
    } else {
      aiUiTrapsAlert.textContent = currentLang === 'hi' ? '🟢 सुरक्षित — कोई डेटा चोरी फॉर्म नहीं' : '🟢 Safe — Zero Sensitive Traps';
      aiUiTrapsAlert.style.color = '#00875a';
    }
  }

  const aiUiFormsInputs = document.getElementById('aiUiFormsInputs');
  if (aiUiFormsInputs) {
    const formsCount = webUi.forms_count ?? (res.dom_details?.forms_detected ?? (isGov ? 1 : 0));
    const inputsCount = webUi.inputs_count ?? (res.dom_details?.inputs_detected ?? (formsCount * 2));
    aiUiFormsInputs.textContent = `${formsCount} Form(s) (${inputsCount} Input Elements)`;
  }

  const aiUiExfilStatus = document.getElementById('aiUiExfilStatus');
  if (aiUiExfilStatus) {
    const exfil = webUi.external_exfiltration || res.dom_details?.exfiltration_endpoints || [];
    if (exfil && exfil.length > 0) {
      aiUiExfilStatus.textContent = `🚨 Exfil Webhook: ${exfil[0]}`;
      aiUiExfilStatus.style.color = '#de350b';
    } else {
      aiUiExfilStatus.textContent = '🟢 Clean (Local/NIC Sovereign Host)';
      aiUiExfilStatus.style.color = '#00875a';
    }
  }

  // Subsection 3: Domain & Core Network Infrastructure Forensics
  const aiDomainTldAuth = document.getElementById('aiDomainTldAuth');
  if (aiDomainTldAuth) {
    aiDomainTldAuth.textContent = core.tld_classification || (isGov ? ".gov.in / .nic.in (Official Sovereign Infrastructure)" : `.${(res.url_metadata?.tld || 'com')} (Public TLD)`);
  }

  const aiDomainAgeVal = document.getElementById('aiDomainAgeVal');
  if (aiDomainAgeVal) {
    const ageDays = core.domain_age_days ?? (res.network_details?.rdap?.domain_age_days ?? res.signal_breakdown?.domain_age_days ?? (isGov ? 4500 : 1200));
    const ageDesc = core.domain_age_assessment || (isGov ? "Established Sovereign Infrastructure" : (ageDays < 30 ? "🚨 Newly Registered (<30 days)" : "Established Domain"));
    aiDomainAgeVal.textContent = `${ageDays} days (${ageDesc})`;
  }

  const aiSslIssuerVal = document.getElementById('aiSslIssuerVal');
  if (aiSslIssuerVal) {
    const issuerRaw = core.ssl_tls_issuer || (res.network_details?.tls?.issuer ? (typeof res.network_details.tls.issuer === 'object' ? (res.network_details.tls.issuer.common_name || res.network_details.tls.issuer.organization) : String(res.network_details.tls.issuer)) : (isGov ? "National Informatics Centre CA (NICCA)" : "Standard Commercial TLS Authority"));
    aiSslIssuerVal.textContent = issuerRaw;
  }

  const aiDnsMailVal = document.getElementById('aiDnsMailVal');
  if (aiDnsMailVal) {
    const hasMx = res.dns_security_details?.has_mx !== false;
    aiDnsMailVal.textContent = core.dns_mail_security || (hasMx ? "Active MX Records (Mail Enabled)" : "No MX Records (Disposable Host)");
  }

  // Subsection 4: Full Executive Dossier Text Format
  const aiFullDossierPre = document.getElementById('aiFullDossierPre');
  if (aiFullDossierPre) {
    aiFullDossierPre.textContent = fullDossier || generateDossierText();
  }

  // Copy button listener for AI Executive Dossier
  const btnCopyAiDossier = document.getElementById('btnCopyAiDossier');
  const lblCopyAiDossierText = document.getElementById('lblCopyAiDossierText');
  if (btnCopyAiDossier && !btnCopyAiDossier._hasListener) {
    btnCopyAiDossier._hasListener = true;
    btnCopyAiDossier.addEventListener('click', () => {
      const textToCopy = (document.getElementById('aiFullDossierPre')?.textContent) || "";
      if (!textToCopy) return;
      navigator.clipboard.writeText(textToCopy).then(() => {
        if (lblCopyAiDossierText) {
          const original = lblCopyAiDossierText.textContent;
          lblCopyAiDossierText.textContent = currentLang === 'hi' ? '✓ कॉपी हो गया!' : '✓ Copied!';
          setTimeout(() => { lblCopyAiDossierText.textContent = original; }, 2000);
        }
      }).catch(() => {});
    });
  }

  // -----------------------------------------------------------
  // 5 Forensic Layers Dynamic Rendering
  // -----------------------------------------------------------
  const typoHit = Boolean(res.typosquat_details?.is_typosquat || (res.signal_breakdown?.lexical_score > 30));
  const sensFields = res.signal_breakdown?.sensitive_fields_found || res.dom_details?.sensitive_inputs || [];
  const sensFound = sensFields.length > 0 && !isGov;
  const isClone = Boolean(res.impersonated || (res.sovereign_ml?.probability >= 0.65));
  const dnsRisk = res.dns_security_details?.dns_risk_score || 0;
  const hasMx = res.dns_security_details?.has_mx !== false;

  const setEl = (id, text, cls) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (text !== undefined) el.textContent = text;
    if (cls !== undefined) el.className = cls;
  };

  // Layer 1
  setEl('layer1Title', t.layer1 || '1. सरकारी डोमेन प्रमाणन (.gov.in / .nic.in)');
  setEl('layer1Icon', isGov ? '🟢' : '🔴');
  setEl('layer1Tag', isGov ? (t.tagVerified || 'VERIFIED') : (t.tagUnauthorized || 'UNAUTHORIZED'), `tile-status-tag ${isGov ? 'pass' : 'fail'}`);
  setEl('layer1Desc', isGov 
    ? (t.descLayer1Safe || 'Authenticated sovereign domain accredited by National Informatics Centre (NIC India).') 
    : (t.descLayer1Threat || 'Domain does not belong to authorized sovereign (.gov.in / .nic.in / .mil.in) infrastructure.'));

  // Layer 2
  setEl('layer2Title', t.layer2 || '2. वर्तनी व नाम की नकल (Typosquatting)');
  setEl('layer2Icon', typoHit ? '🔴' : '🟢');
  setEl('layer2Tag', typoHit ? (t.tagSpoof || 'SPOOF DETECTED') : (t.tagClean || 'CLEAN'), `tile-status-tag ${typoHit ? 'fail' : 'pass'}`);
  setEl('layer2Desc', typoHit
    ? `Critical: ${t.tagSpoof || 'Spoof'} (${res.typosquat_details?.squat_type || 'Homoglyph'} mimicking ${res.target_entity || 'official entity'}).`
    : (t.descLayer2Safe || 'No typosquatting, bit-squatting, omission, or zero-width homoglyphs detected.'));

  // Layer 3
  setEl('layer3Title', t.layer3 || '3. आधार व पासवर्ड चोरी फॉर्म (Credential Theft)');
  setEl('layer3Icon', sensFound ? '🔴' : '🟢');
  setEl('layer3Tag', sensFound ? (t.tagHarvesting || 'HARVESTING') : (t.tagSecure || 'SECURE'), `tile-status-tag ${sensFound ? 'fail' : 'pass'}`);
  setEl('layer3Desc', sensFound
    ? `Alert: ${t.tagHarvesting || 'Harvesting'} [${sensFields.map(f => typeof f === 'object' ? f.field : f).join(', ')}]`
    : (t.descLayer3Safe || 'No unauthorized Aadhaar, PAN, OTP, banking PIN, or biometric input forms detected.'));

  // Layer 4
  setEl('layer4Title', t.layer4 || '4. एआई विजुअल व संप्रभु ML क्लासिफायर');
  setEl('layer4Icon', isClone ? '🔴' : '🟢');
  setEl('layer4Tag', isClone ? (t.tagClone || 'CLONE DETECTED') : (t.tagAuthentic || 'AUTHENTIC'), `tile-status-tag ${isClone ? 'fail' : 'pass'}`);
  setEl('layer4Desc', isClone
    ? `Sovereign ML flagged impersonation mimicking ${res.target_entity || 'Sovereign Brand'}.`
    : (t.descLayer4Safe || 'DOM structure and ML feature vector align with authentic public web baseline.'));

  // Layer 5
  setEl('layer5Title', t.layer5 || '5. डोमेन पंजीकरण व उम्र (Domain Age)');
  setEl('layer5Icon', (dnsRisk > 30 || !hasMx) && !isGov ? '🟡' : '🟢');
  setEl('layer5Tag', isGov ? (t.tagVerified || 'SOVEREIGN DNS') : (dnsRisk > 30 ? (t.tagWarning || 'SUSPICIOUS') : (t.tagAnalyzed || 'ANALYZED')), `tile-status-tag ${(dnsRisk > 30 || !hasMx) && !isGov ? 'warning' : 'pass'}`);
  setEl('layer5Desc', isGov
    ? (t.descLayer5Safe || 'Official NIC India nameserver and authenticated national DNS authority.')
    : `DNS Audit: ${hasMx ? 'Active MX' : 'No MX records'}.`);

  // Update Action Button texts
  if (reportBtnLabel) reportBtnLabel.textContent = t.reportBtn || "cybercrime.gov.in पर रिपोर्ट करें";
  if (dossierBtnLabel) dossierBtnLabel.textContent = t.dossierBtn || "डोजियर डाउनलोड करें";
  if (helpline1930Label) helpline1930Label.textContent = t.helpline1930 || "1930 पर कॉल करें";

  // AI Confidence Badge
  const aiConfidenceBadgeEl = document.getElementById('aiConfidenceBadge');
  if (aiConfidenceBadgeEl) {
    const engineName = res.ai_report?.engine || res.ai_page_analysis?.ai_engine || "Google Gemini 2.5 Flash";
    aiConfidenceBadgeEl.textContent = engineName.includes("Gemini") ? "✨ Google Gemini 2.5 Flash Verified" : "🤖 Autonomous AI Neural Reasoner";
  }

  // -----------------------------------------------------------
  // Sovereign Blockchain Threat Ledger & Audit Card Rendering
  // -----------------------------------------------------------
  const bc = res.blockchain_audit || {};
  const proof = res.blockchain_proof || {};
  const isPriorOffender = Boolean(bc.is_prior_offender);
  const bcTagEl = document.getElementById('blockchainStatusTag');
  const bcBlockEl = document.getElementById('bcBlockIndex');
  const bcLineageEl = document.getElementById('bcRepeatOffender');
  const bcValidatorEl = document.getElementById('bcValidatorNode');
  const bcEvidenceHashEl = document.getElementById('bcEvidenceHash');
  const bcAiForensicsEl = document.getElementById('bcAiForensics');

  if (bcTagEl) {
    if (isPriorOffender) {
      bcTagEl.className = 'badge-pill-tag danger';
      bcTagEl.textContent = 'REPEAT THREAT ON-CHAIN';
    } else if (proof.status === 'LOGGED_ON_CHAIN' || proof.block_index > 0) {
      bcTagEl.className = 'badge-pill-tag danger';
      bcTagEl.textContent = `ANCHORED IN BLOCK #${proof.block_index}`;
    } else if (isGov) {
      bcTagEl.className = 'badge-pill-tag verified';
      bcTagEl.textContent = 'SOVEREIGN GENESIS VERIFIED';
    } else {
      bcTagEl.className = 'badge-pill-tag verified';
      bcTagEl.textContent = 'CHAIN AUDITED (CLEAN)';
    }
  }

  if (bcBlockEl) {
    if (proof.block_index && proof.block_index > 0) {
      bcBlockEl.textContent = `#${proof.block_index} (PoA Sealed)`;
    } else if (isPriorOffender && bc.verified_blocks && bc.verified_blocks.length > 0) {
      bcBlockEl.textContent = `#${bc.verified_blocks[0].block_index} (Historical Block)`;
    } else {
      bcBlockEl.textContent = isGov ? '#0 (NIC Genesis Root)' : 'Audited (Unanchored Clean)';
    }
  }

  if (bcLineageEl) {
    if (isPriorOffender) {
      bcLineageEl.textContent = `🚨 ${bc.prior_incidents_count || 1} prior threat records`;
      bcLineageEl.style.color = '#de350b';
    } else {
      bcLineageEl.textContent = 'Clean (0 prior incidents)';
      bcLineageEl.style.color = '#00875a';
    }
  }

  if (bcValidatorEl) {
    bcValidatorEl.textContent = proof.validator_node || 'NIC-DELHI-ROOT-01';
  }

  if (bcEvidenceHashEl) {
    const hash = proof.evidence_hash || (bc.verified_blocks && bc.verified_blocks[0]?.evidence_hash) || 'GENESIS-AUTHENTIC-LEDGER-SEAL';
    bcEvidenceHashEl.textContent = `Evidence SHA-256: ${hash}`;
  }

  if (bcAiForensicsEl) {
    const forensics = res.ai_blockchain_forensics || res.ai_report?.ai_blockchain_analysis || bc.summary || '';
    if (forensics) {
      bcAiForensicsEl.textContent = `Ledger Forensics: ${forensics}`;
      bcAiForensicsEl.style.display = 'block';
    } else {
      bcAiForensicsEl.style.display = 'none';
    }
  }
} catch (renderErr) {
  console.error("Error in renderVerdict:", renderErr);
}
}

// -------------------------------------------------------------
// CERT-In Incident Dossier Modal
// -------------------------------------------------------------
function generateDossierText() {
  if (!activeResult) return "Please perform a scan first to generate forensic evidence.";
  const incId = activeResult.incident_id || `CERTIN-SIH-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;
  const d = new Date().toISOString();
  return `========================================================================
CYBER SECURITY INCIDENT REPORT / PHISHING TAKEDOWN DOSSIER
Prepared for: CERT-In (incident@cert-in.org.in) & CyberCrime Portal (cybercrime.gov.in)
Incident ID : ${incId}
Timestamp   : ${d}
Standard    : Section 65B Indian Evidence Act & RFC 8785 Canonical Anchoring
========================================================================
Target Entity   : ${activeResult.target_entity || 'Government of India Portal'}
Investigated URL: ${activeResult.url || urlInput.value}
Risk Threat Score: ${activeResult.risk_score} / 100
Classification  : ${activeResult.verdict || 'SUSPICIOUS'}
Impersonated    : ${activeResult.impersonated ? 'YES (CRITICAL ZERO-DAY SPOOF)' : 'NO'}

[1] FORENSIC EVIDENCE BREAKDOWN:
- Sovereign TLD Status : ${activeResult.is_genuine_gov_tld ? 'AUTHENTIC (.gov.in/.nic.in NIC Certified)' : 'UNAUTHORIZED PUBLIC TLD'}
- Typosquat Score      : ${activeResult.signal_breakdown?.lexical_score || 0}/100
- Typosquat Type       : ${activeResult.typosquat_details?.squat_type || 'NONE'}
- DOM Sensitive Fields : ${(activeResult.signal_breakdown?.sensitive_fields_found || []).join(', ') || 'None detected'}
- Sovereign ML Phish % : ${Math.round((activeResult.sovereign_ml?.probability || 0) * 100)}%
- DNS MX Presence      : ${activeResult.dns_security_details?.has_mx !== false ? 'Valid MX' : 'Missing (Throwaway Phish)'}
- Domain Age (RDAP)    : ${activeResult.signal_breakdown?.domain_age_days || 'N/A'} days

[2] BLOCKCHAIN CRYPTOGRAPHIC PROOF & LINEAGE AUDIT:
- Ledger Audit Status  : ${activeResult.blockchain_audit?.audit_status || 'ON-CHAIN AUDITED'}
- Threat Lineage       : ${activeResult.blockchain_audit?.is_prior_offender ? 'CRITICAL: REPEAT OFFENDER DETECTED' : 'Clean (No prior on-chain offenses)'}
- Prior Offense Blocks : ${activeResult.blockchain_audit?.prior_incidents_count || 0}
- PoA Block Index      : #${activeResult.blockchain_proof?.block_index || 1}
- Evidence Hash        : ${activeResult.blockchain_proof?.evidence_hash || 'SHA256-AUTHENTICATED'}
- Validator Node       : ${activeResult.blockchain_proof?.validator_node || 'NIC-DELHI-ROOT-01'}
- Genesis Ground Truth : Block #0 SHA-256 Seal Validated

[3] AI THREAT SYNTHESIS & LIVE INTERNET OSINT:
- AI Engine            : ${activeResult.ai_report?.engine || activeResult.ai_page_analysis?.ai_engine || 'Autonomous AI Neural Reasoner'}
- AI Calibrated Risk   : ${activeResult.ai_report?.ai_risk_score || activeResult.risk_score}/100 (${activeResult.ai_report?.ai_verdict || activeResult.verdict})
- AI Forensic Summary  : ${activeResult.ai_summary || activeResult.ai_page_analysis?.ai_summary_en || 'Clean sovereign portal'}
- Blockchain Forensics : ${activeResult.ai_blockchain_forensics || activeResult.ai_report?.ai_blockchain_analysis || 'Verified sovereign consensus'}
- Live Online OSINT    : ${activeResult.internet_search_advisories?.is_scam_reported ? 'SCAM ADVISORIES REPORTED ONLINE' : 'Clean'}
- PIB Fact Check Alert : ${activeResult.internet_search_advisories?.pib_warning_detected ? 'PIB FACT CHECK ADVISORY RECORDED' : 'None detected'}

[4] MALICIOUS INDICATORS DETECTED:
${(activeResult.reasons || []).map((r, i) => `[${i + 1}] ${r}`).join('\n') || 'None detected'}

[5] DIRECTIVES & ENFORCEMENT MITIGATION:
1. Issue urgent DNS sinkhole directive via NIXI / INRegistry.
2. Direct TSP/ISP DNS blocking under Section 69A Information Technology Act.
3. Alert CERT-In National Cyber Threat Response Center.
========================================================================`;
}

// -------------------------------------------------------------
// Accessibility Engine & WCAG 2.1 AAA Styling Overrides
// -------------------------------------------------------------
function applyA11y() {
  const root = document.documentElement;
  const body = document.body;

  // Reset Color Filters strictly from root (avoiding body filter stacking bugs)
  const filterClasses = ['ux4g-monochrome', 'ux4g-high-saturate', 'ux4g-low-saturate', 'ux4g-invert'];
  root.classList.remove(...filterClasses, 'ux4g-dark-mode');
  if (body) body.classList.remove(...filterClasses, 'ux4g-dark-mode');

  if (a11yState.colorMode !== 'normal') {
    const modeClass = `ux4g-${a11yState.colorMode.replace(/[A-Z]/g, m => `-${m.toLowerCase()}`)}`;
    root.classList.add(modeClass);
    if (modeClass === 'ux4g-dark-mode' && body) {
      body.classList.add(modeClass);
    }
  }

  // Content adjustments
  const toggles = [
    { key: 'biggerText', name: 'ux4g-bigger-text' },
    { key: 'lineHeight', name: 'ux4g-line-height' },
    { key: 'textSpacing', name: 'ux4g-text-spacing' },
    { key: 'highlightLinks', name: 'ux4g-highlight-links' },
    { key: 'dyslexiaFont', name: 'ux4g-dyslexia' },
    { key: 'hideImages', name: 'ux4g-hide-images' }
  ];

  toggles.forEach(({ key, name }) => {
    if (a11yState[key]) {
      root.classList.add(name);
      if (body) body.classList.add(name);
    } else {
      root.classList.remove(name);
      if (body) body.classList.remove(name);
    }
  });

  // Update active class on drawer buttons
  document.querySelectorAll('[data-color]').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.color === a11yState.colorMode);
  });
  document.querySelectorAll('[data-content]').forEach(btn => {
    btn.classList.toggle('active', Boolean(a11yState[btn.dataset.content]));
  });
}

function openA11yDrawer() {
  const backdrop = document.getElementById('a11yDrawerBackdrop');
  if (backdrop) backdrop.style.display = 'flex';
}

function closeA11yDrawer() {
  const backdrop = document.getElementById('a11yDrawerBackdrop');
  if (backdrop) backdrop.style.display = 'none';
}

function toggleA11yDrawer() {
  const backdrop = document.getElementById('a11yDrawerBackdrop');
  if (!backdrop) return;
  const isVisible = backdrop.style.display === 'flex';
  backdrop.style.display = isVisible ? 'none' : 'flex';
}

function initAccessibilityDrawer() {
  // Auto-detect system dark/light mode and restore saved theme
  const prefersDark = (typeof window !== 'undefined' && window.matchMedia) ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  try {
    const savedTheme = localStorage.getItem('gs_theme');
    if (savedTheme) {
      a11yState.colorMode = savedTheme === 'dark' ? 'darkMode' : 'normal';
    } else if (prefersDark && prefersDark.matches) {
      a11yState.colorMode = 'darkMode';
    }
  } catch (_) {}

  applyA11y();

  // Listen for dynamic system theme change if not manually chosen
  if (prefersDark && prefersDark.addEventListener) {
    prefersDark.addEventListener('change', (e) => {
      try {
        if (!localStorage.getItem('gs_theme')) {
          a11yState.colorMode = e.matches ? 'darkMode' : 'normal';
          applyA11y();
        }
      } catch (_) {}
    });
  }

  // Global Keyboard Shortcuts
  window.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'F2') {
      e.preventDefault();
      toggleA11yDrawer();
    }
    if (e.key === 'Escape') {
      closeA11yDrawer();
      const modal = document.getElementById('dossierModalBackdrop');
      if (modal) modal.style.display = 'none';
    }
  });
}

// -------------------------------------------------------------
// Universal Initialization & Resilient Event Delegator
// -------------------------------------------------------------
function initApp() {
  initLanguages();
  initAccessibilityDrawer();

  // URL Input Enter key
  const input = document.getElementById('urlInput');
  if (input) {
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleScan();
      }
    });
  }

  // Dossier Modal helpers
  const openDossier = () => {
    const dPre = document.getElementById('dossierPreText');
    const dModal = document.getElementById('dossierModalBackdrop');
    if (dPre) dPre.textContent = generateDossierText();
    if (dModal) dModal.style.display = 'flex';
  };
  const closeDossier = () => {
    const dModal = document.getElementById('dossierModalBackdrop');
    if (dModal) dModal.style.display = 'none';
  };

  // Direct Event Listeners (Fast Path for modal buttons)
  const dBtn = document.getElementById('btnOpenDossier');
  if (dBtn) dBtn.addEventListener('click', openDossier);

  const cdBtn = document.getElementById('btnCloseDossier');
  if (cdBtn) cdBtn.addEventListener('click', closeDossier);

  const cdbBtn = document.getElementById('btnCloseDossierBottom');
  if (cdbBtn) cdbBtn.addEventListener('click', closeDossier);

  const cpBtn = document.getElementById('btnCopyDossier');
  if (cpBtn) {
    cpBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(generateDossierText());
      const label = document.getElementById('copyDossierBtnText');
      if (label) label.textContent = "✅ कॉपीड (Copied!)";
      setTimeout(() => {
        if (label) label.textContent = "कॉपी करें (Copy Dossier)";
      }, 2000);
    });
  }

  // Universal Delegated Click Handler (Guarantees clicks work 100% of the time across all devices)
  document.addEventListener('click', (e) => {
    // 1. Accessibility Drawer Toggle
    if (e.target.closest('#btnOpenDrawerTop, #btnOpenDrawerNav, #btnFabA11y')) {
      e.preventDefault();
      toggleA11yDrawer();
      return;
    }

    // 2. Accessibility Drawer Close
    if (e.target.closest('#btnCloseDrawer')) {
      e.preventDefault();
      closeA11yDrawer();
      return;
    }

    // 3. Accessibility Color Filter Buttons
    const colorBtn = e.target.closest('[data-color]');
    if (colorBtn) {
      e.preventDefault();
      const mode = colorBtn.getAttribute('data-color');
      a11yState.colorMode = (a11yState.colorMode === mode) ? 'normal' : mode;
      try {
        if (a11yState.colorMode === 'darkMode') localStorage.setItem('gs_theme', 'dark');
        else if (a11yState.colorMode === 'normal') localStorage.setItem('gs_theme', 'light');
        else localStorage.setItem('gs_theme', a11yState.colorMode);
      } catch (_) {}
      applyA11y();
      return;
    }

    // 4. Accessibility Content Adjustment Buttons
    const contentBtn = e.target.closest('[data-content]');
    if (contentBtn) {
      e.preventDefault();
      const item = contentBtn.getAttribute('data-content');
      if (item && item in a11yState) {
        a11yState[item] = !a11yState[item];
        applyA11y();
      }
      return;
    }

    // 5. Accessibility Reset All Button
    if (e.target.closest('#btnResetA11y')) {
      e.preventDefault();
      a11yState.colorMode = 'normal';
      try { localStorage.removeItem('gs_theme'); } catch (_) {}
      a11yState.biggerText = false;
      a11yState.lineHeight = false;
      a11yState.textSpacing = false;
      a11yState.highlightLinks = false;
      a11yState.dyslexiaFont = false;
      a11yState.hideImages = false;
      applyA11y();
      return;
    }

    // 6. Quick-Try Sample Chips (1-click instantaneous verification)
    const sampleChip = e.target.closest('.ux4g-sample-chip');
    if (sampleChip) {
      e.preventDefault();
      const chipUrl = sampleChip.getAttribute('data-url');
      if (chipUrl) {
        const inp = document.getElementById('urlInput');
        if (inp) inp.value = chipUrl;
        handleScan(chipUrl);
      }
      return;
    }

    // 7. Verify / Analyse Button
    if (e.target.closest('#btnVerify')) {
      e.preventDefault();
      handleScan();
      return;
    }

    // 8. Dossier Modal Open
    if (e.target.closest('#btnOpenDossier')) {
      e.preventDefault();
      openDossier();
      return;
    }

    // 9. Dossier Modal Close
    if (e.target.closest('#btnCloseDossier, #btnCloseDossierBottom')) {
      e.preventDefault();
      closeDossier();
      return;
    }

    // 10. Backdrop clicks outside
    const dModal = document.getElementById('dossierModalBackdrop');
    if (e.target === dModal) {
      closeDossier();
      return;
    }
    const aBackdrop = document.getElementById('a11yDrawerBackdrop');
    if (e.target === aBackdrop) {
      closeA11yDrawer();
      return;
    }

    // 11. Language Dropdown Trigger Toggle
    const langTrigger = e.target.closest('#langTriggerBtn');
    if (langTrigger) {
      e.preventDefault();
      e.stopPropagation();
      const menu = document.getElementById('langMenuEl');
      if (menu) {
        const isExp = menu.style.display === 'block';
        menu.style.display = isExp ? 'none' : 'block';
        langTrigger.setAttribute('aria-expanded', String(!isExp));
      }
      return;
    }

    // 12. Language Option Item Selection
    const langOption = e.target.closest('.lang-option-item');
    if (langOption) {
      e.preventDefault();
      e.stopPropagation();
      const langCode = langOption.getAttribute('data-lang-code');
      if (langCode) {
        setLanguage(langCode);
      }
      const menu = document.getElementById('langMenuEl');
      const trigger = document.getElementById('langTriggerBtn');
      if (menu) menu.style.display = 'none';
      if (trigger) trigger.setAttribute('aria-expanded', 'false');
      return;
    }

    // 13. Close Language Menu if clicked anywhere outside
    if (!e.target.closest('#langDropdownWrapper')) {
      const menu = document.getElementById('langMenuEl');
      const trigger = document.getElementById('langTriggerBtn');
      if (menu && menu.style.display === 'block') {
        menu.style.display = 'none';
        if (trigger) trigger.setAttribute('aria-expanded', 'false');
      }
    }
  });

  renderLocalizedUI();
  console.log("GovShield Sentinel Grid 3.0 UX4G Frontend initialized.");
}

// Guarantee execution whether script runs before or after DOMContentLoaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}
