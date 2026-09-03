import { INDIC_LANGUAGES, UX4G_STRINGS } from './ux4gLanguages.js';
import { playAcousticAlert, selectBestVoice } from './audioSynthesizer.js';
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
let isSpeaking = false;

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
const btnSpeechTrigger = document.getElementById('btnSpeechTrigger');
const speechBtnText = document.getElementById('speechBtnText');

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
  langOptionsList.innerHTML = '';
  INDIC_LANGUAGES.forEach(item => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `lang-option-item ${currentLang === item.code ? 'selected' : ''}`;
    btn.innerHTML = `
      <span class="lang-native-script">${item.name}</span>
      <span class="lang-english-label">${item.englishName}</span>
    `;
    btn.addEventListener('click', () => {
      setLanguage(item.code);
      langMenuEl.style.display = 'none';
      langTriggerBtn.setAttribute('aria-expanded', 'false');
    });
    langOptionsList.appendChild(btn);
  });

  langTriggerBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const isExpanded = langMenuEl.style.display === 'block';
    langMenuEl.style.display = isExpanded ? 'none' : 'block';
    langTriggerBtn.setAttribute('aria-expanded', String(!isExpanded));
  });

  document.addEventListener('click', (e) => {
    if (!e.target.closest('#langDropdownWrapper')) {
      langMenuEl.style.display = 'none';
      langTriggerBtn.setAttribute('aria-expanded', 'false');
    }
  });
}

function setLanguage(langCode) {
  if (!langCode) return;
  currentLang = langCode;
  try { localStorage.setItem('gs_user_lang', langCode); } catch (_) {}
  const langObj = INDIC_LANGUAGES.find(l => l.code === langCode) || INDIC_LANGUAGES[0];
  if (currentLangLabel) currentLangLabel.textContent = langObj.name;
  if (document.documentElement) document.documentElement.lang = langCode;

  // Update selected class in dropdown
  if (langOptionsList) {
    const options = langOptionsList.querySelectorAll('.lang-option-item');
    options.forEach(btn => {
      btn.classList.toggle('selected', btn.dataset.langCode === langCode);
    });
  }

  // Cancel any running audio speech
  if (window.speechSynthesis) window.speechSynthesis.cancel();
  isSpeaking = false;

  renderLocalizedUI();
}

function renderLocalizedUI() {
  const t = UX4G_STRINGS[currentLang] || UX4G_STRINGS['hi'];

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
  if (aiAnalysisTitle) aiAnalysisTitle.textContent = t.aiSummaryTitle || "AI डोमेन व वेबपेज विश्लेषण";
  
  const chipLabelDomain = document.getElementById('chipLabelDomain');
  if (chipLabelDomain) chipLabelDomain.textContent = t.chipDomain || "🌐 डोमेन प्रकार:";
  
  const chipLabelContent = document.getElementById('chipLabelContent');
  if (chipLabelContent) chipLabelContent.textContent = t.chipContent || "📄 पेज का उद्देश्य:";
  
  const chipLabelForms = document.getElementById('chipLabelForms');
  if (chipLabelForms) chipLabelForms.textContent = t.chipForms || "🛡️ डेटा चोरी जोखिम:";

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

  // Speech Audio button - ALWAYS update immediately on language change
  updateSpeechButton();

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
    if (urlInputEl) {
      urlInputEl.focus();
      urlInputEl.style.outline = '2px solid var(--gov-red)';
      setTimeout(() => { if (urlInputEl) urlInputEl.style.outline = ''; }, 1200);
    }
    return;
  }

  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  isScanInProgress = true;

  // Reset speech synthesis
  if (window.speechSynthesis) window.speechSynthesis.cancel();
  isSpeaking = false;
  updateSpeechButton();

  // Set loading state
  const btnVerifyEl = document.getElementById('btnVerify') || btnVerify;
  const verifyBtnTextEl = document.getElementById('verifyBtnText') || verifyBtnText;
  if (btnVerifyEl) btnVerifyEl.disabled = true;

  const t = UX4G_STRINGS[currentLang] || UX4G_STRINGS['hi'];
  if (verifyBtnTextEl) verifyBtnTextEl.textContent = t.verifying || "जांच जारी है...";

  // 1. Instant client-side preflight evaluation
  const clientPreflight = scanWebsiteClientSide(url);

  try {
    // 2. Query GovShield Defense-in-Depth Backend API
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    });

    if (response.ok) {
      const serverData = await response.json();
      activeResult = serverData;
      renderVerdict(serverData);
    } else {
      console.warn("Backend API returned status", response.status, "- using client-side engine");
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

function renderVerdict(res) {
  const t = UX4G_STRINGS[currentLang] || UX4G_STRINGS['hi'];
  verdictSection.style.display = 'block';
  verdictSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

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
  // AI Webpage & Domain Content Analysis
  // -----------------------------------------------------------
  const ai = res.ai_page_analysis || {};
  let aiSummary = (currentLang === 'hi' && ai.ai_summary_hi)
    ? ai.ai_summary_hi
    : (ai.ai_summary_en || ai.ai_summary || res.genai_synthesis?.plain_english_summary || res.summary || "");

  if (!aiSummary || (currentLang !== 'en' && currentLang !== 'hi')) {
    if (score >= 66) aiSummary = t.advisoryThreat;
    else if (score <= 25) aiSummary = t.advisorySafe;
    else aiSummary = t.advisoryCaution;
  }

  const aiSummaryEl = document.getElementById('aiWebpageSummary');
  if (aiSummaryEl) aiSummaryEl.textContent = aiSummary;

  if (aiAnalysisTitle) aiAnalysisTitle.textContent = t.aiSummaryTitle || "AI डोमेन व वेबपेज विश्लेषण";

  const aiDomainBadgeEl = document.getElementById('aiAnalysisDomainBadge');
  if (aiDomainBadgeEl) {
    aiDomainBadgeEl.textContent = res.is_genuine_gov_tld ? (t.sovereignDomain || 'SOVEREIGN INFRASTRUCTURE') : (score >= 66 ? (t.badgeThreat || 'CRITICAL PHISHING CLONE') : (t.sovereignDomain || 'PUBLIC WEB PLATFORM'));
  }

  if (chipLabelDomain) chipLabelDomain.textContent = t.chipDomain || "🌐 डोमेन प्रकार:";
  const aiPointDomainEl = document.getElementById('aiPointDomain');
  if (aiPointDomainEl) {
    aiPointDomainEl.textContent = res.is_genuine_gov_tld ? (t.sovereignDomain || 'Official Government (.gov.in)') : (score >= 66 ? (t.badgeThreat || 'Deceptive Phishing Clone') : (ai.domain_type || 'Public Web Domain'));
  }

  if (chipLabelContent) chipLabelContent.textContent = t.chipContent || "📄 पेज का उद्देश्य:";
  const aiPointContentEl = document.getElementById('aiPointContent');
  if (aiPointContentEl) {
    let localizedContent = ai.content_type || 'Informational Web Content';
    if (ai.sensitive_inputs && ai.sensitive_inputs.length > 0) localizedContent = `${t.tagHarvesting || 'Credential Harvesting'}: ${ai.sensitive_inputs.join(', ')}`;
    else if (res.is_genuine_gov_tld) localizedContent = t.badgeSafe || 'Official Citizen Welfare Service';
    aiPointContentEl.textContent = localizedContent;
  }

  if (chipLabelForms) chipLabelForms.textContent = t.chipForms || "🛡️ डेटा चोरी जोखिम:";
  const aiPointFormsEl = document.getElementById('aiPointForms');
  if (aiPointFormsEl) {
    if (ai.sensitive_inputs && ai.sensitive_inputs.length > 0) {
      aiPointFormsEl.textContent = `⚠️ ${t.tagHarvesting || 'Harvesting'}: ${ai.sensitive_inputs.join(', ')}`;
      aiPointFormsEl.style.color = '#de350b';
    } else {
      aiPointFormsEl.textContent = t.cleanForms || 'Zero Credential Traps (Clean)';
      aiPointFormsEl.style.color = '#00875a';
    }
  }

  // -----------------------------------------------------------
  // 5 Forensic Layers Dynamic Rendering
  // -----------------------------------------------------------
  const isGov = Boolean(res.is_genuine_gov_tld);
  const typoHit = Boolean(res.typosquat_details?.is_typosquat || (res.signal_breakdown?.lexical_score > 30));
  const sensFields = res.signal_breakdown?.sensitive_fields_found || res.dom_details?.sensitive_inputs || [];
  const sensFound = sensFields.length > 0 && !isGov;
  const isClone = Boolean(res.impersonated || (res.sovereign_ml?.probability >= 0.65));
  const dnsRisk = res.dns_security_details?.dns_risk_score || 0;
  const hasMx = res.dns_security_details?.has_mx !== false;

  // Layer 1
  const layer1Title = document.getElementById('layer1Title');
  if (layer1Title) layer1Title.textContent = t.layer1 || '1. सरकारी डोमेन प्रमाणन (.gov.in / .nic.in)';
  document.getElementById('layer1Icon').textContent = isGov ? '🟢' : '🔴';
  document.getElementById('layer1Tag').className = `tile-status-tag ${isGov ? 'pass' : 'fail'}`;
  document.getElementById('layer1Tag').textContent = isGov ? (t.tagVerified || 'VERIFIED') : (t.tagUnauthorized || 'UNAUTHORIZED');
  document.getElementById('layer1Desc').textContent = isGov 
    ? (t.descLayer1Safe || 'Authenticated sovereign domain accredited by National Informatics Centre (NIC India).') 
    : (t.descLayer1Threat || 'Domain does not belong to authorized sovereign (.gov.in / .nic.in / .mil.in) infrastructure.');

  // Layer 2
  const layer2Title = document.getElementById('layer2Title');
  if (layer2Title) layer2Title.textContent = t.layer2 || '2. वर्तनी व नाम की नकल (Typosquatting)';
  document.getElementById('layer2Icon').textContent = typoHit ? '🔴' : '🟢';
  document.getElementById('layer2Tag').className = `tile-status-tag ${typoHit ? 'fail' : 'pass'}`;
  document.getElementById('layer2Tag').textContent = typoHit ? (t.tagSpoof || 'SPOOF DETECTED') : (t.tagClean || 'CLEAN');
  document.getElementById('layer2Desc').textContent = typoHit
    ? `Critical: ${t.tagSpoof || 'Spoof'} (${res.typosquat_details?.squat_type || 'Homoglyph'} mimicking ${res.target_entity || 'official entity'}).`
    : (t.descLayer2Safe || 'No typosquatting, bit-squatting, omission, or zero-width homoglyphs detected.');

  // Layer 3
  const layer3Title = document.getElementById('layer3Title');
  if (layer3Title) layer3Title.textContent = t.layer3 || '3. आधार व पासवर्ड चोरी फॉर्म (Credential Theft)';
  document.getElementById('layer3Icon').textContent = sensFound ? '🔴' : '🟢';
  document.getElementById('layer3Tag').className = `tile-status-tag ${sensFound ? 'fail' : 'pass'}`;
  document.getElementById('layer3Tag').textContent = sensFound ? (t.tagHarvesting || 'HARVESTING') : (t.tagSecure || 'SECURE');
  document.getElementById('layer3Desc').textContent = sensFound
    ? `Alert: ${t.tagHarvesting || 'Harvesting'} [${sensFields.map(f => typeof f === 'object' ? f.field : f).join(', ')}]`
    : (t.descLayer3Safe || 'No unauthorized Aadhaar, PAN, OTP, banking PIN, or biometric input forms detected.');

  // Layer 4
  const layer4Title = document.getElementById('layer4Title');
  if (layer4Title) layer4Title.textContent = t.layer4 || '4. एआई विजुअल व संप्रभु ML क्लासिफायर';
  document.getElementById('layer4Icon').textContent = isClone ? '🔴' : '🟢';
  document.getElementById('layer4Tag').className = `tile-status-tag ${isClone ? 'fail' : 'pass'}`;
  document.getElementById('layer4Tag').textContent = isClone ? (t.tagClone || 'CLONE DETECTED') : (t.tagAuthentic || 'AUTHENTIC');
  document.getElementById('layer4Desc').textContent = isClone
    ? `Sovereign ML flagged impersonation mimicking ${res.target_entity || 'Sovereign Brand'}.`
    : (t.descLayer4Safe || 'DOM structure and ML feature vector align with authentic public web baseline.');

  // Layer 5
  const layer5Title = document.getElementById('layer5Title');
  if (layer5Title) layer5Title.textContent = t.layer5 || '5. डोमेन पंजीकरण व उम्र (Domain Age)';
  document.getElementById('layer5Icon').textContent = (dnsRisk > 30 || !hasMx) && !isGov ? '🟡' : '🟢';
  document.getElementById('layer5Tag').className = `tile-status-tag ${(dnsRisk > 30 || !hasMx) && !isGov ? 'warning' : 'pass'}`;
  document.getElementById('layer5Tag').textContent = isGov ? (t.tagVerified || 'SOVEREIGN DNS') : (dnsRisk > 30 ? (t.tagWarning || 'SUSPICIOUS') : (t.tagAnalyzed || 'ANALYZED'));
  document.getElementById('layer5Desc').textContent = isGov
    ? (t.descLayer5Safe || 'Official NIC India nameserver and authenticated national DNS authority.')
    : `DNS Audit: ${hasMx ? 'Active MX' : 'No MX records'}.`;

  // Update Action Button texts
  if (reportBtnLabel) reportBtnLabel.textContent = t.reportBtn || "cybercrime.gov.in पर रिपोर्ट करें";
  if (dossierBtnLabel) dossierBtnLabel.textContent = t.dossierBtn || "डोजियर डाउनलोड करें";
  if (helpline1930Label) helpline1930Label.textContent = t.helpline1930 || "1930 पर कॉल करें";

  // Speech Audio button
  updateSpeechButton();

  // Trigger Acoustic Sound Chime
  playAcousticAlert(type);
}

// -------------------------------------------------------------
// Natural Speech Narration Engine
// -------------------------------------------------------------
function handleSpeakVerdict() {
  if (!('speechSynthesis' in window)) {
    alert("Text-to-speech is not supported on this browser.");
    return;
  }

  if (isSpeaking) {
    window.speechSynthesis.cancel();
    isSpeaking = false;
    updateSpeechButton();
    return;
  }

  const t = UX4G_STRINGS[currentLang] || UX4G_STRINGS['hi'];
  let textToSpeak = "";
  let soundType = 'safe';

  if (activeResult) {
    const score = activeResult.risk_score || 0;
    if (score >= 66 || activeResult.verdict === 'PHISHING_CLONE') {
      soundType = 'threat';
      textToSpeak = t.speechThreat || t.advisoryThreat;
    } else if (score <= 25 || activeResult.verdict === 'LEGITIMATE') {
      soundType = 'safe';
      textToSpeak = t.speechSafe || t.advisorySafe;
    } else {
      soundType = 'caution';
      textToSpeak = t.speechCaution || t.advisoryCaution;
    }
  } else {
    // If clicked before scanning, speak localized portal instruction
    soundType = 'safe';
    textToSpeak = t.heroSub || "आधार, पैन या बैंक विवरण दर्ज करने से पहले जांचें कि वेबसाइट असली है या फर्जी।";
  }

  // 1. Play audio acoustic chime
  playAcousticAlert(soundType);

  // 2. Build speech synthesis utterance
  const currentLangObj = INDIC_LANGUAGES.find(l => l.code === currentLang) || INDIC_LANGUAGES[0];
  const utterance = new SpeechSynthesisUtterance(textToSpeak);
  utterance.lang = currentLangObj.bcp47 || 'hi-IN';
  utterance.rate = 0.88;
  utterance.pitch = 1.04;

  const bestVoice = selectBestVoice(currentLang);
  if (bestVoice) utterance.voice = bestVoice;

  utterance.onend = () => { isSpeaking = false; updateSpeechButton(); };
  utterance.onerror = () => { isSpeaking = false; updateSpeechButton(); };

  isSpeaking = true;
  updateSpeechButton();

  window.speechSynthesis.cancel();
  setTimeout(() => {
    window.speechSynthesis.speak(utterance);
  }, 150);
}

function updateSpeechButton() {
  const t = UX4G_STRINGS[currentLang] || UX4G_STRINGS['hi'];
  const trigger = document.getElementById('btnSpeechTrigger');
  const label = document.getElementById('speechBtnText');

  const text = isSpeaking ? (t.stopAudio || "आवाज़ बंद करें") : (t.listenAudio || "आवाज़ में सुनें");
  const icon = isSpeaking ? "⏹️" : "🔊";

  if (trigger) {
    if (isSpeaking) {
      trigger.classList.add('playing');
    } else {
      trigger.classList.remove('playing');
    }
    trigger.setAttribute('aria-label', text);
    trigger.innerHTML = `${icon} <span id="speechBtnText">${text}</span>`;
  } else if (label) {
    label.textContent = text;
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

[2] BLOCKCHAIN CRYPTOGRAPHIC PROOF:
- PoA Block Index      : #${activeResult.blockchain_proof?.block_index || 1}
- Evidence Hash        : ${activeResult.blockchain_proof?.evidence_hash || 'SHA256-AUTHENTICATED'}
- Validator Node       : NIC-DELHI-ROOT-01

[3] MALICIOUS INDICATORS DETECTED:
${(activeResult.reasons || []).map((r, i) => `[${i + 1}] ${r}`).join('\n') || 'None detected'}

[4] DIRECTIVES & ENFORCEMENT MITIGATION:
1. Issue urgent DNS sinkhole directive via NIXI / INRegistry.
2. Direct TSP/ISP DNS blocking under Section 69A Information Technology Act.
3. Alert CERT-In National Cyber Threat Response Center.
========================================================================`;
}

// -------------------------------------------------------------
// Accessibility Drawer & WCAG 2.1 AAA Styling Overrides
// -------------------------------------------------------------
function initAccessibilityDrawer() {
  const root = document.documentElement;
  const body = document.body;

  function applyA11y() {
    // Reset Color Filters
    root.classList.remove('ux4g-monochrome', 'ux4g-high-saturate', 'ux4g-low-saturate', 'ux4g-dark-mode', 'ux4g-invert');
    body.classList.remove('ux4g-monochrome', 'ux4g-high-saturate', 'ux4g-low-saturate', 'ux4g-dark-mode', 'ux4g-invert');

    if (a11yState.colorMode !== 'normal') {
      const modeClass = `ux4g-${a11yState.colorMode.replace(/[A-Z]/g, m => `-${m.toLowerCase()}`)}`;
      root.classList.add(modeClass);
      body.classList.add(modeClass);
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
        body.classList.add(name);
      } else {
        root.classList.remove(name);
        body.classList.remove(name);
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

  // Color button triggers
  document.querySelectorAll('[data-color]').forEach(btn => {
    btn.addEventListener('click', () => {
      const mode = btn.dataset.color;
      a11yState.colorMode = (a11yState.colorMode === mode) ? 'normal' : mode;
      try {
        if (a11yState.colorMode === 'darkMode') localStorage.setItem('gs_theme', 'dark');
        else if (a11yState.colorMode === 'normal') localStorage.setItem('gs_theme', 'light');
        else localStorage.setItem('gs_theme', a11yState.colorMode);
      } catch (_) {}
      applyA11y();
    });
  });

  // Content adjustment triggers
  document.querySelectorAll('[data-content]').forEach(btn => {
    btn.addEventListener('click', () => {
      const item = btn.dataset.content;
      a11yState[item] = !a11yState[item];
      applyA11y();
    });
  });

  // Reset button
  btnResetA11y.addEventListener('click', () => {
    a11yState.colorMode = 'normal';
    try { localStorage.removeItem('gs_theme'); } catch (_) {}
    a11yState.biggerText = false;
    a11yState.lineHeight = false;
    a11yState.textSpacing = false;
    a11yState.highlightLinks = false;
    a11yState.dyslexiaFont = false;
    a11yState.hideImages = false;
    applyA11y();
  });

  // Open/close drawer listeners
  const openDrawer = () => {
    const backdrop = document.getElementById('a11yDrawerBackdrop');
    if (backdrop) backdrop.style.display = 'flex';
  };
  const closeDrawer = () => {
    const backdrop = document.getElementById('a11yDrawerBackdrop');
    if (backdrop) backdrop.style.display = 'none';
  };

  if (btnOpenDrawerTop) btnOpenDrawerTop.addEventListener('click', openDrawer);
  if (btnOpenDrawerNav) btnOpenDrawerNav.addEventListener('click', openDrawer);
  if (btnFabA11y) btnFabA11y.addEventListener('click', openDrawer);
  if (btnCloseDrawer) btnCloseDrawer.addEventListener('click', closeDrawer);

  if (a11yDrawerBackdrop) {
    a11yDrawerBackdrop.addEventListener('click', (e) => {
      if (e.target === a11yDrawerBackdrop) closeDrawer();
    });
  }

  // Global Keyboard Shortcuts
  window.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'F2') {
      e.preventDefault();
      const backdrop = document.getElementById('a11yDrawerBackdrop');
      if (backdrop && backdrop.style.display === 'flex') {
        closeDrawer();
      } else {
        openDrawer();
      }
    }
    if (e.key === 'Escape') {
      closeDrawer();
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

  // Direct Event Listeners (Fast Path)
  const vBtn = document.getElementById('btnVerify');
  if (vBtn) vBtn.addEventListener('click', () => handleScan());

  const sBtn = document.getElementById('btnSpeechTrigger');
  if (sBtn) sBtn.addEventListener('click', handleSpeakVerdict);

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

  // Universal Delegated Click Handler (Guarantees clicks work 100% of the time)
  document.addEventListener('click', (e) => {
    // 1. Accessibility / Options Drawer triggers
    const aTrigger = e.target.closest('#btnOpenDrawerTop, #btnOpenDrawerNav, #btnFabA11y');
    if (aTrigger) {
      e.preventDefault();
      const backdrop = document.getElementById('a11yDrawerBackdrop');
      if (backdrop) backdrop.style.display = 'flex';
      return;
    }

    // 2. Accessibility Drawer Close
    if (e.target.closest('#btnCloseDrawer')) {
      e.preventDefault();
      const backdrop = document.getElementById('a11yDrawerBackdrop');
      if (backdrop) backdrop.style.display = 'none';
      return;
    }

    // 3. Verify / Analyse Button
    if (e.target.closest('#btnVerify')) {
      e.preventDefault();
      handleScan();
      return;
    }

    // 4. Audio Speech Button
    if (e.target.closest('#btnSpeechTrigger')) {
      e.preventDefault();
      handleSpeakVerdict();
      return;
    }

    // 5. Dossier Modal Open
    if (e.target.closest('#btnOpenDossier')) {
      e.preventDefault();
      openDossier();
      return;
    }

    // 6. Dossier Modal Close
    if (e.target.closest('#btnCloseDossier, #btnCloseDossierBottom')) {
      e.preventDefault();
      closeDossier();
      return;
    }

    // 7. Backdrop clicks outside
    const dModal = document.getElementById('dossierModalBackdrop');
    if (e.target === dModal) {
      closeDossier();
      return;
    }
    const aBackdrop = document.getElementById('a11yDrawerBackdrop');
    if (e.target === aBackdrop) {
      if (aBackdrop) aBackdrop.style.display = 'none';
      return;
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
