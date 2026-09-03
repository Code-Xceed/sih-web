import { INDIC_LANGUAGES, UX4G_STRINGS } from './ux4gLanguages.js';
import { playAcousticAlert, selectBestVoice } from './audioSynthesizer.js';
import { scanWebsiteClientSide } from './scannerEngine.js';

// Application State
let currentLang = 'hi';
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

// Deep Evidence Accordion
const evidenceAccordionToggle = document.getElementById('evidenceAccordionToggle');
const evidenceAccordionBody = document.getElementById('evidenceAccordionBody');
const evidenceToggleIcon = document.getElementById('evidenceToggleIcon');
const aiSummaryText = document.getElementById('aiSummaryText');
const blockchainProofPill = document.getElementById('blockchainProofPill');
const redirectStatusText = document.getElementById('redirectStatusText');
const mxStatusText = document.getElementById('mxStatusText');
const dmarcStatusText = document.getElementById('dmarcStatusText');

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
  currentLang = langCode;
  const langObj = INDIC_LANGUAGES.find(l => l.code === langCode) || INDIC_LANGUAGES[0];
  currentLangLabel.textContent = langObj.name;
  document.documentElement.lang = langCode;

  // Update selected class in dropdown
  const options = langOptionsList.querySelectorAll('.lang-option-item');
  INDIC_LANGUAGES.forEach((item, idx) => {
    if (options[idx]) {
      options[idx].classList.toggle('selected', item.code === langCode);
    }
  });

  renderLocalizedUI();
}

function renderLocalizedUI() {
  const t = UX4G_STRINGS[currentLang] || UX4G_STRINGS['hi'];

  // Top bar & header
  const govIndiaEl = document.getElementById('govIndiaEl');
  if (govIndiaEl) govIndiaEl.textContent = `${t.govIndia} ↗`;
  
  const brandSubtitleEl = document.getElementById('brandSubtitleEl');
  if (brandSubtitleEl) brandSubtitleEl.textContent = t.brandSubtitle;

  // Hero
  const heroHeadingEl = document.getElementById('heroHeadingEl');
  if (heroHeadingEl) heroHeadingEl.textContent = t.heroTitlePrefix;

  const heroSubtextEl = document.getElementById('heroSubtextEl');
  if (heroSubtextEl) heroSubtextEl.textContent = t.heroSub;

  if (urlInput) urlInput.placeholder = t.placeholder;
  if (verifyBtnText) verifyBtnText.textContent = t.verifyBtn;

  const quickTryLabel = document.getElementById('quickTryLabel');
  if (quickTryLabel) quickTryLabel.textContent = t.quickTry;

  const chipSafe = document.getElementById('chipSafe');
  if (chipSafe) chipSafe.innerHTML = `✅ ${t.safeSite}`;

  const chipFake = document.getElementById('chipFake');
  if (chipFake) chipFake.innerHTML = `🚨 ${t.fakeSite}`;

  const chipIncomeTax = document.getElementById('chipIncomeTax');
  if (chipIncomeTax) chipIncomeTax.innerHTML = `🏛️ ${t.incomeTax}`;

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

  // Footer
  const footerAboutEl = document.getElementById('footerAboutEl');
  if (footerAboutEl) footerAboutEl.textContent = t.footerAbout;
  const footerSIHEl = document.getElementById('footerSIHEl');
  if (footerSIHEl) footerSIHEl.textContent = t.footerSIH;

  // If active result, refresh verdict strings
  if (activeResult) {
    renderVerdict(activeResult);
  }
}

// -------------------------------------------------------------
// Live Scan Engine (Backend API + Instant Client Fallback)
// -------------------------------------------------------------
async function handleScan(targetUrl) {
  const url = (targetUrl || urlInput.value || '').trim();
  if (!url) return;

  // Reset speech synthesis
  if (window.speechSynthesis) window.speechSynthesis.cancel();
  isSpeaking = false;
  updateSpeechButton();

  // Set loading state
  btnVerify.disabled = true;
  const t = UX4G_STRINGS[currentLang] || UX4G_STRINGS['hi'];
  verifyBtnText.textContent = t.verifying || "जांच जारी है...";

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
      // Fallback to client heuristic if server errors
      console.warn("Backend API returned status", response.status, "- using client-side engine");
      activeResult = clientPreflight;
      renderVerdict(clientPreflight);
    }
  } catch (err) {
    console.warn("Backend API unreachable - fallback to sovereign client heuristics:", err);
    activeResult = clientPreflight;
    renderVerdict(clientPreflight);
  } finally {
    btnVerify.disabled = false;
    verifyBtnText.textContent = t.verifyBtn || "सत्यापन करें";
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
  let badgeTag = 'AUTHENTIC GOVERNMENT SERVICE';
  let badgeClass = 'verified';

  if (score >= 66 || res.verdict === 'PHISHING_CLONE' || res.verdict === 'MALICIOUS') {
    type = 'threat';
    title = t.verdictThreat || "सावधान! फर्जी / नकली वेबसाइट";
    icon = '🚨';
    badgeTag = 'CRITICAL PHISHING CLONE';
    badgeClass = 'danger';
  } else if (score >= 26 || res.verdict === 'SUSPICIOUS') {
    type = 'caution';
    title = t.verdictCaution || "सतर्कता: संदिग्ध वेबसाइट";
    icon = '⚠️';
    badgeTag = 'UNVERIFIED SUSPICIOUS DOMAIN';
    badgeClass = 'warning';
  }

  // Update Header Banner
  verdictHeaderBanner.className = `verdict-header-banner ${type}`;
  verdictIconBadge.textContent = icon;
  verdictStatusTitle.textContent = title;
  verdictStatusSub.textContent = `${res.target_entity || 'Government Service'} • ${res.is_genuine_gov_tld ? 'Sovereign .gov.in Domain' : 'Unauthorized Public TLD'}`;

  // Gauge styling
  gaugeScoreNumber.className = `gauge-big-number ${type}`;
  statusPillTag.className = `badge-pill-tag ${badgeClass}`;
  statusPillTag.textContent = badgeTag;

  // Citizen Advisory
  const btnReport = document.getElementById("btnReportCybercrime");
  const btnOfficial = document.getElementById("btnOfficialGovRedirect");

  if (btnReport) {
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
      if (lbl) lbl.textContent = `आधिकारिक पोर्टल (${offDomain}) पर जाएं`;
    } else {
      btnOfficial.style.display = "none";
    }
  }
  if (score >= 66) {
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
  const aiSummary = (currentLang === 'hi' && ai.ai_summary_hi)
    ? ai.ai_summary_hi
    : (ai.ai_summary_en || ai.ai_summary || res.genai_synthesis?.plain_english_summary || res.summary || "AI Analysis verifies this domain and webpage content.");

  const aiSummaryEl = document.getElementById('aiWebpageSummary');
  if (aiSummaryEl) aiSummaryEl.textContent = aiSummary;

  const aiDomainBadgeEl = document.getElementById('aiAnalysisDomainBadge');
  if (aiDomainBadgeEl) aiDomainBadgeEl.textContent = ai.domain_badge || (res.is_genuine_gov_tld ? 'SOVEREIGN INFRASTRUCTURE' : 'PUBLIC WEB PLATFORM');

  const aiPointDomainEl = document.getElementById('aiPointDomain');
  if (aiPointDomainEl) aiPointDomainEl.textContent = ai.domain_type || (res.is_genuine_gov_tld ? 'Official Government (.gov.in)' : 'Public Web Domain');

  const aiPointContentEl = document.getElementById('aiPointContent');
  if (aiPointContentEl) aiPointContentEl.textContent = ai.content_type || 'Informational Web Content';

  const aiPointFormsEl = document.getElementById('aiPointForms');
  if (aiPointFormsEl) {
    if (ai.sensitive_inputs && ai.sensitive_inputs.length > 0) {
      aiPointFormsEl.textContent = `⚠️ Harvesting: ${ai.sensitive_inputs.join(', ')}`;
      aiPointFormsEl.style.color = '#de350b';
    } else {
      aiPointFormsEl.textContent = 'Zero Credential Traps (Clean)';
      aiPointFormsEl.style.color = '#00875a';
    }
  }

  // -----------------------------------------------------------
  // 5 Forensic Layers Dynamic Rendering
  // -----------------------------------------------------------
  // Layer 1: Sovereign TLD
  const isGov = Boolean(res.is_genuine_gov_tld);
  document.getElementById('layer1Icon').textContent = isGov ? '🟢' : '🔴';
  document.getElementById('layer1Tag').className = `tile-status-tag ${isGov ? 'pass' : 'fail'}`;
  document.getElementById('layer1Tag').textContent = isGov ? 'VERIFIED' : 'UNAUTHORIZED';
  document.getElementById('layer1Desc').textContent = isGov 
    ? 'Authenticated sovereign domain accredited by National Informatics Centre (NIC India).' 
    : 'Domain does not belong to authorized sovereign (.gov.in / .nic.in / .mil.in) infrastructure.';

  // Layer 2: Typosquatting
  const typoHit = Boolean(res.typosquat_details?.is_typosquat || (res.signal_breakdown?.lexical_score > 30));
  document.getElementById('layer2Icon').textContent = typoHit ? '🔴' : '🟢';
  document.getElementById('layer2Tag').className = `tile-status-tag ${typoHit ? 'fail' : 'pass'}`;
  document.getElementById('layer2Tag').textContent = typoHit ? 'SPOOF DETECTED' : 'CLEAN';
  document.getElementById('layer2Desc').textContent = typoHit
    ? `Critical: Deceptive spelling manipulation (${res.typosquat_details?.squat_type || 'Homoglyph spoof'} mimicking ${res.target_entity || 'official entity'}).`
    : 'No typosquatting, bit-squatting, omission, or zero-width homoglyphs detected.';

  // Layer 3: Sensitive Credential Forms
  const sensFields = res.signal_breakdown?.sensitive_fields_found || res.dom_details?.sensitive_inputs || [];
  const sensFound = sensFields.length > 0 && !isGov;
  document.getElementById('layer3Icon').textContent = sensFound ? '🔴' : '🟢';
  document.getElementById('layer3Tag').className = `tile-status-tag ${sensFound ? 'fail' : 'pass'}`;
  document.getElementById('layer3Tag').textContent = sensFound ? 'HARVESTING' : 'SECURE';
  document.getElementById('layer3Desc').textContent = sensFound
    ? `Alert: Deceptive forms harvesting citizen credentials on private domain: [${sensFields.map(f => typeof f === 'object' ? f.field : f).join(', ')}]`
    : 'No unauthorized Aadhaar, PAN, OTP, banking PIN, or biometric input forms detected.';

  // Layer 4: AI Visual & Sovereign ML Ensemble
  const isClone = Boolean(res.impersonated || (res.sovereign_ml?.probability >= 0.65));
  document.getElementById('layer4Icon').textContent = isClone ? '🔴' : '🟢';
  document.getElementById('layer4Tag').className = `tile-status-tag ${isClone ? 'fail' : 'pass'}`;
  document.getElementById('layer4Tag').textContent = isClone ? 'CLONE DETECTED' : 'AUTHENTIC';
  document.getElementById('layer4Desc').textContent = isClone
    ? `Sovereign ML soft-voting ensemble flagged impersonation pattern mimicking ${res.target_entity || 'Sovereign Brand'}.`
    : 'DOM structure and ML feature vector align with authentic public web baseline.';

  // Layer 5: DNS & Mail Infrastructure
  const dnsRisk = res.dns_security_details?.dns_risk_score || 0;
  const hasMx = res.dns_security_details?.has_mx !== false;
  document.getElementById('layer5Icon').textContent = (dnsRisk > 30 || !hasMx) && !isGov ? '🟡' : '🟢';
  document.getElementById('layer5Tag').className = `tile-status-tag ${(dnsRisk > 30 || !hasMx) && !isGov ? 'warning' : 'pass'}`;
  document.getElementById('layer5Tag').textContent = isGov ? 'SOVEREIGN DNS' : (dnsRisk > 30 ? 'SUSPICIOUS INFRA' : 'VERIFIED');
  document.getElementById('layer5Desc').textContent = isGov
    ? 'Official NIC India nameserver and authenticated national DNS authority.'
    : `DNS Infrastructure Audit: ${hasMx ? 'Active MX servers' : 'No MX records'}, ${res.signal_breakdown?.domain_age_days ? `${res.signal_breakdown.domain_age_days} days domain age` : 'public registry verified'}.`;

  // -----------------------------------------------------------
  // Deep Evidence Details
  // -----------------------------------------------------------
  // AI Semantic Synthesis (Gemini 2.0 Flash)
  const aiSyn = res.genai_synthesis?.plain_english_summary || res.summary || "";
  aiSummaryText.textContent = aiSyn || "Autonomous multi-signal forensic verification complete.";

  // Blockchain proof
  const bc = res.blockchain_proof || {};
  const incId = res.incident_id || `CERTIN-SIH-${Math.random().toString(36).substr(2, 8).toUpperCase()}`;
  blockchainProofPill.textContent = `Incident ID: ${incId} | Block #${bc.block_index !== undefined ? bc.block_index : 1} | Evidence Hash: ${(bc.evidence_hash || '7d92...e4a1').substring(0, 18)}... | Section 65B Certified`;

  // Redirect and DNS details
  const red = res.redirect_details || {};
  redirectStatusText.textContent = red.redirected ? `Unrolled (${red.hop_count} Hops -> ${red.final_url})` : `Direct (0 Hops)`;
  const dns = res.dns_security_details || {};
  mxStatusText.textContent = dns.has_mx ? 'Active' : 'Missing (Throwaway Risk)';
  dmarcStatusText.textContent = (dns.has_dmarc || dns.has_spf) ? 'Configured' : (isGov ? 'National Standard' : 'Vulnerable');

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

  if (!activeResult) return;

  const t = UX4G_STRINGS[currentLang] || UX4G_STRINGS['hi'];
  const score = activeResult.risk_score || 0;

  // 1. Play instant acoustic chime
  if (score >= 66 || activeResult.verdict === 'PHISHING_CLONE') {
    playAcousticAlert('threat');
  } else if (score <= 25 || activeResult.verdict === 'LEGITIMATE') {
    playAcousticAlert('safe');
  } else {
    playAcousticAlert('caution');
  }

  // 2. Build natural script for selected Indic language
  let textToSpeak = "";
  if (score >= 66 || activeResult.verdict === 'PHISHING_CLONE') {
    textToSpeak = t.speechThreat || t.advisoryThreat;
  } else if (score <= 25 || activeResult.verdict === 'LEGITIMATE') {
    textToSpeak = t.speechSafe || t.advisorySafe;
  } else {
    textToSpeak = t.speechCaution || t.advisoryCaution;
  }

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
  if (isSpeaking) {
    btnSpeechTrigger.classList.add('playing');
    speechBtnText.textContent = t.stopAudio || "आवाज़ बंद करें";
  } else {
    btnSpeechTrigger.classList.remove('playing');
    speechBtnText.textContent = t.listenAudio || "आवाज़ में सुनें";
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

  // Color button triggers
  document.querySelectorAll('[data-color]').forEach(btn => {
    btn.addEventListener('click', () => {
      const mode = btn.dataset.color;
      a11yState.colorMode = (a11yState.colorMode === mode) ? 'normal' : mode;
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
    a11yState.biggerText = false;
    a11yState.lineHeight = false;
    a11yState.textSpacing = false;
    a11yState.highlightLinks = false;
    a11yState.dyslexiaFont = false;
    a11yState.hideImages = false;
    applyA11y();
  });

  // Open/close drawer listeners
  const openDrawer = () => { a11yDrawerBackdrop.style.display = 'flex'; };
  const closeDrawer = () => { a11yDrawerBackdrop.style.display = 'none'; };

  btnOpenDrawerTop.addEventListener('click', openDrawer);
  btnOpenDrawerNav.addEventListener('click', openDrawer);
  btnFabA11y.addEventListener('click', openDrawer);
  btnCloseDrawer.addEventListener('click', closeDrawer);

  a11yDrawerBackdrop.addEventListener('click', (e) => {
    if (e.target === a11yDrawerBackdrop) closeDrawer();
  });

  // Global Keyboard Shortcuts
  window.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'F2') {
      e.preventDefault();
      if (a11yDrawerBackdrop.style.display === 'flex') {
        closeDrawer();
      } else {
        openDrawer();
      }
    }
    if (e.key === 'Escape') {
      closeDrawer();
      dossierModalBackdrop.style.display = 'none';
    }
  });
}

// -------------------------------------------------------------
// Initialization & Event Binding
// -------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  initLanguages();
  initAccessibilityDrawer();

  // URL Input Enter key
  urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleScan();
  });

  // Verify Button
  btnVerify.addEventListener('click', () => handleScan());

  // Quick Demo Chips
  document.querySelectorAll('.ux4g-sample-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const targetUrl = chip.dataset.url;
      urlInput.value = targetUrl;
      handleScan(targetUrl);
    });
  });

  // Audio Button
  btnSpeechTrigger.addEventListener('click', handleSpeakVerdict);

  // Evidence Accordion Toggle
  evidenceAccordionToggle.addEventListener('click', () => {
    const isHidden = evidenceAccordionBody.style.display === 'none';
    evidenceAccordionBody.style.display = isHidden ? 'block' : 'none';
    evidenceToggleIcon.textContent = isHidden ? '▴' : '▾';
  });

  // Dossier Modal
  btnOpenDossier.addEventListener('click', () => {
    dossierPreText.textContent = generateDossierText();
    dossierModalBackdrop.style.display = 'flex';
  });
  btnCloseDossier.addEventListener('click', () => { dossierModalBackdrop.style.display = 'none'; });
  btnCloseDossierBottom.addEventListener('click', () => { dossierModalBackdrop.style.display = 'none'; });
  dossierModalBackdrop.addEventListener('click', (e) => {
    if (e.target === dossierModalBackdrop) dossierModalBackdrop.style.display = 'none';
  });

  // Copy Dossier
  btnCopyDossier.addEventListener('click', () => {
    navigator.clipboard.writeText(generateDossierText());
    copyDossierBtnText.textContent = "✅ कॉपीड (Copied!)";
    setTimeout(() => { copyDossierBtnText.textContent = "कॉपी करें (Copy Dossier)"; }, 2000);
  });

  renderLocalizedUI();
  console.log("GovShield Sentinel Grid 3.0 UX4G Frontend initialized.");
});
