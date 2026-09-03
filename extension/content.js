/**
 * GovShield Sentinel Grid 3.0 — Multilingual In-Page Citizen Cyber Defense Alerts
 * Dynamic Integration with GovShield Backend Engine & UX4G 3.0 Standard
 */

// 12 Indic Scheduled Languages + English Dictionary
const GS_ALERT_I18N = {
  en: {
    criticalTag: "CRITICAL CYBER FRAUD",
    suspiciousTag: "SUSPICIOUS PORTAL",
    mimicking: "Mimicking",
    mainWarning: (host) => `Deceptive site (<strong>${escapeHtml(host)}</strong>) is NOT official!`,
    subAdvice: "⚠️ DO NOT enter Aadhaar, PAN, Bank Details, or OTP.",
    reportBtn: "🚨 Report (cybercrime.gov.in)",
    helplineBtn: "📞 1930",
    dismiss: "Dismiss",
    safeTitle: "Website is Safe to Visit",
    safeGovTitle: "Authentic Sovereign Portal",
    safeSubtitle: (host) => `${escapeHtml(host)} — Verified by GovShield`,
    safeGovSubtitle: (entity) => `${escapeHtml(entity)} — Secured by NIC`,
    safePill: "SAFE",
    safeGovPill: "VERIFIED .GOV.IN"
  },
  hi: {
    criticalTag: "गंभीर साइबर धोखाधड़ी",
    suspiciousTag: "संदेहास्पद पोर्टल",
    mimicking: "नकल",
    mainWarning: (host) => `नकली वेबसाइट (<strong>${escapeHtml(host)}</strong>) आधिकारिक नहीं है!`,
    subAdvice: "⚠️ आधार, पैन, बैंक विवरण या OTP कभी दर्ज न करें।",
    reportBtn: "🚨 रिपोर्ट (cybercrime.gov.in)",
    helplineBtn: "📞 1930",
    dismiss: "हटाएं",
    safeTitle: "वेबसाइट सुरक्षित है",
    safeGovTitle: "प्रामाणिक संप्रभु पोर्टल",
    safeSubtitle: (host) => `${escapeHtml(host)} — GovShield द्वारा सत्यापित`,
    safeGovSubtitle: (entity) => `${escapeHtml(entity)} — NIC द्वारा सुरक्षित`,
    safePill: "सुरक्षित",
    safeGovPill: "सत्यापित .GOV.IN"
  },
  bn: {
    criticalTag: "গুরুতর সাইবার জালিয়াতি",
    suspiciousTag: "সন্দেহজনক পোর্টাল",
    mimicking: "অনুকরণ",
    mainWarning: (host) => `নকল ওয়েবসাইট (<strong>${escapeHtml(host)}</strong>) অফিসিয়াল নয়!`,
    subAdvice: "⚠️ আধার, প্যান, ব্যাঙ্ক বিবরণ বা OTP কখনো দেবেন না।",
    reportBtn: "🚨 রিপোর্ট (cybercrime.gov.in)",
    helplineBtn: "📞 1930",
    dismiss: "বন্ধ করুন",
    safeTitle: "ওয়েবসাইট নিরাপদ",
    safeGovTitle: "খাঁটি সরকারি পোর্টাল",
    safeSubtitle: (host) => `${escapeHtml(host)} — GovShield দ্বারা যাচাইকৃত`,
    safeGovSubtitle: (entity) => `${escapeHtml(entity)} — NIC সুরক্ষিত`,
    safePill: "নিরাপদ",
    safeGovPill: "যাচাইকৃত .GOV.IN"
  },
  ta: {
    criticalTag: "தீவிர இணைய மோசடி",
    suspiciousTag: "சந்தேகத்திற்குரிய தளம்",
    mimicking: "போலி",
    mainWarning: (host) => `போலி தளம் (<strong>${escapeHtml(host)}</strong>) அரசு தளம் அல்ல!`,
    subAdvice: "⚠️ ஆதார், பான், வங்கி விவரங்கள் அல்லது OTP பகிர வேண்டாம்.",
    reportBtn: "🚨 புகார் (cybercrime.gov.in)",
    helplineBtn: "📞 1930",
    dismiss: "மூடு",
    safeTitle: "தளம் பாதுகாப்பானது",
    safeGovTitle: "அங்கீகரிக்கப்பட்ட அரசு தளம்",
    safeSubtitle: (host) => `${escapeHtml(host)} — GovShield சரிபார்க்கப்பட்டது`,
    safeGovSubtitle: (entity) => `${escapeHtml(entity)} — NIC பாதுகாப்பு`,
    safePill: "பாதுகாப்பானது",
    safeGovPill: "அரசு தளம்"
  },
  te: {
    criticalTag: "తీవ్రమైన సైబర్ మోసం",
    suspiciousTag: "అనుమానాస్పద పోర్టల్",
    mimicking: "నకిలీ",
    mainWarning: (host) => `నకిలీ సైట్ (<strong>${escapeHtml(host)}</strong>) అధికారికం కాదు!`,
    subAdvice: "⚠️ ఆధార్, పాన్, బ్యాంక్ వివరాలు లేదా OTP నమోదు చేయవద్దు.",
    reportBtn: "🚨 ఫిర్యాదు (cybercrime.gov.in)",
    helplineBtn: "📞 1930",
    dismiss: "మూసివేయి",
    safeTitle: "వెబ్‌సైట్ సురక్షితం",
    safeGovTitle: "అధికారిక ప్రభుత్వ పోర్టల్",
    safeSubtitle: (host) => `${escapeHtml(host)} — GovShield ధృవీకరించింది`,
    safeGovSubtitle: (entity) => `${escapeHtml(entity)} — NIC భద్రత`,
    safePill: "సురక్షితం",
    safeGovPill: "ధృవీకరించబడింది"
  },
  mr: {
    criticalTag: "गंभीर सायबर फसवणूक",
    suspiciousTag: "संशयास्पद पोर्टल",
    mimicking: "नक्कल",
    mainWarning: (host) => `बनावट वेबसाइट (<strong>${escapeHtml(host)}</strong>) अधिकृत नाही!`,
    subAdvice: "⚠️ आधार, पॅन, बँक तपशील किंवा OTP कधीही प्रविष्ट करू नका.",
    reportBtn: "🚨 तक्रार (cybercrime.gov.in)",
    helplineBtn: "📞 1930",
    dismiss: "बंद करा",
    safeTitle: "वेबसाइट सुरक्षित आहे",
    safeGovTitle: "अधिकृत सरकारी पोर्टल",
    safeSubtitle: (host) => `${escapeHtml(host)} — GovShield द्वारे सत्यापित`,
    safeGovSubtitle: (entity) => `${escapeHtml(entity)} — NIC द्वारे सुरक्षित`,
    safePill: "सुरक्षित",
    safeGovPill: "सत्यापित .GOV.IN"
  },
  gu: {
    criticalTag: "ગંભીર સાયબર છેતરપિંડી",
    suspiciousTag: "શંકાસ્પદ પોર્ટલ",
    mimicking: "નકલ",
    mainWarning: (host) => `નકલી વેબસાઇટ (<strong>${escapeHtml(host)}</strong>) સત્તાવાર નથી!`,
    subAdvice: "⚠️ આધાર, પાન, બેંક વિગતો અથવા OTP ક્યારેય આપશો નહીં.",
    reportBtn: "🚨 ફરિયાદ (cybercrime.gov.in)",
    helplineBtn: "📞 1930",
    dismiss: "બંધ કરો",
    safeTitle: "વેબસાઇટ સુરક્ષિત છે",
    safeGovTitle: "સત્તાવાર સરકારી પોર્ટલ",
    safeSubtitle: (host) => `${escapeHtml(host)} — GovShield પ્રમાણિત`,
    safeGovSubtitle: (entity) => `${escapeHtml(entity)} — NIC સુરક્ષા`,
    safePill: "સુરક્ષિત",
    safeGovPill: "પ્રમાણિત .GOV.IN"
  },
  kn: {
    criticalTag: "ತೀವ್ರ ಸೈಬರ್ ವಂಚನೆ",
    suspiciousTag: "ಅನುಮಾನಾಸ್ಪದ ಪೋರ್ಟಲ್",
    mimicking: "ನಕಲಿ",
    mainWarning: (host) => `ನಕಲಿ ಜಾಲತಾಣ (<strong>${escapeHtml(host)}</strong>) ಅಧಿಕೃತವಲ್ಲ!`,
    subAdvice: "⚠️ ಆಧಾರ್, ಪಾನ್, ಬ್ಯಾಂಕ್ ವಿವರ ಅಥವಾ OTP ಹಂಚಿಕೊಳ್ಳಬೇಡಿ.",
    reportBtn: "🚨 ದೂರು (cybercrime.gov.in)",
    helplineBtn: "📞 1930",
    dismiss: "ಮುಚ್ಚಿ",
    safeTitle: "ವೆಬ್‌ಸೈಟ್ ಸುರಕ್ಷಿತವಾಗಿದೆ",
    safeGovTitle: "ಅಧಿಕೃತ ಸರ್ಕಾರಿ ಪೋರ್ಟಲ್",
    safeSubtitle: (host) => `${escapeHtml(host)} — GovShield ಪರಿಶೀಲಿಸಲಾಗಿದೆ`,
    safeGovSubtitle: (entity) => `${escapeHtml(entity)} — NIC ಸುರಕ್ಷತೆ`,
    safePill: "ಸುರಕ್ಷಿತ",
    safeGovPill: "ಪರಿಶೀಲಿಸಲಾಗಿದೆ"
  },
  ml: {
    criticalTag: "ഗുരുതരമായ സൈബർ തട്ടിപ്പ്",
    suspiciousTag: "സംശയാസ്പദമായ പോർട്ടൽ",
    mimicking: "വ്യാജം",
    mainWarning: (host) => `വ്യാജ സൈറ്റ് (<strong>${escapeHtml(host)}</strong>) ഔദ്യോഗികമല്ല!`,
    subAdvice: "⚠️ ആധാർ, പാൻ, ബാങ്ക് വിവരങ്ങൾ അല്ലെങ്കിൽ OTP നൽകരുത്.",
    reportBtn: "🚨 പരാതി (cybercrime.gov.in)",
    helplineBtn: "📞 1930",
    dismiss: "അടയ്ക്കുക",
    safeTitle: "വെബ്സൈറ്റ് സുരക്ഷിതമാണ്",
    safeGovTitle: "ഔദ്യോഗിക സർക്കാർ പോർട്ടൽ",
    safeSubtitle: (host) => `${escapeHtml(host)} — GovShield പരിശോധിച്ചു`,
    safeGovSubtitle: (entity) => `${escapeHtml(entity)} — NIC സുരക്ഷ`,
    safePill: "സുരക്ഷിതം",
    safeGovPill: "സ്ഥിരീകരിച്ചത്"
  },
  pa: {
    criticalTag: "ਗੰਭੀਰ ਸਾਈਬਰ ਧੋਖਾਧੜੀ",
    suspiciousTag: "ਸ਼ੱਕੀ ਪੋਰਟਲ",
    mimicking: "ਨਕਲ",
    mainWarning: (host) => `ਨਕਲੀ ਵੈੱਬਸਾਈਟ (<strong>${escapeHtml(host)}</strong>) ਅਧਿਕਾਰਤ ਨਹੀਂ ਹੈ!`,
    subAdvice: "⚠️ ਆਧਾਰ, ਪੈਨ, ਬੈਂਕ ਵੇਰਵੇ ਜਾਂ OTP ਕਦੇ ਵੀ ਨਾ ਦਿਓ।",
    reportBtn: "🚨 ਰਿਪੋਰਟ (cybercrime.gov.in)",
    helplineBtn: "📞 1930",
    dismiss: "ਬੰਦ ਕਰੋ",
    safeTitle: "ਵੈੱਬਸਾਈਟ ਸੁਰੱਖਿਅਤ ਹੈ",
    safeGovTitle: "ਅਸਲੀ ਸਰਕਾਰੀ ਪੋਰਟਲ",
    safeSubtitle: (host) => `${escapeHtml(host)} — GovShield ਦੁਆਰਾ ਤਸਦੀਕ`,
    safeGovSubtitle: (entity) => `${escapeHtml(entity)} — NIC ਸੁਰੱਖਿਅਤ`,
    safePill: "ਸੁਰੱਖਿਅਤ",
    safeGovPill: "ਤਸਦੀਕਸ਼ੁਦਾ"
  },
  or: {
    criticalTag: "ଗୁରୁତର ସାଇବର ଠକେଇ",
    suspiciousTag: "ସନ୍ଦେହଜନକ ପୋର୍ଟାଲ",
    mimicking: "ନକଲ",
    mainWarning: (host) => `ନକଲି ୱେବସାଇଟ୍ (<strong>${escapeHtml(host)}</strong>) ସରକାରୀ ନୁହେଁ!`,
    subAdvice: "⚠️ ଆଧାର, ପାନ୍, ବ୍ୟାଙ୍କ ବିବରଣୀ କିମ୍ବା OTP କଦାପି ପ୍ରବେଶ କରନ୍ତୁ ନାହିଁ।",
    reportBtn: "🚨 ଅଭିଯୋଗ (cybercrime.gov.in)",
    helplineBtn: "📞 1930",
    dismiss: "ବନ୍ଦ କରନ୍ତୁ",
    safeTitle: "ୱେବସାଇଟ୍ ସୁରକ୍ଷିତ",
    safeGovTitle: "ପ୍ରାମାଣିକ ସରକାରୀ ପୋର୍ଟାଲ",
    safeSubtitle: (host) => `${escapeHtml(host)} — GovShield ଦ୍ୱାରା ଯାଞ୍ଚ ହୋଇଛି`,
    safeGovSubtitle: (entity) => `${escapeHtml(entity)} — NIC ସୁରକ୍ଷିତ`,
    safePill: "ସୁରକ୍ଷିତ",
    safeGovPill: "ଯାଞ୍ଚ ହୋଇଛି"
  },
  as: {
    criticalTag: "গুৰুতৰ চাইবাৰ প্ৰতাৰণা",
    suspiciousTag: "সন্দেহজনক প'ৰ্টেল",
    mimicking: "অনুকৰণ",
    mainWarning: (host) => `ভুৱা ৱেবছাইট (<strong>${escapeHtml(host)}</strong>) চৰকাৰী নহয়!`,
    subAdvice: "⚠️ আধাৰ, পেন, বেংকৰ তথ্য বা OTP কেতিয়াও নিদিব।",
    reportBtn: "🚨 অভিযোগ (cybercrime.gov.in)",
    helplineBtn: "📞 1930",
    dismiss: "বন্ধ কৰক",
    safeTitle: "ৱেবছাইট সুৰক্ষিত",
    safeGovTitle: "প্ৰামাণিক চৰকাৰী প'ৰ্টেল",
    safeSubtitle: (host) => `${escapeHtml(host)} — GovShield দ্বাৰা প্ৰমাণিত`,
    safeGovSubtitle: (entity) => `${escapeHtml(entity)} — NIC সুৰক্ষা`,
    safePill: "সুৰক্ষিত",
    safeGovPill: "প্ৰমাণিত"
  }
};

// Auto-detect system / browser language
function detectSystemLanguage() {
  try {
    const saved = localStorage.getItem("gs_user_lang");
    if (saved && GS_ALERT_I18N[saved]) return saved;
  } catch (_) {}

  const nav = (navigator.language || (navigator.languages && navigator.languages[0]) || "en").toLowerCase();
  for (const code of Object.keys(GS_ALERT_I18N)) {
    if (nav.startsWith(code)) return code;
  }
  return "en";
}

let currentAlertLang = detectSystemLanguage();
let lastAlertData = null;
let lastAlertHost = "";
let lastAlertScore = 85;

// Listen for push notifications from background worker or popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "SHOW_FRAUD_BANNER") {
    renderSecurityAlert(msg.scanData || {}, msg.domain || window.location.hostname, msg.risk_score);
  } else if (msg.action === "SHOW_SAFE_PROMPT") {
    renderSafePrompt(msg.scanData || {}, msg.domain || window.location.hostname);
  }
});

// Proactively query background script for security status on page load
(function initSecurityCheck() {
  if (!window.location.protocol.startsWith("http")) return;

  try {
    chrome.runtime.sendMessage(
      { action: "GET_TAB_SECURITY", url: window.location.href },
      (response) => {
        if (chrome.runtime.lastError) return;
        if (response && response.success && response.scanData) {
          const data = response.scanData;
          const score = Math.round(data.risk_score || 0);
          if (
            score >= 40 ||
            data.verdict === "PHISHING_CLONE" ||
            data.verdict === "MALICIOUS" ||
            data.verdict === "SUSPICIOUS" ||
            (data.impersonated && !data.is_genuine_gov_tld)
          ) {
            renderSecurityAlert(data, window.location.hostname, score);
          } else {
            renderSafePrompt(data, window.location.hostname);
          }
        }
      }
    );
  } catch (_) {}
})();

/* ==========================================================================
   1. High-Impact Cyber Fraud Alert Banner with Mini Language Switcher
   ========================================================================== */
function renderSecurityAlert(data, currentHostname, scoreParam) {
  // Never show risk banner on verified sovereign domains
  if (data.is_genuine_gov_tld) return;

  lastAlertData = data;
  lastAlertHost = currentHostname;
  lastAlertScore = scoreParam || 85;

  // Remove existing banner/prompt if present
  const existingBanner = document.getElementById("govshield-alert-root");
  if (existingBanner) existingBanner.remove();
  const existingSafe = document.getElementById("govshield-safe-prompt");
  if (existingSafe) existingSafe.remove();

  const score = Math.max(0, Math.min(99, Math.round(data.risk_score !== undefined ? data.risk_score : (scoreParam || 85))));
  const isCritical = score >= 60 || data.verdict === "PHISHING_CLONE" || data.verdict === "MALICIOUS";
  const targetEntity = data.target_entity || "Indian Government Portal";
  const cybercrimeUrl = "https://cybercrime.gov.in";

  const t = GS_ALERT_I18N[currentAlertLang] || GS_ALERT_I18N.en;

  const container = document.createElement("div");
  container.id = "govshield-alert-root";
  container.className = "gs-root-scope";

  container.innerHTML = `
    <div id="gs-top-banner" class="gs-banner ${isCritical ? 'gs-critical' : 'gs-caution'}">
      <div class="gs-tricolor-line"></div>
      <div class="gs-banner-content">
        <div class="gs-left-cluster">
          <div class="gs-siren-wrap">
            <span class="gs-siren-icon">${isCritical ? '🚨' : '⚠️'}</span>
          </div>
          <div class="gs-message-cluster">
            <div class="gs-alert-badge-row">
              <span class="gs-alert-tag">${isCritical ? t.criticalTag : t.suspiciousTag}</span>
              <span class="gs-target-tag">${t.mimicking} ${escapeHtml(targetEntity)}</span>
            </div>
            <span class="gs-main-warning">
              ${t.mainWarning(currentHostname)}
            </span>
            <span class="gs-sub-advice">${t.subAdvice}</span>
          </div>
        </div>

        <div class="gs-banner-actions-col">
          <!-- Mini Language Switcher -->
          <div class="gs-mini-lang-wrap" title="Change Language / भाषा बदलें">
            <span class="gs-mini-lang-icon">🌐</span>
            <select id="gs-mini-lang-select" class="gs-mini-lang-select" aria-label="Alert Language">
              <option value="en" ${currentAlertLang === 'en' ? 'selected' : ''}>EN</option>
              <option value="hi" ${currentAlertLang === 'hi' ? 'selected' : ''}>हिन्दी</option>
              <option value="bn" ${currentAlertLang === 'bn' ? 'selected' : ''}>বাংলা</option>
              <option value="ta" ${currentAlertLang === 'ta' ? 'selected' : ''}>தமிழ்</option>
              <option value="te" ${currentAlertLang === 'te' ? 'selected' : ''}>తెలుగు</option>
              <option value="mr" ${currentAlertLang === 'mr' ? 'selected' : ''}>मराठी</option>
              <option value="gu" ${currentAlertLang === 'gu' ? 'selected' : ''}>ગુજરાતી</option>
              <option value="kn" ${currentAlertLang === 'kn' ? 'selected' : ''}>ಕನ್ನಡ</option>
              <option value="ml" ${currentAlertLang === 'ml' ? 'selected' : ''}>മലയാളം</option>
              <option value="pa" ${currentAlertLang === 'pa' ? 'selected' : ''}>ਪੰਜਾਬੀ</option>
              <option value="or" ${currentAlertLang === 'or' ? 'selected' : ''}>ଓଡ଼ିଆ</option>
              <option value="as" ${currentAlertLang === 'as' ? 'selected' : ''}>অসমীয়া</option>
            </select>
          </div>

          <a href="${cybercrimeUrl}" target="_blank" rel="noopener noreferrer" class="gs-btn gs-btn-report" title="File incident directly on National Cyber Crime Portal">
            ${t.reportBtn}
          </a>
          <a href="tel:1930" class="gs-btn gs-btn-helpline" title="National Citizen Cyber Crime Helpline">
            ${t.helplineBtn}
          </a>
          <button type="button" id="gs-btn-dismiss-banner" class="gs-btn-icon-close" title="${t.dismiss}">
            ✕
          </button>
        </div>
      </div>
    </div>
  `;

  document.body.prepend(container);

  // Mini Language Selector Event Listener
  const langSelect = container.querySelector("#gs-mini-lang-select");
  if (langSelect) {
    langSelect.addEventListener("change", (e) => {
      currentAlertLang = e.target.value;
      try { localStorage.setItem("gs_user_lang", currentAlertLang); } catch (_) {}
      if (lastAlertData) {
        renderSecurityAlert(lastAlertData, lastAlertHost, lastAlertScore);
      }
    });
  }

  // Dismiss button
  container.querySelector("#gs-btn-dismiss-banner").addEventListener("click", () => {
    container.classList.add("gs-banner-fade");
    setTimeout(() => container.remove(), 250);
  });
}

/* ==========================================================================
   2. Bottom Green Safe Prompt Toast (For legitimate & safe websites)
   ========================================================================== */
function renderSafePrompt(data, currentHostname) {
  // Don't duplicate if already present
  if (document.getElementById("govshield-safe-prompt")) return;

  const isGov = Boolean(
    data.is_genuine_gov_tld ||
    currentHostname.endsWith(".gov.in") ||
    currentHostname.endsWith(".nic.in") ||
    currentHostname.endsWith(".mil.in")
  );
  const entity = data.target_entity || (isGov ? "Government of India Sovereign Infrastructure" : currentHostname);
  const t = GS_ALERT_I18N[currentAlertLang] || GS_ALERT_I18N.en;

  const toast = document.createElement("div");
  toast.id = "govshield-safe-prompt";
  toast.className = "gs-safe-toast";

  toast.innerHTML = `
    <div class="gs-safe-icon-disc">
      ${isGov ? '🏛️' : '🛡️'}
    </div>
    <div class="gs-safe-body">
      <div class="gs-safe-title-row">
        <strong class="gs-safe-heading">${isGov ? t.safeGovTitle : t.safeTitle}</strong>
        <span class="gs-safe-status-pill">${isGov ? t.safeGovPill : t.safePill}</span>
      </div>
      <span class="gs-safe-subtitle">
        ${isGov ? t.safeGovSubtitle(entity) : t.safeSubtitle(currentHostname)}
      </span>
    </div>
    <button type="button" id="gs-safe-close-btn" class="gs-safe-close-btn" aria-label="Close" title="Dismiss">✕</button>
  `;

  document.body.appendChild(toast);

  // Dismiss on close button click
  toast.querySelector("#gs-safe-close-btn").addEventListener("click", () => {
    dismissSafeToast(toast);
  });

  // Auto-dismiss after 4.5 seconds
  setTimeout(() => {
    if (document.body.contains(toast)) {
      dismissSafeToast(toast);
    }
  }, 4500);
}

function dismissSafeToast(toastEl) {
  toastEl.classList.add("gs-toast-fade");
  setTimeout(() => {
    if (toastEl.parentNode) toastEl.parentNode.removeChild(toastEl);
  }, 300);
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}