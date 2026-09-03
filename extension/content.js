/**
 * GovShield Sentinel Grid 3.0 — High-Impact In-Page Citizen Cyber Defense Alert
 * Dynamic Integration with GovShield Backend Engine & UX4G 3.0 Standard
 */

// Listen for push notifications from background worker or popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "SHOW_FRAUD_BANNER") {
    renderSecurityAlert(msg.scanData || {}, msg.domain || window.location.hostname, msg.risk_score);
  }
});

// Proactively ask background script for security status upon page load
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
          }
        }
      }
    );
  } catch (_) {}
})();

function renderSecurityAlert(data, currentHostname, scoreParam) {
  // Never show alert on genuine sovereign infrastructure
  if (data.is_genuine_gov_tld) return;

  const score = Math.max(0, Math.min(99, Math.round(data.risk_score !== undefined ? data.risk_score : (scoreParam || 85))));
  const isCritical = score >= 60 || data.verdict === "PHISHING_CLONE" || data.verdict === "MALICIOUS";
  const targetEntity = data.target_entity || "Indian Government Scheme";

  // Determine official government counterpart URL
  let officialDomain = data.official_domain || "";
  if (!officialDomain) {
    const tLower = targetEntity.toLowerCase();
    if (tLower.includes("kisan")) officialDomain = "pmkisan.gov.in";
    else if (tLower.includes("tax")) officialDomain = "incometax.gov.in";
    else if (tLower.includes("aadhaar") || tLower.includes("uidai")) officialDomain = "uidai.gov.in";
    else if (tLower.includes("cybercrime") || tLower.includes("1930")) officialDomain = "cybercrime.gov.in";
    else if (tLower.includes("parivahan") || tLower.includes("sarathi")) officialDomain = "parivahan.gov.in";
    else if (tLower.includes("epfo") || tLower.includes("epfindia")) officialDomain = "epfindia.gov.in";
    else if (tLower.includes("passport")) officialDomain = "passportindia.gov.in";
    else officialDomain = "india.gov.in";
  }
  const officialUrl = `https://${officialDomain}`;
  const cybercrimeUrl = "https://cybercrime.gov.in";

  // Dynamic AI summary
  const ai = data.ai_page_analysis || {};
  const aiSummary = ai.ai_summary_en || ai.ai_summary || data.genai_synthesis?.plain_english_summary || data.summary ||
    `AI Content Analysis flags this domain (${currentHostname}) as an unauthorized clone mimicking ${targetEntity}. Zero-trust policy active.`;
  const domainType = ai.domain_type || (isCritical ? "Unauthorized Deceptive Clone" : "Suspicious Web Portal");

  // Remove existing alert container if present to update
  const existing = document.getElementById("govshield-alert-root");
  if (existing) existing.remove();

  const container = document.createElement("div");
  container.id = "govshield-alert-root";
  container.className = "gs-root-scope";

  container.innerHTML = `
    <!-- Top High-Visibility Alert Banner -->
    <div id="gs-top-banner" class="gs-banner ${isCritical ? 'gs-critical' : 'gs-caution'}">
      <div class="gs-tricolor-line"></div>
      <div class="gs-banner-content">
        <div class="gs-banner-badge-col">
          <span class="gs-siren-icon">${isCritical ? '🚨' : '⚠️'}</span>
          <div class="gs-score-badge">${score}/100</div>
        </div>

        <div class="gs-banner-text-col">
          <div class="gs-banner-title-line">
            <span class="gs-banner-title">
              ${isCritical ? 'CYBER FRAUD WARNING' : 'SUSPICIOUS DOMAIN CAUTION'} (GovShield Sentinel Grid)
            </span>
            <span class="gs-pill-impersonated">Mimics ${escapeHtml(targetEntity)}</span>
          </div>
          <div class="gs-banner-desc">
            This site (<strong class="gs-highlight-domain">${escapeHtml(currentHostname)}</strong>) is NOT an authorized sovereign portal!
            <span class="gs-ai-brief">${escapeHtml(aiSummary)}</span>
          </div>
        </div>

        <div class="gs-banner-actions-col">
          <a href="${cybercrimeUrl}" target="_blank" rel="noopener noreferrer" class="gs-btn gs-btn-report" title="File incident directly to National Cyber Crime Portal">
            🚨 Report to cybercrime.gov.in
          </a>
          <a href="${officialUrl}" target="_blank" rel="noopener noreferrer" class="gs-btn gs-btn-official" title="Redirect safely to authenticated Government of India portal">
            🏛️ Go to Official Portal (${officialDomain})
          </a>
          <button type="button" id="gs-btn-open-modal" class="gs-btn gs-btn-steps" title="View safety instructions and full forensic analysis">
            📋 Things To Do
          </button>
          <a href="tel:1930" class="gs-btn gs-btn-helpline" title="24x7 Citizen Cyber Crime Helpline">
            📞 1930
          </a>
          <button type="button" id="gs-btn-dismiss-banner" class="gs-btn-icon-close" title="Dismiss banner (stays in floating pill)">
            ✕
          </button>
        </div>
      </div>
    </div>

    <!-- Floating Reopen Pill (Shown when banner is minimized) -->
    <div id="gs-floating-pill" class="gs-floating-pill ${isCritical ? 'gs-pill-critical' : 'gs-pill-caution'}" style="display: none;">
      <span class="gs-pill-icon">🚨</span>
      <span class="gs-pill-label">GovShield Alert: <strong>${escapeHtml(currentHostname)}</strong> (Risk: ${score}/100)</span>
      <button type="button" id="gs-pill-reopen-btn" class="gs-pill-reopen-btn">View Warnings</button>
    </div>

    <!-- Interactive Safety Modal (Things To Do & Forensics) -->
    <div id="gs-safety-modal" class="gs-modal-backdrop" style="display: none;" role="dialog" aria-modal="true" aria-labelledby="gsModalTitle">
      <div class="gs-modal-card">
        <div class="gs-modal-header">
          <div class="gs-modal-header-left">
            <span class="gs-modal-emblem">🛡️</span>
            <div>
              <h3 id="gsModalTitle" class="gs-modal-headline">GovShield Citizen Threat Defense</h3>
              <p class="gs-modal-subline">National Cyber Crime Reporting & Advisory • CERT-In / I4C Standards</p>
            </div>
          </div>
          <button type="button" id="gs-modal-close-btn" class="gs-modal-close-btn" aria-label="Close modal">✕</button>
        </div>

        <div class="gs-modal-body">
          <div class="gs-modal-threat-box ${isCritical ? 'gs-box-critical' : 'gs-box-caution'}">
            <div class="gs-threat-score-col">
              <span class="gs-threat-score-num">${score}</span>
              <span class="gs-threat-score-denom">/100 RISK</span>
            </div>
            <div class="gs-threat-meta-col">
              <div class="gs-threat-verdict-title">${isCritical ? 'CRITICAL DECEPTIVE CLONE' : 'SUSPICIOUS UNVERIFIED DOMAIN'}</div>
              <p class="gs-threat-entity-note">Target Entity: <strong>${escapeHtml(targetEntity)}</strong> • Architecture: <strong>${escapeHtml(domainType)}</strong></p>
            </div>
          </div>

          <!-- AI Semantic Webpage Analysis -->
          <div class="gs-section-card">
            <h4 class="gs-section-title">🤖 AI Webpage & Domain Analysis</h4>
            <p class="gs-ai-full-text">${escapeHtml(aiSummary)}</p>
          </div>

          <!-- 5 Essential Things To Do -->
          <div class="gs-section-card">
            <h4 class="gs-section-title">⚠️ Essential Things To Do (नागरिक सुरक्षा निर्देश)</h4>
            <ul class="gs-guidance-list">
              <li>
                <span class="gs-g-icon">🛑</span>
                <div class="gs-g-text">
                  <strong>DO NOT Enter Citizen Identity or Banking Credentials:</strong>
                  Never provide your Aadhaar number, PAN, Bank Account, ATM PIN, Password, or OTP on this website.
                </div>
              </li>
              <li>
                <span class="gs-g-icon">💰</span>
                <div class="gs-g-text">
                  <strong>NEVER Pay Any Processing or Registration Fee:</strong>
                  Official government schemes (PM-Kisan, Ayushman Bharat, Subsidies, Job Portals) never demand payments on unofficial domains.
                </div>
              </li>
              <li>
                <span class="gs-g-icon">📞</span>
                <div class="gs-g-text">
                  <strong>Dial 1930 Cyber Fraud Helpline (Golden Hour):</strong>
                  If you have already entered financial credentials or money was deducted, call <strong>1930</strong> immediately to request account freeze.
                </div>
              </li>
              <li>
                <span class="gs-g-icon">⚖️</span>
                <div class="gs-g-text">
                  <strong>Report Incident to National Cyber Crime Portal:</strong>
                  Forward this deceptive domain directly to the Government of India portal for CERT-In takedown action.
                </div>
              </li>
              <li>
                <span class="gs-g-icon">🏛️</span>
                <div class="gs-g-text">
                  <strong>Always Verify the Official Sovereign Domain:</strong>
                  Legitimate Central and State Government portals strictly terminate in <code>.gov.in</code> or <code>.nic.in</code>.
                </div>
              </li>
            </ul>
          </div>
        </div>

        <div class="gs-modal-footer">
          <a href="${cybercrimeUrl}" target="_blank" rel="noopener noreferrer" class="gs-btn gs-btn-report-lg">
            🚨 Report to cybercrime.gov.in
          </a>
          <a href="${officialUrl}" target="_blank" rel="noopener noreferrer" class="gs-btn gs-btn-official-lg">
            🏛️ Go to Authentic Portal (${officialDomain})
          </a>
          <a href="tel:1930" class="gs-btn gs-btn-helpline-lg">
            📞 Dial 1930
          </a>
          <button type="button" id="gs-modal-dismiss-btn" class="gs-btn gs-btn-dismiss-lg">
            I Understand, Return to Page
          </button>
        </div>
      </div>
    </div>
  `;

  document.body.prepend(container);

  // Setup Event Listeners
  const topBanner = container.querySelector("#gs-top-banner");
  const floatingPill = container.querySelector("#gs-floating-pill");
  const modal = container.querySelector("#gs-safety-modal");

  // Dismiss banner -> show floating pill
  container.querySelector("#gs-btn-dismiss-banner").addEventListener("click", () => {
    topBanner.style.display = "none";
    floatingPill.style.display = "flex";
  });

  // Reopen from floating pill
  container.querySelector("#gs-pill-reopen-btn").addEventListener("click", () => {
    topBanner.style.display = "block";
    floatingPill.style.display = "none";
  });

  // Open Detailed Modal
  container.querySelector("#gs-btn-open-modal").addEventListener("click", () => {
    modal.style.display = "flex";
  });

  // Close Modal
  container.querySelector("#gs-modal-close-btn").addEventListener("click", () => {
    modal.style.display = "none";
  });
  container.querySelector("#gs-modal-dismiss-btn").addEventListener("click", () => {
    modal.style.display = "none";
  });

  // Close modal when clicking backdrop
  modal.addEventListener("click", (e) => {
    if (e.target === modal) modal.style.display = "none";
  });
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