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
    <!-- Top High-Visibility Alert Banner (No Popup) -->
    <div id="gs-top-banner" class="gs-banner ${isCritical ? 'gs-critical' : 'gs-caution'}">
      <div class="gs-tricolor-line"></div>
      <div class="gs-banner-content">
        <div class="gs-banner-badge-col">
          <span class="gs-siren-icon">${isCritical ? '🚨' : '⚠️'}</span>
          <div class="gs-score-badge">${score}/100 RISK</div>
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
            <span class="gs-ai-brief">🤖 ${escapeHtml(aiSummary)}</span>
          </div>
          <div class="gs-things-to-do-inline">
            <strong class="gs-ttd-title">⚠️ Things To Do:</strong>
            <span class="gs-ttd-item">🛑 Never enter Aadhaar, PAN, Bank Details, or OTP.</span>
            <span class="gs-ttd-item">💰 Never pay registration or scheme fees on 3rd-party sites.</span>
            <span class="gs-ttd-item">📞 If money was deducted, dial <strong>1930</strong> immediately.</span>
          </div>
        </div>

        <div class="gs-banner-actions-col">
          <a href="${cybercrimeUrl}" target="_blank" rel="noopener noreferrer" class="gs-btn gs-btn-report" title="File incident directly to National Cyber Crime Portal">
            🚨 Report to cybercrime.gov.in
          </a>
          <a href="${officialUrl}" target="_blank" rel="noopener noreferrer" class="gs-btn gs-btn-official" title="Redirect safely to authenticated Government of India portal">
            🏛️ Go to Official Portal (${officialDomain})
          </a>
          <a href="tel:1930" class="gs-btn gs-btn-helpline" title="24x7 Citizen Cyber Crime Helpline">
            📞 Dial 1930
          </a>
          <button type="button" id="gs-btn-dismiss-banner" class="gs-btn-icon-close" title="Dismiss warning banner">
            ✕
          </button>
        </div>
      </div>
    </div>

    <!-- Floating Reopen Pill (Shown when banner is minimized) -->
    <div id="gs-floating-pill" class="gs-floating-pill ${isCritical ? 'gs-pill-critical' : 'gs-pill-caution'}" style="display: none;">
      <span class="gs-pill-icon">🚨</span>
      <span class="gs-pill-label">GovShield Alert: <strong>${escapeHtml(currentHostname)}</strong> (Risk: ${score}/100)</span>
      <button type="button" id="gs-pill-reopen-btn" class="gs-pill-reopen-btn">View Alert</button>
      <button type="button" id="gs-pill-close-btn" class="gs-pill-close-btn" title="Close permanently">✕</button>
    </div>
  `;

  document.body.prepend(container);

  // Setup Event Listeners
  const topBanner = container.querySelector("#gs-top-banner");
  const floatingPill = container.querySelector("#gs-floating-pill");

  // Dismiss banner -> show small floating pill
  container.querySelector("#gs-btn-dismiss-banner").addEventListener("click", () => {
    topBanner.style.display = "none";
    floatingPill.style.display = "flex";
  });

  // Reopen banner from floating pill
  container.querySelector("#gs-pill-reopen-btn").addEventListener("click", () => {
    topBanner.style.display = "block";
    floatingPill.style.display = "none";
  });

  // Permanently close floating pill
  container.querySelector("#gs-pill-close-btn").addEventListener("click", () => {
    container.remove();
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