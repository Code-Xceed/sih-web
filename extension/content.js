/**
 * GovShield Sentinel Grid 3.0 — Minimal In-Page Citizen Cyber Defense Alerts
 * Dynamic Integration with GovShield Backend Engine & UX4G 3.0 Standard
 */

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
   1. Minimal In-Page Cyber Fraud Alert Banner (Top of page)
   ========================================================================== */
function renderSecurityAlert(data, currentHostname, scoreParam) {
  // Never show risk banner on verified sovereign domains
  if (data.is_genuine_gov_tld) return;

  // Remove existing banner/prompt if present
  const existingBanner = document.getElementById("govshield-alert-root");
  if (existingBanner) existingBanner.remove();
  const existingSafe = document.getElementById("govshield-safe-prompt");
  if (existingSafe) existingSafe.remove();

  const score = Math.max(0, Math.min(99, Math.round(data.risk_score !== undefined ? data.risk_score : (scoreParam || 85))));
  const isCritical = score >= 60 || data.verdict === "PHISHING_CLONE" || data.verdict === "MALICIOUS";
  const targetEntity = data.target_entity || "Indian Government Portal";

  const cybercrimeUrl = "https://cybercrime.gov.in";

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
              <span class="gs-alert-tag">${isCritical ? 'CRITICAL CYBER FRAUD' : 'SUSPICIOUS PORTAL'}</span>
              <span class="gs-target-tag">Mimicking ${escapeHtml(targetEntity)}</span>
            </div>
            <span class="gs-main-warning">
              Deceptive site (<strong class="gs-domain-highlight">${escapeHtml(currentHostname)}</strong>) is NOT official!
            </span>
            <span class="gs-sub-advice">⚠️ DO NOT enter Aadhaar, PAN, Bank Details, or OTP.</span>
          </div>
        </div>

        <div class="gs-banner-actions-col">
          <a href="${cybercrimeUrl}" target="_blank" rel="noopener noreferrer" class="gs-btn gs-btn-report" title="File incident directly on National Cyber Crime Portal">
            🚨 Report (cybercrime.gov.in)
          </a>
          <a href="tel:1930" class="gs-btn gs-btn-helpline" title="National Citizen Cyber Crime Helpline">
            📞 1930
          </a>
          <button type="button" id="gs-btn-dismiss-banner" class="gs-btn-icon-close" title="Dismiss alert banner">
            ✕
          </button>
        </div>
      </div>
    </div>
  `;

  document.body.prepend(container);

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

  const toast = document.createElement("div");
  toast.id = "govshield-safe-prompt";
  toast.className = "gs-safe-toast";

  toast.innerHTML = `
    <div class="gs-safe-icon-disc">
      ${isGov ? '🏛️' : '🛡️'}
    </div>
    <div class="gs-safe-body">
      <div class="gs-safe-title-row">
        <strong class="gs-safe-heading">${isGov ? 'Authentic Sovereign Portal' : 'Website is Safe to Visit'}</strong>
        <span class="gs-safe-status-pill">${isGov ? 'VERIFIED .GOV.IN' : 'SAFE'}</span>
      </div>
      <span class="gs-safe-subtitle">
        ${isGov ? `${escapeHtml(entity)} — Secured by NIC` : `${escapeHtml(currentHostname)} — Verified by GovShield`}
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