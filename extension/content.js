// GovShield Sentinel Grid 3.0 — High-Visibility Citizen Protection Banner
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "SHOW_FRAUD_BANNER") {
    injectWarningBanner(msg.domain);
  }
});

function injectWarningBanner(domain) {
  if (document.getElementById("govshield-warning-banner")) return;

  const banner = document.createElement("div");
  banner.id = "govshield-warning-banner";
  banner.innerHTML = `
    <div class="gs-banner-inner">
      <div class="gs-banner-icon">🚨</div>
      <div class="gs-banner-text">
        <strong>CYBER FRAUD ALERT (GovShield Sentinel Grid):</strong>
        This domain (<span class="gs-domain">${domain}</span>) is an unauthorized cyber clone impersonating Indian Government services!
        DO NOT submit Aadhaar, PAN, OTP, or Bank details.
      </div>
      <div class="gs-banner-actions">
        <a href="tel:1930" class="gs-btn-1930">📞 Dial 1930</a>
        <button type="button" id="gs-btn-dismiss" class="gs-btn-dismiss">Dismiss</button>
      </div>
    </div>
  `;

  document.body.prepend(banner);

  document.getElementById("gs-btn-dismiss").addEventListener("click", () => {
    banner.remove();
  });
}