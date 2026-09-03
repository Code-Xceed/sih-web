/**
 * GovShield Sentinel Grid - Content Script
 * Extracts DOM metadata and renders authoritative in-page security banners for all domains (Safe, Suspicious, Risky).
 */

(function () {
  // Avoid duplicate injection
  if (window.__govshield_injected) return;
  window.__govshield_injected = true;

  // 1. Extract DOM Features
  function extractPageMetadata() {
    try {
      const forms = Array.from(document.querySelectorAll('form'));
      const inputs = Array.from(document.querySelectorAll('input, select, textarea'));
      const sensitiveInputs = [];

      inputs.forEach(inp => {
        const type = (inp.type || '').toLowerCase();
        const name = (inp.name || '').toLowerCase();
        const id = (inp.id || '').toLowerCase();
        const placeholder = (inp.placeholder || '').toLowerCase();
        const combined = `${name} ${id} ${placeholder}`;

        if (type === 'password' || combined.includes('pass')) {
          sensitiveInputs.push('Password');
        } else if (combined.includes('aadhaar') || combined.includes('aadhar') || combined.includes('uid')) {
          sensitiveInputs.push('Aadhaar Number');
        } else if (combined.includes('pan')) {
          sensitiveInputs.push('PAN Card Number');
        } else if (combined.includes('otp')) {
          sensitiveInputs.push('One-Time Password (OTP)');
        } else if (combined.includes('bank') || combined.includes('acc') || combined.includes('card')) {
          sensitiveInputs.push('Banking / Financial Details');
        }
      });

      // Sample HTML slice
      const htmlSlice = document.documentElement ? document.documentElement.outerHTML.slice(0, 75000) : "";

      return {
        url: window.location.href,
        title: document.title || "",
        formsCount: forms.length,
        sensitiveInputs: Array.from(new Set(sensitiveInputs)),
        htmlContent: htmlSlice
      };
    } catch (e) {
      return { url: window.location.href, formsCount: 0, sensitiveInputs: [], htmlContent: "" };
    }
  }

  // 2. Mount Banner Helper with Guaranteed DOM Insertion
  function mountBanner(bannerElement) {
    if (document.body) {
      document.body.prepend(bannerElement);
    } else if (document.documentElement) {
      document.documentElement.prepend(bannerElement);
    } else {
      window.addEventListener('DOMContentLoaded', () => {
        if (document.body) {
          document.body.prepend(bannerElement);
        } else {
          document.documentElement.prepend(bannerElement);
        }
      });
    }
  }

  // 3. In-Page Universal Security Banner (Safe, Suspicious, Risky)
  function showSecurityBanner(scanResult) {
    if (!scanResult) return;

    const existing = document.getElementById('govshield-phishing-banner');
    if (existing) existing.remove();

    const score = Number(scanResult.risk_score) || 0;
    const verdict = scanResult.verdict || "LEGITIMATE";
    const targetEntity = scanResult.target_entity || "Official Indian Government Portal";
    const aiInsight = scanResult.genai_analysis?.plain_english_explanation || scanResult.summary || "";

    const banner = document.createElement('div');
    banner.id = 'govshield-phishing-banner';

    // Only display in-page alert banner on RISKY and SUSPICIOUS sites
    const isCritical = verdict === "PHISHING_CLONE" || verdict === "MALICIOUS" || score >= 65;
    const isSuspicious = verdict === "SUSPICIOUS" || (score >= 35 && score < 65);
    if (!isCritical && !isSuspicious) {
      // Safe website: Keep page clean and unblocked
      return;
    }

    const isPibScam = (scanResult.category === "GOVERNMENT_IMPERSONATION_SCAM") ||
      (scanResult.reasons && scanResult.reasons.some(r => r.includes("PIB") || r.includes("Press Information Bureau")));

    let bannerClass = "";
    let iconSvg = "";
    let titleText = "";
    let pillText = "";
    let descHtml = "";
    let actionsHtml = "";

    if (isCritical) {
      bannerClass = "govshield-banner-risk";
      iconSvg = `
        <svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
          <line x1="12" y1="9" x2="12" y2="13"></line>
          <line x1="12" y1="17" x2="12.01" y2="17"></line>
        </svg>
      `;
      titleText = "GOVSHIELD CYBER DEFENSE ALERT / साइबर चेतावनी";
      pillText = `RISK SCORE: ${score}/100 • CRITICAL`;

      let pibNoticeHtml = "";
      if (isPibScam) {
        pibNoticeHtml = `
          <div style="background: rgba(239, 68, 68, 0.25); border: 1px solid #EF4444; border-radius: 4px; padding: 4px 8px; margin-bottom: 6px; font-size: 0.82rem; color: #FCA5A5;">
            ⚠️ <strong>PIB Fact Check Alert:</strong> Flagged by Press Information Bureau as a fraudulent recruitment fee / scheme portal!
          </div>
        `;
      }

      descHtml = `
        ${pibNoticeHtml}
        <div style="font-size: 0.92rem; font-weight: 800; color: #FFFFFF; margin-bottom: 4px;">
          🛑 सावधान! यह फर्जी वेबसाइट है। यहाँ आधार नंबर, पैन या बैंक OTP बिल्कुल न भरें।
        </div>
        <div>
          Deceptive lookalike domain detected! This website imitates <strong>${targetEntity}</strong> to steal citizen credentials or collect fake application fees.
        </div>
      `;
      if (aiInsight) {
        descHtml += ` <span class="govshield-ai-insight">🤖 AI: ${aiInsight}</span>`;
      }
      actionsHtml = `
        <a href="tel:1930" class="govshield-btn" style="background:#DC2626; color:#FFF; text-decoration:none; display:inline-flex; align-items:center; gap:4px; font-weight:700;">📞 1930 Helpline</a>
        <button id="govshield-leave-btn" class="govshield-btn govshield-btn-primary">Leave Unsafe Site</button>
        <button id="govshield-dismiss-btn" class="govshield-btn govshield-btn-secondary">Dismiss</button>
      `;
    } else {
      // Suspicious site
      bannerClass = "govshield-banner-susp";
      iconSvg = `
        <svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="12" y1="8" x2="12" y2="12"></line>
          <line x1="12" y1="16" x2="12.01" y2="16"></line>
        </svg>
      `;
      titleText = "GOVSHIELD SECURITY NOTICE: POTENTIAL LOOKALIKE";
      pillText = `RISK SCORE: ${score}/100 • SUSPICIOUS`;
      descHtml = `
        <div style="font-weight: 600; color: #FFFFFF; margin-bottom: 2px;">
          चेतावनी: यह वेबसाइट आधिकारिक सरकारी (.gov.in) पोर्टल नहीं है।
        </div>
        <div>
          Caution: This website contains keywords matching <strong>${targetEntity}</strong> but is NOT hosted on an official .gov.in domain. Verify carefully before submitting details.
        </div>
      `;
      actionsHtml = `
        <a href="tel:1930" class="govshield-btn" style="background:#DC2626; color:#FFF; text-decoration:none; display:inline-flex; align-items:center; gap:4px; font-weight:700;">📞 1930</a>
        <button id="govshield-dismiss-btn" class="govshield-btn govshield-btn-secondary">Acknowledge</button>
      `;
    }

    banner.className = bannerClass;
    banner.innerHTML = `
      <div class="govshield-banner-content">
        <div class="govshield-banner-icon">
          ${iconSvg}
        </div>
        <div class="govshield-banner-text">
          <div class="govshield-banner-title">
            <span>${titleText}</span>
            <span class="govshield-risk-pill">${pillText}</span>
            <span class="govshield-ai-tag">Gemini 2.0 Flash AI</span>
          </div>
          <div class="govshield-banner-desc">
            ${descHtml}
          </div>
        </div>
        <div class="govshield-banner-actions">
          ${actionsHtml}
        </div>
      </div>
    `;

    mountBanner(banner);

    document.getElementById('govshield-leave-btn')?.addEventListener('click', () => {
      window.location.href = 'https://india.gov.in';
    });

    document.getElementById('govshield-dismiss-btn')?.addEventListener('click', () => {
      banner.remove();
    });
  }

  // 4. Send DOM and Handle Immediate Response
  const domData = extractPageMetadata();
  chrome.runtime.sendMessage({
    action: "DOM_EXTRACTED",
    url: window.location.href,
    domData: domData
  }, (response) => {
    if (response && response.success && response.result) {
      showSecurityBanner(response.result);
    }
  });

  // 5. Listen for broadcast update signals from background service worker
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'SHOW_SECURITY_BANNER' && msg.data) {
      showSecurityBanner(msg.data);
    }
  });

})();
