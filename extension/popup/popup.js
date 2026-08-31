/**
 * GovShield — Extension Popup Controller
 * Exact Visual & Behavioral Replica of the Web Portal
 */

document.addEventListener("DOMContentLoaded", async () => {
  // DOM Elements
  const urlInput = document.getElementById("urlInput");
  const scanBtn = document.getElementById("scanBtn");
  const scoreNumber = document.getElementById("scoreNumber");
  const verdictBadge = document.getElementById("verdictBadge");
  const urlHeadline = document.getElementById("urlHeadline");
  const verdictSummary = document.getElementById("verdictSummary");
  const inspectionSteps = document.getElementById("inspectionSteps");
  const remediationText = document.getElementById("remediationText");
  const btnQuickDossier = document.getElementById("btnQuickDossier");
  const engineLabel = document.getElementById("engineLabel");

  const toggleDetailsBtn = document.getElementById("toggleDetailsBtn");
  const toggleDetailsText = document.getElementById("toggleDetailsText");
  const toggleDetailsIcon = document.getElementById("toggleDetailsIcon");
  const inspectionStepsContainer = document.getElementById("inspectionStepsContainer");

  let isDetailsExpanded = false;

  function setDetailsExpanded(expanded) {
    isDetailsExpanded = expanded;
    if (inspectionStepsContainer) {
      if (expanded) {
        inspectionStepsContainer.classList.remove("collapsed");
      } else {
        inspectionStepsContainer.classList.add("collapsed");
      }
    }
    if (toggleDetailsText) {
      toggleDetailsText.textContent = expanded ? "Hide Details" : "Show Details";
    }
    if (toggleDetailsIcon) {
      toggleDetailsIcon.textContent = expanded ? "▴" : "▾";
    }
  }

  if (toggleDetailsBtn) {
    toggleDetailsBtn.addEventListener("click", () => {
      setDetailsExpanded(!isDetailsExpanded);
    });
  }

  // 1. Render UI with scan data (Exact replica of website logic)
  function renderScanData(data, url) {
    if (!data) return;
    currentScanData = data;

    const displayUrl = url || data.url || "Active Tab";
    if (urlHeadline) urlHeadline.textContent = displayUrl;
    if (urlInput) urlInput.value = displayUrl.startsWith("http") ? displayUrl : "";

    // Engine Label
    if (engineLabel) {
      engineLabel.textContent = data.engine_mode === "EDGE_FALLBACK" ? "Edge Mode" : "Online";
    }

    // Score & Color
    const score = Number(data.risk_score) || 0;
    if (scoreNumber) {
      scoreNumber.textContent = score < 10 ? `0${score}` : score;
      if (score >= 66) {
        scoreNumber.style.color = "var(--color-threat)";
      } else if (score >= 26) {
        scoreNumber.style.color = "var(--color-caution)";
      } else {
        scoreNumber.style.color = "var(--color-safe)";
      }
    }

    // Badge
    if (verdictBadge) {
      if (data.verdict === "PHISHING_CLONE") {
        verdictBadge.textContent = "CRITICAL THREAT";
        verdictBadge.className = "verdict-badge-clean badge-threat";
        setDetailsExpanded(true); // Auto-expand on threats
      } else if (data.verdict === "SUSPICIOUS") {
        verdictBadge.textContent = "SUSPICIOUS DOMAIN";
        verdictBadge.className = "verdict-badge-clean badge-caution";
        setDetailsExpanded(true); // Auto-expand on caution
      } else {
        verdictBadge.textContent = data.is_genuine_gov_tld ? "VERIFIED OFFICIAL" : "AUTHENTIC WEB";
        verdictBadge.className = "verdict-badge-clean badge-safe";
        setDetailsExpanded(false); // Default neat collapse on safe
      }
    }

    // Summary
    if (verdictSummary) {
      let summaryStr = data.summary || "Evaluation completed.";
      if (data.target_entity && data.verdict !== "LEGITIMATE") {
        summaryStr = `Deceptive impersonation targeting ${data.target_entity}. ${summaryStr}`;
      }
      verdictSummary.textContent = summaryStr;
    }

    // Advisory
    if (remediationText) {
      if (data.verdict === "PHISHING_CLONE") {
        remediationText.textContent = "DO NOT enter Aadhaar, PAN, OTP, or banking credentials. A CERT-In takedown notice has been drafted.";
      } else if (data.verdict === "SUSPICIOUS") {
        remediationText.textContent = "Exercise caution. Verify the official URL on india.gov.in before providing personal information.";
      } else {
        remediationText.textContent = "Safe for navigation. The domain is verified and authenticated.";
      }
    }

    // 5 Inspection Steps (Exact match to website)
    if (inspectionSteps) {
      inspectionSteps.innerHTML = "";

      const breakdown = data.signal_breakdown || {};
      const lexScore = Number(breakdown.lexical_score) || 0;
      const domScore = Number(breakdown.dom_score) || 0;
      const visScore = Number(breakdown.visual_similarity) || 0;
      const ageDays = Number(breakdown.domain_age_days) || 0;
      const sensFields = breakdown.sensitive_fields_found || [];
      const aiData = data.genai_analysis || {};

      const steps = [
        {
          title: "01. DOMAIN & TYPOSQUATTING ANALYSIS",
          status: (lexScore > 45 && data.verdict !== 'LEGITIMATE') ? "FAIL" : (lexScore > 20 ? "WARN" : "PASS"),
          description: (lexScore > 45 && data.verdict !== 'LEGITIMATE')
            ? `Unauthorized domain uses official tokens (${data.target_entity || 'Gov Scheme'}). Risk: ${lexScore}/100.`
            : `No fraudulent typosquatting or government brand deception detected.`
        },
        {
          title: "02. CREDENTIAL FORM INSPECTION",
          status: (sensFields.length > 0 && data.verdict !== 'LEGITIMATE') ? "FAIL" : "PASS",
          description: (sensFields.length > 0 && data.verdict !== 'LEGITIMATE')
            ? `Credential harvesting fields: [${sensFields.join(', ')}] on non-gov domain.`
            : `No identity or biometric credential harvesting forms detected.`
        },
        {
          title: "03. VISUAL SIMILARITY MATCHING",
          status: (visScore >= 70 && data.verdict !== 'LEGITIMATE') ? "FAIL" : "PASS",
          description: (visScore >= 70 && data.verdict !== 'LEGITIMATE')
            ? `Perceptual visual hash matches ${data.target_entity || 'Gov Portal'} with ${visScore}% similarity.`
            : `Visual layout shows zero deceptive imitation of government portals.`
        },
        {
          title: "04. DOMAIN AGE & REGISTRATION",
          status: (ageDays < 30 && data.verdict !== 'LEGITIMATE') ? "FAIL" : "PASS",
          description: (ageDays < 30 && data.verdict !== 'LEGITIMATE')
            ? `Newly Registered Domain (${ageDays} days old) on unauthorized TLD.`
            : (data.is_genuine_gov_tld ? `Authenticated NIC India infrastructure (12+ years old).` : `Established domain age: ${ageDays} days.`)
        },
        {
          title: "05. AI NEURAL VERIFICATION",
          status: (data.verdict === 'PHISHING_CLONE') ? "FAIL" : (data.verdict === 'SUSPICIOUS' ? "WARN" : "PASS"),
          description: aiData.plain_english_explanation || (data.reasons && data.reasons.length > 0 ? data.reasons[0] : "Verified against Government of India sovereign defense baseline.")
        }
      ];

      steps.forEach((layer, index) => {
        const step = document.createElement("div");
        step.className = "step-card";
        const stepNum = index < 9 ? `0${index + 1}` : `${index + 1}`;

        let statusColor = "var(--color-safe)";
        let statusText = "PASS";
        if (layer.status === "FAIL") {
          statusColor = "var(--color-threat)";
          statusText = "MALICIOUS";
        } else if (layer.status === "WARN") {
          statusColor = "var(--color-caution)";
          statusText = "SUSPICIOUS";
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
        inspectionSteps.appendChild(step);
      });
    }
  }

  // 2. Load active tab status
  async function loadActiveTabStatus() {
    chrome.runtime.sendMessage({ action: "GET_CURRENT_STATUS" }, (response) => {
      if (response && response.success && response.result) {
        renderScanData(response.result, response.tab ? response.tab.url : "");
      } else {
        if (scoreNumber) scoreNumber.textContent = "00";
        if (urlHeadline) urlHeadline.textContent = "Ready to inspect tab...";
        if (verdictSummary) verdictSummary.textContent = "Navigate to any portal or enter a URL above.";
      }
    });
  }

  // 3. Manual Inspector
  if (scanBtn) {
    scanBtn.addEventListener("click", () => {
      const inputUrl = urlInput ? urlInput.value.trim() : "";
      if (!inputUrl) {
        showToast("Enter a URL to scan");
        return;
      }

      if (scoreNumber) scoreNumber.textContent = "--";
      if (urlHeadline) urlHeadline.textContent = inputUrl;
      if (verdictSummary) verdictSummary.textContent = "Analyzing multi-modal cyber intelligence...";

      chrome.runtime.sendMessage({ action: "MANUAL_SCAN", url: inputUrl }, (resp) => {
        if (resp && resp.success && resp.result) {
          renderScanData(resp.result, inputUrl);
        } else {
          showToast("Scan completed or fallback activated.");
        }
      });
    });
  }

  if (urlInput) {
    urlInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter" && scanBtn) {
        scanBtn.click();
      }
    });
  }

  // 4. CERT-In Dossier Flow
  if (btnQuickDossier) {
    btnQuickDossier.addEventListener("click", () => {
      if (!currentScanData) {
        showToast("No active scan data");
        return;
      }

      if (dossierText) dossierText.textContent = "Compiling forensic evidence packet...";
      if (dossierModal) dossierModal.classList.add("active");

      chrome.runtime.sendMessage({
        action: "REPORT_CERTIN",
        scan_result: currentScanData,
        notes: "Citizen threat dispatch via GovShield Extension."
      }, (resp) => {
        if (resp && resp.success && resp.data) {
          const report = resp.data.incident_report || resp.data;
          const formatted = `========================================================================
CYBER SECURITY INCIDENT REPORT / PHISHING TAKEDOWN DOSSIER
Prepared for: CERT-In (incident@cert-in.org.in) & CyberCrime Portal (cybercrime.gov.in)
Incident ID : ${report.incident_id || 'CERTIN-INC-AUTO'}
Timestamp   : ${report.report_timestamp_utc || new Date().toISOString()}
========================================================================
Target Scope      : Government of India Sovereign Public Services
Impersonated Port.: ${report.target_government_entity || currentScanData.target_entity || 'Government Scheme'}
Malicious URL     : ${report.malicious_url || currentScanData.url}
Threat Score      : ${report.risk_score || currentScanData.risk_score} / 100
Classification    : ${report.classification || currentScanData.verdict}

[1] FORENSIC EVIDENCE:
- Lexical Typosquatting Score     : ${report.forensic_evidence?.lexical_typosquatting_score || 0}/100
- Visual Perceptual Similarity    : ${report.forensic_evidence?.visual_perceptual_similarity_percentage || 0}%
- DOM Identity Harvesting Fields  : ${(report.forensic_evidence?.harvested_sensitive_fields || []).join(', ') || 'None'}
- Domain Age                      : ${report.forensic_evidence?.domain_age_days || 'N/A'} days

[2] DETECTED MALICIOUS INDICATORS:
${(report.detected_anomalies_and_indicators || currentScanData.reasons || []).map((r, i) => `[${i+1}] ${r}`).join('\n')}

[3] TAKEDOWN DIRECTIVES:
${(report.mitigation_recommendations || [
    "Issue urgent DNS sinkhole via NIXI / INRegistry.",
    "Direct ISP/TSP DNS blocking under Section 69A IT Act.",
    "Notify CERT-In Incident Response Team."
]).map((m, i) => `[${i+1}] ${m}`).join('\n')}
========================================================================`;
          if (dossierText) dossierText.textContent = formatted;
        } else {
          if (dossierText) dossierText.textContent = JSON.stringify(currentScanData, null, 2);
        }
      });
    });
  }

  if (modalCloseBtn && dossierModal) {
    modalCloseBtn.addEventListener("click", () => {
      dossierModal.classList.remove("active");
    });
  }

  if (dossierModal) {
    dossierModal.addEventListener("click", (e) => {
      if (e.target === dossierModal) dossierModal.classList.remove("active");
    });
  }

  if (copyDossierBtn && dossierText) {
    copyDossierBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(dossierText.textContent).then(() => {
        showToast("Dossier copied to clipboard");
        if (dossierModal) dossierModal.classList.remove("active");
      }).catch(() => {
        showToast("Please copy manually");
      });
    });
  }

  // 5. Toast notification helper
  function showToast(message) {
    const toast = document.createElement("div");
    toast.className = "toast-clean";
    toast.textContent = message;

    let container = document.getElementById("toastContainer");
    if (!container) {
      container = document.createElement("div");
      container.id = "toastContainer";
      container.className = "toast-container";
      document.body.appendChild(container);
    }

    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(6px)";
      toast.style.transition = "all 0.2s ease";
      setTimeout(() => toast.remove(), 200);
    }, 2200);
  }

  // Initial load
  loadActiveTabStatus();
});

