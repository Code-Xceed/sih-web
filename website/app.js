/**
 * GovShield / SatyaGov — Web Portal Controller
 * Seamlessly integrated with FastAPI Multimodal AI Backend (Gemini 2.0 Flash)
 */

document.addEventListener('DOMContentLoaded', () => {
    const API_BASE = window.location.origin.startsWith('http') ? window.location.origin : '';
    let currentAnalysisResult = null;

    // Elements
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const resultsWrapper = document.getElementById('resultsWrapper');
    const statusPill = document.querySelector('.status-pill');

    // 1. Live Backend Health Check
    async function checkBackendHealth() {
        try {
            const resp = await fetch(`${API_BASE}/api/health`);
            if (resp.ok) {
                if (statusPill) {
                    statusPill.innerHTML = `<span class="status-dot"></span><span>Online</span>`;
                }
            }
        } catch (e) {
            if (statusPill) {
                statusPill.innerHTML = `<span class="status-dot" style="background:#d97706;"></span><span>Offline</span>`;
            }
        }
    }
    checkBackendHealth();

    // 2. Scan Trigger Handlers
    if (scanBtn) {
        scanBtn.addEventListener('click', () => {
            const url = urlInput ? urlInput.value.trim() : '';
            if (!url) {
                showToast("Please enter a URL to scan");
                if (urlInput) urlInput.focus();
                return;
            }
            executeScan(url);
        });
    }

    if (urlInput) {
        urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const url = urlInput.value.trim();
                if (url) executeScan(url);
            }
        });
    }

    // 3. Execute Scan against Actual AI Backend
    async function executeScan(url) {
        let normalizedUrl = url.trim();
        if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
            normalizedUrl = 'https://' + normalizedUrl;
        }

        if (scanBtn) {
            scanBtn.innerHTML = `<span>Analyzing AI...</span>`;
            scanBtn.disabled = true;
        }

        try {
            const response = await fetch(`${API_BASE}/api/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: normalizedUrl })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const scanResult = await response.json();
            currentAnalysisResult = scanResult;
            renderRealVerdict(scanResult, normalizedUrl);

        } catch (err) {
            console.warn("FastAPI backend error:", err);
            showToast("Connection to AI backend failed. Please try again.");
        } finally {
            if (scanBtn) {
                scanBtn.innerHTML = `<span>Inspect</span> ↵`;
                scanBtn.disabled = false;
            }
        }
    }

    // 4. Render Real Backend Verdict
    function renderRealVerdict(res, originalUrl) {
        if (!resultsWrapper) return;
        resultsWrapper.style.display = 'block';

        const score = Number(res.risk_score) || 0;
        const scoreEl = document.getElementById('scoreNumber');
        if (scoreEl) {
            scoreEl.textContent = score < 10 ? `0${score}` : score;
            if (score >= 66) {
                scoreEl.style.color = 'var(--color-threat)';
            } else if (score >= 26) {
                scoreEl.style.color = 'var(--color-caution)';
            } else {
                scoreEl.style.color = 'var(--color-safe)';
            }
        }

        const badgeEl = document.getElementById('verdictBadge');
        if (badgeEl) {
            if (res.verdict === 'PHISHING_CLONE') {
                badgeEl.textContent = 'CRITICAL PHISHING CLONE';
                badgeEl.className = 'verdict-badge-clean badge-threat';
            } else if (res.verdict === 'SUSPICIOUS') {
                badgeEl.textContent = 'SUSPICIOUS LOOKALIKE';
                badgeEl.className = 'verdict-badge-clean badge-caution';
            } else {
                badgeEl.textContent = res.is_genuine_gov_tld ? 'VERIFIED OFFICIAL PORTAL' : 'AUTHENTIC WEB PLATFORM';
                badgeEl.className = 'verdict-badge-clean badge-safe';
            }
        }

        const urlEl = document.getElementById('urlHeadline');
        if (urlEl) urlEl.textContent = originalUrl || res.url;

        const summaryEl = document.getElementById('verdictSummary');
        if (summaryEl) {
            let summaryText = res.summary || "Scan completed.";
            if (res.target_entity && res.verdict !== 'LEGITIMATE') {
                summaryText = `Deceptive impersonation targeting ${res.target_entity}. ${summaryText}`;
            }
            summaryEl.textContent = summaryText;
        }

        const remediationEl = document.getElementById('remediationText');
        if (remediationEl) {
            if (res.verdict === 'PHISHING_CLONE') {
                remediationEl.textContent = "DO NOT enter Aadhaar, PAN, OTP, or banking credentials. A CERT-In takedown notice has been drafted.";
            } else if (res.verdict === 'SUSPICIOUS') {
                remediationEl.textContent = "Exercise caution. Verify the official URL on india.gov.in before providing personal information.";
            } else {
                remediationEl.textContent = "Safe for navigation. The domain is verified and authenticated.";
            }
        }

        // 5 Inspection Steps
        const stepsEl = document.getElementById('inspectionSteps');
        if (stepsEl) {
            stepsEl.innerHTML = '';

            const breakdown = res.signal_breakdown || {};
            const lexScore = Number(breakdown.lexical_score) || 0;
            const domScore = Number(breakdown.dom_score) || 0;
            const visScore = Number(breakdown.visual_similarity) || 0;
            const ageDays = Number(breakdown.domain_age_days) || 0;
            const sensFields = breakdown.sensitive_fields_found || [];
            const aiData = res.genai_analysis || {};

            const steps = [
                {
                    title: "01. DOMAIN & TYPOSQUATTING ANALYSIS",
                    status: (lexScore > 45 && res.verdict !== 'LEGITIMATE') ? "FAIL" : (lexScore > 20 ? "WARN" : "PASS"),
                    description: (lexScore > 45 && res.verdict !== 'LEGITIMATE')
                        ? `Unauthorized domain uses official government entity tokens (${res.target_entity || 'Public Service'}). Lexical risk: ${lexScore}/100.`
                        : `No fraudulent typosquatting or government brand deception detected.`
                },
                {
                    title: "02. CREDENTIAL FORM INSPECTION",
                    status: (sensFields.length > 0 && res.verdict !== 'LEGITIMATE') ? "FAIL" : "PASS",
                    description: (sensFields.length > 0 && res.verdict !== 'LEGITIMATE')
                        ? `Form action harvesting citizen identity tokens: [${sensFields.join(', ')}] on non-governmental domain.`
                        : `No citizen identity or biometric token harvesting forms detected.`
                },
                {
                    title: "03. VISUAL SIMILARITY MATCHING",
                    status: (visScore >= 70 && res.verdict !== 'LEGITIMATE') ? "FAIL" : "PASS",
                    description: (visScore >= 70 && res.verdict !== 'LEGITIMATE')
                        ? `Perceptual visual hash matches ${res.target_entity || 'Gov Portal'} layout with ${visScore}% lookalike similarity.`
                        : `Visual layout and color signatures show zero deceptive imitation of government portals.`
                },
                {
                    title: "04. DOMAIN AGE & REGISTRATION",
                    status: (ageDays < 30 && res.verdict !== 'LEGITIMATE') ? "FAIL" : "PASS",
                    description: (ageDays < 30 && res.verdict !== 'LEGITIMATE')
                        ? `Newly Registered Domain (${ageDays} days old) on unauthorized top-level domain.`
                        : (res.is_genuine_gov_tld ? `Authenticated National Informatics Centre (NIC India) infrastructure (12+ years old).` : `Established domain age: ${ageDays} days.`)
                },
                {
                    title: "05. AI NEURAL VERIFICATION",
                    status: (res.verdict === 'PHISHING_CLONE') ? "FAIL" : (res.verdict === 'SUSPICIOUS' ? "WARN" : "PASS"),
                    description: aiData.plain_english_explanation || (res.reasons && res.reasons.length > 0 ? res.reasons[0] : "Verified against Government of India sovereign defense baseline.")
                }
            ];

            steps.forEach((layer, index) => {
                const step = document.createElement('div');
                step.className = 'step-card';
                const stepNum = index < 9 ? `0${index + 1}` : `${index + 1}`;

                let statusColor = 'var(--color-safe)';
                let statusText = 'PASS';
                if (layer.status === 'FAIL') {
                    statusColor = 'var(--color-threat)';
                    statusText = 'MALICIOUS';
                } else if (layer.status === 'WARN') {
                    statusColor = 'var(--color-caution)';
                    statusText = 'SUSPICIOUS';
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
                stepsEl.appendChild(step);
            });
        }

        resultsWrapper.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // 5. CERT-In Takedown Dossier Modal
    const dossierModal = document.getElementById('dossierModal');
    const modalCloseBtn = document.getElementById('modalCloseBtn');
    const dossierText = document.getElementById('dossierText');
    const copyDossierBtn = document.getElementById('copyDossierBtn');
    const btnQuickDossier = document.getElementById('btnQuickDossier');

    async function openDossier(res) {
        if (!res) {
            showToast("Scan a URL first");
            return;
        }

        let dossierContent = '';
        try {
            const resp = await fetch(`${API_BASE}/api/report-certin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scan_result: res, reporter_notes: "Web Portal Inspection Dossier" })
            });
            if (resp.ok) {
                const reportJson = await resp.json();
                const report = reportJson.incident_report || reportJson;
                dossierContent = `========================================================================
CYBER SECURITY INCIDENT REPORT / PHISHING TAKEDOWN DOSSIER
Prepared for: CERT-In (incident@cert-in.org.in) & CyberCrime Portal (cybercrime.gov.in)
Incident ID : ${report.incident_id || 'CERTIN-INC-AUTO'}
Timestamp   : ${report.report_timestamp_utc || new Date().toISOString()}
========================================================================
Target Scope      : Government of India Sovereign Public Services
Impersonated Port.: ${report.target_government_entity || res.target_entity || 'Government Scheme'}
Malicious URL     : ${report.malicious_url || res.url}
Threat Score      : ${report.risk_score || res.risk_score} / 100
Classification    : ${report.classification || res.verdict}

[1] FORENSIC EVIDENCE:
- Lexical Typosquatting Score     : ${report.forensic_evidence?.lexical_typosquatting_score || 0}/100
- Visual Perceptual Similarity    : ${report.forensic_evidence?.visual_perceptual_similarity_percentage || 0}%
- DOM Identity Harvesting Fields  : ${(report.forensic_evidence?.harvested_sensitive_fields || []).join(', ') || 'None'}
- Domain Age                      : ${report.forensic_evidence?.domain_age_days || 'N/A'} days

[2] DETECTED MALICIOUS INDICATORS:
${(report.detected_anomalies_and_indicators || res.reasons || []).map((r, i) => `[${i+1}] ${r}`).join('\n')}

[3] TAKEDOWN DIRECTIVES:
${(report.mitigation_recommendations || [
    "Issue urgent DNS sinkhole via NIXI / INRegistry.",
    "Direct ISP/TSP DNS blocking under Section 69A IT Act.",
    "Notify CERT-In Incident Response Team."
]).map((m, i) => `[${i+1}] ${m}`).join('\n')}
========================================================================`;
            }
        } catch (e) {
            dossierContent = JSON.stringify(res, null, 2);
        }

        if (dossierText) dossierText.textContent = dossierContent;
        if (dossierModal) dossierModal.classList.add('active');
    }

    if (btnQuickDossier) {
        btnQuickDossier.addEventListener('click', () => {
            openDossier(currentAnalysisResult);
        });
    }

    if (modalCloseBtn && dossierModal) {
        modalCloseBtn.addEventListener('click', () => {
            dossierModal.classList.remove('active');
        });
    }

    if (dossierModal) {
        dossierModal.addEventListener('click', (e) => {
            if (e.target === dossierModal) dossierModal.classList.remove('active');
        });
    }

    if (copyDossierBtn && dossierText) {
        copyDossierBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(dossierText.textContent).then(() => {
                showToast("Dossier copied to clipboard");
                if (dossierModal) dossierModal.classList.remove('active');
            }).catch(() => {
                showToast("Please copy manually");
            });
        });
    }

    // 7. Toast Helper
    function showToast(message) {
        const toast = document.createElement('div');
        toast.className = 'toast-clean';
        toast.textContent = message;
        
        let container = document.getElementById('toastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toastContainer';
            container.className = 'toast-container';
            document.body.appendChild(container);
        }

        container.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(6px)';
            toast.style.transition = 'all 0.2s ease';
            setTimeout(() => toast.remove(), 200);
        }, 2400);
    }
});
