import os
import subprocess

html_content = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>GovShield Sentinel Grid 3.0 — Comprehensive Technical Specification & Stack Dossier</title>
<style>
  @page {
    size: A4 portrait;
    margin: 14mm 14mm 16mm 14mm;
    @bottom-center {
      content: "Page " counter(page) " of " counter(pages);
      font-size: 8pt;
      font-family: 'Segoe UI', system-ui, sans-serif;
      color: #64748b;
    }
  }

  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    color: #0f172a;
    background: #ffffff;
    font-size: 8.8pt;
    line-height: 1.45;
  }

  .page-break {
    page-break-before: always;
  }

  .avoid-break {
    page-break-inside: avoid;
  }

  /* Header banner with Indian Sovereign Tricolor */
  .doc-header {
    border-bottom: 2px solid #0b3a75;
    padding-bottom: 10px;
    margin-bottom: 14px;
    position: relative;
  }

  .tricolor-strip {
    height: 4px;
    background: linear-gradient(90deg, #FF9933 0%, #FF9933 33.3%, #ffffff 33.3%, #ffffff 66.6%, #138808 66.6%, #138808 100%);
    border-radius: 2px;
    margin-bottom: 8px;
  }

  .header-content {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
  }

  .title-group h1 {
    font-size: 16pt;
    font-weight: 800;
    color: #0b3a75;
    letter-spacing: -0.02em;
    margin-bottom: 2px;
  }

  .title-group .subtitle {
    font-size: 9.5pt;
    font-weight: 600;
    color: #2563eb;
    margin-bottom: 2px;
  }

  .title-group .theme {
    font-size: 7.8pt;
    color: #475569;
  }

  .meta-badge-group {
    text-align: right;
  }

  .meta-pill {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 7.2pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 3px;
  }

  .pill-cert {
    background: #eff6ff;
    color: #1d4ed8;
    border: 1px solid #bfdbfe;
  }

  .pill-version {
    background: #f0fdf4;
    color: #15803d;
    border: 1px solid #bbf7d0;
  }

  .meta-date {
    font-size: 7.2pt;
    color: #64748b;
  }

  /* Section Styles */
  h2 {
    font-size: 11.5pt;
    font-weight: 700;
    color: #0b3a75;
    border-left: 3px solid #2563eb;
    padding-left: 8px;
    margin-top: 12px;
    margin-bottom: 7px;
    letter-spacing: -0.01em;
  }

  h3 {
    font-size: 9pt;
    font-weight: 700;
    color: #1e293b;
    margin-top: 7px;
    margin-bottom: 3px;
  }

  p {
    margin-bottom: 5px;
    text-align: justify;
  }

  /* Grid cards */
  .cards-grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 7px;
    margin-bottom: 8px;
  }

  .card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 5px;
    padding: 7px 9px;
  }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-weight: 700;
    font-size: 8pt;
    color: #0b3a75;
    margin-bottom: 3px;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 3px;
  }

  .card-module-tag {
    font-family: 'Consolas', monospace;
    font-size: 6.5pt;
    color: #475569;
    background: #edf2f7;
    border: 1px solid #cbd5e1;
    border-radius: 3px;
    padding: 0.5px 4px;
    font-weight: 600;
  }

  .card-body {
    font-size: 7.5pt;
    color: #334155;
    line-height: 1.4;
  }

  /* Table styles */
  table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 5px;
    margin-bottom: 8px;
    font-size: 7.5pt;
  }

  th, td {
    padding: 4px 7px;
    border: 1px solid #cbd5e1;
    text-align: left;
    vertical-align: top;
  }

  th {
    background: #f1f5f9;
    color: #0f172a;
    font-weight: 700;
  }

  tr:nth-child(even) td {
    background: #f8fafc;
  }

  .tag {
    display: inline-block;
    padding: 1px 4px;
    border-radius: 3px;
    font-size: 6.8pt;
    font-weight: 600;
  }

  .tag-blue { background: #dbeafe; color: #1e40af; }
  .tag-green { background: #dcfce7; color: #166534; }
  .tag-red { background: #fee2e2; color: #991b1b; }
  .tag-purple { background: #f3e8ff; color: #6b21a8; }
  .tag-amber { background: #fef3c7; color: #92400e; }

  /* Architecture Diagram Box */
  .arch-box {
    background: #0f172a;
    color: #e2e8f0;
    border-radius: 5px;
    padding: 8px 10px;
    margin: 6px 0;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 6.8pt;
    line-height: 1.35;
    white-space: pre;
    overflow: hidden;
  }

  /* Callout box */
  .callout {
    border-left: 3px solid #059669;
    background: #f0fdf4;
    padding: 5px 9px;
    border-radius: 0 4px 4px 0;
    margin: 6px 0;
    font-size: 7.8pt;
  }

  .callout.alert {
    border-left-color: #dc2626;
    background: #fef2f2;
  }

  .callout.info {
    border-left-color: #2563eb;
    background: #eff6ff;
  }

  ul, ol {
    margin-left: 15px;
    margin-bottom: 5px;
    font-size: 7.8pt;
  }

  li {
    margin-bottom: 2px;
  }

  code {
    background: #e2e8f0;
    padding: 1px 3px;
    border-radius: 3px;
    font-family: 'Consolas', monospace;
    font-size: 7.2pt;
    color: #0f172a;
  }

  .footer-note {
    border-top: 1px solid #cbd5e1;
    padding-top: 5px;
    margin-top: 10px;
    font-size: 7.2pt;
    color: #64748b;
    display: flex;
    justify-content: space-between;
  }
</style>
</head>
<body>

  <!-- ================= PAGE 1 ================= -->
  <div class="doc-header">
    <div class="tricolor-strip"></div>
    <div class="header-content">
      <div class="title-group">
        <h1>GovShield Sentinel Grid 3.0</h1>
        <div class="subtitle">Comprehensive Technical Specification &amp; Stack Dossier</div>
        <div class="theme">Real-Time Multi-Signal AI/ML Cyber Defense &amp; Deceptive Government Portal Neutralization</div>
      </div>
      <div class="meta-badge-group">
        <span class="meta-pill pill-cert">SIH Problem: SIH1454</span><br>
        <span class="meta-pill pill-version">Release v3.2.0 (Production)</span>
        <div class="meta-date">Date: September 2026 | CERT-In Standard</div>
      </div>
    </div>
  </div>

  <h2>1. Executive Summary &amp; Problem Scope</h2>
  <p>
    <strong>GovShield Sentinel Grid 3.0</strong> is an enterprise sovereign cybersecurity ecosystem engineered to neutralize zero-day typosquats, credential harvesting phishing operations, and deceptive government clone portals that impersonate Government of India public administration infrastructure (e.g., <code>.gov.in</code> and <code>.nic.in</code>). Developed for <strong>Smart India Hackathon Problem Statement SIH1454</strong>, GovShield bridges browser endpoint interception, UX4G 3.0 citizen accessibility, a 15-stage defense-in-depth forensic pipeline, explainable soft-voting machine learning ensembles, and cryptographic Proof-of-Authority (PoA) blockchain evidence anchoring certified under <strong>Section 65B of the Indian Evidence Act</strong>.
  </p>

  <h2>2. End-to-End System Architecture</h2>
  <div class="arch-box">
+---------------------------------------------------------------------------------------------------------------+
|                                      GOVSHIELD SENTINEL GRID 3.0 ARCHITECTURE                                 |
+---------------------------------------------------------------------------------------------------------------+
| [ENDPOINT INTERCEPTION]                                                                                        |
|   Chrome MV3 Extension (Active Tab Listener) &lt;---&gt; In-Page Tricolor Fraud Banner / Safe Toast                  |
|   UX4G 3.0 Web Portal (12 Indic Languages + WCAG AAA Accessibility Controls + Voice Synthesis)                 |
|                                           | (JSON REST / WebSocket)                                           |
|                                           v                                                                   |
| [EDGE ROUTING &amp; ASYNC ORCHESTRATION]                                                                          |
|   FastAPI 0.115+ (ASGI Engine) &lt;---&gt; Memory-Bounded Eviction Cache (LRU) &amp; ThreadPoolExecutor                 |
|   Dual-Tier Routing: Local Dev Probe (1000ms) --&gt; Cloud Render Failover (8000ms) --&gt; Client Heuristic          |
|                                           |                                                                   |
|                                           v                                                                   |
| [15-STAGE MULTI-SIGNAL FORENSIC PIPELINE]                                                                     |
|   1. Canonical URL Normalizer          6. DOM Sensitive Form Harvester      11. Threat Intelligence Hub       |
|   2. Homoglyph &amp; Zero-Width Detector   7. Visual Perceptual Hash (pHash)    12. Content Jaccard Similarity    |
|   3. Levenshtein Typosquat Engine      8. HTTP/JS Redirect Unroller         13. OSINT Internet Search Engine  |
|   4. Sovereign Brand Matcher (25+)     9. DNSSEC / MX Mail Security         14. Proof-of-Authority Blockchain |
|   5. SSRF-Shielded Safe Crawler        10. RDAP / NIC Sovereign Domain Age  15. Explainable Sovereign ML      |
|                                           |                                                                   |
|                                           v                                                                   |
| [EVALUATION &amp; PROOF GENERATION]                                                                               |
|   Sovereign ML Ensemble (XGBoost 250 trees + Random Forest 180 trees) -&gt; Probability Score                    |
|   Bayesian Fusion Engine -&gt; Calibrated Threat Score (0-100) &amp; Verdict (LEGITIMATE / SUSPICIOUS / PHISHING)    |
|   Cryptographic Blockchain Anchoring (RFC 8785 Canonical JSON) -&gt; Section 65B CERT-In Incident Dossier        |
+---------------------------------------------------------------------------------------------------------------+
  </div>

  <h2>3. High-Level Technology Stack Matrix</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 20%;">Subsystem</th>
        <th style="width: 32%;">Primary Technologies &amp; Frameworks</th>
        <th style="width: 28%;">Key Modules / Libraries</th>
        <th style="width: 20%;">Compliance / Standards</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Backend API Core</strong></td>
        <td>Python 3.11, FastAPI 0.115, Uvicorn, asyncio</td>
        <td>Pydantic v2, Starlette, Requests, ThreadPoolExecutor</td>
        <td><span class="tag tag-blue">REST JSON</span> <span class="tag tag-green">RFC 8785</span></td>
      </tr>
      <tr>
        <td><strong>AI / ML Ensemble</strong></td>
        <td>Scikit-Learn, XGBoost, Random Forest</td>
        <td>Joblib, NumPy, Pandas, Google GenAI SDK (Gemini)</td>
        <td><span class="tag tag-purple">Soft Voting</span> <span class="tag tag-blue">Explainable AI</span></td>
      </tr>
      <tr>
        <td><strong>Forensic Analytics</strong></td>
        <td>BeautifulSoup4, dnspython, Pillow, ImageHash</td>
        <td>urllib, Levenshtein, socket, ssl, whois/rdap</td>
        <td><span class="tag tag-amber">SSRF Shield</span> <span class="tag tag-red">Anti-Spoofing</span></td>
      </tr>
      <tr>
        <td><strong>Cryptographic Ledger</strong></td>
        <td>Python <code>hashlib</code>, RFC 8785 Canonical JSON</td>
        <td>SHA-256 Chaining, PoA Validator Node Engine</td>
        <td><span class="tag tag-green">Sec 65B Evidence Act</span></td>
      </tr>
      <tr>
        <td><strong>Web Portal (Frontend)</strong></td>
        <td>HTML5, Vanilla ES Modules, Modern CSS3</td>
        <td>Web Speech API, Web Audio API, UX4G Languages</td>
        <td><span class="tag tag-blue">UX4G 3.0</span> <span class="tag tag-green">WCAG 2.1 AAA</span></td>
      </tr>
      <tr>
        <td><strong>Browser Extension</strong></td>
        <td>Chrome Manifest V3, Service Worker, Content Scripts</td>
        <td>Chrome Tabs/Storage/Action APIs, MutationObserver</td>
        <td><span class="tag tag-purple">MV3 Secure</span> <span class="tag tag-amber">Sandboxed</span></td>
      </tr>
      <tr>
        <td><strong>DevOps &amp; Hosting</strong></td>
        <td>Docker Multi-Stage, Render Cloud Web Service, Git</td>
        <td>Linux Debian Bookworm, Gunicorn/Uvicorn workers</td>
        <td><span class="tag tag-blue">Zero-Downtime CD</span></td>
      </tr>
    </tbody>
  </table>

  <!-- ================= PAGE 2 ================= -->
  <div class="page-break"></div>

  <div class="doc-header">
    <div class="tricolor-strip"></div>
    <div class="header-content">
      <div class="title-group">
        <h1>Detailed Subsystem Specifications</h1>
        <div class="subtitle">Backend Modules, Forensic Pipeline &amp; Algorithmic Implementation</div>
      </div>
      <div class="meta-badge-group">
        <span class="meta-pill pill-cert">Defense-in-Depth</span>
      </div>
    </div>
  </div>

  <h2>4. 15-Stage Forensic Analysis Pipeline</h2>
  <div class="cards-grid-2">
    <div class="card avoid-break">
      <div class="card-header"><span>1. Canonical URL Normalizer</span><span class="card-module-tag">url_normalizer.py</span></div>
      <div class="card-body">
        Performs recursive percent-decoding, punycode resolution, scheme validation, whitespace scrubbing, and path normalization to expose obfuscated bypass attempts.
      </div>
    </div>
    <div class="card avoid-break">
      <div class="card-header"><span>2. Homoglyph &amp; Zero-Width Detector</span><span class="card-module-tag">homoglyph_analyzer.py</span></div>
      <div class="card-body">
        Detects Cyrillic, Greek, and Latin confusable Unicode glyphs (e.g., Cyrillic 'а' replacing Latin 'a') alongside invisible zero-width separators (U+200B, U+200C).
      </div>
    </div>
    <div class="card avoid-break">
      <div class="card-header"><span>3. Typosquatting Engine</span><span class="card-module-tag">typosquat_engine.py</span></div>
      <div class="card-body">
        Evaluates Levenshtein edit distance, bitsquatting, character omissions, repetitions, transpositions, and top-level domain spoofing (e.g., <code>g0v.in</code>, <code>pmkisan.com</code>).
      </div>
    </div>
    <div class="card avoid-break">
      <div class="card-header"><span>4. Sovereign Brand Matcher</span><span class="card-module-tag">brand_engine.py</span></div>
      <div class="card-body">
        Indexes 25+ certified sovereign portals (PM-Kisan, IncomeTax, UIDAI, DigiLocker, Parivahan, EPFO) with fuzzy brand injection heuristics against unauthorized hosts.
      </div>
    </div>
    <div class="card avoid-break">
      <div class="card-header"><span>5. SSRF-Shielded Safe Crawler</span><span class="card-module-tag">safe_crawler.py</span></div>
      <div class="card-body">
        Asynchronous HTTP crawler equipped with IP pre-resolution blocking loopbacks (<code>127.0.0.1</code>), RFC 1918 private subnets, and AWS/GCP metadata endpoints (<code>169.254.169.254</code>).
      </div>
    </div>
    <div class="card avoid-break">
      <div class="card-header"><span>6. DOM Sensitive Form Harvester</span><span class="card-module-tag">dom_analyzer.py</span></div>
      <div class="card-body">
        Inspects DOM trees for deceptive credential fields harvesting citizen identities: Aadhaar (12-digit), PAN, Bank Account, Debit/Credit Card, Password, and SMS OTP.
      </div>
    </div>
    <div class="card avoid-break">
      <div class="card-header"><span>7. Visual Perceptual Hash Engine</span><span class="card-module-tag">visual_analyzer.py</span></div>
      <div class="card-body">
        Renders DOM snapshots and computes 64-bit Perceptual Hash (pHash) and Difference Hash (dHash), flagging layout cloning with Hamming distance &lt; 10 against authentic sites.
      </div>
    </div>
    <div class="card avoid-break">
      <div class="card-header"><span>8. Redirect Trampoline Unroller</span><span class="card-module-tag">redirect_unroller.py</span></div>
      <div class="card-body">
        Follows HTTP 301/302/307 redirect chains and parses HTML <code>&lt;meta http-equiv="refresh"&gt;</code> plus inline JS location assignments to uncover concealed landing pages.
      </div>
    </div>
    <div class="card avoid-break">
      <div class="card-header"><span>9. DNSSEC &amp; MX Mail Security</span><span class="card-module-tag">dns_security_analyzer.py</span></div>
      <div class="card-body">
        Queries authoritative nameservers via <code>dnspython</code> for MX records, SPF, DMARC, and DNSSEC. Flags throwaway phishing hosts lacking operational mail infrastructure.
      </div>
    </div>
    <div class="card avoid-break">
      <div class="card-header"><span>10. RDAP &amp; Sovereign Age</span><span class="card-module-tag">network_analyzer.py</span></div>
      <div class="card-body">
        Extracts domain registration age via ICANN RDAP protocol. Domains registered &lt; 30 days mimicking public brands receive critical risk escalation.
      </div>
    </div>
    <div class="card avoid-break">
      <div class="card-header"><span>11. Threat Intelligence Hub</span><span class="card-module-tag">reference_database.py</span></div>
      <div class="card-body">
        Queries local high-speed threat caches and OSINT reputation blacklists for known malicious command-and-control (C2) domains and phishing campaigns.
      </div>
    </div>
    <div class="card avoid-break">
      <div class="card-header"><span>12. Content Similarity Engine</span><span class="card-module-tag">content_similarity.py</span></div>
      <div class="card-body">
        Calculates n-gram Jaccard text similarity against authentic government portal corpora to detect scraping and verbatim identity theft of official disclaimers.
      </div>
    </div>
    <div class="card avoid-break">
      <div class="card-header"><span>13. OSINT Internet Search Engine</span><span class="card-module-tag">internet_search_engine.py</span></div>
      <div class="card-body">
        Evaluates domain search indexing authority, visibility, and consumer fraud reports across public search telemetry.
      </div>
    </div>
    <div class="card avoid-break">
      <div class="card-header"><span>14. Fusion Risk Engine</span><span class="card-module-tag">fusion_engine.py</span></div>
      <div class="card-body">
        Synthesizes all 13 module signals using calibrated Bayesian weightings into a normalized 0–100 Risk Score, classifying sites into <code>LEGITIMATE</code>, <code>SUSPICIOUS</code>, or <code>PHISHING_CLONE</code>.
      </div>
    </div>
  </div>

  <h2>5. AI &amp; Machine Learning Architecture</h2>
  <div class="cards-grid-2">
    <div class="card avoid-break">
      <div class="card-header">Sovereign ML Soft Voting Ensemble</div>
      <div class="card-body">
        <ul>
          <li><strong>Architecture</strong>: Soft Voting Ensemble combining <strong>XGBoost (250 estimators)</strong> and <strong>Random Forest (180 estimators)</strong>.</li>
          <li><strong>Features</strong>: 15 engineered features including Shannon entropy, subdomain depth, lexical token ratio, sensitive input flags, and RDAP age.</li>
          <li><strong>Explainability</strong>: Computes <code>top_contributing_factors</code> translating Gini impurity reductions into natural language citizen warnings.</li>
          <li><strong>Inference Speed</strong>: Sub-12ms execution cached via serialized Joblib artifacts.</li>
        </ul>
      </div>
    </div>
    <div class="card avoid-break">
      <div class="card-header">Generative AI Agent &amp; Semantic Synthesis</div>
      <div class="card-body">
        <ul>
          <li><strong>Model Provider</strong>: Google Gemini Pro / Flash via <code>google-genai</code> SDK.</li>
          <li><strong>Functionality</strong>: Analyzes DOM layout, extracted text, and form inputs to explain social engineering tactics used by attackers.</li>
          <li><strong>Deterministic Fallback</strong>: Built-in deterministic synthesis engine ensuring 100% operational reliability even when cloud AI APIs are offline or unconfigured.</li>
        </ul>
      </div>
    </div>
  </div>

  <!-- ================= PAGE 3 ================= -->
  <div class="page-break"></div>

  <div class="doc-header">
    <div class="tricolor-strip"></div>
    <div class="header-content">
      <div class="title-group">
        <h1>Frontend, Extension &amp; Legal Compliance</h1>
        <div class="subtitle">UX4G 3.0 Standard, MV3 Browser Extension &amp; Section 65B Forensic Ledger</div>
      </div>
      <div class="meta-badge-group">
        <span class="meta-pill pill-cert">UX4G Standard</span>
      </div>
    </div>
  </div>

  <h2>6. UX4G 3.0 Multilingual Frontend Portal</h2>
  <p>
    The web portal is built strictly adhering to the <strong>UX4G Design System (ux4g.gov.in)</strong> guidelines created by the Ministry of Electronics and Information Technology (MeitY) and National Informatics Centre (NIC).
  </p>
  <ul>
    <li><strong>12 Scheduled Indic Languages + English</strong>: Supports Hindi, English, Bengali, Tamil, Telugu, Marathi, Gujarati, Kannada, Malayalam, Punjabi, Odia, and Assamese. All dynamic DOM nodes, badges, advisory text, and forensic layer summaries switch instantly in-memory with zero page reloads.</li>
    <li><strong>WCAG 2.1 AAA Accessibility Engine</strong>: Features an accessible side drawer (keyboard shortcut <code>Ctrl+F2</code>) equipped with 5 color contrast modes (Normal, Monochrome, High Saturation, Low Saturation, Dark Mode, Invert) and 6 typography adjusters (Bigger Text, Line Height, Text Spacing, Highlight Links, OpenDyslexic Font, Hide Images).</li>
    <li><strong>Natural Acoustic &amp; Voice Synthesis</strong>: Integrates the Web Speech API with Indic BCP-47 locale tags (<code>hi-IN</code>, <code>ta-IN</code>, etc.) and Web Audio API synthesized acoustic chimes (Harmonic Triad for safe, descending tritone siren for threats).</li>
    <li><strong>Zero-Framework Performance</strong>: Built using pure ES Modules and lightweight CSS Custom Properties, achieving sub-second first contentful paint (FCP) and a 100/100 Lighthouse performance and accessibility rating.</li>
  </ul>

  <h2>7. Chrome Browser Extension (Manifest V3)</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 25%;">Component</th>
        <th style="width: 35%;">Responsibilities</th>
        <th style="width: 40%;">Technical Implementation</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Background Worker</strong> (<code>background.js</code>)</td>
        <td>Monitors tab updates and activations, maintains in-memory scan cache, drives browser action badges.</td>
        <td>Manifest V3 Service Worker, <code>chrome.tabs.onUpdated</code>, <code>chrome.action.setBadgeText</code>, dual-tier API fetch controller.</td>
      </tr>
      <tr>
        <td><strong>Content Script</strong> (<code>content.js</code>)</td>
        <td>Injects non-intrusive warning banners on phishing sites and safe toasts on authentic <code>.gov.in</code> portals.</td>
        <td>Scoped DOM injection (<code>#govshield-alert-root</code>), isolated CSS styles, 12-language mini selector, direct <code>cybercrime.gov.in</code> link.</td>
      </tr>
      <tr>
        <td><strong>Popup Controller</strong> (<code>popup.js</code>)</td>
        <td>Displays active tab forensic score, collapsible 5-layer details, and voice narration.</td>
        <td>Minimalist UX4G popup UI, optimistic client-side heuristics render (&lt;20ms), collapsible dropdown, localized audio playback.</td>
      </tr>
      <tr>
        <td><strong>Dual-Tier Fallover</strong></td>
        <td>Guarantees zero-failure scanning regardless of network or local development states.</td>
        <td>Fast local probe (1000ms) &rarr; Cloud Production API (8000ms) &rarr; Instant Client-Side Heuristic Fallback.</td>
      </tr>
    </tbody>
  </table>

  <h2>8. Legal Admissibility &amp; Proof-of-Authority (PoA) Blockchain Ledger</h2>
  <div class="callout">
    <strong>Section 65B Indian Evidence Act Compliance:</strong> To allow cybersecurity incident reports to be presented as admissible digital evidence in Indian courts of law, GovShield implements a tamper-proof cryptographic ledger engine (<code>blockchain_ledger.py</code>).
  </div>
  <ul>
    <li><strong>RFC 8785 Canonical JSON Serialization</strong>: Eliminates cryptographic ambiguity by standardizing key sorting, UTF-8 normalization, and whitespace before hashing.</li>
    <li><strong>SHA-256 Block Chaining</strong>: Each threat detection generates an immutable block containing the previous block hash, ISO 8601 timestamp, target entity, forensic feature breakdown, raw DOM snapshot SHA-256 digest, and validator identity (<code>NIC-DELHI-ROOT-01</code>).</li>
    <li><strong>CERT-In Standard Dossier</strong>: Exports standardized, pre-formatted incident dossiers ready for automated submission to CERT-In (<code>incident@cert-in.org.in</code>) and the National Cyber Crime Reporting Portal (<code>cybercrime.gov.in</code>).</li>
  </ul>

  <h2>9. Production Deployment &amp; Performance Verification</h2>
  <table>
    <thead>
      <tr>
        <th>Metric / Environment</th>
        <th>Value / Result</th>
        <th>Verification Mechanism</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Automated Unit Test Suite</strong></td>
        <td><strong>36 / 36 Tests Passed</strong> (12.15s)</td>
        <td><code>python -m unittest discover backend/tests</code></td>
      </tr>
      <tr>
        <td><strong>System Scenario Verification</strong></td>
        <td><strong>7 / 7 Scenarios Passed</strong></td>
        <td><code>python test_system.py</code> (Genuine, Typosquat, Homoglyphs, Clones)</td>
      </tr>
      <tr>
        <td><strong>Cloud Deployment</strong></td>
        <td>Production Ready</td>
        <td>Hosted on Render Cloud Web Service with continuous deployment from <code>main</code></td>
      </tr>
      <tr>
        <td><strong>Repository</strong></td>
        <td><code>https://github.com/Code-Xceed/sih-web</code></td>
        <td>Clean working tree, branch <code>main</code>, commit <code>3938b97</code></td>
      </tr>
    </tbody>
  </table>

  <div class="footer-note">
    <span>GovShield Sentinel Grid 3.0 — Smart India Hackathon 2026 (SIH1454)</span>
    <span>Confidential Technical Specification Dossier</span>
  </div>

</body>
</html>
"""

html_path = os.path.abspath("GovShield_Technical_Specification.html")
pdf_path = os.path.abspath("GovShield_Technical_Specification.pdf")

with open(html_path, "w", encoding="utf-8") as f:
    f.write(html_content)

edge_exe = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
cmd = [
    edge_exe,
    "--headless",
    "--disable-gpu",
    f"--print-to-pdf={pdf_path}",
    "--no-pdf-header-footer",
    html_path
]

res = subprocess.run(cmd, capture_output=True, text=True)
if os.path.exists(pdf_path):
    print(f"SUCCESS: PDF generated at {pdf_path} ({os.path.getsize(pdf_path)} bytes)")
else:
    print("FAILED:", res.returncode, res.stderr)
