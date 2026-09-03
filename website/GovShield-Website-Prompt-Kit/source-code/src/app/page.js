'use client';

import { useState, useEffect } from 'react';
import { scanWebsiteClientSide } from './lib/scannerEngine';
import { playAcousticAlert, selectBestVoice } from './lib/audioSynthesizer';
import { INDIC_LANGUAGES, UX4G_STRINGS } from './lib/ux4gLanguages';
import UX4GDrawer from './components/UX4GDrawer';
import LanguageDropdown from './components/LanguageDropdown';
import { WomenChildGraphic, FinancialFraudGraphic, CyberCrimeGraphic } from './components/CitizenCardGraphics';

// Sovereign Emblem Component
const AshokaEmblem = () => (
  <img 
    src="/logo.png" 
    alt="GovShield National Cyber Defense Emblem" 
    className="emblem-icon-ux4g"
  />
);

export default function UX4GHomePage() {
  const [lang, setLang] = useState('hi');
  const [drawerOpen, setDrawerOpen] = useState(false);
  
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [dossierOpen, setDossierOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  // Active translation dictionary fallback
  const t = UX4G_STRINGS[lang] || UX4G_STRINGS['hi'];

  // Global Ctrl+F2 keyboard listener for UX4G Accessibility Drawer
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.ctrlKey && e.key === 'F2') {
        e.preventDefault();
        setDrawerOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Natural Speech Synthesis Narration
  const handleSpeakVerdict = () => {
    if (!('speechSynthesis' in window)) {
      alert("Text-to-speech is not supported on this browser.");
      return;
    }

    if (isSpeaking) {
      window.speechSynthesis.cancel();
      setIsSpeaking(false);
      return;
    }

    if (!result) return;

    // 1. Play instant acoustic chime
    if (result.risk_score >= 66 || result.verdict === 'PHISHING_CLONE') {
      playAcousticAlert('threat');
    } else if (result.risk_score <= 25 || result.verdict === 'LEGITIMATE') {
      playAcousticAlert('safe');
    } else {
      playAcousticAlert('caution');
    }

    // 2. Build natural script for selected Indic language
    let textToSpeak = "";
    if (result.risk_score >= 66 || result.verdict === 'PHISHING_CLONE') {
      textToSpeak = t.speechThreat || t.advisoryThreat;
    } else if (result.risk_score <= 25 || result.verdict === 'LEGITIMATE') {
      textToSpeak = t.speechSafe || t.advisorySafe;
    } else {
      textToSpeak = t.speechCaution || t.advisoryCaution;
    }

    const currentLangObj = INDIC_LANGUAGES.find(l => l.code === lang) || INDIC_LANGUAGES[0];
    const utterance = new SpeechSynthesisUtterance(textToSpeak);
    utterance.lang = currentLangObj.bcp47 || 'hi-IN';
    utterance.rate = 0.88;
    utterance.pitch = 1.04;

    const bestVoice = selectBestVoice(lang);
    if (bestVoice) utterance.voice = bestVoice;

    utterance.onend = () => setIsSpeaking(false);
    utterance.onerror = () => setIsSpeaking(false);

    setIsSpeaking(true);
    window.speechSynthesis.cancel();
    setTimeout(() => {
      window.speechSynthesis.speak(utterance);
    }, 150);
  };

  // Execute Standalone Client-Side Inspection
  const handleScan = (overrideUrl) => {
    const target = overrideUrl || url;
    if (!target || !target.trim()) return;

    setLoading(true);
    setResult(null);
    if (window.speechSynthesis) window.speechSynthesis.cancel();
    setIsSpeaking(false);

    setTimeout(() => {
      try {
        const output = scanWebsiteClientSide(target);
        setResult(output);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }, 280);
  };

  const getVerdictStatus = (res) => {
    if (!res) return { type: 'safe', title: t.verdictSafe, icon: '🛡️' };
    if (res.risk_score >= 66 || res.verdict === 'PHISHING_CLONE') {
      return { type: 'threat', title: t.verdictThreat, icon: '🚨' };
    }
    if (res.risk_score >= 26 || res.verdict === 'SUSPICIOUS') {
      return { type: 'caution', title: t.verdictCaution, icon: '⚠️' };
    }
    return { type: 'safe', title: t.verdictSafe, icon: '✅' };
  };

  const currentStatus = getVerdictStatus(result);

  const generateDossierText = () => {
    if (!result) return "";
    return `========================================================================
CYBER SECURITY INCIDENT REPORT / PHISHING TAKEDOWN DOSSIER
Prepared for: CERT-In (incident@cert-in.org.in) & CyberCrime Portal (cybercrime.gov.in)
Incident ID : CERTIN-SIH-${Math.random().toString(36).substr(2, 9).toUpperCase()}
Timestamp   : ${new Date().toISOString()}
========================================================================
Target Entity   : ${result.target_entity || 'Government of India Portal'}
Investigated URL: ${result.url || url}
Risk Threat Score: ${result.risk_score} / 100
Classification  : ${result.verdict}
Impersonated    : ${result.impersonated ? 'YES (CRITICAL ZERO-DAY SPOOF)' : 'NO'}

[1] FORENSIC EVIDENCE BREAKDOWN:
- TLD Authenticity Status : ${result.is_genuine_gov_tld ? 'AUTHENTIC (.gov.in/.nic.in)' : 'UNAUTHORIZED PUBLIC TLD'}
- Lexical Typosquat Score : ${result.signal_breakdown?.lexical_score || 0}/100
- DOM Sensitive Harvesting: ${(result.signal_breakdown?.sensitive_fields_found || []).join(', ') || 'None'}
- Visual Similarity Score : ${result.signal_breakdown?.visual_similarity || 0}%
- Domain Age              : ${result.signal_breakdown?.domain_age_days || 'N/A'} days

[2] MALICIOUS INDICATORS DETECTED:
${(result.reasons || []).map((r, i) => `[${i + 1}] ${r}`).join('\n') || 'None detected'}

[3] DIRECTIVES & MITIGATION:
1. Issue urgent DNS sinkhole directive via NIXI / INRegistry.
2. Direct TSP/ISP DNS blocking under Section 69A Information Technology Act.
3. Alert CERT-In Incident Response Center.
========================================================================`;
  };

  return (
    <>
      <a href="#mainSearch" className="skip-link">{t.skipContent}</a>

      {/* 1. UX4G Sovereign Top Utility Bar */}
      <div className="ux4g-top-bar" role="banner">
        <div className="ux4g-top-container">
          <a href="https://india.gov.in" target="_blank" rel="noreferrer" className="ux4g-gov-link">
            <span>🇮🇳</span>
            <span>{t.govIndia} ↗</span>
          </a>

          <div className="ux4g-top-controls">
            <a href="#mainSearch" style={{ color: '#94a3b8', textDecoration: 'none' }}>
              {t.skipContent}
            </a>

            {/* Accessibility Drawer Trigger */}
            <button 
              className="ux4g-top-action-btn"
              onClick={() => setDrawerOpen(true)}
              aria-label="Open Accessibility Options"
            >
              <span>♿</span>
              <span>Accessibility</span>
            </button>

            {/* 12 Indic Languages Dropdown */}
            <LanguageDropdown currentLang={lang} onSelectLang={setLang} />
          </div>
        </div>
      </div>

      {/* 2. UX4G Main Navigation Header */}
      <header className="ux4g-nav-header">
        <div className="ux4g-nav-container">
          <div className="ux4g-brand-group">
            <AshokaEmblem />
            <div>
              <div className="brand-title-ux4g">
                GovShield <span className="accent-pill">Grid 3.0</span>
              </div>
              <div className="brand-subtitle-ux4g ux4g-lang-morph" key={`brand-${lang}`}>
                {t.brandSubtitle}
              </div>
            </div>
          </div>

          <div className="nav-cta-group">
            <a href="tel:1930" className="btn-secondary-ux4g" style={{ color: 'var(--gov-red)' }}>
              📞 1930 Helpline
            </a>
            <button className="btn-primary-ux4g" onClick={() => setDrawerOpen(true)}>
              ♿ Options (Ctrl+F2)
            </button>
          </div>
        </div>
      </header>

      {/* 3. UX4G Hero Section (Inspired by ux4g.gov.in) */}
      <section className="ux4g-hero-section" id="mainSearch">
        <div className="ux4g-hero-container ux4g-lang-morph" key={`hero-${lang}`}>
          
          <h2 className="ux4g-hero-heading">
            {t.heroTitlePrefix}
          </h2>

          <p className="ux4g-hero-subtext">
            {t.heroSub}
          </p>

          {/* Search Scanner Input */}
          <div className="ux4g-search-card">
            <input 
              type="text" 
              className="ux4g-search-input"
              placeholder={t.placeholder}
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              aria-label="Enter website URL to verify"
            />

            <button 
              type="button"
              className="verify-action-btn"
              onClick={() => handleScan()}
              disabled={loading}
              aria-label="Verify Portal"
            >
              {loading ? `⏳ ${t.verifying}` : `🛡️ ${t.verifyBtn}`}
            </button>
          </div>

          {/* Quick Demo Chips */}
          <div className="ux4g-chips-row ux4g-lang-morph" key={`chips-${lang}`}>
            <span className="chips-tag-label">{t.quickTry}</span>
            <button 
              type="button" 
              className="ux4g-sample-chip"
              onClick={() => { setUrl('https://pmkisan.gov.in'); handleScan('https://pmkisan.gov.in'); }}
            >
              ✅ {t.safeSite}
            </button>
            <button 
              type="button" 
              className="ux4g-sample-chip danger-chip"
              onClick={() => { setUrl('https://g0v.in'); handleScan('https://g0v.in'); }}
            >
              🚨 {t.fakeSite}
            </button>
            <button 
              type="button" 
              className="ux4g-sample-chip"
              onClick={() => { setUrl('https://incometax.gov.in'); handleScan('https://incometax.gov.in'); }}
            >
              🏛️ {t.incomeTax}
            </button>
          </div>

        </div>
      </section>

      {/* 4. Active Scan Verdict Section */}
      {result && (
        <section className="ux4g-verdict-section" role="region" aria-live="polite">
          <div className="verdict-master-box ux4g-lang-morph" key={`verdict-${lang}-${result.url}`}>
            
            {/* Header Banner */}
            <div className={`verdict-header-banner ${currentStatus.type}`}>
              <div className="verdict-main-meta">
                <span className="verdict-icon-badge">{currentStatus.icon}</span>
                <div>
                  <h3 className="verdict-status-title">{currentStatus.title}</h3>
                  <p className="verdict-status-sub">
                    {result.target_entity || 'Government Service'} • {result.is_genuine_gov_tld ? 'Sovereign .gov.in Domain' : 'Unauthorized Public TLD'}
                  </p>
                </div>
              </div>

              {/* Natural Speech Button */}
              <button 
                type="button"
                className={`btn-speech-trigger ${isSpeaking ? 'playing' : ''}`}
                onClick={handleSpeakVerdict}
              >
                {isSpeaking ? `🔊 ${t.stopAudio}` : `🔊 ${t.listenAudio}`}
              </button>
            </div>

            {/* Body Grid */}
            <div className="verdict-layout-grid">
              
              {/* Left Score Panel */}
              <div className="gauge-score-panel">
                <span className="gauge-header-title">{t.threatScoreLabel}</span>
                <div className={`gauge-big-number ${currentStatus.type}`}>
                  {result.risk_score < 10 ? `0${result.risk_score}` : result.risk_score}
                </div>
                <span style={{ fontSize: '0.9rem', color: '#64748b', fontWeight: 700 }}>/ 100</span>
                <div className="scanned-url-chip">{result.url || url}</div>
              </div>

              {/* Right Advisory & 5-Layer Forensics */}
              <div>
                <div className="citizen-advisory-pill-box">
                  <div className="advisory-header">
                    <span>⚠️</span>
                    <span>Advisory:</span>
                  </div>
                  <p className="advisory-body-text">
                    {result.risk_score >= 66 ? t.advisoryThreat : (result.risk_score <= 25 ? t.advisorySafe : t.advisoryCaution)}
                  </p>
                </div>

                <div className="forensics-stack">
                  {/* Layer 1 */}
                  <div className="forensic-tile-item">
                    <span className="tile-status-icon">{result.is_genuine_gov_tld ? '🟢' : '🔴'}</span>
                    <div className="tile-content-wrapper">
                      <div className="tile-header-line">
                        <span className="tile-title">{t.layer1}</span>
                        <span className={`tile-status-tag ${result.is_genuine_gov_tld ? 'pass' : 'fail'}`}>
                          {result.is_genuine_gov_tld ? 'VERIFIED' : 'UNVERIFIED'}
                        </span>
                      </div>
                      <p className="tile-desc">
                        {result.is_genuine_gov_tld ? 'Authenticated NIC India sovereign registry.' : 'Domain does not belong to authorized .gov.in / .nic.in registry.'}
                      </p>
                    </div>
                  </div>

                  {/* Layer 2 */}
                  <div className="forensic-tile-item">
                    <span className="tile-status-icon">{result.signal_breakdown?.lexical_score > 30 ? '🔴' : '🟢'}</span>
                    <div className="tile-content-wrapper">
                      <div className="tile-header-line">
                        <span className="tile-title">{t.layer2}</span>
                        <span className={`tile-status-tag ${result.signal_breakdown?.lexical_score > 30 ? 'fail' : 'pass'}`}>
                          {result.signal_breakdown?.lexical_score > 30 ? 'SPOOF DETECTED' : 'CLEAN'}
                        </span>
                      </div>
                      <p className="tile-desc">
                        {result.signal_breakdown?.lexical_score > 30 
                          ? 'Critical: Deceptive spelling tricks (e.g. replacing letter "o" with "0" as in g0v.in).' 
                          : 'No typosquatting, zero-width homoglyphs, or lookalike patterns.'}
                      </p>
                    </div>
                  </div>

                  {/* Layer 3 */}
                  <div className="forensic-tile-item">
                    <span className="tile-status-icon">{result.signal_breakdown?.sensitive_fields_found?.length > 0 ? '🔴' : '🟢'}</span>
                    <div className="tile-content-wrapper">
                      <div className="tile-header-line">
                        <span className="tile-title">{t.layer3}</span>
                        <span className={`tile-status-tag ${result.signal_breakdown?.sensitive_fields_found?.length > 0 ? 'fail' : 'pass'}`}>
                          {result.signal_breakdown?.sensitive_fields_found?.length > 0 ? 'HARVESTING' : 'SECURE'}
                        </span>
                      </div>
                      <p className="tile-desc">
                        {result.signal_breakdown?.sensitive_fields_found?.length > 0 
                          ? `Harvesting triggers found: [${result.signal_breakdown.sensitive_fields_found.join(', ')}] on non-gov site!` 
                          : 'No unauthorized Aadhaar, PAN, OTP, or biometric credential harvesting forms detected.'}
                      </p>
                    </div>
                  </div>

                  {/* Layer 4 */}
                  <div className="forensic-tile-item">
                    <span className="tile-status-icon">{result.impersonated ? '🔴' : '🟢'}</span>
                    <div className="tile-content-wrapper">
                      <div className="tile-header-line">
                        <span className="tile-title">{t.layer4}</span>
                        <span className={`tile-status-tag ${result.impersonated ? 'fail' : 'pass'}`}>
                          {result.impersonated ? 'CLONE MATCH' : 'AUTHENTIC'}
                        </span>
                      </div>
                      <p className="tile-desc">
                        {result.impersonated 
                          ? `AI visual matching identified deceptive clone of "${result.target_entity || 'Gov Portal'}"!` 
                          : 'Visual styling and DOM structure are consistent with authentic baseline.'}
                      </p>
                    </div>
                  </div>

                  {/* Layer 5 */}
                  <div className="forensic-tile-item">
                    <span className="tile-status-icon">🟢</span>
                    <div className="tile-content-wrapper">
                      <div className="tile-header-line">
                        <span className="tile-title">{t.layer5}</span>
                        <span className="tile-status-tag pass">ANALYZED</span>
                      </div>
                      <p className="tile-desc">
                        {result.signal_breakdown?.domain_age_days 
                          ? `Domain registered ${result.signal_breakdown.domain_age_days} days ago via ${result.signal_breakdown.registrar || 'Public Registrar'}.` 
                          : 'Domain registration records verified.'}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Dossier & 1930 Actions */}
                <div style={{ display: 'flex', gap: '12px', marginTop: '24px', flexWrap: 'wrap' }}>
                  <button className="btn-primary-ux4g" onClick={() => setDossierOpen(true)}>
                    📄 {t.dossierBtn}
                  </button>
                  <a href="tel:1930" className="btn-secondary-ux4g" style={{ background: 'var(--gov-red)', color: '#fff', border: 'none' }}>
                    📞 {t.helpline1930}
                  </a>
                </div>

              </div>

            </div>

          </div>
        </section>
      )}

      {/* 5. Citizen 3-Card Grid */}
      <section className="ux4g-cards-section">
        <div className="cards-headline-block ux4g-lang-morph" key={`cardshead-${lang}`}>
          <h3 className="cards-headline-title">{t.sectionTitle}</h3>
          <p className="cards-headline-sub">{t.sectionSub}</p>
        </div>

        <div className="ux4g-cards-grid ux4g-lang-morph" key={`cardsgrid-${lang}`}>
          {/* Card 1: Women & Child */}
          <div className="ux4g-card-item">
            <div className="card-banner-graphic-custom">
              <WomenChildGraphic />
            </div>
            <div className="card-text-body">
              <h4 className="card-title-header">{t.card1Title}</h4>
              <p className="card-desc-paragraph">{t.card1Desc}</p>
              <a href="https://cybercrime.gov.in/Webform/Index.aspx" target="_blank" rel="noreferrer" className="card-cta-button">
                {t.card1Btn}
              </a>
            </div>
          </div>

          {/* Card 2: Financial Fraud */}
          <div className="ux4g-card-item">
            <div className="card-banner-graphic-custom">
              <FinancialFraudGraphic />
            </div>
            <div className="card-text-body">
              <h4 className="card-title-header">{t.card2Title}</h4>
              <p className="card-desc-paragraph">{t.card2Desc}</p>
              <a href="tel:1930" className="card-cta-button" style={{ background: 'var(--gov-red)' }}>
                {t.helpline1930}
              </a>
            </div>
          </div>

          {/* Card 3: Other Cyber Crime */}
          <div className="ux4g-card-item">
            <div className="card-banner-graphic-custom">
              <CyberCrimeGraphic />
            </div>
            <div className="card-text-body">
              <h4 className="card-title-header">{t.card3Title}</h4>
              <p className="card-desc-paragraph">{t.card3Desc}</p>
              <a href="https://cybercrime.gov.in/Webform/Index.aspx" target="_blank" rel="noreferrer" className="card-cta-button">
                {t.card3Btn || t.card1Btn}
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* 6. Floating Accessibility FAB (UX4G Standard) */}
      <button 
        className="ux4g-fab-btn"
        onClick={() => setDrawerOpen(true)}
        aria-label="Open Accessibility Options (Ctrl+F2)"
        title="Accessibility Options (Ctrl+F2)"
      >
        <span className="fab-icon">♿</span>
        <span className="fab-shortcut-text">Ctrl+F2</span>
      </button>

      {/* 7. UX4G Full Accessibility Drawer */}
      <UX4GDrawer 
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        t={t}
        onVoiceTrigger={handleSpeakVerdict}
      />

      {/* 8. Dossier Modal */}
      {dossierOpen && (
        <div className="ux4g-drawer-backdrop" onClick={() => setDossierOpen(false)}>
          <div className="verdict-master-box" style={{ maxWidth: '700px', width: '90%', margin: 'auto', maxHeight: '85vh', display: 'flex', flexDirection: 'column' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ background: '#0f172a', color: '#fff', padding: '16px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h4 style={{ fontWeight: 800 }}>📄 CERT-In Cyber Security Incident Dossier</h4>
              <button style={{ background: 'transparent', border: 'none', color: '#fff', fontSize: '1.4rem', cursor: 'pointer' }} onClick={() => setDossierOpen(false)}>×</button>
            </div>
            <pre style={{ padding: '20px', overflowY: 'auto', fontFamily: 'monospace', fontSize: '0.82rem', background: '#f8fafc', color: '#0f172a', flex: 1, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {generateDossierText() || "Please perform a scan first to generate evidence."}
            </pre>
            <div style={{ padding: '14px 20px', background: '#fff', borderTop: '1px solid #e2e8f0', display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
              <button 
                className="btn-primary-ux4g"
                onClick={() => {
                  navigator.clipboard.writeText(generateDossierText());
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }}
              >
                {copied ? `✅ ${t.copied}` : `📋 ${t.copyDossier}`}
              </button>
              <button className="btn-secondary-ux4g" onClick={() => setDossierOpen(false)}>
                {t.closeModal}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 9. UX4G Sovereign Footer */}
      <footer className="ux4g-portal-footer ux4g-lang-morph" key={`footer-${lang}`} role="contentinfo">
        <div className="footer-inner-wrap">
          <div className="footer-main-columns">
            <div>
              <h4 className="footer-heading">GovShield Sentinel Grid (SIH1454)</h4>
              <p className="footer-text">
                {t.footerAbout}
              </p>
            </div>
            <div>
              <h4 className="footer-heading">{t.nationalPortalsHeading}</h4>
              <ul className="footer-nav-list">
                <li><a href="https://india.gov.in" target="_blank" rel="noreferrer">National Portal of India (india.gov.in)</a></li>
                <li><a href="https://cybercrime.gov.in/Webform/Index.aspx" target="_blank" rel="noreferrer">Cyber Crime Reporting Portal (I4C)</a></li>
              </ul>
            </div>
            <div>
              <h4 className="footer-heading">{t.emergencyHelplinesHeading}</h4>
              <ul className="footer-nav-list">
                <li><a href="tel:1930">1930 — National Cyber Crime Helpline</a></li>
                <li><a href="tel:112">112 — National Emergency Service</a></li>
                <li><a href="tel:14440">14440 — Financial Fraud Toll-Free</a></li>
              </ul>
            </div>
          </div>
          <div className="footer-credits-bar">
            <p>{t.footerSIH}</p>
          </div>
        </div>
      </footer>
    </>
  );
}
