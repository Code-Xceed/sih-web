"use client";
import { useState, useEffect } from 'react';
import SpatialBackground from '../components/SpatialBackground';

export default function Home() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  // Parallax background mouse tracking
  useEffect(() => {
    const handleMouseMove = (e) => {
      const x = (e.clientX / window.innerWidth - 0.5) * 2; // Range -1 to 1
      const y = (e.clientY / window.innerHeight - 0.5) * 2;
      document.body.style.setProperty('--mouse-x', x);
      document.body.style.setProperty('--mouse-y', y);
    };
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  const handleScan = async () => {
    if (!url) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch("http://localhost:8000/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      const data = await res.json();
      setResult(data);
    } catch (err) {
      console.error(err);
      alert("Backend API is unreachable.");
    } finally {
      setLoading(false);
    }
  };

  const getVerdictClass = (score) => {
    if (score >= 70) return 'badge-threat';
    if (score >= 35) return 'badge-caution';
    return 'badge-safe';
  };

  return (
    <>
      <SpatialBackground />
      <div className="app-container">


      <div className="main-center-wrapper">
        {/* Hero Typographic Section */}
        <section className="hero-minimal">
          <h1 className="hero-title-large">
            <span style={{ color: 'var(--color-threat)' }}>Fake</span> Government<br/>Portal Detector.
          </h1>
          <p className="hero-tagline">
            Algorithmic 6-layer scanner identifying typosquatting, subdomain masquerading, and fraudulent clones targeting Indian citizens.
          </p>
        </section>

        {/* URL Scanner Core */}
        <main className="scanner-section">
        {/* Search Box */}
        <div className="search-box-minimal">
          <input 
            type="url" 
            id="urlInput" 
            className="url-input-clean" 
            placeholder="Enter website URL (e.g., https://pmkisan-gov-in-update.online)" 
            autoComplete="off"
            spellCheck="false"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleScan()}
          />
          <button id="scanBtn" className="btn-scan-action" onClick={handleScan} disabled={loading}>
            <span>{loading ? "Scanning..." : "Inspect"}</span> {loading ? "" : "↵"}
          </button>
        </div>

        {/* Dynamic Result Card */}
        {result && (
          <div id="resultsWrapper">
            <div className="verdict-card-minimal">
              
              {/* Verdict Header */}
              <div className="verdict-header-block">
                <div className="verdict-number-row">
                  <div className="giant-score" id="scoreNumber" style={{
                    color: result.risk_score >= 70 ? 'var(--color-threat)' : result.risk_score >= 35 ? 'var(--color-caution)' : 'var(--color-safe)'
                  }}>
                    {result.risk_score < 10 ? `0${result.risk_score}` : result.risk_score}
                  </div>
                  <div className="verdict-text-group">
                    <span id="verdictBadge" className={`verdict-badge-clean ${getVerdictClass(result.risk_score)}`}>
                      {result.verdict}
                    </span>
                    <div className="target-url-line" id="urlHeadline">{result.target_url}</div>
                    <p className="verdict-summary-line" id="verdictSummary">
                      Node.js heuristic engine completed full scan of target URL.
                    </p>
                  </div>
                </div>
                <div className="verdict-actions">
                  <button id="btnQuickDossier" className="btn-dossier-pill" onClick={() => alert("Dossier generation is mock-implemented.")}>
                    <span>📄</span> Copy Incident Report
                  </button>
                </div>
              </div>

              {/* Inspection Steps Mockup */}
              <div className="inspection-steps-grid" id="inspectionSteps">
                <div className="step-card">
                  <div className="step-number">01</div>
                  <div className="step-content">
                    <div className="step-header">
                      <span className="step-title">Domain Lexical Analysis</span>
                      <span className="step-status" style={{color: 'var(--color-safe)'}}>[PASS]</span>
                    </div>
                    <p className="step-desc">Checked for typosquatting & homoglyphs against government TLDs.</p>
                  </div>
                </div>

                <div className="step-card">
                  <div className="step-number">02</div>
                  <div className="step-content">
                    <div className="step-header">
                      <span className="step-title">Screenshot Telemetry</span>
                      <span className="step-status" style={{color: 'var(--color-safe)'}}>[PASS]</span>
                    </div>
                    {result.screenshot_id ? (
                      <p className="step-desc" style={{marginTop: "5px"}}>
                        <a href={result.screenshot_id} target="_blank" rel="noreferrer" style={{color: '#999', textDecoration: 'underline'}}>View Captured Screenshot</a>
                      </p>
                    ) : (
                      <p className="step-desc">Failed to capture screenshot.</p>
                    )}
                  </div>
                </div>
              </div>

              {/* Citizen Advisory */}
              <div className="advisory-footer">
                <span style={{fontWeight: 700, color: 'var(--text-pure)'}}>ADVISORY: </span>
                <span id="remediationText" style={{flex: 1}}>
                  {result.risk_score >= 70 ? "DO NOT ENTER PERSONAL DETAILS. Report immediately." : "Appears to be a safe, legitimate domain."}
                </span>
              </div>
            </div>
          </div>
        )}
      </main>
      </div>
    </div>
    </>
  );
}
