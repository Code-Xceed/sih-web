'use client';

import { useState, useEffect } from 'react';

export default function UX4GDrawer({ 
  isOpen, 
  onClose, 
  t, 
  onVoiceTrigger 
}) {
  // Accessibility state
  const [colorMode, setColorMode] = useState('normal'); // 'normal', 'monochrome', 'highSaturate', 'lowSaturate', 'darkMode', 'invert'
  const [biggerText, setBiggerText] = useState(false);
  const [lineHeight, setLineHeight] = useState(false);
  const [textSpacing, setTextSpacing] = useState(false);
  const [highlightLinks, setHighlightLinks] = useState(false);
  const [dyslexiaFont, setDyslexiaFont] = useState(false);
  const [hideImages, setHideImages] = useState(false);

  // Apply classes to document root and body
  useEffect(() => {
    const root = document.documentElement;
    const body = document.body;
    
    // Reset filters
    root.classList.remove('ux4g-monochrome', 'ux4g-high-saturate', 'ux4g-low-saturate', 'ux4g-dark-mode', 'ux4g-invert');
    body.classList.remove('ux4g-monochrome', 'ux4g-high-saturate', 'ux4g-low-saturate', 'ux4g-dark-mode', 'ux4g-invert');
    
    if (colorMode === 'monochrome') { root.classList.add('ux4g-monochrome'); body.classList.add('ux4g-monochrome'); }
    if (colorMode === 'highSaturate') { root.classList.add('ux4g-high-saturate'); body.classList.add('ux4g-high-saturate'); }
    if (colorMode === 'lowSaturate') { root.classList.add('ux4g-low-saturate'); body.classList.add('ux4g-low-saturate'); }
    if (colorMode === 'darkMode') { root.classList.add('ux4g-dark-mode'); body.classList.add('ux4g-dark-mode'); }
    if (colorMode === 'invert') { root.classList.add('ux4g-invert'); body.classList.add('ux4g-invert'); }

    // Content adjustments applied to root & body
    [
      { active: biggerText, name: 'ux4g-bigger-text' },
      { active: lineHeight, name: 'ux4g-line-height' },
      { active: textSpacing, name: 'ux4g-text-spacing' },
      { active: highlightLinks, name: 'ux4g-highlight-links' },
      { active: dyslexiaFont, name: 'ux4g-dyslexia' },
      { active: hideImages, name: 'ux4g-hide-images' },
    ].forEach(({ active, name }) => {
      if (active) {
        root.classList.add(name);
        body.classList.add(name);
      } else {
        root.classList.remove(name);
        body.classList.remove(name);
      }
    });
  }, [colorMode, biggerText, lineHeight, textSpacing, highlightLinks, dyslexiaFont, hideImages]);

  const handleReset = () => {
    setColorMode('normal');
    setBiggerText(false);
    setLineHeight(false);
    setTextSpacing(false);
    setHighlightLinks(false);
    setDyslexiaFont(false);
    setHideImages(false);
  };

  if (!isOpen) return null;

  return (
    <div className="ux4g-drawer-backdrop" onClick={onClose}>
      <div className="ux4g-drawer-panel" onClick={(e) => e.stopPropagation()}>
        {/* Header Bar */}
        <div className="ux4g-drawer-header">
          <div className="ux4g-header-title">
            <span>♿</span>
            <span>{t.a11yTitle || "Accessibility Options by UX4G"}</span>
          </div>
          <button className="ux4g-close-btn" onClick={onClose} aria-label="Close Drawer">✕</button>
        </div>

        {/* Scrollable Content */}
        <div className="ux4g-drawer-scroll">
          
          {/* Section 1: Color & Contrast Adjustment */}
          <div className="ux4g-section-group">
            <h4 className="ux4g-section-title">{t.colorAdjust || "Color & Contrast"}</h4>
            <div className="ux4g-tiles-grid cols-3">
              
              <button 
                className={`ux4g-tile-btn ${colorMode === 'monochrome' ? 'active' : ''}`}
                onClick={() => setColorMode(colorMode === 'monochrome' ? 'normal' : 'monochrome')}
              >
                <span className="tile-icon">💧</span>
                <span className="tile-label">{t.monochrome || "Monochrome"}</span>
              </button>

              <button 
                className={`ux4g-tile-btn ${colorMode === 'highSaturate' ? 'active' : ''}`}
                onClick={() => setColorMode(colorMode === 'highSaturate' ? 'normal' : 'highSaturate')}
              >
                <span className="tile-icon">🌓</span>
                <span className="tile-label">{t.highSaturate || "High Saturate"}</span>
              </button>

              <button 
                className={`ux4g-tile-btn ${colorMode === 'lowSaturate' ? 'active' : ''}`}
                onClick={() => setColorMode(colorMode === 'lowSaturate' ? 'normal' : 'lowSaturate')}
              >
                <span className="tile-icon">💧</span>
                <span className="tile-label">{t.lowSaturate || "Low Saturate"}</span>
              </button>

              <button 
                className={`ux4g-tile-btn ${colorMode === 'darkMode' ? 'active' : ''}`}
                onClick={() => setColorMode(colorMode === 'darkMode' ? 'normal' : 'darkMode')}
              >
                <span className="tile-icon">🌙</span>
                <span className="tile-label">{t.darkMode || "Dark Mode"}</span>
              </button>

              <button 
                className={`ux4g-tile-btn ${colorMode === 'invert' ? 'active' : ''}`}
                onClick={() => setColorMode(colorMode === 'invert' ? 'normal' : 'invert')}
              >
                <span className="tile-icon">◩</span>
                <span className="tile-label">{t.invertColors || "Invert Colors"}</span>
              </button>

            </div>
          </div>

          {/* Section 2: Content Adjustment */}
          <div className="ux4g-section-group">
            <h4 className="ux4g-section-title">{t.contentAdjust || "Content Adjustment"}</h4>
            <div className="ux4g-tiles-grid cols-3">
              
              <button 
                className={`ux4g-tile-btn ${biggerText ? 'active' : ''}`}
                onClick={() => setBiggerText(!biggerText)}
              >
                <span className="tile-icon">A+</span>
                <span className="tile-label">{t.biggerText || "Bigger Text"}</span>
              </button>

              <button 
                className={`ux4g-tile-btn ${lineHeight ? 'active' : ''}`}
                onClick={() => setLineHeight(!lineHeight)}
              >
                <span className="tile-icon">⇕</span>
                <span className="tile-label">{t.lineHeight || "Line Height"}</span>
              </button>

              <button 
                className={`ux4g-tile-btn ${textSpacing ? 'active' : ''}`}
                onClick={() => setTextSpacing(!textSpacing)}
              >
                <span className="tile-icon">A↔A</span>
                <span className="tile-label">{t.textSpacing || "Text Spacing"}</span>
              </button>

              <button 
                className={`ux4g-tile-btn ${highlightLinks ? 'active' : ''}`}
                onClick={() => setHighlightLinks(!highlightLinks)}
              >
                <span className="tile-icon">🔗</span>
                <span className="tile-label">{t.highlightLinks || "Highlight Links"}</span>
              </button>

              <button 
                className={`ux4g-tile-btn ${dyslexiaFont ? 'active' : ''}`}
                onClick={() => setDyslexiaFont(!dyslexiaFont)}
              >
                <span className="tile-icon">Df</span>
                <span className="tile-label">{t.dyslexiaFont || "Dyslexia Friendly"}</span>
              </button>

              <button 
                className={`ux4g-tile-btn ${hideImages ? 'active' : ''}`}
                onClick={() => setHideImages(!hideImages)}
              >
                <span className="tile-icon">🚫🖼️</span>
                <span className="tile-label">{t.hideImages || "Hide Images"}</span>
              </button>

            </div>
          </div>

        </div>

        {/* Footer Bar with Reset */}
        <div className="ux4g-drawer-footer" style={{ justifyContent: 'center' }}>
          <button className="ux4g-reset-btn" onClick={handleReset} style={{ width: '100%', justifyContent: 'center' }}>
            <span>🔄</span>
            <span>{t.resetAll || "Reset"}</span>
          </button>
        </div>

      </div>
    </div>
  );
}
