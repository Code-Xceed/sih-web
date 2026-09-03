'use client';

import { useState, useRef, useEffect } from 'react';
import { INDIC_LANGUAGES } from '../lib/ux4gLanguages';

export default function LanguageDropdown({ currentLang, onSelectLang }) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef(null);

  const activeLangObj = INDIC_LANGUAGES.find(l => l.code === currentLang) || INDIC_LANGUAGES[0];

  useEffect(() => {
    function handleClickOutside(e) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div className="ux4g-lang-wrapper" ref={dropdownRef}>
      <button 
        className="ux4g-top-action-btn lang-select-trigger"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        aria-label="Select Language"
      >
        <span>🌐</span>
        <span className="lang-trigger-text">{activeLangObj.name}</span>
        <span className="dropdown-arrow-icon">▾</span>
      </button>

      {isOpen && (
        <div className="ux4g-lang-menu">
          <div className="lang-menu-header">
            <span className="lang-menu-title">Select Language</span>
            <span className="lang-count-badge">12 Languages</span>
          </div>
          <div className="lang-menu-list">
            {INDIC_LANGUAGES.map((item) => (
              <button
                key={item.code}
                className={`lang-option-item ${currentLang === item.code ? 'selected' : ''}`}
                onClick={() => {
                  onSelectLang(item.code);
                  setIsOpen(false);
                }}
              >
                <span className="lang-native-script">{item.name}</span>
                <span className="lang-english-label">{item.englishName}</span>
              </button>
            ))}
          </div>
          <div className="lang-menu-footer">
            <span>Powered by Bhashini & UX4G</span>
          </div>
        </div>
      )}
    </div>
  );
}
