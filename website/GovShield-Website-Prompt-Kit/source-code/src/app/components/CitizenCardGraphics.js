'use client';

// Graphic 1: Women & Child Cyber Safety Illustration (Matching cybercrime.gov.in)
export const WomenChildGraphic = () => (
  <svg viewBox="0 0 400 200" fill="none" xmlns="http://www.w3.org/2000/svg" className="card-custom-svg" aria-label="Women and Child Cyber Safety Illustration">
    <defs>
      <linearGradient id="bgGrad1" x1="0" y1="0" x2="400" y2="200" gradientUnits="userSpaceOnUse">
        <stop stopColor="#ff7675" />
        <stop offset="1" stopColor="#d63031" />
      </linearGradient>
      <linearGradient id="shieldGrad1" x1="0" y1="0" x2="0" y2="140" gradientUnits="userSpaceOnUse">
        <stop stopColor="#ffffff" stopOpacity="0.95" />
        <stop offset="1" stopColor="#ffeaa7" stopOpacity="0.9" />
      </linearGradient>
      <filter id="shadow1" x="-10" y="-10" width="420" height="220">
        <feDropShadow dx="0" dy="6" stdDeviation="8" floodColor="#000000" floodOpacity="0.2" />
      </filter>
    </defs>
    
    {/* Background */}
    <rect width="400" height="200" fill="url(#bgGrad1)" />
    
    {/* Decorative Rings */}
    <circle cx="200" cy="100" r="140" stroke="#ffffff" strokeOpacity="0.1" strokeWidth="2" strokeDasharray="6 6" />
    <circle cx="200" cy="100" r="90" stroke="#ffffff" strokeOpacity="0.15" strokeWidth="2" />

    {/* Center Protective Shield */}
    <g filter="url(#shadow1)">
      <path d="M200 20 L260 50 C260 125 200 165 200 165 C200 165 140 125 140 50 Z" fill="url(#shieldGrad1)" stroke="#ffffff" strokeWidth="4" />
      <path d="M200 32 L248 56 C248 116 200 150 200 150 C200 150 152 116 152 56 Z" fill="#fff5f5" />
    </g>

    {/* Mother & Child Silhouette inside Shield */}
    <circle cx="188" cy="74" r="13" fill="#d63031" />
    <path d="M168 120 C168 98 208 98 208 120 Z" fill="#d63031" />
    <circle cx="214" cy="85" r="9" fill="#e17055" />
    <path d="M198 122 C198 106 230 106 230 122 Z" fill="#e17055" />

    {/* Left Side: Stop Hand Badge */}
    <g transform="translate(35, 55)" filter="url(#shadow1)">
      <rect width="90" height="90" rx="45" fill="#ffffff" />
      <circle cx="45" cy="45" r="38" fill="#ff7675" />
      <rect x="41" y="26" width="9" height="26" rx="4" fill="#ffffff" />
      <rect x="30" y="32" width="9" height="20" rx="4" fill="#ffffff" />
      <rect x="52" y="30" width="9" height="22" rx="4" fill="#ffffff" />
      <path d="M27 48 C27 62 38 70 45 70 C52 70 63 62 63 48 L63 40 L27 40 Z" fill="#ffffff" />
    </g>

    {/* Right Side: Security Lock Badge */}
    <g transform="translate(275, 55)" filter="url(#shadow1)">
      <rect width="90" height="90" rx="45" fill="#ffffff" />
      <circle cx="45" cy="45" r="38" fill="#2d3436" />
      <rect x="30" y="44" width="30" height="24" rx="4" fill="#ffeaa7" />
      <path d="M37 44 V34 C37 28 53 28 53 34 V44" stroke="#ffeaa7" strokeWidth="5" strokeLinecap="round" fill="none" />
      <circle cx="45" cy="54" r="3" fill="#2d3436" />
    </g>
  </svg>
);

// Graphic 2: Financial Fraud & 1930 Helpline Illustration (Matching cybercrime.gov.in)
export const FinancialFraudGraphic = () => (
  <svg viewBox="0 0 400 200" fill="none" xmlns="http://www.w3.org/2000/svg" className="card-custom-svg" aria-label="Financial Cyber Fraud and 1930 Helpline Illustration">
    <defs>
      <linearGradient id="bgGrad2" x1="0" y1="0" x2="400" y2="200" gradientUnits="userSpaceOnUse">
        <stop stopColor="#0984e3" />
        <stop offset="1" stopColor="#00cec9" />
      </linearGradient>
      <linearGradient id="cardGrad" x1="0" y1="0" x2="160" y2="100" gradientUnits="userSpaceOnUse">
        <stop stopColor="#2d3436" />
        <stop offset="1" stopColor="#636e72" />
      </linearGradient>
      <filter id="shadow2" x="-10" y="-10" width="420" height="220">
        <feDropShadow dx="0" dy="6" stdDeviation="8" floodColor="#000000" floodOpacity="0.25" />
      </filter>
    </defs>

    {/* Background */}
    <rect width="400" height="200" fill="url(#bgGrad2)" />

    {/* Decorative Grid Lines */}
    <circle cx="200" cy="100" r="140" stroke="#ffffff" strokeOpacity="0.1" strokeWidth="2" strokeDasharray="6 6" />
    <circle cx="200" cy="100" r="90" stroke="#ffffff" strokeOpacity="0.15" strokeWidth="2" />

    {/* Center-Left: Bank Card with Phishing Alert */}
    <g transform="translate(35, 45)" filter="url(#shadow2)">
      <rect width="160" height="100" rx="12" fill="url(#cardGrad)" stroke="#ffffff" strokeWidth="2.5" />
      {/* EMV Chip */}
      <rect x="20" y="26" width="24" height="20" rx="4" fill="#fdcb6e" />
      <line x1="20" y1="36" x2="44" y2="36" stroke="#b2bec3" strokeWidth="1.5" />
      {/* Contactless waves */}
      <path d="M52 28 C57 33 57 39 52 44" stroke="#ffffff" strokeWidth="2.5" strokeLinecap="round" fill="none" opacity="0.85" />
      {/* Card Number Dots */}
      <circle cx="26" cy="68" r="3.5" fill="#ffffff" opacity="0.9" />
      <circle cx="36" cy="68" r="3.5" fill="#ffffff" opacity="0.9" />
      <circle cx="46" cy="68" r="3.5" fill="#ffffff" opacity="0.9" />
      <circle cx="56" cy="68" r="3.5" fill="#ffffff" opacity="0.9" />
      <circle cx="74" cy="68" r="3.5" fill="#ffffff" opacity="0.9" />
      <circle cx="84" cy="68" r="3.5" fill="#ffffff" opacity="0.9" />
      <circle cx="94" cy="68" r="3.5" fill="#ffffff" opacity="0.9" />
      <circle cx="104" cy="68" r="3.5" fill="#ffffff" opacity="0.9" />
      {/* RuPay / Visa logo mockup */}
      <circle cx="128" cy="78" r="11" fill="#eb4d4b" opacity="0.9" />
      <circle cx="140" cy="78" r="11" fill="#f0932b" opacity="0.9" />
      
      {/* Warning Alert Badge on Card */}
      <g transform="translate(118, -10)">
        <polygon points="18,0 36,32 0,32" fill="#e74c3c" stroke="#ffffff" strokeWidth="2.5" />
        <text x="18" y="27" textAnchor="middle" fill="#ffffff" fontSize="18" fontWeight="900">!</text>
      </g>
    </g>

    {/* Center-Right: 1930 Emergency Phone Shield */}
    <g transform="translate(225, 35)" filter="url(#shadow2)">
      <rect width="140" height="120" rx="16" fill="#ffffff" stroke="#00cec9" strokeWidth="3.5" />
      {/* Phone Icon in red circle */}
      <circle cx="70" cy="42" r="24" fill="#d63031" />
      <text x="70" y="51" textAnchor="middle" fill="#ffffff" fontSize="22">📞</text>
      {/* 1930 Big Bold Text */}
      <text x="70" y="86" textAnchor="middle" fill="#0984e3" fontSize="24" fontWeight="900" fontFamily="sans-serif">
        1930
      </text>
      <text x="70" y="104" textAnchor="middle" fill="#2d3436" fontSize="10" fontWeight="900" letterSpacing="0.8">
        24x7 HELPLINE
      </text>
    </g>
  </svg>
);

// Graphic 3: Other Cyber Crime Illustration (True to cybercrime.gov.in)
export const CyberCrimeGraphic = () => (
  <svg viewBox="0 0 400 200" fill="none" xmlns="http://www.w3.org/2000/svg" className="card-custom-svg" aria-label="Other Cyber Crime Illustration">
    <defs>
      <linearGradient id="bgGrad3" x1="0" y1="0" x2="400" y2="200" gradientUnits="userSpaceOnUse">
        <stop stopColor="#6c5ce7" />
        <stop offset="1" stopColor="#4834d4" />
      </linearGradient>
      <filter id="shadow3" x="-10" y="-10" width="420" height="220">
        <feDropShadow dx="0" dy="6" stdDeviation="8" floodColor="#000000" floodOpacity="0.3" />
      </filter>
    </defs>

    {/* Background */}
    <rect width="400" height="200" fill="url(#bgGrad3)" />

    {/* Network Cyber Lines */}
    <circle cx="200" cy="100" r="140" stroke="#ffffff" strokeOpacity="0.1" strokeWidth="2" strokeDasharray="6 6" />
    <circle cx="200" cy="100" r="90" stroke="#ffffff" strokeOpacity="0.15" strokeWidth="2" />
    <line x1="80" y1="60" x2="200" y2="100" stroke="#ffffff" strokeOpacity="0.2" strokeWidth="2" strokeDasharray="4 4" />
    <line x1="320" y1="60" x2="200" y2="100" stroke="#ffffff" strokeOpacity="0.2" strokeWidth="2" strokeDasharray="4 4" />
    <line x1="80" y1="140" x2="200" y2="100" stroke="#ffffff" strokeOpacity="0.2" strokeWidth="2" strokeDasharray="4 4" />
    <line x1="320" y1="140" x2="200" y2="100" stroke="#ffffff" strokeOpacity="0.2" strokeWidth="2" strokeDasharray="4 4" />

    {/* Center: Cyber Hacker Silhouette with Laptop */}
    <g transform="translate(145, 30)" filter="url(#shadow3)">
      {/* Hacker Hood */}
      <path d="M55 25 C30 25 22 55 20 85 C32 85 78 85 90 85 C88 55 80 25 55 25 Z" fill="#1e272e" stroke="#00d2d3" strokeWidth="2" />
      {/* Hacker Face / Glasses Glow */}
      <ellipse cx="55" cy="55" rx="16" ry="10" fill="#0f172a" />
      <rect x="42" y="52" width="10" height="6" rx="2" fill="#00d2d3" />
      <rect x="58" y="52" width="10" height="6" rx="2" fill="#00d2d3" />
      
      {/* Laptop Base & Screen */}
      <rect x="15" y="85" width="80" height="42" rx="4" fill="#2f3640" stroke="#ffffff" strokeWidth="1.5" />
      <rect x="22" y="90" width="66" height="28" rx="2" fill="#000000" />
      {/* Skull / Terminal prompt on laptop */}
      <circle cx="55" cy="100" r="5" fill="#ff4757" />
      <rect x="52" y="105" width="6" height="3" rx="1" fill="#ff4757" />
      <line x1="30" y1="96" x2="42" y2="96" stroke="#00d2d3" strokeWidth="1.5" strokeLinecap="round" />
      <line x1="30" y1="102" x2="38" y2="102" stroke="#00d2d3" strokeWidth="1.5" strokeLinecap="round" />
      <line x1="68" y1="96" x2="80" y2="96" stroke="#00d2d3" strokeWidth="1.5" strokeLinecap="round" />
      <line x1="72" y1="102" x2="80" y2="102" stroke="#00d2d3" strokeWidth="1.5" strokeLinecap="round" />
      {/* Laptop bottom bar */}
      <path d="M5 127 L105 127 L95 133 L15 133 Z" fill="#718093" />
    </g>

    {/* Top Left: Settings Gear & Network */}
    <g transform="translate(45, 30)" filter="url(#shadow3)">
      <circle cx="30" cy="30" r="26" fill="#ffffff" />
      <circle cx="30" cy="30" r="18" fill="#4834d4" />
      <text x="30" y="38" textAnchor="middle" fill="#ffffff" fontSize="18">⚙️</text>
    </g>

    {/* Top Right: Compromised Alert Triangle */}
    <g transform="translate(295, 30)" filter="url(#shadow3)">
      <circle cx="30" cy="30" r="26" fill="#ffffff" />
      <polygon points="30,12 48,44 12,44" fill="#fbc531" stroke="#2f3640" strokeWidth="2" />
      <text x="30" y="40" textAnchor="middle" fill="#2f3640" fontSize="16" fontWeight="900">!</text>
    </g>

    {/* Bottom Left: Unlocked Security Padlock */}
    <g transform="translate(45, 115)" filter="url(#shadow3)">
      <circle cx="30" cy="30" r="26" fill="#ffffff" />
      <rect x="18" y="30" width="24" height="18" rx="3" fill="#38ada9" />
      {/* Open shackle */}
      <path d="M22 30 V22 C22 17 34 17 34 22" stroke="#38ada9" strokeWidth="4" strokeLinecap="round" fill="none" />
      <circle cx="30" cy="39" r="2" fill="#ffffff" />
    </g>

    {/* Bottom Right: Compromised Cloud / User ID */}
    <g transform="translate(295, 115)" filter="url(#shadow3)">
      <circle cx="30" cy="30" r="26" fill="#ffffff" />
      <rect x="16" y="20" width="28" height="22" rx="4" fill="#0984e3" />
      <circle cx="30" cy="28" r="4" fill="#ffffff" />
      <path d="M22 40 C22 35 38 35 38 40 Z" fill="#ffffff" />
      <circle cx="40" cy="20" r="7" fill="#e84118" />
      <text x="40" y="24" textAnchor="middle" fill="#ffffff" fontSize="9" fontWeight="900">🔒</text>
    </g>
  </svg>
);
