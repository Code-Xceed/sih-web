/**
 * GovShield Sentinel Grid 3.0
 * Professional Web Audio Tone Synthesizer & Multilingual Indic Voice Engine
 * Supports 12 Scheduled Indian Languages + English
 */

// Cache browser voices dynamically
let cachedVoices = [];

function refreshVoices() {
  if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
    const list = window.speechSynthesis.getVoices();
    if (list && list.length > 0) {
      cachedVoices = list;
    }
  }
}

if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
  refreshVoices();
  window.speechSynthesis.onvoiceschanged = refreshVoices;
  // Poll in intervals to catch asynchronous online voices (Edge Natural / Chrome voices)
  setTimeout(refreshVoices, 300);
  setTimeout(refreshVoices, 1000);
  setTimeout(refreshVoices, 2500);
}

/**
 * Synthesize elegant acoustic sound chimes using Web Audio API
 * Returns a Promise that resolves when the chime completes, so speech begins cleanly!
 */
export function playAcousticAlert(type = 'safe') {
  return new Promise((resolve) => {
    try {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (!AudioContext) return resolve();
      const ctx = new AudioContext();
      const now = ctx.currentTime;

      if (type === 'threat') {
        // Authoritative clean double-pulse alert (587Hz -> 440Hz -> 370Hz sine wave)
        // Pulse 1: D5 (587Hz) to A4 (440Hz)
        const osc1 = ctx.createOscillator();
        const gain1 = ctx.createGain();
        osc1.type = 'sine';
        osc1.frequency.setValueAtTime(587.33, now);
        osc1.frequency.exponentialRampToValueAtTime(440.00, now + 0.12);
        gain1.gain.setValueAtTime(0.15, now);
        gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.14);
        osc1.connect(gain1);
        gain1.connect(ctx.destination);
        osc1.start(now);
        osc1.stop(now + 0.14);

        // Pulse 2: D5 (587Hz) to F#4 (370Hz)
        const osc2 = ctx.createOscillator();
        const gain2 = ctx.createGain();
        osc2.type = 'sine';
        osc2.frequency.setValueAtTime(587.33, now + 0.16);
        osc2.frequency.exponentialRampToValueAtTime(369.99, now + 0.32);
        gain2.gain.setValueAtTime(0.16, now + 0.16);
        gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
        osc2.connect(gain2);
        gain2.connect(ctx.destination);
        osc2.start(now + 0.16);
        osc2.stop(now + 0.35);

        setTimeout(resolve, 380);
      } else if (type === 'caution') {
        // Gentle mellow two-tone (A4 440Hz -> F4 349Hz triangle wave)
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(440.00, now);
        osc.frequency.setValueAtTime(349.23, now + 0.12);
        gain.gain.setValueAtTime(0.12, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.28);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(now);
        osc.stop(now + 0.28);

        setTimeout(resolve, 300);
      } else {
        // Crystalline uplifting major-third chime (C5 523Hz -> G5 784Hz sine wave)
        const osc1 = ctx.createOscillator();
        const gain1 = ctx.createGain();
        osc1.type = 'sine';
        osc1.frequency.setValueAtTime(523.25, now);
        gain1.gain.setValueAtTime(0.10, now);
        gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.14);
        osc1.connect(gain1);
        gain1.connect(ctx.destination);
        osc1.start(now);
        osc1.stop(now + 0.14);

        const osc2 = ctx.createOscillator();
        const gain2 = ctx.createGain();
        osc2.type = 'sine';
        osc2.frequency.setValueAtTime(783.99, now + 0.10);
        gain2.gain.setValueAtTime(0.12, now + 0.10);
        gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.32);
        osc2.connect(gain2);
        gain2.connect(ctx.destination);
        osc2.start(now + 0.10);
        osc2.stop(now + 0.32);

        setTimeout(resolve, 340);
      }
    } catch (e) {
      console.debug("Audio synthesis skipped:", e);
      resolve();
    }
  });
}

/// Target voice profile configurations for all 12 Indian Languages
const LANG_PROFILES = {
  hi: { prefix: 'hi', bcp47: 'hi-IN', names: ['swara', 'madhur', 'kalpana', 'hemant', 'hindi', 'lekha', 'हिन्दी'] },
  en: { prefix: 'en', bcp47: 'en-IN', names: ['neerja', 'prabhat', 'rishi', 'sangeeta', 'heera', 'ravi', 'zira', 'david', 'george'] },
  bn: { prefix: 'bn', bcp47: 'bn-IN', names: ['bashkar', 'tanishaa', 'bengali', 'bangla', 'বাংলা'] },
  ta: { prefix: 'ta', bcp47: 'ta-IN', names: ['valluvar', 'pallavi', 'tamil', 'தமிழ்'] },
  te: { prefix: 'te', bcp47: 'te-IN', names: ['mohan', 'shruti', 'telugu', 'తెలుగు'] },
  mr: { prefix: 'mr', bcp47: 'mr-IN', names: ['manohar', 'aarohi', 'marathi', 'मराठी'] },
  gu: { prefix: 'gu', bcp47: 'gu-IN', names: ['niranjan', 'dhwani', 'gujarati', 'ગુજરાતી'] },
  kn: { prefix: 'kn', bcp47: 'kn-IN', names: ['gagan', 'sapna', 'kannada', 'ಕನ್ನಡ'] },
  ml: { prefix: 'ml', bcp47: 'ml-IN', names: ['midhun', 'sobhana', 'malayalam', 'മലയാളം'] },
  pa: { prefix: 'pa', bcp47: 'pa-IN', names: ['raavi', 'gurmukhi', 'punjabi', 'ਪੰਜਾਬੀ'] },
  or: { prefix: 'or', bcp47: 'or-IN', names: ['odia', 'oriya', 'ଓଡ଼ିଆ'] },
  as: { prefix: 'as', bcp47: 'as-IN', names: ['assamese', 'অসমীয়া'] }
};

/**
 * Intelligent Voice Selection & Compatibility Routing
 * Returns { voice, langTag, isNative }
 * - If a native voice exists for the target Indic language, it matches and selects it!
 * - If the client OS does not have a native voice for that language installed (e.g. Odia/Assamese),
 *   it gracefully selects a high quality Indian Hindi/English voice and flags isNative: false.
 */
export function selectBestVoice(lang = 'hi') {
  if (typeof window === 'undefined' || !('speechSynthesis' in window)) {
    return { voice: null, langTag: 'en-IN', isNative: false };
  }

  // Get current voices (or from cache)
  let voices = window.speechSynthesis.getVoices();
  if (!voices || voices.length === 0) voices = cachedVoices;
  if (!voices || voices.length === 0) {
    return { voice: null, langTag: LANG_PROFILES[lang]?.bcp47 || 'hi-IN', isNative: false };
  }

  const profile = LANG_PROFILES[lang] || LANG_PROFILES['hi'];

  // 1. Search for Exact Native Regional Voice (where language code matches)
  const langMatchVoices = voices.filter(v => {
    const vLang = (v.lang || '').toLowerCase().replace('_', '-');
    return vLang === profile.prefix || vLang.startsWith(profile.prefix + '-');
  });

  if (langMatchVoices.length > 0) {
    // Prefer Natural / Online / Neural / Google high-fidelity voices
    const bestMatch = langMatchVoices.find(v => {
      const n = (v.name || '').toLowerCase();
      return n.includes('natural') || n.includes('online') || n.includes('google') || n.includes('neural');
    }) || langMatchVoices[0];

    return {
      voice: bestMatch,
      langTag: bestMatch.lang || profile.bcp47,
      isNative: true
    };
  }

  // 2. Search by unique name keywords for the language
  const nameMatchVoices = voices.filter(v => {
    const vName = (v.name || '').toLowerCase();
    return profile.names.some(n => vName.includes(n));
  });

  if (nameMatchVoices.length > 0) {
    const bestName = nameMatchVoices[0];
    return {
      voice: bestName,
      langTag: bestName.lang || profile.bcp47,
      isNative: true
    };
  }

  // 3. If NO regional voice is installed on client system:
  // Route to Indian English or Indian Hindi voice (which can pronounce Indian words accurately)
  const indianVoices = voices.filter(v => {
    const vLang = (v.lang || '').toLowerCase();
    const vName = (v.name || '').toLowerCase();
    return vLang.includes('hi') || vLang.includes('en-in') || vName.includes('india') || vName.includes('rishi') || vName.includes('neerja') || vName.includes('swara') || vName.includes('madhur');
  });

  if (indianVoices.length > 0) {
    const bestIndian = indianVoices.find(v => {
      const n = (v.name || '').toLowerCase();
      return n.includes('natural') || n.includes('online') || n.includes('google');
    }) || indianVoices[0];

    return {
      voice: bestIndian,
      langTag: bestIndian.lang || 'en-IN',
      isNative: false
    };
  }

  // 4. Fallback to system default
  return {
    voice: voices[0] || null,
    langTag: voices[0]?.lang || 'en-US',
    isNative: false
  };
}
