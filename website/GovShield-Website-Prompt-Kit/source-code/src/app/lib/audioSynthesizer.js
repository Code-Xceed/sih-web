/**
 * Professional Web Audio Tone Synthesizer & Multilingual Indic Voice Engine
 * Supports 12 Indian Languages + English
 */

// Synthesize pleasant acoustic sound chimes
export function playAcousticAlert(type = 'safe') {
  try {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (!AudioContext) return;
    const ctx = new AudioContext();

    if (type === 'threat') {
      const now = ctx.currentTime;
      const osc1 = ctx.createOscillator();
      const gain1 = ctx.createGain();
      osc1.type = 'sawtooth';
      osc1.frequency.setValueAtTime(880, now);
      osc1.frequency.exponentialRampToValueAtTime(440, now + 0.15);
      gain1.gain.setValueAtTime(0.25, now);
      gain1.gain.exponentialRampToValueAtTime(0.01, now + 0.18);
      osc1.connect(gain1);
      gain1.connect(ctx.destination);
      osc1.start(now);
      osc1.stop(now + 0.18);

      const osc2 = ctx.createOscillator();
      const gain2 = ctx.createGain();
      osc2.type = 'sawtooth';
      osc2.frequency.setValueAtTime(987.77, now + 0.22);
      osc2.frequency.exponentialRampToValueAtTime(493.88, now + 0.4);
      gain2.gain.setValueAtTime(0.25, now + 0.22);
      gain2.gain.exponentialRampToValueAtTime(0.01, now + 0.42);
      osc2.connect(gain2);
      gain2.connect(ctx.destination);
      osc2.start(now + 0.22);
      osc2.stop(now + 0.42);
    } else if (type === 'caution') {
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(523.25, now);
      osc.frequency.setValueAtTime(440.00, now + 0.15);
      gain.gain.setValueAtTime(0.2, now);
      gain.gain.exponentialRampToValueAtTime(0.01, now + 0.35);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now);
      osc.stop(now + 0.35);
    } else {
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(587.33, now);
      osc.frequency.exponentialRampToValueAtTime(880.00, now + 0.12);
      gain.gain.setValueAtTime(0.18, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.5);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now);
      osc.stop(now + 0.5);
    }
  } catch (e) {
    console.debug("Audio synthesis skipped:", e);
  }
}

// Language to Voice Search Keywords & Fallbacks
const LANG_VOICE_MAP = {
  hi: ['hi', 'hindi', 'lekha', 'swara', 'madhur', 'हिन्दी'],
  bn: ['bn', 'bengali', 'bangla', 'বাংলা'],
  ta: ['ta', 'tamil', 'valluvar', 'தமிழ்'],
  te: ['te', 'telugu', 'మోహన్', 'తెలుగు'],
  mr: ['mr', 'marathi', 'मराठी'],
  gu: ['gu', 'gujarati', 'ગુજરાતી'],
  kn: ['kn', 'kannada', 'ಕನ್ನಡ'],
  ml: ['ml', 'malayalam', 'മലയാളം'],
  pa: ['pa', 'punjabi', 'ਪੰਜਾਬੀ'],
  or: ['or', 'odia', 'oriya', 'ଓଡ଼ିଆ'],
  as: ['as', 'assamese', 'অসমীয়া'],
  en: ['en-in', 'india', 'rishi', 'samantha', 'google', 'natural']
};

export function selectBestVoice(lang = 'hi') {
  if (!('speechSynthesis' in window)) return null;
  const voices = window.speechSynthesis.getVoices();
  if (!voices || voices.length === 0) return null;

  const keywords = LANG_VOICE_MAP[lang] || LANG_VOICE_MAP['hi'];

  // 1. Check for specific regional language voice match
  const matchedVoice = voices.find(v => {
    const vLang = v.lang.toLowerCase();
    const vName = v.name.toLowerCase();
    return keywords.some(k => vLang.includes(k) || vName.includes(k));
  });
  if (matchedVoice) return matchedVoice;

  // 2. Check for general Indian English / Hindi voice as high quality phonetic fallback
  const indianFallback = voices.find(v => 
    v.lang.includes('hi') || v.lang.includes('IN') || v.name.includes('India') || v.name.includes('Rishi')
  );
  if (indianFallback) return indianFallback;

  return voices[0] || null;
}
