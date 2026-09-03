# GovShield Sentinel (SIH 2026) — Complete Frontend & UI Master Prompt

Copy and paste the exact prompt below into any new Antigravity session (along with attaching `logo.png` and the preview screenshots in this folder) to recreate the 100% exact website frontend.

---

```markdown
You are an expert Frontend Architect specializing in Government Design Systems (UX4G 3.0), Next.js 14/15 App Router, and WCAG 2.1 AAA Accessibility.

Build the complete, production-ready frontend for **GovShield Sentinel Grid 3.0** (Smart India Hackathon 2026 — Problem Statement SIH1454: National Multi-Signal Phishing, Typosquatting & Fake Government Website Detection System).

### 🏛️ Visual Design System & Brand Identity:
1. **Design System**: Strict alignment with **UX4G Design System 3.0** (`ux4g.gov.in`) and Government of India web standards.
2. **Colors**:
   - Primary: `#5c3cf6` (UX4G Purple/Indigo), Hover: `#4a2ae0`
   - National Saffron: `#ff9933` / `#e35d16`, National Green: `#138808` / `#00875a`
   - Danger/Threat: `#de350b` / `#be123c`, Caution/Suspicious: `#f59e0b` / `#d97706`
   - Background Canvas: `#f8fafc`, Card Surface: `#ffffff`, Border: `#e2e8f0`
   - Dark Mode: Canvas `#090d16`, Card `#182234`, Border `#2d3748`, Text `#f8fafc`
3. **Typography**: Google Fonts `Inter`, `Noto Sans Devanagari`, `JetBrains Mono`.
4. **Logo & Emblem**: Scaled official sovereign emblem (`58px × 72px`) featuring the Ashoka Lion Capital merged with the Cyber Shield Chakra symbol (`/logo.png`).

---

### 📦 Key Features & Component Hierarchy:

#### 1. Tricolor Top Bar & Language Selector
- Top bar with subtle Indian tricolor gradient stripe (`#ff9933 33.3%`, `#ffffff 33.3% 66.6%`, `#138808 66.6%`).
- Left: `🇮🇳 भारत सरकार | Government of India` and a functional "Skip to main content" link (`#mainSearch`).
- Right: Quick accessibility trigger (`♿ Accessibility`) and a **12-Language Dropdown** supporting:
  - **Hindi (`hi`)**, **English (`en`)**, **Bengali (`bn`)**, **Tamil (`ta`)**, **Telugu (`te`)**, **Marathi (`mr`)**, **Gujarati (`gu`)**, **Kannada (`kn`)**, **Malayalam (`ml`)**, **Punjabi (`pa`)**, **Odia (`or`)**, **Assamese (`as`)**.
  - Smooth morph animation (`ux4gMorphFade`) across all UI text whenever the language is switched.

#### 2. Primary Navigation Header
- Scaled official logo (`/logo.png`), Brand title: `GovShield` with `Grid 3.0` pill badge (`#eff2ff` / `#5c3cf6`) and dynamically translated subtitle ("National Multi-Signal Phishing & Fake Portal Detection System").
- Right action CTAs: `📞 1930 Helpline` (red accent) and `♿ Options (Ctrl+F2)` (primary purple).

#### 3. Hero Scanner Section
- Subtle 28px dot grid background pattern (`radial-gradient`).
- Bold, single-line headline (`Verify Any Government Portal Instantly.` / `किसी भी सरकारी वेबसाइट की तुरंत जांच करें।`) + subtext.
- Elevated search card with URL input field and `🛡️ Verify Portal` button (full-width 48px touch targets on mobile).
- Quick Test Sample Chips:
  - `✅ Safe Portal (PM-Kisan)` (`https://pmkisan.gov.in`)
  - `🚨 Fake Typosquat (g0v.in)` (`https://g0v.in`)
  - `🏛️ IncomeTax (Authentic)` (`https://incometax.gov.in`)

#### 4. Master Verdict & 5-Layer Forensic Results
When a URL is scanned (using client-side heuristic engine), display:
- **Verdict Header Banner**:
  - Safe (`#00875a`), Threat/Fake Clone (`#de350b`), Caution (`#f59e0b`).
  - Large Risk Score (`0-100`), status badge (`VERIFIED AUTHENTIC` / `CRITICAL THREAT: FAKE CLONE`), and `🔊 Listen Audio` voice narration button with acoustic alert chimes.
- **Citizen Advisory Callout**: Clear instructions (e.g. *"DANGER! This website is a deceptive clone imitating government services. NEVER enter your Aadhaar, Bank Details, PAN, or OTP here!"*).
- **5-Layer Forensic Breakdown**:
  1. Sovereign TLD Authentication (`.gov.in / .nic.in`)
  2. Typosquatting & Spelling Traps Check (`Levenshtein distance`)
  3. Identity & Credential Theft Forms (Aadhaar, PAN, Bank, OTP input field detection)
  4. AI Visual Lookalike Detection (94% lookalike clone confidence)
  5. Domain Age & Registry Verification (WHOIS age & NIC validation)
- **Action Buttons**: `📋 CERT-In Dossier` (opens full legal markdown takedown dossier modal with copy button) and `📞 Call Helpline 1930`.

#### 5. Citizen Cyber Defense Services (3-Card Grid)
Custom high-contrast vector illustrations inspired by official `cybercrime.gov.in`:
- **Card 1: Women & Child Cyber Safety** (Confidential reporting CTA -> `https://cybercrime.gov.in`)
- **Card 2: Financial Cyber Fraud Defense** (Instant 1930 Helpline CTA -> `tel:1930`)
- **Card 3: Other Cyber Crime** (Hooded hacker & terminal vector illustration, incident reporting CTA -> `https://cybercrime.gov.in`)
- Full dynamic translation across all 12 Indian languages.

#### 6. UX4G Full Accessibility Drawer (`♿ Ctrl+F2`)
Slide-in side drawer featuring:
- **Color & Contrast (5 Tiles)**: `Monochrome`, `High Saturate`, `Low Saturate`, `Dark Mode`, `Invert Colors`.
- **Content Adjustment (6 Tiles)**:
  - `A+ Bigger Text` (scales root HTML `rem` by +25% and deep element typography).
  - `⇕ Line Height` (line-height: 2).
  - `A↔A Text Spacing` (letter-spacing: 0.08em).
  - `🔗 Highlight Links` (yellow underline + bold).
  - `Df Dyslexia Friendly` (Comic Sans MS / Dyslexia font).
  - `🚫🖼️ Hide Images` (opacity: 0.05).
- **Full-Width Reset Button**: Restores all styles to default.

#### 7. Mobile & Vertical Device Responsiveness
- Fully responsive across 320px - 768px portrait devices (Android / iOS).
- Touch-friendly 48px tap targets, fluid `clamp()` font sizes, single-column card stacking, and full-width mobile drawer.

#### 8. Sovereign Footer
- GovShield Sentinel info, National Portals (`india.gov.in`, `cybercrime.gov.in`), Emergency helplines (`1930`, `112`, `14440`), and SIH 2026 credits bar.

---

### 💻 Code Deliverables:
1. `src/app/layout.js`: Viewport metadata, fonts, theme color.
2. `src/app/page.js`: Homepage component with state, scanner engine, audio synthesizer, and cards.
3. `src/app/globals.css`: Full CSS styling with UX4G variables, a11y overrides, morph animations, and responsive media queries.
4. `src/app/components/CitizenCardGraphics.js`: Clean custom SVG illustrations for the 3 citizen cards.
5. `src/app/components/UX4GDrawer.js`: Accessibility drawer component.
6. `src/app/components/LanguageDropdown.js`: 12-language picker component.
7. `src/app/lib/ux4gLanguages.js`: Complete 12-language dictionary.
8. `src/app/lib/scannerEngine.js`: Client-side heuristic multi-signal detection engine.
```
