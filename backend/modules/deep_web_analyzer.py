"""
GovShield Sentinel Grid — Deep Web Analyzer
Performs comprehensive local forensic analysis of crawled web pages:
  1. HTTP Security Headers Audit (CSP, HSTS, X-Frame-Options, etc.)
  2. Page Metadata & Content Intelligence (title, meta, OG, Twitter Cards)
  3. Link Topology Analysis (internal vs external, suspicious outbound)
  4. Technology Stack Fingerprinting (server, CMS, frameworks, CDN)
  5. Tracker & Analytics Script Detection
  6. Cookie Security Audit

All analysis runs locally — no external API calls required.
"""

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Tracker Signatures (regex patterns matched against script src + inline JS)
# ---------------------------------------------------------------------------
TRACKER_SIGNATURES = {
    "Google Analytics": {
        "pattern": r"(google-analytics\.com/(analytics|ga)\.js|googletagmanager\.com/gtag/js\?id=G-|gtag\(\s*['\"]config['\"])",
        "category": "Analytics"
    },
    "Google Tag Manager": {
        "pattern": r"googletagmanager\.com/gtm\.js\?id=GTM-",
        "category": "Tag Manager"
    },
    "Meta (Facebook) Pixel": {
        "pattern": r"(connect\.facebook\.net/[a-zA-Z_]+/fbevents\.js|fbq\(\s*['\"]init['\"])",
        "category": "Advertising"
    },
    "Hotjar": {
        "pattern": r"static\.hotjar\.com/c/hotjar-",
        "category": "Session Replay"
    },
    "Microsoft Clarity": {
        "pattern": r"www\.clarity\.ms/tag/",
        "category": "Session Replay"
    },
    "Mixpanel": {
        "pattern": r"cdn\.mxpnl\.com/libs/mixpanel",
        "category": "Product Analytics"
    },
    "Segment": {
        "pattern": r"cdn\.segment\.com/analytics\.js",
        "category": "Customer Data Platform"
    },
    "TikTok Pixel": {
        "pattern": r"analytics\.tiktok\.com/i18n/pixel/",
        "category": "Advertising"
    },
    "Yandex Metrica": {
        "pattern": r"mc\.yandex\.ru/metrika/",
        "category": "Analytics"
    },
    "Amplitude": {
        "pattern": r"cdn\.amplitude\.com/libs/",
        "category": "Product Analytics"
    },
    "Criteo": {
        "pattern": r"static\.criteo\.net/js/",
        "category": "Advertising"
    },
    "LinkedIn Insight": {
        "pattern": r"snap\.licdn\.com/li\.lms-analytics/",
        "category": "Advertising"
    },
    "Pinterest Tag": {
        "pattern": r"s\.pinimg\.com/ct/core\.js",
        "category": "Advertising"
    },
    "Heap Analytics": {
        "pattern": r"cdn\.heapanalytics\.com/js/heap-",
        "category": "Product Analytics"
    },
    "Intercom": {
        "pattern": r"widget\.intercom\.io/widget/",
        "category": "Customer Support"
    },
    "Drift": {
        "pattern": r"js\.driftt\.com/include/",
        "category": "Customer Support"
    },
    "Crypto Miner (CoinHive/CoinIMP)": {
        "pattern": r"(coinhive\.min\.js|coin-hive\.com/lib|authedmine\.com|crypto-loot\.com|coinimp\.com/scripts|minero\.cc)",
        "category": "Cryptocurrency Miner"
    },
}

# ---------------------------------------------------------------------------
# Technology Fingerprint Patterns
# ---------------------------------------------------------------------------
CMS_SIGNATURES = {
    "WordPress": [r"/wp-content/", r"/wp-includes/", r'name=["\']generator["\']\s+content=["\']WordPress'],
    "Joomla": [r"/media/jui/", r"/administrator/", r'content=["\']Joomla'],
    "Drupal": [r"/sites/default/files/", r"/misc/drupal\.js", r'content=["\']Drupal'],
    "Shopify": [r"cdn\.shopify\.com", r"Shopify\.theme"],
    "Wix": [r"static\.wixstatic\.com", r"wix-code-sdk"],
    "Squarespace": [r"static1\.squarespace\.com", r"squarespace-cdn"],
    "Ghost": [r'content=["\']Ghost'],
    "Magento": [r"/skin/frontend/", r"/js/mage/", r"Mage\.Cookies"],
}

FRAMEWORK_SIGNATURES = {
    "jQuery": r"jquery[.-](\d+\.\d+)",
    "React": r"(react\.production\.min\.js|react-dom|__NEXT_DATA__|_reactRoot)",
    "Angular": r"(angular\.min\.js|ng-version|ng-app)",
    "Vue.js": r"(vue\.min\.js|vue\.runtime|__vue__|v-cloak)",
    "Bootstrap": r"(bootstrap\.min\.(js|css)|getbootstrap\.com)",
    "Tailwind CSS": r"tailwindcss|tailwind\.min\.css",
    "Next.js": r"(_next/static|__NEXT_DATA__)",
    "Nuxt.js": r"(__nuxt|_nuxt/)",
    "Svelte": r"svelte",
    "Ember.js": r"ember\.min\.js",
    "Backbone.js": r"backbone\.min\.js",
    "Lodash": r"lodash\.min\.js",
    "Moment.js": r"moment\.min\.js",
    "D3.js": r"d3\.min\.js",
    "Chart.js": r"chart\.min\.js",
    "Socket.IO": r"socket\.io\.min\.js",
    "Alpine.js": r"alpine\.min\.js|x-data",
    "HTMX": r"htmx\.min\.js|hx-get|hx-post",
}

CDN_SIGNATURES = {
    "Cloudflare": r"(cloudflare|cf-ray|cf-cache-status|cdnjs\.cloudflare\.com)",
    "AWS CloudFront": r"(cloudfront\.net|x-amz-cf-id)",
    "Akamai": r"(akamai|akamaized\.net|edgesuite\.net)",
    "Fastly": r"(fastly|x-served-by.*cache-)",
    "Google Cloud CDN": r"(googleapis\.com|gstatic\.com)",
    "Azure CDN": r"(azureedge\.net|azure\.microsoft\.com)",
    "KeyCDN": r"kxcdn\.com",
    "jsDelivr": r"cdn\.jsdelivr\.net",
    "unpkg": r"unpkg\.com",
    "StackPath": r"stackpathdns\.com",
    "Vercel": r"vercel\.app|_vercel",
    "Netlify": r"netlify\.app|netlify\.com",
}

# Security header definitions with risk ratings
SECURITY_HEADERS = {
    "Strict-Transport-Security": {"weight": 20, "risk_if_missing": "High — vulnerable to SSL stripping (MITM)"},
    "Content-Security-Policy": {"weight": 25, "risk_if_missing": "High — vulnerable to XSS and code injection"},
    "X-Frame-Options": {"weight": 15, "risk_if_missing": "Medium — vulnerable to clickjacking"},
    "X-Content-Type-Options": {"weight": 10, "risk_if_missing": "Medium — vulnerable to MIME-sniffing attacks"},
    "Referrer-Policy": {"weight": 10, "risk_if_missing": "Low — may leak sensitive URLs in Referer header"},
    "Permissions-Policy": {"weight": 10, "risk_if_missing": "Low — browser APIs (camera/mic/geolocation) unrestricted"},
    "X-XSS-Protection": {"weight": 5, "risk_if_missing": "Low — deprecated but still useful for older browsers"},
    "Cross-Origin-Opener-Policy": {"weight": 5, "risk_if_missing": "Low — no cross-origin isolation"},
}


class DeepWebAnalyzer:
    """Comprehensive local website forensic analyzer."""

    def analyze(
        self,
        url: str,
        html_content: Optional[str] = None,
        response_headers: Optional[Dict[str, str]] = None,
        cookies_raw: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Performs full deep analysis of a web page.
        All analysis is local — no external API calls.
        """
        html = html_content or ""
        headers = response_headers or {}
        parsed_url = urllib.parse.urlparse(url)
        hostname = (parsed_url.hostname or "").lower()

        return {
            "security_headers": self._audit_security_headers(headers),
            "page_metadata": self._extract_page_metadata(html, url),
            "link_analysis": self._analyze_links(html, url, hostname),
            "tech_stack": self._fingerprint_tech_stack(html, headers),
            "trackers": self._detect_trackers(html),
            "cookies": self._audit_cookies(cookies_raw or [], headers),
        }

    # ------------------------------------------------------------------
    # 1. Security Headers Audit
    # ------------------------------------------------------------------
    def _audit_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Grade the HTTP security header configuration (A+ through F)."""
        # Normalize header keys to title-case for consistent lookup
        norm = {k.title(): v for k, v in headers.items()}

        total_weight = sum(h["weight"] for h in SECURITY_HEADERS.values())
        earned = 0
        details = {}
        missing_critical = []

        for header_name, meta in SECURITY_HEADERS.items():
            present = header_name in norm or header_name.lower() in {k.lower() for k in headers}
            value = norm.get(header_name) or headers.get(header_name.lower())

            details[header_name] = {
                "present": present,
                "value": value,
            }
            if present:
                earned += meta["weight"]
            else:
                details[header_name]["risk"] = meta["risk_if_missing"]
                if meta["weight"] >= 15:
                    missing_critical.append(header_name)

        score = round((earned / total_weight) * 100) if total_weight > 0 else 0

        # Letter grade
        if score >= 95:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 55:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        # Info leakage detection
        info_leakage = {}
        for leak_header in ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime", "X-Generator"]:
            val = norm.get(leak_header) or headers.get(leak_header.lower())
            if val:
                info_leakage[leak_header] = val

        return {
            "grade": grade,
            "score": score,
            "headers": details,
            "missing_critical": missing_critical,
            "info_leakage": info_leakage,
        }

    # ------------------------------------------------------------------
    # 2. Page Metadata & Content Intelligence
    # ------------------------------------------------------------------
    def _extract_page_metadata(self, html: str, base_url: str) -> Dict[str, Any]:
        """Extract title, meta tags, Open Graph, Twitter Cards, canonical URL, favicons."""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return {"error": "HTML parsing failed"}

        # Title
        title = None
        if soup.title and soup.title.string:
            title = soup.title.string.strip()[:200]

        # Meta tags
        meta_description = None
        language = None
        meta_robots = None
        og_tags = {}
        twitter_tags = {}

        for meta in soup.find_all("meta"):
            name = (meta.get("name") or meta.get("property") or "").strip().lower()
            content = (meta.get("content") or "").strip()
            http_equiv = (meta.get("http-equiv") or "").strip().lower()

            if not content:
                continue

            if name == "description":
                meta_description = content[:300]
            elif name == "robots":
                meta_robots = content
            elif name.startswith("og:"):
                og_tags[name] = content[:200]
            elif name.startswith("twitter:"):
                twitter_tags[name] = content[:200]
            elif http_equiv == "content-language" or name == "language":
                language = content

        # Language from <html lang="">
        html_tag = soup.find("html")
        if html_tag and html_tag.get("lang") and not language:
            language = html_tag.get("lang").strip()[:10]

        # Canonical URL
        canonical = None
        can_tag = soup.find("link", rel=lambda x: x and "canonical" in str(x).lower())
        if can_tag and can_tag.get("href"):
            canonical = can_tag["href"].strip()

        # Favicons
        favicons = []
        for icon in soup.find_all("link", rel=lambda x: x and any(i in str(x).lower() for i in ["icon", "shortcut"])):
            href = icon.get("href")
            if href:
                favicons.append(urllib.parse.urljoin(base_url, href))

        return {
            "title": title,
            "meta_description": meta_description,
            "language": language,
            "meta_robots": meta_robots,
            "canonical_url": canonical,
            "open_graph": og_tags if og_tags else None,
            "twitter_card": twitter_tags if twitter_tags else None,
            "favicons": favicons[:5],
            "has_structured_metadata": bool(og_tags or twitter_tags or meta_description),
        }

    # ------------------------------------------------------------------
    # 3. Link Topology Analysis
    # ------------------------------------------------------------------
    def _analyze_links(self, html: str, base_url: str, base_hostname: str) -> Dict[str, Any]:
        """Extract and classify all links as internal or external."""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return {"internal_count": 0, "external_count": 0, "external_domains": []}

        # Extract base registered domain for comparison
        base_parts = base_hostname.split(".")
        if len(base_parts) >= 2:
            base_root = ".".join(base_parts[-2:])
        else:
            base_root = base_hostname

        internal_links = set()
        external_links = set()
        external_domains = set()
        mailto_count = 0
        tel_count = 0
        suspicious_links = []

        SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".work", ".buzz", ".tk", ".ml", ".ga", ".cf", ".gq", ".icu", ".cam", ".rest"}

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()

            if not href or href.startswith("#") or href.startswith("javascript:") or href.startswith("data:"):
                continue
            if href.startswith("mailto:"):
                mailto_count += 1
                continue
            if href.startswith("tel:"):
                tel_count += 1
                continue

            absolute = urllib.parse.urljoin(base_url, href)
            parsed = urllib.parse.urlparse(absolute)

            if parsed.scheme not in ("http", "https"):
                continue

            target_host = (parsed.hostname or "").lower()
            if not target_host:
                continue

            target_parts = target_host.split(".")
            if len(target_parts) >= 2:
                target_root = ".".join(target_parts[-2:])
            else:
                target_root = target_host

            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if len(clean_url) > 500:
                continue

            if target_root == base_root:
                internal_links.add(clean_url)
            else:
                external_links.add(clean_url)
                external_domains.add(target_host)

                # Check for suspicious TLDs in external links
                for tld in SUSPICIOUS_TLDS:
                    if target_host.endswith(tld):
                        suspicious_links.append({"url": clean_url, "reason": f"Suspicious TLD: {tld}"})
                        break

        return {
            "internal_count": len(internal_links),
            "external_count": len(external_links),
            "external_domains": sorted(list(external_domains))[:30],
            "suspicious_external_links": suspicious_links[:10],
            "mailto_count": mailto_count,
            "tel_count": tel_count,
            "total_links": len(internal_links) + len(external_links),
        }

    # ------------------------------------------------------------------
    # 4. Technology Stack Fingerprinting
    # ------------------------------------------------------------------
    def _fingerprint_tech_stack(self, html: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Detect CMS, frameworks, CDN, and server technology from HTML + headers."""
        combined = html + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
        combined_lower = combined.lower()

        # Server
        norm = {k.lower(): v for k, v in headers.items()}
        web_server = norm.get("server")
        powered_by = norm.get("x-powered-by")

        # CMS Detection
        detected_cms = None
        for cms_name, patterns in CMS_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    detected_cms = cms_name
                    break
            if detected_cms:
                break

        # Framework Detection
        detected_frameworks = []
        for fw_name, pattern in FRAMEWORK_SIGNATURES.items():
            if re.search(pattern, combined, re.IGNORECASE):
                detected_frameworks.append(fw_name)

        # CDN Detection
        detected_cdn = None
        for cdn_name, pattern in CDN_SIGNATURES.items():
            if re.search(pattern, combined, re.IGNORECASE):
                detected_cdn = cdn_name
                break

        # Programming language hints
        lang = None
        if powered_by:
            pb_lower = powered_by.lower()
            if "php" in pb_lower:
                lang = "PHP"
            elif "asp.net" in pb_lower:
                lang = "ASP.NET"
            elif "express" in pb_lower:
                lang = "Node.js"
            elif "django" in pb_lower or "python" in pb_lower:
                lang = "Python"
            elif "ruby" in pb_lower:
                lang = "Ruby"
        if not lang and detected_cms == "WordPress":
            lang = "PHP"

        return {
            "web_server": web_server,
            "powered_by": powered_by,
            "cms": detected_cms,
            "frameworks": detected_frameworks[:10],
            "cdn": detected_cdn,
            "programming_language": lang,
        }

    # ------------------------------------------------------------------
    # 5. Tracker & Analytics Script Detection
    # ------------------------------------------------------------------
    def _detect_trackers(self, html: str) -> List[Dict[str, str]]:
        """Detect known third-party trackers and analytics scripts."""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return []

        # Collect all script sources and inline script content
        script_sources = []
        inline_scripts = []
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                script_sources.append(src)
            elif script.string:
                inline_scripts.append(script.string[:2000])

        combined = "\n".join(script_sources) + "\n" + "\n".join(inline_scripts)

        detected = []
        for name, info in TRACKER_SIGNATURES.items():
            if re.search(info["pattern"], combined, re.IGNORECASE):
                detected.append({
                    "name": name,
                    "category": info["category"],
                })

        return detected

    # ------------------------------------------------------------------
    # 6. Cookie Security Audit
    # ------------------------------------------------------------------
    def _audit_cookies(self, cookies_raw: List[str], headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze Set-Cookie headers for security flags."""
        # Collect all Set-Cookie headers
        set_cookies = cookies_raw[:]

        # Also check from headers dict
        for key, val in headers.items():
            if key.lower() == "set-cookie":
                set_cookies.append(val)

        if not set_cookies:
            return {"total": 0, "insecure_count": 0, "details": []}

        details = []
        insecure_count = 0
        tracking_count = 0

        TRACKING_COOKIE_PATTERNS = ["_ga", "_gid", "_fbp", "_fbc", "_gcl", "hubspot", "_hjid", "_clck", "_clsk"]

        for cookie_str in set_cookies:
            parts = cookie_str.split(";")
            if not parts:
                continue

            name_val = parts[0].strip()
            name = name_val.split("=")[0].strip() if "=" in name_val else name_val
            flags_str = cookie_str.lower()

            has_secure = "secure" in flags_str
            has_httponly = "httponly" in flags_str
            has_samesite = "samesite" in flags_str
            is_insecure = not has_secure or not has_httponly

            is_tracking = any(tp in name.lower() for tp in TRACKING_COOKIE_PATTERNS)

            if is_insecure:
                insecure_count += 1
            if is_tracking:
                tracking_count += 1

            details.append({
                "name": name[:50],
                "secure": has_secure,
                "httponly": has_httponly,
                "samesite": has_samesite,
                "is_tracking": is_tracking,
            })

        return {
            "total": len(details),
            "insecure_count": insecure_count,
            "tracking_count": tracking_count,
            "details": details[:20],
        }
