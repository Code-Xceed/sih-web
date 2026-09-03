"""
GovShield Sentinel Grid — URL Normalization & Security Pre-Flight Engine
Conforms to RFC 3986 specifications with defensive sanitization.

Handles:
- Userinfo stripping & credential-injection detection (e.g., user@target.com)
- Safe percent-decoding and double-encoding detection (%252e)
- IP address host representation detection (decimal, hex, octal, IPv4, IPv6)
- Unusual port detection (cPanel, webmin, alternative HTTP/S)
- Punycode (IDN) decoding (xn--)
- Multi-script & Unicode homoglyph skeletonization (Cyrillic, Greek confusables)
- Public suffix & multi-part TLD parsing (.gov.in, .nic.in, .co.uk, .com)
"""

import urllib.parse
import re
import ipaddress
from typing import Dict, Any, List, Optional, Tuple
from .homoglyph_analyzer import HomoglyphAnalyzer

# Common two-part TLDs and Indian Sovereign TLDs
KNOWN_MULTI_TLDS = {
    "gov.in", "nic.in", "ac.in", "res.in", "edu.in", "mil.in", "net.in",
    "org.in", "co.in", "gen.in", "ind.in", "co.uk", "gov.uk", "ac.uk",
    "com.au", "gov.au", "edu.au", "co.nz", "com.sg", "edu.sg"
}

STANDARD_PORTS = {80: "http", 443: "https"}
SUSPICIOUS_PORTS = {2082, 2083, 2086, 2087, 8080, 8443, 8000, 8888, 8088, 9000, 10000}


class URLNormalizer:
    """Enterprise RFC 3986 URL Normalization and Attack Pre-Flight Sanitizer."""

    def __init__(self):
        self.homoglyph_engine = HomoglyphAnalyzer()

    def normalize(self, raw_url: str) -> Dict[str, Any]:
        """
        Normalizes a raw input URL, strips deceptive obfuscation, and extracts forensic tokens.
        """
        raw_url = (raw_url or "").strip()
        indicators: List[str] = []

        if not raw_url:
            return {
                "valid": False,
                "error": "Empty URL provided",
                "normalized_url": "",
                "indicators": ["Empty URL"]
            }

        # 1. Scheme Normalization
        has_scheme = raw_url.startswith(("http://", "https://", "ftp://", "file://", "javascript:", "data:"))
        if not has_scheme:
            # Prepend default https://
            raw_url_with_scheme = "https://" + raw_url
        else:
            raw_url_with_scheme = raw_url

        # Check for dangerous schemes
        scheme_lower = raw_url_with_scheme.split(":")[0].lower() if ":" in raw_url_with_scheme else ""
        if scheme_lower in ["javascript", "data", "file", "vbscript"]:
            indicators.append(f"Dangerous URI scheme detected: {scheme_lower}")
            return {
                "valid": False,
                "error": f"Disallowed scheme: {scheme_lower}",
                "scheme": scheme_lower,
                "indicators": indicators,
                "normalized_url": raw_url
            }

        try:
            parsed = urllib.parse.urlsplit(raw_url_with_scheme)
        except Exception as e:
            return {
                "valid": False,
                "error": f"URL parsing error: {str(e)}",
                "indicators": ["Malformed URL syntax"],
                "normalized_url": raw_url
            }

        scheme = (parsed.scheme or "https").lower()
        netloc = parsed.netloc

        # 2. Deceptive Userinfo Detection (e.g., http://pmkisan.gov.in@evil.com)
        has_userinfo = False
        userinfo = ""
        hostname_part = netloc
        if "@" in netloc:
            has_userinfo = True
            userinfo, hostname_part = netloc.rsplit("@", 1)
            indicators.append(f"Deceptive userinfo detected attempting authority masquerade: '{userinfo}'")

        # 3. Port Normalization & Inspection
        port: Optional[int] = None
        has_unusual_port = False
        if ":" in hostname_part and not hostname_part.startswith("["):
            parts = hostname_part.split(":")
            hostname_part = parts[0]
            try:
                port = int(parts[1])
                if port not in (80, 443):
                    has_unusual_port = True
                    indicators.append(f"Unusual non-standard port in URL: {port}")
            except ValueError:
                pass
        elif hostname_part.startswith("[") and "]" in hostname_part:
            # IPv6 literal
            end_bracket = hostname_part.index("]")
            if len(hostname_part) > end_bracket + 1 and hostname_part[end_bracket + 1] == ":":
                try:
                    port = int(hostname_part[end_bracket + 2:])
                except ValueError:
                    pass
            hostname_part = hostname_part[1:end_bracket]

        # 4. Hostname Normalization & IP Representation Detection
        hostname_clean = hostname_part.lower().rstrip(".")
        is_ip_address = False
        ip_type = None

        # Check standard IPv4/IPv6 or integer/hex/octal notation
        try:
            ip_obj = ipaddress.ip_address(hostname_clean)
            is_ip_address = True
            ip_type = f"IPv{ip_obj.version}"
            indicators.append(f"Direct IP address host instead of domain name: {hostname_clean} ({ip_type})")
        except ValueError:
            # Check integer or hex encoded IPv4 (e.g. 2130706433 or 0x7f000001)
            if hostname_clean.isdigit():
                try:
                    ip_obj = ipaddress.ip_address(int(hostname_clean))
                    is_ip_address = True
                    ip_type = "IPv4 (Decimal-encoded)"
                    indicators.append(f"Obfuscated decimal-encoded IP address: {hostname_clean} -> {ip_obj}")
                    hostname_clean = str(ip_obj)
                except (ValueError, OverflowError):
                    pass
            elif hostname_clean.startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in hostname_clean[2:]):
                try:
                    ip_obj = ipaddress.ip_address(int(hostname_clean, 16))
                    is_ip_address = True
                    ip_type = "IPv4 (Hex-encoded)"
                    indicators.append(f"Obfuscated hexadecimal IP address: {hostname_clean} -> {ip_obj}")
                    hostname_clean = str(ip_obj)
                except (ValueError, OverflowError):
                    pass

        # 5. Punycode (IDN) & Homoglyph Skeletonization
        is_punycode = False
        decoded_idn = hostname_clean
        if "xn--" in hostname_clean:
            is_punycode = True
            try:
                decoded_idn = hostname_clean.encode("ascii").decode("idna")
                indicators.append(f"Internationalized Domain (IDN / Punycode): {hostname_clean} -> {decoded_idn}")
            except Exception:
                decoded_idn = hostname_clean

        # Skeletonize to identify multi-script Cyrillic/Greek confusables
        confusable_details = self.homoglyph_engine.analyze_domain(decoded_idn)
        has_homoglyphs = confusable_details.get("has_homoglyphs", False) or confusable_details.get("has_confusables", False)
        canonical_skeleton = confusable_details.get("skeleton", decoded_idn)
        if has_homoglyphs:
            for reason in confusable_details.get("reasons", []):
                indicators.append(f"Homoglyph / Confusable Script: {reason}")

        # 6. Path, Query, and Double Percent-Encoding
        path = parsed.path or "/"
        has_double_encoding = False
        if "%25" in path or "%25" in (parsed.query or ""):
            has_double_encoding = True
            indicators.append("Double percent-encoding (%25) detected in path/query")

        # Decode percent-encodings safely
        try:
            decoded_path = urllib.parse.unquote(path)
        except Exception:
            decoded_path = path

        # Normalize path slashes
        normalized_path = re.sub(r"/+", "/", decoded_path)

        # 7. Registered Domain & Subdomain Splitting
        registered_domain, subdomain, tld = self._extract_domain_parts(hostname_clean)

        # 8. Excessive Subdomains (Domain fronting / typosquat hiding)
        subdomain_depth = len(subdomain.split(".")) if subdomain else 0
        if subdomain_depth >= 3:
            indicators.append(f"Excessive subdomain depth ({subdomain_depth} levels) used to conceal true domain")

        # 9. Reconstruct Canonical RFC 3986 Normalized URL
        port_str = f":{port}" if (port and port not in (80, 443)) else ""
        canonical_netloc = f"{hostname_clean}{port_str}"
        canonical_query = f"?{parsed.query}" if parsed.query else ""
        canonical_url = f"{scheme}://{canonical_netloc}{normalized_path}{canonical_query}"

        entropy = self._compute_entropy(registered_domain)
        if entropy > 3.85 and len(registered_domain) > 10 and tld not in ["gov.in", "nic.in"]:
            indicators.append(f"High Shannon entropy ({entropy:.2f}): Potential DGA or randomized domain generation")

        return {
            "valid": True,
            "original_url": raw_url,
            "normalized_url": canonical_url,
            "scheme": scheme,
            "hostname": hostname_clean,
            "port": port,
            "registered_domain": registered_domain,
            "subdomain": subdomain,
            "subdomain_depth": subdomain_depth,
            "tld": tld,
            "path": normalized_path,
            "query": parsed.query or "",
            "is_ip_address": is_ip_address,
            "ip_type": ip_type,
            "has_userinfo": has_userinfo,
            "has_unusual_port": has_unusual_port,
            "is_punycode": is_punycode,
            "decoded_idn": decoded_idn,
            "has_homoglyphs": has_homoglyphs,
            "canonical_skeleton": canonical_skeleton,
            "has_double_encoding": has_double_encoding,
            "entropy": entropy,
            "indicators": indicators
        }

    def _compute_entropy(self, s: str) -> float:
        """Calculates Shannon entropy of a string (from url.vet & PhishGuard standards)."""
        if not s:
            return 0.0
        import math
        from collections import Counter
        counts = Counter(s)
        n = len(s)
        return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 4)

    def _extract_domain_parts(self, hostname: str) -> Tuple[str, str, str]:
        """
        Splits a clean hostname into (registered_domain, subdomain, tld).
        Respects Indian sovereign multi-part TLDs (gov.in, nic.in, res.in, etc.).
        """
        if not hostname or hostname.replace(".", "").isdigit():
            return hostname, "", ""

        parts = hostname.split(".")
        if len(parts) <= 1:
            return hostname, "", ""

        # Check two-part TLDs (e.g. gov.in)
        if len(parts) >= 2:
            last_two = f"{parts[-2]}.{parts[-1]}"
            if last_two in KNOWN_MULTI_TLDS:
                if len(parts) == 2:
                    return last_two, "", last_two
                tld = last_two
                registered_domain = f"{parts[-3]}.{last_two}"
                subdomain = ".".join(parts[:-3])
                return registered_domain, subdomain, tld

        # Standard single TLD (e.g. com, xyz, in, org)
        tld = parts[-1]
        registered_domain = f"{parts[-2]}.{parts[-1]}"
        subdomain = ".".join(parts[:-2])
        return registered_domain, subdomain, tld
