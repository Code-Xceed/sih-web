"""
GovShield Sentinel Grid — Live Internet OSINT & Web Threat Intelligence Search Engine
SIH 2026 Problem Statement SIH1454

Architecture Note:
Performs real-time internet search and OSINT lookups for unknown/suspicious domains:
1. Searches for live cyber scam warnings, PIB Fact Check alerts, and police FIR advisories.
2. Queries for authentic sovereign (.gov.in / .nic.in) counterparts to detect unauthorized
   private lookalike portals claiming to be government schemes.
3. Safe timeout (2.5s), offline resilient, with in-memory caching.
"""

import urllib.request
import urllib.parse
import json
import re
import time
from typing import Dict, Any, List, Optional


class InternetSearchEngine:
    """Real-time web search and OSINT advisory discovery engine."""

    def __init__(self, timeout: float = 2.5):
        self.timeout = timeout
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = 3600  # 1 hour
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36 GovShield/2.2"
        )

    def _query_duckduckgo_lite(self, query: str) -> List[Dict[str, str]]:
        """
        Executes a lightweight DuckDuckGo HTML query to extract search results without API keys.
        """
        encoded_query = urllib.parse.quote_plus(query)
        url = f"https://html.duckduckgo.com/html/?q={encoded_query}"
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9"
        }

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
                return self._parse_html_results(content)
        except Exception:
            # Fallback or offline safe
            return []

    def _parse_html_results(self, html: str) -> List[Dict[str, str]]:
        """Extracts titles, URLs, and snippets from HTML search results."""
        results = []
        # Match result snippets: <a class="result__snippet" ...>...</a> or result__body
        snippets = re.findall(r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>', html, re.DOTALL | re.IGNORECASE)
        titles = re.findall(r'<a[^>]+class="result__url"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', html, re.DOTALL | re.IGNORECASE)

        for i in range(min(len(snippets), 5)):
            clean_snippet = re.sub(r'<[^>]+>', '', snippets[i]).strip()
            raw_url = titles[i][0] if i < len(titles) else ""
            # DuckDuckGo wraps destination in /l/?kh=-1&uddg=URL
            actual_url = raw_url
            if "uddg=" in raw_url:
                try:
                    match = re.search(r'uddg=([^&]+)', raw_url)
                    if match:
                        actual_url = urllib.parse.unquote(match.group(1))
                except Exception:
                    pass

            results.append({
                "snippet": clean_snippet,
                "url": actual_url
            })

        return results

    def investigate_domain_osint(self, domain: str, entity_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Conducts comprehensive live web research on a candidate domain:
        1. Checks for fraud, scam, or PIB warnings.
        2. Discovers authentic sovereign counterpart (.gov.in) if a government scheme is claimed.
        """
        clean_domain = domain.lower().strip()
        cache_key = f"{clean_domain}:{entity_name or ''}"
        now = time.time()

        if cache_key in self.cache:
            entry = self.cache[cache_key]
            if (now - entry["timestamp"]) < self.cache_ttl:
                return entry["data"]

        advisory_findings: List[Dict[str, Any]] = []
        is_scam_reported = False
        scam_confidence = 0.0
        official_gov_counterpart = None
        reasons: List[str] = []

        # 1. Search for live fraud / scam reports
        query_scam = f'"{clean_domain}" (fraud OR scam OR fake OR "fact check" OR advisory OR FIR)'
        scam_results = self._query_duckduckgo_lite(query_scam)

        scam_keywords = ["fake", "fraud", "scam", "pib fact check", "unauthorized", "illegal", "warning", "fir"]
        for res in scam_results:
            text = res["snippet"].lower()
            if any(kw in text for kw in scam_keywords):
                is_scam_reported = True
                scam_confidence = max(scam_confidence, 0.95)
                advisory_findings.append({
                    "source": "Web OSINT Advisory",
                    "url": res.get("url"),
                    "snippet": res.get("snippet")
                })
                reasons.append(f"Public cyber threat alert / fact check identified: {res.get('snippet')[:140]}...")

        # 2. Search for genuine government counterpart if scheme tokens exist
        tokens = [t for t in re.split(r'[-.]', clean_domain) if t not in ["co", "in", "org", "net", "com", "www"]]
        if entity_name or len(tokens) >= 2:
            search_terms = entity_name or " ".join(tokens)
            query_gov = f'"{search_terms}" site:gov.in'
            gov_results = self._query_duckduckgo_lite(query_gov)

            for res in gov_results:
                gov_url = res.get("url", "")
                if ".gov.in" in gov_url or ".nic.in" in gov_url:
                    parsed_gov = urllib.parse.urlsplit(gov_url)
                    official_gov_counterpart = parsed_gov.netloc.lower()
                    break

        evidence = {
            "searched": True,
            "domain": clean_domain,
            "is_scam_reported": is_scam_reported,
            "scam_confidence": scam_confidence,
            "official_gov_counterpart": official_gov_counterpart,
            "advisory_findings": advisory_findings,
            "reasons": reasons
        }

        self.cache[cache_key] = {
            "timestamp": now,
            "data": evidence
        }

        return evidence
