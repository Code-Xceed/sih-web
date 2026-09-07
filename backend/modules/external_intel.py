"""
GovShield Sentinel Grid — External Threat Intelligence Aggregator
Queries multiple free external APIs in parallel for enriched threat data:
  1. Shodan InternetDB — Open ports, CVEs, hostnames (FREE, no key)
  2. URLhaus (abuse.ch) — Active malware distribution (FREE, no key)
  3. Mozilla HTTP Observatory — Security headers grade (FREE, no key)
  4. Google Safe Browsing — Malware/phishing blacklist (FREE, optional key)
  5. VirusTotal — Multi-engine AV consensus (FREE tier, optional key)

All calls run in parallel with strict timeouts. Any failure returns None.
"""

import os
import socket
import json
import urllib.request
import urllib.parse
import urllib.error
import base64
from typing import Any, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


class ExternalIntelligence:
    """Aggregates threat intelligence from multiple free external sources."""

    def __init__(self):
        self.safebrowsing_key = os.environ.get("GOOGLE_SAFEBROWSING_KEY", "")
        self.virustotal_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self._pool = ThreadPoolExecutor(max_workers=5)

    def gather(
        self,
        url: str,
        hostname: str,
        ip_address: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Queries all external intel sources in parallel.
        Returns a dict with keys: shodan, urlhaus, observatory, safe_browsing, virustotal.
        Any source that fails or times out returns None.
        """
        # Resolve IP if not provided
        if not ip_address:
            try:
                ip_address = socket.gethostbyname(hostname)
            except Exception:
                ip_address = None

        results = {
            "shodan": None,
            "urlhaus": None,
            "observatory": None,
            "safe_browsing": None,
            "virustotal": None,
        }

        # Submit all tasks in parallel
        futures = {}

        if ip_address:
            futures["shodan"] = self._pool.submit(self._query_shodan, ip_address)

        futures["urlhaus"] = self._pool.submit(self._query_urlhaus, url)
        futures["observatory"] = self._pool.submit(self._query_observatory, hostname)

        if self.safebrowsing_key:
            futures["safe_browsing"] = self._pool.submit(self._query_safe_browsing, url)

        if self.virustotal_key:
            futures["virustotal"] = self._pool.submit(self._query_virustotal, url)

        # Harvest results with 6-second timeout per source
        for source_name, future in futures.items():
            try:
                results[source_name] = future.result(timeout=6)
            except Exception as e:
                results[source_name] = {"error": str(e)[:100]}

        return results

    # ------------------------------------------------------------------
    # 1. Shodan InternetDB (FREE, no key required)
    # ------------------------------------------------------------------
    def _query_shodan(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Query Shodan InternetDB for open ports, CVEs, and services."""
        try:
            req = urllib.request.Request(
                f"https://internetdb.shodan.io/{ip_address}",
                headers={"Accept": "application/json", "User-Agent": "GovShield/2.0"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 404:
                    return {"ip": ip_address, "open_ports": [], "vulnerabilities": [], "message": "No data available"}
                data = json.loads(resp.read().decode("utf-8"))
                return {
                    "ip": data.get("ip", ip_address),
                    "open_ports": data.get("ports", []),
                    "vulnerabilities": data.get("vulns", []),
                    "cpes": data.get("cpes", [])[:10],
                    "hostnames": data.get("hostnames", [])[:10],
                    "tags": data.get("tags", []),
                }
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"ip": ip_address, "open_ports": [], "vulnerabilities": [], "message": "No data in InternetDB"}
            return None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # 2. URLhaus (abuse.ch) — FREE, no key required
    # ------------------------------------------------------------------
    def _query_urlhaus(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Check if URL is listed as malware distribution in URLhaus."""
        try:
            post_data = urllib.parse.urlencode({"url": target_url}).encode("utf-8")
            req = urllib.request.Request(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data=post_data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "GovShield/2.0"
                },
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            if data.get("query_status") == "ok":
                return {
                    "found": True,
                    "url_status": data.get("url_status"),
                    "threat": data.get("threat"),
                    "tags": data.get("tags", []),
                    "date_added": data.get("date_added"),
                }
            return {"found": False}
        except Exception:
            return None

    # ------------------------------------------------------------------
    # 3. Mozilla HTTP Observatory — FREE, no key required
    # ------------------------------------------------------------------
    def _query_observatory(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Get security headers grade from Mozilla Observatory."""
        try:
            # Use the current MDN Observatory API v2
            url = f"https://observatory-api.mdn.mozilla.net/api/v2/scan?host={urllib.parse.quote(hostname)}"
            req = urllib.request.Request(
                url,
                method="POST",
                headers={"User-Agent": "GovShield/2.0", "Content-Length": "0"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {
                    "grade": data.get("grade"),
                    "score": data.get("score"),
                    "tests_passed": data.get("tests_passed"),
                    "tests_failed": data.get("tests_failed"),
                }
        except Exception:
            # Try GET as fallback (for cached results)
            try:
                url = f"https://observatory-api.mdn.mozilla.net/api/v2/scan?host={urllib.parse.quote(hostname)}"
                req = urllib.request.Request(url, headers={"User-Agent": "GovShield/2.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return {
                        "grade": data.get("grade"),
                        "score": data.get("score"),
                        "tests_passed": data.get("tests_passed"),
                        "tests_failed": data.get("tests_failed"),
                    }
            except Exception:
                return None

    # ------------------------------------------------------------------
    # 4. Google Safe Browsing — FREE (10k req/day, requires GCP key)
    # ------------------------------------------------------------------
    def _query_safe_browsing(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Check URL against Google Safe Browsing threat lists."""
        if not self.safebrowsing_key:
            return None
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.safebrowsing_key}"
            payload = json.dumps({
                "client": {"clientId": "govshield", "clientVersion": "2.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": target_url}],
                },
            }).encode("utf-8")

            req = urllib.request.Request(
                api_url,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "GovShield/2.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            matches = data.get("matches", [])
            return {
                "is_safe": len(matches) == 0,
                "threats": [m.get("threatType") for m in matches],
            }
        except Exception:
            return None

    # ------------------------------------------------------------------
    # 5. VirusTotal — FREE tier (4 req/min, 500/day, requires key)
    # ------------------------------------------------------------------
    def _query_virustotal(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Check URL reputation across 70+ antivirus engines."""
        if not self.virustotal_key:
            return None
        try:
            url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

            req = urllib.request.Request(
                api_url,
                headers={
                    "x-apikey": self.virustotal_key,
                    "Accept": "application/json",
                    "User-Agent": "GovShield/2.0",
                },
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "reputation": attrs.get("reputation"),
                "categories": attrs.get("categories"),
            }
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"malicious": 0, "message": "URL not yet scanned by VirusTotal"}
            return None
        except Exception:
            return None
