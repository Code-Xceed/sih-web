"""
GovShield Sentinel Grid — DNS & Mail Infrastructure Security Analyzer.
Incorporates best-of-breed DNS and infrastructure auditing from url.vet:
- Name Server (NS) validity & hosting resilience
- Mail Exchange (MX) presence check (disposable vs legitimate infrastructure)
- SPF and DMARC spoofing defense records
- DNS-over-HTTPS (DoH) queries with non-blocking failover
"""

from __future__ import annotations

import json
import socket
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

DOH_GOOGLE_API = "https://dns.google/resolve"
DISPOSABLE_DYNAMIC_DNS = {
    "duckdns.org", "no-ip.com", "ngrok.io", "dynu.com", "freedns.afraid.org",
    "zapto.org", "ddns.net", "hopto.org", "servebeer.com", "bounceme.net"
}


class DNSSecurityAnalyzer:
    """Audits DNS records, mail infrastructure, and email spoofing protections."""

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    def _query_doh(self, name: str, record_type: str) -> List[Dict[str, Any]]:
        """Queries DNS-over-HTTPS (DoH) via Google Public DNS with safe fallback."""
        try:
            url = f"{DOH_GOOGLE_API}?name={name}&type={record_type}"
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/dns-json", "User-Agent": "GovShield-DNS/2.2"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
                return data.get("Answer", [])
        except Exception:
            return []

    def analyze(self, domain_or_url: str) -> Dict[str, Any]:
        """Audits domain DNS, NS, MX, and DMARC security posture."""
        clean = domain_or_url.strip().lower()
        if "://" in clean:
            domain = urlparse(clean).netloc.split(":")[0]
        else:
            domain = clean.split("/")[0].split(":")[0]

        is_gov = domain.endswith(".gov.in") or domain.endswith(".nic.in")

        # 1. IP Resolution
        ips: List[str] = []
        try:
            addr_info = socket.getaddrinfo(domain, None)
            ips = list({res[4][0] for res in addr_info if res[4]})
        except Exception:
            # Fallback to DoH
            a_records = self._query_doh(domain, "A")
            ips = [r["data"] for r in a_records if "data" in r]

        has_valid_ip = len(ips) > 0

        # 2. Name Servers (NS) Check
        ns_records = self._query_doh(domain, "NS")
        ns_hosts = [r["data"].rstrip(".") for r in ns_records if "data" in r]
        has_ns = len(ns_hosts) > 0 or is_gov

        is_dynamic_dns = any(
            any(ns_host.endswith(d) for d in DISPOSABLE_DYNAMIC_DNS)
            for ns_host in ns_hosts
        ) or any(domain.endswith(d) for d in DISPOSABLE_DYNAMIC_DNS)

        # 3. Mail Exchange (MX) Check
        # Legitimate portals almost universally have MX records; throwaway scams rarely do.
        mx_records = self._query_doh(domain, "MX")
        mx_hosts = [r["data"] for r in mx_records if "data" in r]
        has_mx = len(mx_hosts) > 0 or is_gov

        # 4. DMARC / SPF Spoofing Protections
        dmarc_name = f"_dmarc.{domain}"
        dmarc_records = self._query_doh(dmarc_name, "TXT")
        has_dmarc = any("v=DMARC1" in r.get("data", "") for r in dmarc_records)

        txt_records = self._query_doh(domain, "TXT")
        has_spf = any("v=spf1" in r.get("data", "") for r in txt_records)

        # Calculate DNS Risk Score (0 = robust enterprise/gov DNS, 100 = throwaway scam)
        dns_risk = 0.0
        findings: List[str] = []

        if not has_valid_ip:
            dns_risk += 35.0
            findings.append("Domain does not resolve to an active IP address.")

        if is_dynamic_dns:
            dns_risk += 45.0
            findings.append("Hosted on dynamic / disposable free DNS provider.")

        # C4 Fix: Only penalize missing MX for domains that claim to be government entities.
        # Legitimate commercial sites (google.com, amazon.com) often lack bare-domain MX records.
        has_sovereign_tokens = any(
            token in domain for token in [
                "gov", "nic", "pmkisan", "aadhaar", "uidai", "incometax", "epf",
                "parivahan", "passport", "digilocker", "sbi", "irctc", "scholarship",
                "yojana", "subsidy", "kyc", "eshram", "samagra"
            ]
        )
        if not has_mx and not is_gov and has_sovereign_tokens:
            dns_risk += 20.0
            findings.append("No active Mail Exchange (MX) records found (typical of throwaway phishing clones).")

        if not has_dmarc and not has_spf and not is_gov and has_sovereign_tokens:
            dns_risk += 15.0
            findings.append("Missing SPF/DMARC records (vulnerable to email impersonation).")

        if is_gov:
            dns_risk = 0.0
            findings = ["Official National Informatics Centre (NIC) Sovereign DNS Infrastructure."]

        return {
            "domain": domain,
            "has_valid_ip": has_valid_ip,
            "ip_addresses": ips[:4],
            "has_ns": has_ns,
            "name_servers": ns_hosts[:4],
            "has_mx": has_mx,
            "mail_servers": mx_hosts[:2],
            "has_spf": has_spf,
            "has_dmarc": has_dmarc,
            "is_dynamic_dns": is_dynamic_dns,
            "dns_risk_score": min(dns_risk, 100.0),
            "findings": findings
        }
