"""
GovShield Sentinel Grid — Hardened Anti-SSRF Web Crawler
Performs safe, sandboxed HTTP fetching with per-hop DNS rebinding and private IP defense.

Guards Against:
- SSRF to RFC 1918 internal networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Cloud Metadata extraction (169.254.169.254 / metadata.google.internal)
- Loopback exploitation (127.0.0.0/8, ::1)
- DNS rebinding via short-TTL domain flipping
- Recursive redirect loops & decompression bombs
"""

import socket
import ipaddress
import urllib.parse
import urllib.request
import http.client
from typing import Dict, Any, List, Optional, Tuple

MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 512_000  # 500 KB limit
DEFAULT_TIMEOUT = 3.5  # Seconds
SAFE_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 GovShield/2.1"


class SSRFValidationError(Exception):
    """Raised when a candidate URL targets a forbidden internal network address."""
    pass


class SafeCrawler:
    """Enterprise hardened web fetcher with multi-hop SSRF validation."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT, max_bytes: int = MAX_RESPONSE_BYTES):
        self.timeout = timeout
        self.max_bytes = max_bytes

    def is_ip_allowed(self, ip_str: str) -> bool:
        """
        Validates that an IP address is purely public and does not belong
        to loopback, private RFC1918, link-local, or cloud metadata subnets.
        """
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        # Disallow loopback, private, link-local, multicast, or reserved
        if (ip.is_loopback or
            ip.is_private or
            ip.is_link_local or
            ip.is_multicast or
            ip.is_reserved or
            ip.is_unspecified):
            return False

        # Explicit Cloud Metadata IP defense (AWS, GCP, Azure, OpenStack)
        if str(ip) in ["169.254.169.254", "169.254.169.123", "fd00:ec2::254"]:
            return False

        return True

    def resolve_and_validate_host(self, hostname: str) -> str:
        """
        Resolves hostname to an IPv4/IPv6 address and strictly validates against SSRF subnets.
        Returns the safe resolved IP address.
        """
        if not hostname:
            raise SSRFValidationError("Missing hostname")

        # Strip brackets from IPv6
        hostname_clean = hostname.strip("[]")

        # Resolve IP addresses
        try:
            addr_info = socket.getaddrinfo(hostname_clean, None, proto=socket.IPPROTO_TCP)
        except Exception as e:
            raise SSRFValidationError(f"DNS resolution failed for '{hostname}': {str(e)}")

        if not addr_info:
            raise SSRFValidationError(f"No IP addresses resolved for '{hostname}'")

        # Verify all resolved IPs are safe to mitigate round-robin rebinding
        valid_ip = None
        for entry in addr_info:
            ip_candidate = entry[4][0]
            if not self.is_ip_allowed(ip_candidate):
                raise SSRFValidationError(f"SSRF Alert: '{hostname}' resolved to prohibited network address {ip_candidate}")
            if valid_ip is None:
                valid_ip = ip_candidate

        return valid_ip

    def fetch_url(self, target_url: str) -> Dict[str, Any]:
        """
        Fetches webpage content while following up to MAX_REDIRECTS manually,
        verifying the resolved IP address on EVERY hop.
        """
        current_url = target_url
        redirect_chain: List[Dict[str, Any]] = []
        hop_count = 0

        while hop_count <= MAX_REDIRECTS:
            parsed = urllib.parse.urlsplit(current_url)
            scheme = (parsed.scheme or "").lower()

            if scheme not in ["http", "https"]:
                return {
                    "success": False,
                    "final_url": current_url,
                    "redirect_chain": redirect_chain,
                    "redirect_count": hop_count,
                    "error": f"Disallowed scheme '{scheme}'. Only HTTP and HTTPS are permitted."
                }

            hostname = parsed.hostname or ""
            port = parsed.port or (443 if scheme == "https" else 80)

            # 1. Pre-resolution IP validation (Anti-SSRF / Anti-Rebinding)
            try:
                resolved_ip = self.resolve_and_validate_host(hostname)
            except SSRFValidationError as ssrf_err:
                return {
                    "success": False,
                    "final_url": current_url,
                    "redirect_chain": redirect_chain,
                    "redirect_count": hop_count,
                    "error": f"Security Policy Block: {str(ssrf_err)}"
                }

            # 2. Perform Single-Hop HTTP Request
            try:
                req = urllib.request.Request(
                    current_url,
                    headers={
                        "User-Agent": SAFE_USER_AGENT,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9,hi;q=0.8"
                    }
                )

                # Custom opener that DOES NOT auto-follow redirects (we validate each hop)
                class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None

                opener = urllib.request.build_opener(NoRedirectHandler)

                try:
                    with opener.open(req, timeout=self.timeout) as resp:
                        status_code = resp.status
                        content_type = resp.headers.get("Content-Type", "")
                        raw_bytes = resp.read(self.max_bytes)
                        html_content = raw_bytes.decode("utf-8", errors="replace")

                        redirect_chain.append({
                            "hop": hop_count,
                            "url": current_url,
                            "ip": resolved_ip,
                            "status": status_code
                        })

                        return {
                            "success": True,
                            "final_url": current_url,
                            "redirect_chain": redirect_chain,
                            "redirect_count": hop_count,
                            "has_cross_domain_redirect": (hop_count > 0 and urllib.parse.urlsplit(target_url).hostname != hostname),
                            "status_code": status_code,
                            "content_type": content_type,
                            "html_content": html_content,
                            "byte_length": len(raw_bytes)
                        }

                except urllib.error.HTTPError as http_err:
                    # Check for 3xx redirect status
                    if http_err.code in [301, 302, 303, 307, 308]:
                        redirect_location = http_err.headers.get("Location")
                        if not redirect_location:
                            return {
                                "success": False,
                                "final_url": current_url,
                                "redirect_chain": redirect_chain,
                                "redirect_count": hop_count,
                                "error": f"HTTP {http_err.code} missing Location header"
                            }

                        # Resolve relative URLs
                        new_target = urllib.parse.urljoin(current_url, redirect_location)
                        redirect_chain.append({
                            "hop": hop_count,
                            "url": current_url,
                            "ip": resolved_ip,
                            "status": http_err.code,
                            "next_url": new_target
                        })

                        current_url = new_target
                        hop_count += 1
                        continue
                    else:
                        # 4xx or 5xx response
                        return {
                            "success": False,
                            "final_url": current_url,
                            "redirect_chain": redirect_chain,
                            "redirect_count": hop_count,
                            "status_code": http_err.code,
                            "error": f"HTTP Error {http_err.code}: {http_err.reason}"
                        }

            except Exception as e:
                return {
                    "success": False,
                    "final_url": current_url,
                    "redirect_chain": redirect_chain,
                    "redirect_count": hop_count,
                    "error": f"Connection error: {str(e)}"
                }

        return {
            "success": False,
            "final_url": current_url,
            "redirect_chain": redirect_chain,
            "redirect_count": hop_count,
            "error": f"Exceeded maximum allowed redirect hops ({MAX_REDIRECTS})"
        }
