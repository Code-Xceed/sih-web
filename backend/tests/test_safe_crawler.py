"""
Unit tests for Hardened Anti-SSRF Safe Crawler.
Verifies blocking of RFC 1918, loopback, link-local, and cloud metadata IPs.
"""

import sys
import os
import unittest

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from modules.safe_crawler import SafeCrawler, SSRFValidationError


class TestSafeCrawler(unittest.TestCase):
    def setUp(self):
        self.crawler = SafeCrawler()

    def test_blocks_loopback_ips(self):
        self.assertFalse(self.crawler.is_ip_allowed("127.0.0.1"))
        self.assertFalse(self.crawler.is_ip_allowed("127.0.0.2"))
        self.assertFalse(self.crawler.is_ip_allowed("::1"))

    def test_blocks_private_rfc1918_ips(self):
        # 10.0.0.0/8
        self.assertFalse(self.crawler.is_ip_allowed("10.0.0.1"))
        self.assertFalse(self.crawler.is_ip_allowed("10.254.254.254"))
        # 172.16.0.0/12
        self.assertFalse(self.crawler.is_ip_allowed("172.16.0.1"))
        self.assertFalse(self.crawler.is_ip_allowed("172.31.255.255"))
        # 192.168.0.0/16
        self.assertFalse(self.crawler.is_ip_allowed("192.168.1.1"))
        self.assertFalse(self.crawler.is_ip_allowed("192.168.0.254"))

    def test_blocks_cloud_metadata_endpoints(self):
        # AWS / GCP / Azure metadata endpoint
        self.assertFalse(self.crawler.is_ip_allowed("169.254.169.254"))
        self.assertFalse(self.crawler.is_ip_allowed("169.254.1.1"))

    def test_allows_legitimate_public_ips(self):
        self.assertTrue(self.crawler.is_ip_allowed("8.8.8.8"))
        self.assertTrue(self.crawler.is_ip_allowed("1.1.1.1"))
        self.assertTrue(self.crawler.is_ip_allowed("142.250.190.46"))

    def test_fetch_rejects_forbidden_localhost(self):
        res = self.crawler.fetch_url("http://127.0.0.1:8000/internal-admin")
        self.assertFalse(res["success"])
        self.assertIn("Security Policy Block", res.get("error", ""))


if __name__ == "__main__":
    unittest.main()
