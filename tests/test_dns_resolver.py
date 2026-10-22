import unittest
from ioc_analyzer.core.dns_resolver import DNSResolver


class TestDNSResolver(unittest.TestCase):
    def setUp(self):
        self.resolver = DNSResolver(timeout=3.0)

    def test_extract_target(self):
        self.assertEqual(
            self.resolver.extract_resolvable_target("http://microsoft-security-update.s3.amazonaws.com/login.php"),
            "microsoft-security-update.s3.amazonaws.com"
        )
        self.assertEqual(
            self.resolver.extract_resolvable_target("192.168.1.1:8080"),
            "192.168.1.1"
        )
        self.assertEqual(
            self.resolver.extract_resolvable_target("example.com"),
            "example.com"
        )

    def test_resolve_localhost_ip(self):
        # 127.0.0.1 o 8.8.8.8
        res = self.resolver.resolve("127.0.0.1")
        self.assertEqual(res["query_type"], "ip")
        self.assertIn(res["status"], ["success", "no_records"])


if __name__ == "__main__":
    unittest.main()
