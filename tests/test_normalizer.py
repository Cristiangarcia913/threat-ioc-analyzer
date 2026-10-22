import unittest
from ioc_analyzer.core.normalizer import normalize, IOCNormalizer


class TestNormalizer(unittest.TestCase):
    def setUp(self):
        self.norm = IOCNormalizer()

    def test_normalize_ip(self):
        self.assertEqual(normalize("192.168.1.1"), "192.168.1.1")
        self.assertEqual(normalize("192.168.1.1:8080"), "192.168.1.1:8080")
        self.assertEqual(normalize("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), "2001:db8:85a3::8a2e:370:7334")

    def test_normalize_domain(self):
        self.assertEqual(normalize("EXAMPLE.COM"), "example.com")
        self.assertEqual(normalize("http://evil.com/"), "http://evil.com/")
        self.assertEqual(self.norm.normalize_domain("http://evil.com/path"), "evil.com")

    def test_normalize_url(self):
        self.assertEqual(normalize("HTTP://EXAMPLE.COM/Path/file.php?A=1%202"), "http://example.com/Path/file.php?A=1 2")


if __name__ == "__main__":
    unittest.main()
