import unittest
from ioc_analyzer.core.classifier import classify, IOCType


class TestClassifier(unittest.TestCase):
    def test_classify_ip(self):
        self.assertEqual(classify("192.168.1.1"), IOCType.IPV4)
        self.assertEqual(classify("93.123.85.239"), IOCType.IPV4)
        self.assertEqual(classify("196.251.80.5:3778"), IOCType.IPV4_PORT)
        self.assertEqual(classify("2001:db8::1"), IOCType.IPV6)

    def test_classify_domain(self):
        self.assertEqual(classify("miraicnc.ddns.net"), IOCType.DOMAIN)
        self.assertEqual(classify("rebirthbot.icu"), IOCType.DOMAIN)
        self.assertEqual(classify("google.com"), IOCType.DOMAIN)

    def test_classify_url(self):
        self.assertEqual(classify("http://93.123.85.239/mirai.m68k"), IOCType.URL)
        self.assertEqual(classify("https://example.com/login.php?user=admin"), IOCType.URL)

    def test_classify_hashes(self):
        self.assertEqual(classify("d41d8cd98f00b204e9800998ecf8427e"), IOCType.HASH_MD5)
        self.assertEqual(classify("da39a3ee5e6b4b0d3255bfef95601890afd80709"), IOCType.HASH_SHA1)
        self.assertEqual(classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), IOCType.HASH_SHA256)

    def test_classify_email(self):
        self.assertEqual(classify("attacker@malicious-domain.com"), IOCType.EMAIL)


if __name__ == "__main__":
    unittest.main()
