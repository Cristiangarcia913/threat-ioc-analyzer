import unittest
from ioc_analyzer.core.deobfuscator import deobfuscate, defang, is_obfuscated


class TestDeobfuscator(unittest.TestCase):
    def test_protocol_deobfuscation(self):
        self.assertEqual(deobfuscate("hxxp://evil[.]com"), "http://evil.com")
        self.assertEqual(deobfuscate("hxxps://evil[.]com"), "https://evil.com")
        self.assertEqual(deobfuscate("h**p://evil[.]com"), "http://evil.com")
        self.assertEqual(deobfuscate("h**ps://evil[.]com"), "https://evil.com")
        self.assertEqual(deobfuscate("htxp://evil[.]com"), "http://evil.com")
        self.assertEqual(deobfuscate("fxp://evil[.]com"), "ftp://evil.com")

    def test_dots_deobfuscation(self):
        self.assertEqual(deobfuscate("evil[.]com"), "evil.com")
        self.assertEqual(deobfuscate("evil(.)com"), "evil.com")
        self.assertEqual(deobfuscate("evil{.}com"), "evil.com")
        self.assertEqual(deobfuscate("evil[dot]com"), "evil.com")
        self.assertEqual(deobfuscate("evil(dot)com"), "evil.com")
        self.assertEqual(deobfuscate("evil{dot}com"), "evil.com")
        self.assertEqual(deobfuscate("evil\\.com"), "evil.com")

    def test_ip_deobfuscation(self):
        self.assertEqual(deobfuscate("192[.]168[.]1[.]1"), "192.168.1.1")
        self.assertEqual(deobfuscate("93[.]123[.]85[.]239"), "93.123.85.239")

    def test_mirai_samples_deobfuscation(self):
        self.assertEqual(
            deobfuscate("hxxp://93[.]123[.]85[.]239/mirai[.]m68k"),
            "http://93.123.85.239/mirai.m68k"
        )
        self.assertEqual(
            deobfuscate("rebirthbot[.]icu"),
            "rebirthbot.icu"
        )

    def test_is_obfuscated(self):
        self.assertTrue(is_obfuscated("hxxp://evil[.]com"))
        self.assertTrue(is_obfuscated("1.2.3[.]4"))
        self.assertFalse(is_obfuscated("http://clean.com"))
        self.assertFalse(is_obfuscated("1.2.3.4"))

    def test_defang(self):
        self.assertEqual(defang("http://evil.com"), "hxxp://evil[.]com")
        self.assertEqual(defang("admin@evil.com"), "admin[@]evil[.]com")


if __name__ == "__main__":
    unittest.main()
