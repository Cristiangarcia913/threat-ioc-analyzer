import unittest
from ioc_analyzer.core.pipeline import IOCPipeline
from ioc_analyzer.core.classifier import IOCType


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.pipeline = IOCPipeline()

    def test_pipeline_single_ioc_no_network(self):
        res = self.pipeline.process_single(
            "hxxp://93[.]123[.]85[.]239/mirai[.]m68k",
            skip_dns=True,
            skip_rdap=True
        )
        self.assertEqual(res["original"], "hxxp://93[.]123[.]85[.]239/mirai[.]m68k")
        self.assertTrue(res["was_obfuscated"])
        self.assertEqual(res["deobfuscated"], "http://93.123.85.239/mirai.m68k")
        self.assertEqual(res["normalized"], "http://93.123.85.239/mirai.m68k")
        self.assertEqual(res["type"], IOCType.URL)

    def test_pipeline_mirai_samples(self):
        samples = [
            "miraicnc[.]ddns[.]net",
            "45[.]77[.]89[.]12",
            "196[.]251[.]80[.]5:3778"
        ]
        results = self.pipeline.process_batch(samples, skip_dns=True, skip_rdap=True)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["type"], IOCType.DOMAIN)
        self.assertEqual(results[1]["type"], IOCType.IPV4)
        self.assertEqual(results[2]["type"], IOCType.IPV4_PORT)


if __name__ == "__main__":
    unittest.main()
