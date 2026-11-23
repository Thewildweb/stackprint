import os
import unittest

from stackprint import Scanner


@unittest.skipUnless(os.environ.get("STACKPRINT_BIN"), "STACKPRINT_BIN not set")
class ClientTest(unittest.TestCase):
    def test_scan_in_order(self):
        with Scanner() as sc:
            docs = [
                {"url": "https://a.test/", "html": '<meta name="generator" content="WordPress 6.5.3">'},
                {"url": "https://b.test/", "headers": [["Server", "nginx/1.24.0"]]},
            ]
            results = list(sc.scan_many(docs))
        self.assertEqual([r["url"] for r in results], ["https://a.test/", "https://b.test/"])
        wp = {d["tech_id"]: d for d in results[0]["detections"]}["wordpress"]
        self.assertEqual(wp["version"], "6.5.3")
        ng = {d["tech_id"]: d for d in results[1]["detections"]}["nginx"]
        self.assertEqual(ng["version"], "1.24.0")


if __name__ == "__main__":
    unittest.main()
