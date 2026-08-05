import gzip
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from firmatlas.intelligence.feeds import FeedMeta, NvdFeedMirror, iter_vulnerability_items
from firmatlas.intelligence.sources import SourceError


class NvdFeedTests(unittest.TestCase):
    def test_meta_parse_and_streaming_parser(self) -> None:
        payload = json.dumps({"resultsPerPage": 2, "vulnerabilities": [
            {"cve": {"id": "CVE-2002-0001"}},
            {"cve": {"id": "CVE-2002-0002"}},
        ]}).encode()
        with TemporaryDirectory() as directory:
            path = Path(directory) / "feed.json.gz"
            with gzip.open(path, "wb") as output:
                output.write(payload)
            meta = FeedMeta.parse(
                "lastModifiedDate:2026-08-05T00:00:00-04:00\n"
                "size:{}\nzipSize:0\ngzSize:{}\nsha256:{}\n".format(
                    len(payload), path.stat().st_size, hashlib.sha256(payload).hexdigest()
                )
            )

            NvdFeedMirror.verify(path, meta)
            items = list(iter_vulnerability_items(path, chunk_size=19))

        self.assertEqual(["CVE-2002-0001", "CVE-2002-0002"], [item["cve"]["id"] for item in items])

    def test_integrity_failure_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "feed.json.gz"
            with gzip.open(path, "wb") as output:
                output.write(b"{}")
            meta = FeedMeta("now", 2, 0, path.stat().st_size, "0" * 64)
            with self.assertRaises(SourceError):
                NvdFeedMirror.verify(path, meta)

    def test_verified_cache_is_reused_without_network(self) -> None:
        payload = b'{"vulnerabilities":[]}'
        with TemporaryDirectory() as directory:
            mirror = NvdFeedMirror(directory)
            path = Path(directory) / "nvdcve-2.0-2002.json.gz"
            with gzip.open(path, "wb") as output:
                output.write(payload)
            meta = FeedMeta("now", len(payload), 0, path.stat().st_size, hashlib.sha256(payload).hexdigest())
            mirror._open = lambda _url: self.fail("network should not be used")

            self.assertEqual(path, mirror.download("2002", meta))

    def test_years_include_timeline_start_and_current(self) -> None:
        names = list(NvdFeedMirror.yearly_names(2026))
        self.assertEqual("2002", names[0])
        self.assertEqual("2026", names[-1])
        self.assertEqual(25, len(names))


if __name__ == "__main__":
    unittest.main()
