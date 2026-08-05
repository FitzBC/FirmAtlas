"""Fast end-to-end assertions for intelligence filter correctness and latency."""

from __future__ import annotations

import json
import sys
import time
from typing import Any, Callable, Dict
from urllib.request import urlopen


BASE_URL = "http://127.0.0.1:8787/api/intelligence/vulnerabilities"
MAX_SECONDS = 1.5


def fetch(query: str) -> Dict[str, Any]:
    started = time.perf_counter()
    with urlopen("{}?{}".format(BASE_URL, query), timeout=10) as response:
        payload = json.load(response)["data"]
    elapsed = time.perf_counter() - started
    print("{:<58} {:>7.3f}s {:>7} hits".format(query, elapsed, payload["total"]))
    if elapsed > MAX_SECONDS:
        raise AssertionError("filter exceeded {:.1f}s latency budget".format(MAX_SECONDS))
    return payload


def assert_items(query: str, predicate: Callable[[Dict[str, Any]], bool]) -> None:
    page = fetch(query)
    if not page["items"]:
        raise AssertionError("expected non-empty results for {}".format(query))
    if not all(predicate(item) for item in page["items"]):
        raise AssertionError("response contains items outside filter: {}".format(query))


def main() -> int:
    assert_items("relevance=firmware&severity=CRITICAL&limit=50", lambda item: item["severity"] == "CRITICAL")
    assert_items("relevance=firmware&kev=true&limit=50", lambda item: item["kev"] is True)
    assert_items("relevance=firmware&exploit=true&limit=50", lambda item: item["has_exploit"] is True)
    assert_items("relevance=firmware&vendor=Tenda&limit=50", lambda item: (item["vendor"] or "").lower() == "tenda")
    assert_items(
        "relevance=firmware&vendor=Tenda&severity=CRITICAL&exploit=true&limit=50",
        lambda item: (item["vendor"] or "").lower() == "tenda"
        and item["severity"] == "CRITICAL"
        and item["has_exploit"] is True,
    )
    print("all filter assertions passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError) as error:
        print("FAILED: {}".format(error), file=sys.stderr)
        raise SystemExit(1)
