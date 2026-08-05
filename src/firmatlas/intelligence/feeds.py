"""NVD JSON 2.0 feed mirroring and bounded-memory parsing."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any, Dict, Iterator, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .sources import SourceError, normalize_nvd


NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
FIRST_NVD_YEAR = 2002


@dataclass(frozen=True)
class FeedMeta:
    last_modified: str
    size: int
    zip_size: int
    gz_size: int
    sha256: str

    @classmethod
    def parse(cls, text: str) -> "FeedMeta":
        values: Dict[str, str] = {}
        for line in text.splitlines():
            key, separator, value = line.partition(":")
            if separator:
                values[key.strip()] = value.strip()
        required = ("lastModifiedDate", "size", "zipSize", "gzSize", "sha256")
        missing = [key for key in required if key not in values]
        if missing:
            raise ValueError("invalid NVD feed metadata; missing {}".format(", ".join(missing)))
        return cls(
            last_modified=values["lastModifiedDate"],
            size=int(values["size"]),
            zip_size=int(values["zipSize"]),
            gz_size=int(values["gzSize"]),
            sha256=values["sha256"].lower(),
        )


class NvdFeedMirror:
    def __init__(
        self,
        cache_dir: str = "var/nvd-feeds",
        base_url: str = NVD_FEED_BASE,
        timeout: float = 120.0,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    @staticmethod
    def yearly_names(current_year: Optional[int] = None) -> Iterator[str]:
        year = current_year or datetime.now(timezone.utc).year
        for value in range(FIRST_NVD_YEAR, year + 1):
            yield str(value)

    def fetch_meta(self, name: str) -> FeedMeta:
        with self._open(self._url(name, "meta")) as response:
            return FeedMeta.parse(response.read().decode("utf-8"))

    def download(self, name: str, meta: Optional[FeedMeta] = None) -> Path:
        meta = meta or self.fetch_meta(name)
        target = self.cache_dir / self._filename(name)
        partial = target.with_suffix(target.suffix + ".part")
        if target.exists() and target.stat().st_size == meta.gz_size:
            try:
                self.verify(target, meta)
                partial.unlink(missing_ok=True)
                return target
            except (OSError, SourceError):
                target.unlink(missing_ok=True)
        try:
            with self._open(self._url(name, "json.gz")) as response, partial.open("wb") as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
            if partial.stat().st_size != meta.gz_size:
                raise SourceError(
                    "NVD feed {} compressed size mismatch: expected {}, received {}".format(
                        name, meta.gz_size, partial.stat().st_size
                    )
                )
            self.verify(partial, meta)
            partial.replace(target)
            return target
        except BaseException:
            partial.unlink(missing_ok=True)
            raise

    @staticmethod
    def verify(path: Path, meta: FeedMeta) -> None:
        digest = hashlib.sha256()
        size = 0
        with gzip.open(path, "rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
        if size != meta.size or digest.hexdigest().lower() != meta.sha256:
            raise SourceError("NVD feed integrity check failed for {}".format(path.name))

    @staticmethod
    def records(path: Path) -> Iterator[Any]:
        for item in iter_vulnerability_items(path):
            yield normalize_nvd(item.get("cve", item))

    def _url(self, name: str, extension: str) -> str:
        return "{}/nvdcve-2.0-{}.{}".format(self.base_url, name, extension)

    @staticmethod
    def _filename(name: str) -> str:
        return "nvdcve-2.0-{}.json.gz".format(name)

    def _open(self, url: str):
        request = Request(
            url,
            headers={
                "Accept": "application/json, text/plain, */*",
                "User-Agent": "FirmAtlas/0.2 (+https://github.com/FitzBC/FirmAtlas)",
            },
        )
        try:
            return urlopen(request, timeout=self.timeout)
        except (HTTPError, URLError, TimeoutError) as error:
            raise SourceError("failed to fetch {}: {}".format(url, error)) from error


def iter_vulnerability_items(path: Path, chunk_size: int = 1024 * 1024) -> Iterator[Dict[str, Any]]:
    """Stream the top-level vulnerabilities array without loading a yearly feed."""
    decoder = json.JSONDecoder()
    buffer = ""
    position = 0
    array_started = False
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        while True:
            chunk = stream.read(chunk_size)
            eof = not chunk
            buffer = buffer[position:] + chunk
            position = 0
            if not array_started:
                marker = buffer.find('"vulnerabilities"')
                if marker < 0:
                    if eof:
                        raise ValueError("NVD feed has no vulnerabilities array")
                    continue
                bracket = buffer.find("[", marker)
                if bracket < 0:
                    if eof:
                        raise ValueError("invalid NVD vulnerabilities array")
                    continue
                position = bracket + 1
                array_started = True
            while True:
                while position < len(buffer) and buffer[position] in " \r\n\t,":
                    position += 1
                if position < len(buffer) and buffer[position] == "]":
                    return
                try:
                    item, position = decoder.raw_decode(buffer, position)
                except json.JSONDecodeError:
                    if eof:
                        raise ValueError("truncated NVD feed near byte {}".format(position))
                    break
                if isinstance(item, dict):
                    yield item
