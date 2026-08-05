"""Application service coordinating source updates and persistence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import threading
import traceback
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from uuid import uuid4

from .models import RelevancePolicy, VulnerabilityRecord
from .relevance import FirmwareRelevanceClassifier
from .repository import IntelligenceRepository
from .sources import CisaKevSource, NvdSource
from .feeds import NvdFeedMirror


class SyncAlreadyRunning(RuntimeError):
    pass


class IntelligenceService:
    def __init__(
        self,
        repository: IntelligenceRepository,
        nvd: Optional[NvdSource] = None,
        cisa: Optional[CisaKevSource] = None,
        classifier: Optional[FirmwareRelevanceClassifier] = None,
        feed_mirror: Optional[NvdFeedMirror] = None,
    ) -> None:
        self.repository = repository
        self.nvd = nvd or NvdSource()
        self.cisa = cisa or CisaKevSource()
        self.classifier = classifier or FirmwareRelevanceClassifier()
        self.feed_mirror = feed_mirror or NvdFeedMirror()
        self._sync_lock = threading.Lock()
        self._start_lock = threading.Lock()
        self._pending_sync = False
        self.repository.fail_interrupted_sync_runs()

    def sync(self, sources: Sequence[str], days: int = 1) -> Dict[str, Any]:
        if not self._sync_lock.acquire(blocking=False):
            raise SyncAlreadyRunning("an intelligence update is already running")
        run_id = uuid4().hex
        sources = tuple(dict.fromkeys(sources))
        unknown = set(sources) - {"nvd", "cisa-kev"}
        if unknown:
            self._sync_lock.release()
            raise ValueError(
                "unsupported intelligence sources: {}".format(
                    ", ".join(sorted(unknown))
                )
            )
        days = max(1, min(int(days), 120))
        fetched = 0
        relevant = 0
        run_started = False
        try:
            self.repository.start_sync_run(run_id, sources)
            run_started = True
            policy = self.repository.get_policy()
            now = datetime.now(timezone.utc)
            if "nvd" in sources:
                cursor_value = self.repository.get_cursor("nvd")
                requested_start = now - timedelta(days=days)
                if cursor_value:
                    cursor = datetime.fromisoformat(
                        cursor_value.replace("Z", "+00:00")
                    )
                    requested_start = max(
                        requested_start, cursor - timedelta(minutes=5)
                    )
                counts = self._ingest(
                    self.nvd.fetch_modified(requested_start, now), policy
                )
                fetched += counts[0]
                relevant += counts[1]
                self.repository.save_cursor("nvd", now.isoformat())
            if "cisa-kev" in sources:
                counts = self._ingest(self.cisa.fetch_all(), policy)
                fetched += counts[0]
                relevant += counts[1]
                self.repository.save_cursor("cisa-kev", now.isoformat())
            self.repository.reclassify(self.classifier, policy)
            self.repository.refresh_analytics()
            self.repository.finish_sync_run(run_id, "succeeded", fetched, relevant)
        except BaseException as error:
            if run_started:
                self.repository.finish_sync_run(
                    run_id,
                    "failed",
                    fetched,
                    relevant,
                    "{}: {}".format(type(error).__name__, error),
                )
            raise
        finally:
            self._sync_lock.release()
        return self.repository.latest_sync_run() or {"run_id": run_id}

    def start_sync(self, sources: Sequence[str], days: int = 1) -> str:
        with self._start_lock:
            if self._pending_sync or self._sync_lock.locked():
                raise SyncAlreadyRunning("an intelligence update is already running")
            self._pending_sync = True
            request_id = uuid4().hex

        def run() -> None:
            try:
                self.sync(sources, days)
            except BaseException:
                traceback.print_exc()
            finally:
                with self._start_lock:
                    self._pending_sync = False

        threading.Thread(
            target=run,
            name="firmatlas-intelligence-{}".format(request_id),
            daemon=True,
        ).start()
        return request_id

    def update_policy(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        current = self.repository.get_policy().to_dict()
        current.update(payload)
        policy = RelevancePolicy.from_dict(current)
        self._validate_policy(policy)
        self.repository.save_policy(policy)
        count = self.repository.reclassify(self.classifier, policy)
        self.repository.refresh_analytics()
        return {"policy": policy.to_dict(), "reclassified_count": count}

    def bootstrap_feeds(
        self,
        years: Optional[Sequence[str]] = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        names = tuple(years or self.feed_mirror.yearly_names())
        invalid = [name for name in names if not name.isdigit()]
        if invalid:
            raise ValueError("year feeds must be numeric")
        return self._sync_feeds(names, force=force, mode="bootstrap")

    def update_feeds(self, force: bool = False) -> Dict[str, Any]:
        yearly_states = [
            state for state in self.repository.list_feed_states()
            if state["feed_name"].isdigit() and state["status"] == "imported"
        ]
        expected = tuple(self.feed_mirror.yearly_names())
        missing = [name for name in expected if not any(state["feed_name"] == name for state in yearly_states)]
        if missing:
            raise ValueError(
                "full feed bootstrap is incomplete; missing {} year feeds".format(len(missing))
            )
        modified = self.repository.get_feed_state("modified")
        names: Sequence[str] = ("modified",)
        if modified and modified.get("imported_at"):
            imported_at = datetime.fromisoformat(str(modified["imported_at"]).replace("Z", "+00:00"))
            if datetime.now(timezone.utc) - imported_at > timedelta(days=8):
                names = expected + ("modified",)
        return self._sync_feeds(names, force=force, mode="update")

    def _sync_feeds(
        self,
        names: Sequence[str],
        force: bool,
        mode: str,
    ) -> Dict[str, Any]:
        if not self._sync_lock.acquire(blocking=False):
            raise SyncAlreadyRunning("an intelligence update is already running")
        imported = 0
        relevant = 0
        skipped: List[str] = []
        completed: List[str] = []
        policy = self.repository.get_policy()
        needs_fts_rebuild = False
        try:
            for name in names:
                meta = self.feed_mirror.fetch_meta(name)
                state = self.repository.get_feed_state(name)
                if not force and state and state.get("sha256") == meta.sha256 and state.get("status") == "imported":
                    skipped.append(name)
                    continue
                try:
                    path = self.feed_mirror.download(name, meta)
                    needs_fts_rebuild = True
                    counts = self._ingest(
                        self.feed_mirror.records(path), policy,
                        batch_size=2000, maintain_fts=False, maintain_cwes=False,
                    )
                    imported += counts[0]
                    relevant += counts[1]
                    completed.append(name)
                    self.repository.save_feed_state(
                        name, meta.last_modified, meta.sha256, "imported",
                        str(Path(path).resolve()), counts[0], counts[1],
                    )
                except BaseException as error:
                    self.repository.save_feed_state(
                        name, meta.last_modified, meta.sha256, "failed", error=str(error)
                    )
                    raise
        finally:
            try:
                if needs_fts_rebuild:
                    self.repository.rebuild_fts()
                    self.repository.rebuild_cwe_index()
                    self.repository.refresh_analytics()
            finally:
                self._sync_lock.release()
        return {
            "mode": mode,
            "feeds_imported": completed,
            "feeds_skipped": skipped,
            "imported_count": imported,
            "relevant_count": relevant,
            "feed_states": self.repository.list_feed_states(),
        }

    def _ingest(
        self,
        records: Iterable[VulnerabilityRecord],
        policy: RelevancePolicy,
        batch_size: int = 1,
        maintain_fts: bool = True,
        maintain_cwes: bool = True,
    ) -> Tuple[int, int]:
        fetched = 0
        relevant = 0
        batch: List[Tuple[VulnerabilityRecord, Any]] = []
        for record in records:
            if not record.identifier:
                continue
            decision = self.classifier.classify(record, policy)
            batch.append((record, decision))
            if len(batch) >= batch_size:
                counts = self.repository.upsert_many(
                    batch, maintain_fts=maintain_fts, maintain_cwes=maintain_cwes
                )
                fetched += counts[0]
                relevant += counts[1]
                batch = []
        if batch:
            counts = self.repository.upsert_many(
                batch, maintain_fts=maintain_fts, maintain_cwes=maintain_cwes
            )
            fetched += counts[0]
            relevant += counts[1]
        return fetched, relevant

    @staticmethod
    def _validate_policy(policy: RelevancePolicy) -> None:
        if not (
            0
            <= policy.review_threshold
            <= policy.likely_threshold
            <= policy.strong_threshold
            <= 100
        ):
            raise ValueError("thresholds must be ordered between 0 and 100")
        for values in (
            policy.firmware_keywords,
            policy.device_keywords,
            policy.vendor_keywords,
            policy.firmware_only_vendors,
        ):
            if len(values) > 100:
                raise ValueError("each keyword group is limited to 100 entries")
