"""Application module for cached vulnerability semantic analysis."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import threading
import traceback
from typing import Any, Dict, Optional
from uuid import uuid4

from .repository import IntelligenceRepository
from .semantic import (
    OpenAICompatibleSemanticAnalyzer,
    RuleSemanticAnalyzer,
    SemanticModelSettings,
    merge_analysis,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SemanticAnalysisAlreadyRunning(RuntimeError):
    pass


class SemanticAnalysisService:
    """Deep module: cache, persistence and batch lifecycle behind two analysis methods."""

    def __init__(
        self,
        repository: IntelligenceRepository,
        rule_analyzer: Optional[RuleSemanticAnalyzer] = None,
        llm_analyzer: Optional[OpenAICompatibleSemanticAnalyzer] = None,
    ) -> None:
        self.repository = repository
        self.rule_analyzer = rule_analyzer or RuleSemanticAnalyzer()
        self.llm_analyzer = llm_analyzer or OpenAICompatibleSemanticAnalyzer()
        self._batch_lock = threading.Lock()
        self._start_lock = threading.Lock()
        self._pending_batch = False
        self.repository.fail_interrupted_semantic_jobs()

    def analyze_identifier(self, identifier: str, force: bool = False) -> Dict[str, Any]:
        vulnerability = self.repository.get(identifier)
        if not vulnerability:
            raise KeyError(identifier)
        return self._analyze_vulnerability(vulnerability, force)

    def _analyze_vulnerability(
        self,
        vulnerability: Dict[str, Any],
        force: bool = False,
        use_llm: Optional[bool] = None,
    ) -> Dict[str, Any]:
        identifier = vulnerability["identifier"]
        settings = self._settings()
        # A full-corpus job is rules-only unless its caller explicitly opts in.
        # Single-record analysis keeps following the configured model setting.
        if use_llm is False:
            settings = replace(settings, enabled=False)
        input_sha256 = self._input_sha256(vulnerability)
        fingerprint = settings.fingerprint()
        cached = self.repository.get_semantic_analysis(
            identifier, input_sha256, fingerprint
        )
        if cached and not force:
            cached["cached"] = True
            return cached
        started_at = _now()
        rules = self.rule_analyzer.analyze_text(
            identifier, vulnerability["title"], vulnerability["summary"]
        )
        result = rules.to_dict()
        strategy = "rules"
        status = "succeeded"
        warning = None
        prompt_tokens = 0
        completion_tokens = 0
        if settings.active:
            strategy = "hybrid"
            try:
                model_result = self.llm_analyzer.enrich(
                    identifier, vulnerability["title"], vulnerability["summary"],
                    rules, settings,
                )
                usage = model_result.pop("usage", {})
                prompt_tokens = int(usage.get("prompt_tokens") or 0)
                completion_tokens = int(usage.get("completion_tokens") or 0)
                result = merge_analysis(rules, model_result)
            except BaseException as error:
                status = "partial"
                warning = "{}: {}".format(type(error).__name__, error)[:1000]
        saved = self.repository.save_semantic_analysis(
            {
                "analysis_id": uuid4().hex,
                "vulnerability_identifier": identifier,
                "input_sha256": input_sha256,
                "analyzer_fingerprint": fingerprint,
                "strategy": strategy,
                "status": status,
                "result": result,
                "warning": warning,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "created_at": started_at,
                "finished_at": _now(),
            }
        )
        saved["cached"] = False
        return saved

    def get_settings(self) -> Dict[str, Any]:
        return self._settings().public_dict()

    def update_settings(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        current = self._settings()
        value = {
            "enabled": current.enabled,
            "base_url": current.base_url,
            "model": current.model,
            "api_key": current.api_key,
            "timeout_seconds": current.timeout_seconds,
            "temperature": current.temperature,
            "max_tokens": current.max_tokens,
        }
        value.update({key: item for key, item in payload.items() if key != "has_api_key"})
        if "api_key" in payload and not str(payload.get("api_key") or "").strip():
            value["api_key"] = "" if payload.get("clear_api_key") else current.api_key
        value.pop("clear_api_key", None)
        settings = SemanticModelSettings.from_dict(value)
        self.repository.save_semantic_settings(value)
        return settings.public_dict()

    def test_model(self, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        settings = self._settings()
        if payload:
            value = {
                "enabled": settings.enabled, "base_url": settings.base_url,
                "model": settings.model, "api_key": settings.api_key,
                "timeout_seconds": settings.timeout_seconds,
                "temperature": settings.temperature, "max_tokens": settings.max_tokens,
            }
            value.update({key: item for key, item in payload.items() if key in value and item != ""})
            settings = SemanticModelSettings.from_dict(value)
        if not settings.api_key:
            raise ValueError("model API key is required")
        return self.llm_analyzer.test_connection(settings)

    def run_batch(self, force: bool = False, use_llm: bool = False) -> Dict[str, Any]:
        if not self._batch_lock.acquire(blocking=False):
            raise SemanticAnalysisAlreadyRunning("semantic analysis is already running")
        job_id = uuid4().hex
        overview = self.repository.semantic_overview()
        strategy = "hybrid" if use_llm and self._settings().active else "rules"
        self.repository.start_semantic_job(job_id, strategy, force, overview["total"])
        processed = analyzed = cached_count = failed = interfaces = parameters = 0
        after = ""
        try:
            while True:
                candidates = self.repository.semantic_candidates(after, 500)
                if not candidates:
                    break
                for vulnerability in candidates:
                    processed += 1
                    after = vulnerability["identifier"]
                    try:
                        result = self._analyze_vulnerability(
                            vulnerability, force, use_llm=use_llm
                        )
                        if result["cached"]:
                            cached_count += 1
                        else:
                            analyzed += 1
                            interfaces += len(result["result"].get("interfaces", []))
                            parameters += len(result["result"].get("parameters", []))
                    except BaseException:
                        failed += 1
                    if processed % 100 == 0:
                        self.repository.update_semantic_job(
                            job_id, processed_count=processed,
                            analyzed_count=analyzed, cached_count=cached_count,
                            failed_count=failed, interfaces_count=interfaces,
                            parameters_count=parameters,
                        )
            self.repository.update_semantic_job(
                job_id, status="succeeded", processed_count=processed,
                analyzed_count=analyzed, cached_count=cached_count,
                failed_count=failed, interfaces_count=interfaces,
                parameters_count=parameters, finished_at=_now(),
            )
        except BaseException as error:
            self.repository.update_semantic_job(
                job_id, status="failed", processed_count=processed,
                analyzed_count=analyzed, cached_count=cached_count,
                failed_count=failed, interfaces_count=interfaces,
                parameters_count=parameters, finished_at=_now(),
                error="{}: {}".format(type(error).__name__, error),
            )
            raise
        finally:
            self._batch_lock.release()
        return self.repository.latest_semantic_job() or {"job_id": job_id}

    def start_batch(self, force: bool = False, use_llm: bool = False) -> str:
        with self._start_lock:
            latest = self.repository.latest_semantic_job()
            if self._pending_batch or self._batch_lock.locked() or (latest and latest["status"] == "running"):
                raise SemanticAnalysisAlreadyRunning("semantic analysis is already running")
            self._pending_batch = True
            request_id = uuid4().hex

        def run() -> None:
            try:
                self.run_batch(force, use_llm=use_llm)
            except BaseException:
                traceback.print_exc()
            finally:
                with self._start_lock:
                    self._pending_batch = False

        threading.Thread(target=run, name="firmatlas-semantic-{}".format(request_id), daemon=True).start()
        return request_id

    def overview(self) -> Dict[str, Any]:
        return self.repository.semantic_overview()

    def latest_job(self) -> Optional[Dict[str, Any]]:
        return self.repository.latest_semantic_job()

    def _settings(self) -> SemanticModelSettings:
        return SemanticModelSettings.from_dict(
            self.repository.get_semantic_settings() or {}
        )

    @staticmethod
    def _input_sha256(vulnerability: Dict[str, Any]) -> str:
        value = json.dumps(
            {
                "identifier": vulnerability["identifier"],
                "title": vulnerability.get("title") or "",
                "summary": vulnerability.get("summary") or "",
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(value.encode("utf-8")).hexdigest()
