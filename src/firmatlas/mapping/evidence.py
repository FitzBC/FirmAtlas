"""Content-verified capture of replayable mapping evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json

from .domain import (
    AnalyzerIdentity,
    EVIDENCE_SCHEMA_VERSION,
    EvidenceAtom,
    EvidenceSpan,
    ObservationKind,
    SpanKind,
)
from .inventory import SourceArtifactEntry


_CONTENT_KINDS = frozenset({"file", "hardlink", "archive", "archive_member"})


@dataclass(frozen=True)
class SpanSelection:
    kind: SpanKind
    start_byte: int
    end_byte: int


@dataclass(frozen=True)
class EvidenceClaim:
    subject_ref: str
    predicate: str
    object_value: str
    observation_kind: ObservationKind
    capability: str
    confidence: float


def _text_position(content: bytes, offset: int) -> tuple:
    prefix = content[:offset].decode("utf-8")
    line = prefix.count("\n") + 1
    column = len(prefix.rsplit("\n", 1)[-1]) + 1
    return line, column


def _verify_source_content(source: SourceArtifactEntry, content: bytes) -> str:
    if source.kind not in _CONTENT_KINDS:
        raise ValueError(
            "source kind {} cannot publish content evidence".format(source.kind)
        )
    if source.content_sha256 is None:
        raise ValueError("evidence source must have a content SHA-256")
    if len(content) != source.size:
        raise ValueError("evidence content size does not match source inventory")
    content_sha256 = hashlib.sha256(content).hexdigest()
    if content_sha256 != source.content_sha256:
        raise ValueError("evidence content digest does not match source inventory")
    return content_sha256


def _typed_locator(content: bytes, selection: SpanSelection) -> tuple:
    if selection.kind is SpanKind.TEXT_UTF8:
        try:
            content.decode("utf-8")
            start_line, start_column = _text_position(content, selection.start_byte)
            end_line, end_column = _text_position(content, selection.end_byte)
        except UnicodeDecodeError as exc:
            raise ValueError(
                "text evidence requires valid UTF-8 and codepoint-aligned offsets"
            ) from exc
        locator = "text_utf8:bytes={}-{};lines={}:{}-{}:{}".format(
            selection.start_byte,
            selection.end_byte,
            start_line,
            start_column,
            end_line,
            end_column,
        )
        return locator, start_line, start_column, end_line, end_column
    if selection.kind is SpanKind.BINARY:
        locator = "binary:bytes={}-{}".format(
            selection.start_byte, selection.end_byte
        )
        return locator, None, None, None, None
    raise ValueError("unsupported evidence span kind")


def _evidence_id(
    span: EvidenceSpan,
    claim: EvidenceClaim,
    producer: AnalyzerIdentity,
) -> str:
    payload = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "span": asdict(span),
        "claim": asdict(claim),
        "producer": asdict(producer),
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        default=lambda value: value.value,
    ).encode("utf-8")
    return "evidence:{}".format(hashlib.sha256(encoded).hexdigest())


def capture_evidence(
    source: SourceArtifactEntry,
    content: bytes,
    selection: SpanSelection,
    claim: EvidenceClaim,
    producer: AnalyzerIdentity,
) -> EvidenceAtom:
    """Publish one minimal claim only after its exact source span is verified."""

    content_sha256 = _verify_source_content(source, content)
    if not 0 <= selection.start_byte < selection.end_byte <= len(content):
        raise ValueError("evidence byte range must be nonempty and within source")
    for label, value in (
        ("subject_ref", claim.subject_ref),
        ("predicate", claim.predicate),
        ("capability", claim.capability),
        ("producer name", producer.name),
        ("producer version", producer.version),
    ):
        if not value.strip():
            raise ValueError("{} must not be empty".format(label))
    if not 0.0 <= float(claim.confidence) <= 1.0:
        raise ValueError("evidence confidence must be between 0 and 1")

    excerpt = content[selection.start_byte : selection.end_byte]
    if (
        claim.observation_kind is ObservationKind.DIRECT_STATIC
        and selection.kind is SpanKind.TEXT_UTF8
        and claim.object_value.encode("utf-8") not in excerpt
    ):
        raise ValueError(
            "direct_static object_value must occur in the selected text span"
        )
    locator, start_line, start_column, end_line, end_column = _typed_locator(
        content, selection
    )

    span = EvidenceSpan(
        artifact_path=source.canonical_path,
        artifact_sha256=content_sha256,
        locator=locator,
        span_kind=selection.kind,
        start_byte=selection.start_byte,
        end_byte=selection.end_byte,
        excerpt_sha256=hashlib.sha256(excerpt).hexdigest(),
        start_line=start_line,
        start_column=start_column,
        end_line=end_line,
        end_column=end_column,
    )
    return EvidenceAtom(
        evidence_id=_evidence_id(span, claim, producer),
        subject_ref=claim.subject_ref,
        predicate=claim.predicate,
        object_value=claim.object_value,
        source_span=span,
        producer=producer.name,
        producer_version=producer.version,
        observation_kind=claim.observation_kind,
        capability=claim.capability,
        confidence=claim.confidence,
    )


def replay_evidence(
    evidence: EvidenceAtom,
    source: SourceArtifactEntry,
    content: bytes,
) -> bytes:
    """Return the exact excerpt only when every persisted locator still verifies."""

    span = evidence.source_span
    _verify_source_content(source, content)
    if source.canonical_path != span.artifact_path:
        raise ValueError("evidence path does not match source inventory")
    if source.content_sha256 != span.artifact_sha256:
        raise ValueError("evidence artifact digest does not match source inventory")
    if (
        span.start_byte is None
        or span.end_byte is None
        or not 0 <= span.start_byte < span.end_byte <= len(content)
    ):
        raise ValueError("evidence span does not contain a valid byte range")
    excerpt = content[span.start_byte : span.end_byte]
    if hashlib.sha256(excerpt).hexdigest() != span.excerpt_sha256:
        raise ValueError("evidence excerpt digest does not match source bytes")
    selection = SpanSelection(span.span_kind, span.start_byte, span.end_byte)
    try:
        (
            expected_locator,
            start_line,
            start_column,
            end_line,
            end_column,
        ) = _typed_locator(content, selection)
    except ValueError as exc:
        raise ValueError("legacy or unsupported evidence span cannot be replayed") from exc
    if (
        span.start_line,
        span.start_column,
        span.end_line,
        span.end_column,
    ) != (start_line, start_column, end_line, end_column):
        raise ValueError("evidence text coordinates do not replay")
    if span.locator != expected_locator:
        raise ValueError("evidence locator does not replay")
    return excerpt
