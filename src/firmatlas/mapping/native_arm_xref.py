"""Deterministic ARM32 PIC literal cross-references for firmware ELF files."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import struct
from typing import Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry
from .native_deep import (
    _ALLOC,
    _ARM_MACHINE,
    _EXEC,
    _file_offset_for_address,
    _find_pic_base,
    _parse_elf,
    _word_at_address,
)


ARM_LITERAL_XREF_SCHEMA_VERSION = "firmatlas.mapping.arm-literal-xref/v1alpha1"
_PRODUCER = AnalyzerIdentity("native-arm-literal-xref", "0.1.0")
ARM_FEATURE_PIVOT_SCHEMA_VERSION = (
    "firmatlas.mapping.arm-feature-pivot/v1alpha1"
)
_FEATURE_PIVOT_PRODUCER = AnalyzerIdentity(
    "native-arm-feature-pivot", "0.1.0"
)
_CONTENT_KINDS = frozenset({"file", "hardlink", "archive", "archive_member"})


@dataclass(frozen=True)
class ArmLiteralAnchor:
    target_ref: str
    literal_value: str

    def __post_init__(self) -> None:
        if not self.target_ref.strip() or not self.literal_value.strip():
            raise ValueError("ARM literal anchor requires target_ref and literal_value")
        if "\x00" in self.literal_value:
            raise ValueError("ARM literal anchor cannot contain NUL")


@dataclass(frozen=True)
class ArmFeaturePivotAnchor:
    target_ref: str
    feature_token: str

    def __post_init__(self) -> None:
        if (
            not self.target_ref.strip()
            or len(self.feature_token.strip()) < 4
            or not self.feature_token.strip().isascii()
            or not self.feature_token.strip().isalnum()
        ):
            raise ValueError(
                "ARM feature pivot requires an ASCII alphanumeric token "
                "of at least four characters"
            )


@dataclass(frozen=True)
class ArmFunctionTarget:
    target_ref: str
    function_address: int

    def __post_init__(self) -> None:
        if not self.target_ref.strip() or self.function_address < 0:
            raise ValueError("ARM function target requires identity and address")


@dataclass(frozen=True)
class ArmLiteralXrefProfile:
    name: str = "arm32-pic-got-literal/v1"
    max_pic_base_distance: int = 16 * 1024

    def __post_init__(self) -> None:
        if not self.name.strip() or self.max_pic_base_distance <= 0:
            raise ValueError("ARM literal xref profile is invalid")


@dataclass(frozen=True)
class ArmLiteralXrefPolicy:
    max_source_bytes: int = 64 * 1024 * 1024
    max_anchors: int = 10_000
    max_xrefs: int = 20_000

    def __post_init__(self) -> None:
        if min(self.max_source_bytes, self.max_anchors, self.max_xrefs) <= 0:
            raise ValueError("ARM literal xref limits must be positive")


@dataclass(frozen=True)
class ArmLiteralXref:
    xref_id: str
    target_ref: str
    literal_value: str
    literal_address: int
    literal_offset: int
    instruction_address: int
    instruction_offset: int
    function_start_address: int
    function_start_offset: int
    pic_base_address: int
    pic_base_offset: int
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class ArmLiteralXrefResult:
    source_path: str
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    profile: str
    xrefs: Tuple[ArmLiteralXref, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[str, ...] = ()
    schema_version: str = ARM_LITERAL_XREF_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "xrefs": [asdict(item) for item in self.xrefs],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
        }


@dataclass(frozen=True)
class ArmFeaturePivot:
    pivot_id: str
    target_ref: str
    feature_token: str
    literal_value: str
    function_start_address: int
    instruction_address: int
    route_binding_ref: str
    route_token: str
    handler_identity: str
    handler_symbol: str
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class ArmFeaturePivotResult:
    source_path: str
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    profile: str
    pivots: Tuple[ArmFeaturePivot, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[str, ...] = ()
    schema_version: str = ARM_FEATURE_PIVOT_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "pivots": [asdict(item) for item in self.pivots],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
        }


def _empty(
    source: SourceArtifactEntry,
    profile: ArmLiteralXrefProfile,
    status: CoverageStatus,
    diagnostic: str,
    processed_bytes: int = 0,
) -> ArmLiteralXrefResult:
    return ArmLiteralXrefResult(
        source.canonical_path,
        status,
        processed_bytes,
        _PRODUCER,
        profile.name,
        (),
        (),
        (diagnostic,),
    )


def _identity(source_path: str, anchor: ArmLiteralAnchor, address: int) -> str:
    raw = json.dumps(
        [source_path, anchor.target_ref, anchor.literal_value, address],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return "arm-literal-xref:" + hashlib.sha256(raw).hexdigest()


def _function_start(elf, content: bytes, address: int, maximum: int):
    executable = next((
        section for section in elf.sections
        if section.section_type == 1
        and section.flags & (_ALLOC | _EXEC) == (_ALLOC | _EXEC)
        and section.address <= address < section.address + section.size
    ), None)
    if executable is None:
        return None
    lower = max(executable.address, address - maximum)
    for candidate in range(address, lower - 1, -4):
        word = _word_at_address(elf, content, candidate)
        if (
            word is not None
            and word & 0xFFFF0000 == 0xE92D0000
            and word & (1 << 14)
        ):
            offset = _file_offset_for_address(elf, candidate)
            if offset is not None:
                return candidate, offset
    return None


def discover_arm_literal_xrefs(
    source: SourceArtifactEntry,
    content: bytes,
    anchors: Tuple[ArmLiteralAnchor, ...],
    profile: ArmLiteralXrefProfile = ArmLiteralXrefProfile(),
    policy: ArmLiteralXrefPolicy = ArmLiteralXrefPolicy(),
) -> ArmLiteralXrefResult:
    """Prove ARM32 PIC GOT-relative references to exact anchored literals."""
    if source.kind not in _CONTENT_KINDS:
        return _empty(source, profile, CoverageStatus.UNSUPPORTED, "unsupported_source_kind")
    if source.content_sha256 is None or len(content) != source.size \
            or hashlib.sha256(content).hexdigest() != source.content_sha256:
        return _empty(source, profile, CoverageStatus.FAILED, "source_mismatch")
    if len(content) > policy.max_source_bytes:
        return _empty(source, profile, CoverageStatus.SKIPPED_BY_POLICY, "source_budget_exceeded")
    ordered_anchors = tuple(sorted(set(anchors), key=lambda item: (
        item.target_ref, item.literal_value,
    )))
    if len(ordered_anchors) > policy.max_anchors:
        return _empty(source, profile, CoverageStatus.SKIPPED_BY_POLICY, "anchor_budget_exceeded")
    try:
        elf = _parse_elf(content)
        if elf.pointer_size != 4 or elf.machine != _ARM_MACHINE:
            return _empty(
                source, profile, CoverageStatus.UNSUPPORTED,
                "unsupported_architecture", len(content),
            )
        got = next((
            section for section in elf.sections
            if section.name == ".got" and section.section_type == 1
            and section.flags & _ALLOC and not section.flags & _EXEC
        ), None)
        if got is None:
            return _empty(
                source, profile, CoverageStatus.UNSUPPORTED,
                "missing_got_section", len(content),
            )
    except TypeError:
        return _empty(source, profile, CoverageStatus.UNSUPPORTED, "unsupported_binary_format")
    except (ValueError, struct.error) as exc:
        return _empty(
            source, profile, CoverageStatus.FAILED,
            "malformed_elf:{}".format(exc), len(content),
        )

    locations = {}
    for anchor in ordered_anchors:
        needle = anchor.literal_value.encode("utf-8") + b"\x00"
        for section in elf.sections:
            if not (
                section.section_type == 1
                and section.flags & _ALLOC
                and not section.flags & _EXEC
            ):
                continue
            cursor = 0
            section_bytes = content[section.offset : section.offset + section.size]
            while True:
                relative = section_bytes.find(needle, cursor)
                if relative < 0:
                    break
                locations.setdefault(section.address + relative, []).append(
                    (anchor, section.offset + relative)
                )
                cursor = relative + 1

    xrefs = []
    atoms = []
    limited = False
    for section in elf.sections:
        if not (
            section.section_type == 1
            and section.flags & (_ALLOC | _EXEC) == (_ALLOC | _EXEC)
        ):
            continue
        for relative in range(0, max(0, section.size - 8 + 1), 4):
            instruction_offset = section.offset + relative
            instruction_address = section.address + relative
            load, add = struct.unpack_from(
                elf.endian_prefix + "II", content, instruction_offset
            )
            if load & 0x0F7F0000 != 0x051F0000:
                continue
            register = (load >> 12) & 0xF
            if register in {4, 15} or add != (
                0xE0840000 | (register << 12) | register
            ):
                continue
            displacement = load & 0xFFF
            literal_pointer_address = instruction_address + 8 + (
                displacement if load & 0x00800000 else -displacement
            )
            delta = _word_at_address(elf, content, literal_pointer_address)
            if delta is None:
                continue
            resolved_address = (got.address + delta) & 0xFFFFFFFF
            if resolved_address not in locations:
                continue
            function = _function_start(
                elf, content, instruction_address, profile.max_pic_base_distance
            )
            pic_base = _find_pic_base(
                elf, content, instruction_address, got.address,
                profile.max_pic_base_distance,
            )
            if function is None or pic_base is None:
                continue
            for anchor, literal_offset in locations[resolved_address]:
                if len(xrefs) >= policy.max_xrefs:
                    limited = True
                    break
                xref_id = _identity(source.canonical_path, anchor, instruction_address)
                literal_atom = capture_evidence(
                    source, content,
                    SpanSelection(
                        SpanKind.BINARY, literal_offset,
                        literal_offset + len(anchor.literal_value.encode("utf-8")),
                    ),
                    EvidenceClaim(
                        xref_id, "mentions_literal", anchor.literal_value,
                        ObservationKind.DIRECT_STATIC, "mentions_literal", 1.0,
                    ), _PRODUCER,
                )
                pic_atom = capture_evidence(
                    source, content,
                    SpanSelection(SpanKind.BINARY, pic_base[1], pic_base[1] + 8),
                    EvidenceClaim(
                        xref_id, "establishes_pic_base",
                        "got@0x{:08x}".format(got.address),
                        ObservationKind.DETERMINISTIC_DERIVED,
                        "establishes_pic_base", 1.0,
                    ), _PRODUCER,
                )
                xref_atom = capture_evidence(
                    source, content,
                    SpanSelection(
                        SpanKind.BINARY, instruction_offset, instruction_offset + 8
                    ),
                    EvidenceClaim(
                        xref_id, "references_literal", anchor.literal_value,
                        ObservationKind.DETERMINISTIC_DERIVED,
                        "references_literal", 1.0,
                    ), _PRODUCER,
                )
                function_atom = capture_evidence(
                    source, content,
                    SpanSelection(SpanKind.BINARY, function[1], function[1] + 4),
                    EvidenceClaim(
                        xref_id, "bounds_candidate_function",
                        "{}@0x{:08x}".format(source.canonical_path, function[0]),
                        ObservationKind.DETERMINISTIC_DERIVED,
                        "bounds_candidate_function", 0.9,
                    ), _PRODUCER,
                )
                evidence_ids = tuple(atom.evidence_id for atom in (
                    literal_atom, pic_atom, xref_atom, function_atom,
                ))
                atoms.extend((literal_atom, pic_atom, xref_atom, function_atom))
                xrefs.append(ArmLiteralXref(
                    xref_id, anchor.target_ref, anchor.literal_value,
                    resolved_address, literal_offset, instruction_address,
                    instruction_offset, function[0], function[1], pic_base[0],
                    pic_base[1], "arm32.pic-got-literal", evidence_ids,
                ))
            if limited:
                break
        if limited:
            break
    return ArmLiteralXrefResult(
        source.canonical_path,
        CoverageStatus.PARTIAL if limited else CoverageStatus.COMPLETED,
        len(content), _PRODUCER, profile.name,
        tuple(sorted(xrefs, key=lambda item: item.xref_id)),
        tuple(sorted(atoms, key=lambda item: item.evidence_id)),
        ("arm_literal_xref.xref_budget_exhausted",) if limited else (),
    )


def _allocated_ascii_literals(elf, content: bytes, minimum: int = 4):
    values = set()
    for section in elf.sections:
        if not (
            section.section_type == 1
            and section.flags & _ALLOC
            and not section.flags & _EXEC
        ):
            continue
        raw = content[section.offset : section.offset + section.size]
        index = 0
        while index < len(raw):
            start = index
            while index < len(raw) and 0x20 <= raw[index] <= 0x7E:
                index += 1
            if (
                index - start >= minimum
                and index < len(raw)
                and raw[index] == 0
            ):
                value = raw[start:index].decode("ascii")
                if value.strip():
                    values.add(value)
            index = max(index + 1, start + 1)
    return tuple(sorted(values))


def discover_arm_feature_pivots(
    source: SourceArtifactEntry,
    content: bytes,
    anchors: Tuple[ArmFeaturePivotAnchor, ...],
    registrar: "NativeDeepResult",
    profile: ArmLiteralXrefProfile = ArmLiteralXrefProfile(),
    policy: ArmLiteralXrefPolicy = ArmLiteralXrefPolicy(),
) -> ArmFeaturePivotResult:
    """Join bounded feature-related literals to verified ARM route handlers."""

    if registrar.source_path != source.canonical_path:
        raise ValueError("ARM feature pivot registrar source does not match")
    ordered = tuple(sorted(set(anchors), key=lambda item: (
        item.feature_token.lower(), item.target_ref,
    )))
    if len(ordered) > policy.max_anchors:
        return ArmFeaturePivotResult(
            source.canonical_path,
            CoverageStatus.SKIPPED_BY_POLICY,
            0,
            _FEATURE_PIVOT_PRODUCER,
            profile.name,
            (),
            (),
            ("arm_feature_pivot.anchor_budget_exceeded",),
        )
    probe = discover_arm_literal_xrefs(source, content, (), profile, policy)
    if probe.coverage_status is not CoverageStatus.COMPLETED:
        return ArmFeaturePivotResult(
            source.canonical_path,
            probe.coverage_status,
            probe.processed_bytes,
            _FEATURE_PIVOT_PRODUCER,
            profile.name,
            (),
            probe.evidence_atoms,
            probe.diagnostics,
        )
    try:
        elf = _parse_elf(content)
        literals = _allocated_ascii_literals(elf, content)
    except (TypeError, ValueError, struct.error):
        literals = ()
    anchor_by_internal_ref = {
        "feature-pivot-anchor:" + hashlib.sha256(json.dumps(
            [anchor.target_ref, anchor.feature_token.lower()],
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()).hexdigest(): anchor
        for anchor in ordered
    }
    literal_anchors = tuple(
        ArmLiteralAnchor(internal_ref, literal)
        for internal_ref, anchor in anchor_by_internal_ref.items()
        for literal in literals
        if anchor.feature_token.lower() in literal.lower()
    )
    if len(literal_anchors) > policy.max_anchors:
        return ArmFeaturePivotResult(
            source.canonical_path,
            CoverageStatus.SKIPPED_BY_POLICY,
            len(content),
            _FEATURE_PIVOT_PRODUCER,
            profile.name,
            (),
            (),
            ("arm_feature_pivot.literal_budget_exceeded",),
        )
    xrefs = discover_arm_literal_xrefs(
        source, content, literal_anchors, profile, policy
    )
    bindings = {}
    for item in registrar.bindings:
        bindings.setdefault(item.handler_address, []).append(item)
    evidence_by_id = {
        atom.evidence_id: atom
        for atom in (*xrefs.evidence_atoms, *registrar.evidence_atoms)
    }
    pivots = []
    for xref in xrefs.xrefs:
        matched_bindings = bindings.get(xref.function_start_address, ())
        anchor = anchor_by_internal_ref[xref.target_ref]
        if not matched_bindings:
            continue
        for binding in matched_bindings:
            if binding.handler_symbol is None:
                continue
            pivot_id = "arm-feature-pivot:" + hashlib.sha256(json.dumps(
                [
                    source.canonical_path,
                    anchor.target_ref,
                    anchor.feature_token.lower(),
                    xref.literal_value,
                    xref.instruction_address,
                    binding.binding_id,
                ],
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()).hexdigest()
            literal_atom = capture_evidence(
                source,
                content,
                SpanSelection(
                    SpanKind.BINARY,
                    xref.literal_offset,
                    xref.literal_offset
                    + len(xref.literal_value.encode("utf-8")),
                ),
                EvidenceClaim(
                    pivot_id,
                    "matches_feature_literal",
                    "{}->{}".format(
                        anchor.feature_token.lower(), xref.literal_value
                    ),
                    ObservationKind.DETERMINISTIC_DERIVED,
                    "matches_feature_literal",
                    0.9,
                ),
                _FEATURE_PIVOT_PRODUCER,
            )
            handler_atom = capture_evidence(
                source,
                content,
                SpanSelection(
                    SpanKind.BINARY,
                    xref.instruction_offset,
                    xref.instruction_offset + 8,
                ),
                EvidenceClaim(
                    pivot_id,
                    "associates_feature_with_registered_handler",
                    "{}->{}".format(
                        anchor.feature_token.lower(), binding.route_token
                    ),
                    ObservationKind.DETERMINISTIC_DERIVED,
                    "associates_feature_with_registered_handler",
                    0.9,
                ),
                _FEATURE_PIVOT_PRODUCER,
            )
            evidence_by_id[literal_atom.evidence_id] = literal_atom
            evidence_by_id[handler_atom.evidence_id] = handler_atom
            evidence_ids = tuple(dict.fromkeys((
                *xref.evidence_ids,
                *binding.evidence_ids,
                literal_atom.evidence_id,
                handler_atom.evidence_id,
            )))
            pivots.append(ArmFeaturePivot(
                pivot_id,
                anchor.target_ref,
                anchor.feature_token.lower(),
                xref.literal_value,
                xref.function_start_address,
                xref.instruction_address,
                binding.binding_id,
                binding.route_token,
                binding.handler_identity,
                binding.handler_symbol,
                "arm32.feature-literal-xref+verified-registrar-handler",
                evidence_ids,
            ))
    limited = len(pivots) > policy.max_xrefs
    if limited:
        pivots = sorted(pivots, key=lambda item: item.pivot_id)[:policy.max_xrefs]
    selected_evidence_ids = {
        evidence_id for item in pivots for evidence_id in item.evidence_ids
    }
    coverage = (
        CoverageStatus.COMPLETED
        if (
            xrefs.coverage_status is CoverageStatus.COMPLETED
            and registrar.coverage_status is CoverageStatus.COMPLETED
            and not limited
        )
        else CoverageStatus.PARTIAL
    )
    diagnostics = tuple(sorted({
        *xrefs.diagnostics,
        *(
            ()
            if registrar.coverage_status is CoverageStatus.COMPLETED
            else ("arm_feature_pivot.registrar_coverage_incomplete",)
        ),
        *(("arm_feature_pivot.pivot_budget_exhausted",) if limited else ()),
    }))
    return ArmFeaturePivotResult(
        source.canonical_path,
        coverage,
        len(content),
        _FEATURE_PIVOT_PRODUCER,
        profile.name,
        tuple(sorted(pivots, key=lambda item: item.pivot_id)),
        tuple(sorted(
            (
                atom for evidence_id, atom in evidence_by_id.items()
                if evidence_id in selected_evidence_ids
            ),
            key=lambda atom: atom.evidence_id,
        )),
        diagnostics,
    )


def discover_arm_function_literal_xrefs(
    source: SourceArtifactEntry,
    content: bytes,
    targets: Tuple[ArmFunctionTarget, ...],
    profile: ArmLiteralXrefProfile = ArmLiteralXrefProfile(),
    policy: ArmLiteralXrefPolicy = ArmLiteralXrefPolicy(),
) -> ArmLiteralXrefResult:
    """Enumerate bounded allocated literals referenced by selected ARM functions."""
    ordered_targets = tuple(sorted(set(targets), key=lambda item: (
        item.function_address, item.target_ref,
    )))
    if not ordered_targets:
        return ArmLiteralXrefResult(
            source.canonical_path, CoverageStatus.NOT_APPLICABLE, 0, _PRODUCER,
            profile.name, (), (), ("no_function_targets",),
        )
    probe = discover_arm_literal_xrefs(source, content, (), profile, policy)
    if probe.coverage_status is not CoverageStatus.COMPLETED:
        return probe
    try:
        elf = _parse_elf(content)
        literals = _allocated_ascii_literals(elf, content)
    except (TypeError, ValueError, struct.error):
        return probe
    limited = len(literals) > policy.max_anchors
    literals = literals[:policy.max_anchors]
    xrefs = []
    atoms_by_id = {}
    diagnostics = set()
    for target in ordered_targets:
        result = discover_arm_literal_xrefs(
            source,
            content,
            tuple(ArmLiteralAnchor(target.target_ref, value) for value in literals),
            profile,
            policy,
        )
        diagnostics.update(result.diagnostics)
        selected = tuple(
            item for item in result.xrefs
            if item.function_start_address == target.function_address
        )
        selected_ids = {
            evidence_id for item in selected for evidence_id in item.evidence_ids
        }
        xrefs.extend(selected)
        atoms_by_id.update(
            (atom.evidence_id, atom) for atom in result.evidence_atoms
            if atom.evidence_id in selected_ids
        )
    if len(xrefs) > policy.max_xrefs:
        xrefs = sorted(xrefs, key=lambda item: item.xref_id)[:policy.max_xrefs]
        selected_ids = {
            evidence_id for item in xrefs for evidence_id in item.evidence_ids
        }
        atoms_by_id = {
            evidence_id: atom for evidence_id, atom in atoms_by_id.items()
            if evidence_id in selected_ids
        }
        limited = True
    if limited:
        diagnostics.add("arm_literal_xref.anchor_or_xref_budget_exhausted")
    return ArmLiteralXrefResult(
        source.canonical_path,
        CoverageStatus.PARTIAL if limited else CoverageStatus.COMPLETED,
        len(content), _PRODUCER, profile.name,
        tuple(sorted(xrefs, key=lambda item: item.xref_id)),
        tuple(sorted(atoms_by_id.values(), key=lambda item: item.evidence_id)),
        tuple(sorted(diagnostics)),
    )
