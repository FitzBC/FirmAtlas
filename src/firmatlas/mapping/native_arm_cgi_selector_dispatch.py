"""Deterministic inventory of unanchored ARM CGI transport selectors."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import struct
from typing import Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry
from .native_arm_configuration_text_import_flow import _calls, _stable_id, _symbol
from .native_arm_xref import _function_start
from .native_cgi_dispatch import ArmCgiDispatchProfile, _Candidate, _scan
from .native_cross_elf_call import ArmCrossElfArtifact, _function_end, _parse
from .native_deep import (
    _ALLOC,
    _EXEC,
    _arm_branch_target,
    _find_pic_base,
    _parse_elf,
    _R_ARM_GLOB_DAT,
    _read_arm_relocations,
    _read_route_literal,
    _word_at_address,
)
from .scheduler import SchedulerObligation


ARM_CGI_SELECTOR_DISPATCH_SCHEMA_VERSION = (
    "firmatlas.mapping.arm-cgi-selector-dispatch/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("native-arm-cgi-selector-dispatch", "0.1.0")


@dataclass(frozen=True)
class ArmCgiSelectorArtifact:
    source: SourceArtifactEntry
    content: bytes


@dataclass(frozen=True)
class ArmCgiSelectorProfile:
    name: str = "arm32-cgi-transport-selector-inventory/v1"
    owner_symbol: str = "webs_Tenda_CGI_BIN_Handler"
    transport_namespace: str = "cgi-bin"
    maximum_function_bytes: int = 16 * 1024
    minimum_selectors: int = 2

    def __post_init__(self) -> None:
        if (
            not self.name.strip()
            or not self.owner_symbol.strip()
            or not self.transport_namespace.strip()
            or min(self.maximum_function_bytes, self.minimum_selectors) <= 0
        ):
            raise ValueError("CGI selector profile requires identity")


@dataclass(frozen=True)
class ArmCgiSelectorPolicy:
    max_artifacts: int = 256
    max_total_bytes: int = 256 * 1024 * 1024
    max_selectors: int = 20_000

    def __post_init__(self) -> None:
        if min(self.max_artifacts, self.max_total_bytes, self.max_selectors) <= 0:
            raise ValueError("CGI selector budgets must be positive")


@dataclass(frozen=True)
class ArmCgiSelectorDispatch:
    selector_id: str
    source_path: str
    transport_namespace: str
    namespace_registration_address: int
    namespace_registrar_address: int
    owner_identity: str
    dispatcher_identity: str
    selector: str
    comparison_width: int
    comparison_address: int
    handler_address: int
    handler_identity: str
    interface_path: str
    interface_path_status: str
    method: str
    method_status: str
    loader_activation_status: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class ArmCgiSelectorDispatchResult:
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    profile: str
    selectors: Tuple[ArmCgiSelectorDispatch, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    open_obligations: Tuple[SchedulerObligation, ...]
    diagnostics: Tuple[str, ...] = ()
    schema_version: str = ARM_CGI_SELECTOR_DISPATCH_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "selectors": [asdict(item) for item in self.selectors],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
            "open_obligations": [asdict(item) for item in self.open_obligations],
        }


def _verify_source(artifact: ArmCgiSelectorArtifact) -> None:
    source, content = artifact.source, artifact.content
    if (
        source.kind not in {"file", "hardlink", "archive_member"}
        or source.content_sha256 is None
        or source.size != len(content)
        or hashlib.sha256(content).hexdigest() != source.content_sha256
    ):
        raise ValueError("source_mismatch")


def _atom(parsed, subject: str, start: int, end: int,
          predicate: str, value: str, capability: str) -> EvidenceAtom:
    offset = parsed.elf.address_offset(start, end - start)
    return capture_evidence(
        parsed.artifact.source,
        parsed.artifact.content,
        SpanSelection(SpanKind.BINARY, offset, offset + end - start),
        EvidenceClaim(
            subject, predicate, value, ObservationKind.DETERMINISTIC_DERIVED,
            capability, 1.0,
        ),
        _PRODUCER,
    )


def _literal_atom(parsed, subject: str, literal: str, span,
                  predicate: str, capability: str) -> EvidenceAtom:
    return capture_evidence(
        parsed.artifact.source,
        parsed.artifact.content,
        SpanSelection(SpanKind.BINARY, span[1], span[2]),
        EvidenceClaim(
            subject, predicate, literal, ObservationKind.DETERMINISTIC_DERIVED,
            capability, 1.0,
        ),
        _PRODUCER,
    )


def _scan_prefix_width_selectors(elf, content: bytes,
                                 profile: ArmCgiDispatchProfile):
    """Recover valid string-switch arms whose compare width is a token prefix."""
    got = next((section for section in elf.sections if section.name == ".got"), None)
    if got is None:
        return ()
    executable = tuple(section for section in elf.sections if (
        section.section_type == 1
        and section.flags & (_ALLOC | _EXEC) == (_ALLOC | _EXEC)
    ))
    candidates = []
    for section in executable:
        for relative in range(0, section.size - 52 + 1, 4):
            offset = section.offset + relative
            words = struct.unpack_from(elf.endian_prefix + "13I", content, offset)
            if not (
                words[1] & 0xFFFFF000 == 0xE59F3000
                and words[2] == 0xE0843003
                and words[3] == 0xE1A01003
                and words[4] & 0xFFFFFF00 == 0xE3A02000
                and words[5] & 0xFF000000 == 0xEB000000
                and words[6] == 0xE1A03000
                and words[7] == 0xE3530000
                and words[8] & 0xFF000000 == 0x1A000000
                and words[12] & 0xFF000000 == 0xEB000000
            ):
                continue
            address = section.address + relative
            pic = _find_pic_base(
                elf, content, address, got.address,
                profile.max_function_scan_bytes,
            )
            function = _function_start(
                elf, content, address, profile.max_function_scan_bytes
            )
            literal_address = address + 12 + (words[1] & 0xFFF)
            route_delta = _word_at_address(elf, content, literal_address)
            route = None if route_delta is None else _read_route_literal(
                elf, content, (got.address + route_delta) & 0xFFFFFFFF,
                profile.max_route_bytes,
            )
            width = words[4] & 0xFF
            if (
                pic is None or function is None or route is None
                or width <= 0 or width > len(route[0].encode("utf-8"))
            ):
                continue
            comparison_target = _arm_branch_target(address + 20, words[5])
            handler_address = _arm_branch_target(address + 48, words[12])
            branch_target = _arm_branch_target(address + 32, words[8])
            if branch_target <= address + 48 or not all(any(
                item.address <= target < item.address + item.size
                for item in executable
            ) for target in (comparison_target, handler_address)):
                continue
            candidates.append(_Candidate(
                route[0], route[1], function[0], pic[1], address, offset,
                comparison_target, handler_address, offset + 48,
            ))
    grouped = {}
    for item in candidates:
        grouped.setdefault(
            (item.dispatcher_address, item.comparison_target_address), []
        ).append(item)
    return tuple(item for item in candidates if len({
        entry.dispatch_token for entry in grouped[
            (item.dispatcher_address, item.comparison_target_address)
        ]
    }) >= profile.min_dispatcher_entries)


def _namespace_binding(parsed, namespace: str, owner_symbol: str):
    """Prove prefix -> exported handler at a repeated ARM registrar callsite."""
    elf, content = _parse_elf(parsed.artifact.content), parsed.artifact.content
    got = next((section for section in elf.sections if section.name == ".got"), None)
    if got is None:
        return None
    relocations = _read_arm_relocations(elf, content, (_R_ARM_GLOB_DAT,))
    executable = tuple(section for section in elf.sections if (
        section.section_type == 1
        and section.flags & (_ALLOC | _EXEC) == (_ALLOC | _EXEC)
    ))
    found = []
    for section in executable:
        for relative in range(28, section.size, 4):
            offset = section.offset + relative
            words = struct.unpack_from(elf.endian_prefix + "8I", content, offset - 28)
            if not (
                words[0] & 0xFFFFF000 == 0xE59F3000
                and words[1] == 0xE0843003
                and words[2] == 0xE1A00003
                and words[3] == 0xE3A01000
                and words[4] == 0xE3A02000
                and words[5] & 0xFFFFF000 == 0xE59F3000
                and words[6] == 0xE7943003
                and words[7] & 0xFF000000 == 0xEB000000
            ):
                continue
            callsite = section.address + relative
            route_delta = _word_at_address(
                elf, content, callsite - 20 + (words[0] & 0xFFF)
            )
            handler_delta = _word_at_address(
                elf, content, callsite + (words[5] & 0xFFF)
            )
            if route_delta is None or handler_delta is None:
                continue
            route = _read_route_literal(
                elf, content, (got.address + route_delta) & 0xFFFFFFFF, 256
            )
            relocation = relocations.get(
                (got.address + handler_delta) & 0xFFFFFFFF
            )
            if route is None or relocation is None:
                continue
            found.append((
                route[0], route[1], relocation.symbol.name,
                relocation.source_offset, callsite,
                _arm_branch_target(callsite, words[7]),
            ))
    registrar_counts = {}
    for item in found:
        registrar_counts.setdefault(item[5], set()).add((item[0], item[2]))
    return next((item for item in found if (
        item[0].rstrip("/") == "/" + namespace.strip("/")
        and item[2] == owner_symbol
        and len(registrar_counts[item[5]]) >= 2
    )), None)


def _arm_word(parsed, address: int) -> int:
    return struct.unpack_from(
        "<I", parsed.artifact.content, parsed.elf.address_offset(address, 4)
    )[0]


def _path_segment_parser_span(parsed, owner_address: int, owner_end: int,
                              dispatcher_call: int):
    """Verify sixth-argument path splitting before selector dispatch."""
    calls = _calls(parsed, owner_address, owner_end)
    slash_calls = tuple(callsite for callsite, symbol, _ in calls if (
        symbol == "strchr"
        and callsite < dispatcher_call
        and _arm_word(parsed, callsite - 4) == 0xE3A0102F
    ))
    if len(slash_calls) < 2:
        return None
    first, second = slash_calls[-2:]
    first_store = _arm_word(parsed, first + 4)
    second_input = _arm_word(parsed, second - 8)
    second_store = _arm_word(parsed, second + 4)
    dispatch_selector = _arm_word(parsed, dispatcher_call - 4)
    first_slot = first_store & 0xFFF
    if not (
        first_store & 0xFFFFF000 == 0xE50B0000
        and second_input == 0xE51B0000 | first_slot
        and second_store & 0xFFFFF000 == 0xE50B0000
        and dispatch_selector == 0xE51B2000 | first_slot
        and any(
            _arm_word(parsed, address) == 0xE59B3008
            for address in range(owner_address, first, 4)
        )
        and any(
            symbol == "strncpy" and callsite < first
            for callsite, symbol, _ in calls
        )
        and any(
            _arm_word(parsed, address) & 0xFFFFF000 == 0xE5C32000
            for address in range(second + 4, min(second + 36, dispatcher_call), 4)
        )
    ):
        return None
    start = next(
        address for address in range(owner_address, first, 4)
        if _arm_word(parsed, address) == 0xE59B3008
    )
    return start, dispatcher_call + 4


def discover_arm_cgi_selector_dispatches(
    artifacts: Tuple[ArmCgiSelectorArtifact, ...],
    profile: ArmCgiSelectorProfile = ArmCgiSelectorProfile(),
    policy: ArmCgiSelectorPolicy = ArmCgiSelectorPolicy(),
) -> ArmCgiSelectorDispatchResult:
    """Recover firmware-owned CGI selector inventories without route anchors."""
    total = sum(len(item.content) for item in artifacts)
    if len(artifacts) > policy.max_artifacts:
        return ArmCgiSelectorDispatchResult(
            CoverageStatus.SKIPPED_BY_POLICY, 0, _PRODUCER, profile.name,
            (), (), (), ("artifact_budget_exceeded",),
        )
    if total > policy.max_total_bytes:
        return ArmCgiSelectorDispatchResult(
            CoverageStatus.SKIPPED_BY_POLICY, 0, _PRODUCER, profile.name,
            (), (), (), ("byte_budget_exceeded",),
        )
    try:
        for artifact in artifacts:
            _verify_source(artifact)
    except ValueError:
        return ArmCgiSelectorDispatchResult(
            CoverageStatus.FAILED, total, _PRODUCER, profile.name,
            (), (), (), ("source_mismatch",),
        )

    selectors = []
    atoms = []
    obligations = []
    diagnostics = []
    truncated = False
    for artifact in artifacts:
        if not artifact.content.startswith(b"\x7fELF"):
            continue
        try:
            parsed = _parse(ArmCrossElfArtifact(artifact.source, artifact.content))
            deep_elf = _parse_elf(artifact.content)
            scan_profile = ArmCgiDispatchProfile(
                min_dispatcher_entries=profile.minimum_selectors,
                max_function_scan_bytes=profile.maximum_function_bytes,
            )
            candidates = {
                (item.dispatcher_address, item.dispatch_token): item
                for item in (
                    *_scan(deep_elf, artifact.content, scan_profile),
                    *_scan_prefix_width_selectors(
                        deep_elf, artifact.content, scan_profile
                    ),
                )
            }.values()
        except (KeyError, TypeError, ValueError, struct.error) as exc:
            diagnostics.append("artifact_parse_failed:{}:{}".format(
                artifact.source.canonical_path, exc
            ))
            continue
        owner = _symbol(parsed, profile.owner_symbol)
        namespace_binding = _namespace_binding(
            parsed, profile.transport_namespace, profile.owner_symbol
        )
        if owner is None or not candidates or namespace_binding is None:
            continue
        owner_end = _function_end(parsed, owner.address, profile.maximum_function_bytes)
        dispatcher_addresses = {item.dispatcher_address for item in candidates}
        if len(dispatcher_addresses) != 1:
            diagnostics.append("selector_dispatcher_ambiguous:{}".format(
                artifact.source.canonical_path
            ))
            continue
        dispatcher_address = next(iter(dispatcher_addresses))
        owner_call = next((
            callsite for callsite, _, target in _calls(parsed, owner.address, owner_end)
            if target == dispatcher_address
        ), None)
        if owner_call is None:
            diagnostics.append("owner_to_selector_dispatcher_missing:{}".format(
                artifact.source.canonical_path
            ))
            continue
        path_parser_span = _path_segment_parser_span(
            parsed, owner.address, owner_end, owner_call
        )
        if path_parser_span is None:
            diagnostics.append("cgi_path_segment_parser_missing:{}".format(
                artifact.source.canonical_path
            ))
            continue
        for candidate in sorted(candidates, key=lambda item: item.dispatch_token):
            if len(selectors) >= policy.max_selectors:
                truncated = True
                continue
            selector_id = _stable_id(
                "native-cgi-selector",
                artifact.source.canonical_path,
                owner.address,
                dispatcher_address,
                candidate.dispatch_token,
                candidate.handler_address,
            )
            proof = (
                _literal_atom(
                    parsed, selector_id, namespace_binding[0],
                    (namespace_binding[0], namespace_binding[1],
                     namespace_binding[1] + len(namespace_binding[0].encode())),
                    "registers_cgi_transport_namespace",
                    "registers_cgi_transport_namespace",
                ),
                _atom(
                    parsed, selector_id, namespace_binding[4],
                    namespace_binding[4] + 4,
                    "binds_cgi_namespace_owner", profile.owner_symbol,
                    "binds_cgi_namespace_owner",
                ),
                capture_evidence(
                    artifact.source,
                    artifact.content,
                    SpanSelection(
                        SpanKind.BINARY,
                        namespace_binding[3],
                        namespace_binding[3] + 8,
                    ),
                    EvidenceClaim(
                        selector_id, "resolves_cgi_namespace_owner_symbol",
                        profile.owner_symbol,
                        ObservationKind.DETERMINISTIC_DERIVED,
                        "resolves_cgi_namespace_owner_symbol", 1.0,
                    ),
                    _PRODUCER,
                ),
                _atom(
                    parsed, selector_id, path_parser_span[0], path_parser_span[1],
                    "parses_cgi_path_segment", "second_path_segment",
                    "parses_cgi_path_segment",
                ),
                _atom(
                    parsed, selector_id, owner_call, owner_call + 4,
                    "invokes_cgi_selector_dispatcher",
                    "0x{:08x}".format(dispatcher_address),
                    "invokes_cgi_selector_dispatcher",
                ),
                capture_evidence(
                    artifact.source,
                    artifact.content,
                    SpanSelection(
                        SpanKind.BINARY,
                        candidate.route_offset,
                        candidate.route_offset + len(candidate.dispatch_token.encode()),
                    ),
                    EvidenceClaim(
                        selector_id, "declares_cgi_selector",
                        candidate.dispatch_token,
                        ObservationKind.DETERMINISTIC_DERIVED,
                        "declares_cgi_selector", 1.0,
                    ),
                    _PRODUCER,
                ),
                _atom(
                    parsed, selector_id, candidate.comparison_address,
                    candidate.comparison_address + 36,
                    "dispatches_cgi_selector", candidate.dispatch_token,
                    "dispatches_cgi_selector",
                ),
                _atom(
                    parsed, selector_id, candidate.handler_address,
                    candidate.handler_address + 4,
                    "binds_cgi_selector_handler",
                    "{}@0x{:08x}".format(
                        artifact.source.canonical_path, candidate.handler_address
                    ),
                    "binds_cgi_selector_handler",
                ),
                _atom(
                    parsed, selector_id, candidate.comparison_address,
                    candidate.comparison_address + 52,
                    "derives_cgi_interface_path",
                    "/{}/{}".format(
                        profile.transport_namespace.strip("/"),
                        candidate.dispatch_token,
                    ),
                    "derives_cgi_interface_path",
                ),
            )
            comparison_width = struct.unpack_from(
                "<I", artifact.content,
                parsed.elf.address_offset(candidate.comparison_address + 16, 4),
            )[0] & 0xFF
            interface_path = "/{}/{}".format(
                profile.transport_namespace.strip("/"), candidate.dispatch_token
            )
            handler_end = _function_end(
                parsed, candidate.handler_address, profile.maximum_function_bytes
            )
            loader_calls = {
                symbol for _, symbol, _ in _calls(
                    parsed, candidate.handler_address, handler_end
                )
                if symbol in {"load_url_mib", "reload_url_mib"}
            }
            selector = ArmCgiSelectorDispatch(
                selector_id,
                artifact.source.canonical_path,
                profile.transport_namespace,
                namespace_binding[4],
                namespace_binding[5],
                "{}@0x{:08x}".format(
                    artifact.source.canonical_path, owner.address
                ),
                "{}@0x{:08x}".format(
                    artifact.source.canonical_path, dispatcher_address
                ),
                candidate.dispatch_token,
                comparison_width,
                candidate.comparison_address,
                candidate.handler_address,
                "{}@0x{:08x}".format(
                    artifact.source.canonical_path, candidate.handler_address
                ),
                interface_path,
                "deterministic_derived",
                "",
                "unresolved",
                "direct_handler_call" if loader_calls else "no_direct_handler_call",
                tuple(item.evidence_id for item in proof),
            )
            selectors.append(selector)
            atoms.extend(proof)
            obligations.append(SchedulerObligation(
                _stable_id(
                    "native-cgi-selector-obligation", selector_id,
                    "binds_cgi_selector_http_method",
                ),
                selector_id,
                "binds_cgi_selector_http_method",
                "The normalized CGI path and handler are proven, but no "
                "selector-specific HTTP method guard was observed.",
                80,
                (),
            ))
            if candidate.dispatch_token == "UploadWebsite":
                obligations.append(SchedulerObligation(
                    _stable_id(
                        "native-cgi-selector-obligation", selector_id,
                        "binds_configuration_url_loader_activation",
                    ),
                    selector_id,
                    "binds_configuration_url_loader_activation",
                    "The upload handler reaches daily URL-store operations, but "
                    "no edge to the configuration URL document loader was observed.",
                    95,
                    (),
                ))
    if truncated:
        diagnostics.append("selector_budget_exceeded")
    status = CoverageStatus.PARTIAL if diagnostics else CoverageStatus.COMPLETED
    return ArmCgiSelectorDispatchResult(
        status,
        total,
        _PRODUCER,
        profile.name,
        tuple(sorted(selectors, key=lambda item: (
            item.source_path, item.selector, item.handler_address
        ))),
        tuple(sorted(
            {item.evidence_id: item for item in atoms}.values(),
            key=lambda item: item.evidence_id,
        )),
        tuple(sorted(obligations, key=lambda item: item.obligation_id)),
        tuple(sorted(set(diagnostics))),
    )
