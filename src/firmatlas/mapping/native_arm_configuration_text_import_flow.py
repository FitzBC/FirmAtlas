"""Evidence-backed ARM configuration text-document import recovery."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import struct
from typing import Optional, Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry
from .native_arm_configuration_blob_flow import (
    ArmConfigurationBlobArtifact,
    _pic_base,
    _word,
    discover_arm_configuration_blob_flows,
)
from .native_cross_elf_call import (
    ArmCrossElfArtifact,
    _branch_target,
    _function_end,
    _parse,
)
from .native_deep import _parse_elf, _read_route_literal


ARM_CONFIGURATION_TEXT_IMPORT_FLOW_SCHEMA_VERSION = (
    "firmatlas.mapping.arm-configuration-text-import-flow/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("native-arm-configuration-text-import-flow", "0.1.0")


@dataclass(frozen=True)
class ArmConfigurationTextImportArtifact:
    source: SourceArtifactEntry
    content: bytes


@dataclass(frozen=True)
class ArmConfigurationTextImportProfile:
    name: str = "arm32-cfm-key-value-import/v1"
    upload_symbol: str = "tpi_sys_cfg_upload"
    restore_symbol: str = "RestoreMTD"
    init_symbol: str = "InitDefaultCfm"
    load_symbol: str = "load_mib"
    primary_runtime_path: str = "/webroot/default.cfg"
    secondary_runtime_path: str = "/webroot/default_url.cfg"
    source_document_suffix: str = "webroot_ro/default.cfg"
    startup_script_suffix: str = "etc_ro/init.d/rcS"
    section_delimiter: str = "##the public configure end##"
    import_command: str = "cfm Upload"
    state_scope: str = "cfm/default_mib/*"
    maximum_function_bytes: int = 16 * 1024

    def __post_init__(self) -> None:
        values = (
            self.name, self.upload_symbol, self.restore_symbol, self.init_symbol,
            self.load_symbol, self.primary_runtime_path,
            self.secondary_runtime_path, self.source_document_suffix,
            self.startup_script_suffix, self.section_delimiter,
            self.import_command, self.state_scope,
        )
        if any(not item.strip() for item in values) or self.maximum_function_bytes <= 0:
            raise ValueError("configuration text-import profile requires identity")


@dataclass(frozen=True)
class ArmConfigurationTextImportPolicy:
    max_artifacts: int = 256
    max_total_bytes: int = 256 * 1024 * 1024
    max_declared_keys: int = 20_000

    def __post_init__(self) -> None:
        if min(self.max_artifacts, self.max_total_bytes, self.max_declared_keys) <= 0:
            raise ValueError("configuration text-import budgets must be positive")


@dataclass(frozen=True)
class ArmConfigurationTextImportFlow:
    flow_id: str
    upload_path: str
    upload_identity: str
    restore_path: str
    restore_identity: str
    ipc_client_identity: str
    ipc_dispatcher_identity: str
    request_opcode: int
    payload_literal: str
    parser_identity: str
    primary_runtime_path: str
    secondary_runtime_path: str
    source_document_path: str
    section_delimiter: str
    import_command: str
    state_scope: str
    write_granularity: str
    declared_keys: Tuple[str, ...]
    evidence_ids: Tuple[str, ...]
    key_evidence: Tuple[Tuple[str, str], ...]


@dataclass(frozen=True)
class ArmConfigurationTextImportFlowResult:
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    profile: str
    flows: Tuple[ArmConfigurationTextImportFlow, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[str, ...] = ()
    schema_version: str = ARM_CONFIGURATION_TEXT_IMPORT_FLOW_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "flows": [asdict(item) for item in self.flows],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
        }


def _stable_id(prefix: str, *values: object) -> str:
    encoded = json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode()
    return prefix + ":" + hashlib.sha256(encoded).hexdigest()


def _symbol(parsed, name: str):
    return next((item for item in parsed.exports if item.name == name), None)


def _call(parsed, address: int) -> Tuple[Optional[str], Optional[int]]:
    target = _branch_target(address, _word(parsed, address))
    if target is None:
        return None, None
    imported = parsed.plt.get(target)
    if imported is not None:
        return imported[0], target
    return next((item.name for item in parsed.exports if item.address == target), None), target


def _calls(parsed, start: int, end: int) -> Tuple[Tuple[int, Optional[str], int], ...]:
    found = []
    for address in range(start, end, 4):
        name, target = _call(parsed, address)
        if target is not None:
            found.append((address, name, target))
    return tuple(found)


def _pic_literals(parsed, start: int, end: int) -> dict:
    base = _pic_base(parsed, start, end)
    if base is None:
        return {}
    deep = _parse_elf(parsed.artifact.content)
    found = {}
    for address in range(start, end - 4, 4):
        instruction = _word(parsed, address)
        register = instruction >> 12 & 0xF
        if instruction & 0xFFFF0000 != 0xE59F0000:
            continue
        if _word(parsed, address + 4) != 0xE0840000 | register << 12 | register:
            continue
        delta = parsed.elf.read_u32(address + 8 + (instruction & 0xFFF))
        literal = _read_route_literal(
            deep, parsed.artifact.content, (base + delta) & 0xFFFFFFFF, 256
        )
        if literal is not None:
            found[literal[0]] = (address, literal[1], literal[1] + len(literal[0]))
    return found


def _binary_atom(parsed, flow_id: str, start: int, end: int,
                 predicate: str, value: str, capability: str) -> EvidenceAtom:
    offset = parsed.elf.address_offset(start, end - start)
    return capture_evidence(
        parsed.artifact.source,
        parsed.artifact.content,
        SpanSelection(SpanKind.BINARY, offset, offset + end - start),
        EvidenceClaim(
            flow_id, predicate, value, ObservationKind.DETERMINISTIC_DERIVED,
            capability, 1.0,
        ),
        _PRODUCER,
    )


def _literal_atom(parsed, flow_id: str, literal: str, span: Tuple[int, int, int],
                  predicate: str, capability: str) -> EvidenceAtom:
    return capture_evidence(
        parsed.artifact.source,
        parsed.artifact.content,
        SpanSelection(SpanKind.BINARY, span[1], span[2]),
        EvidenceClaim(
            flow_id, predicate, literal, ObservationKind.DETERMINISTIC_DERIVED,
            capability, 1.0,
        ),
        _PRODUCER,
    )


def _key_rows(content: bytes) -> Tuple[Tuple[str, int, int], ...]:
    # The firmware parser tokenizes by newline and then separates on '='.  Keep
    # duplicates because the source document is ordered and can override keys.
    text = content.decode("utf-8-sig")
    rows = []
    cursor = len(content) - len(content.lstrip(b"\xef\xbb\xbf"))
    for raw in text.splitlines(keepends=True):
        encoded = raw.encode("utf-8")
        bare = raw.rstrip("\r\n")
        stripped = bare.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key:
                line_without_indent = bare.lstrip()
                key_start = cursor + len(bare) - len(line_without_indent)
                rows.append((key, key_start, key_start + len(key.encode("utf-8"))))
        cursor += len(encoded)
    return tuple(rows)


def _verify_source(artifact: ArmConfigurationTextImportArtifact) -> None:
    source, content = artifact.source, artifact.content
    if (
        source.kind not in {"file", "hardlink", "archive_member"}
        or source.content_sha256 is None
        or source.size != len(content)
        or hashlib.sha256(content).hexdigest() != source.content_sha256
    ):
        raise ValueError("source_mismatch")


def discover_arm_configuration_text_import_flows(
    artifacts: Tuple[ArmConfigurationTextImportArtifact, ...],
    profile: ArmConfigurationTextImportProfile = ArmConfigurationTextImportProfile(),
    policy: ArmConfigurationTextImportPolicy = ArmConfigurationTextImportPolicy(),
) -> ArmConfigurationTextImportFlowResult:
    """Recover upload-to-key/value-store flows without inventing HTTP parameters."""
    total = sum(len(item.content) for item in artifacts)
    if len(artifacts) > policy.max_artifacts:
        return ArmConfigurationTextImportFlowResult(
            CoverageStatus.SKIPPED_BY_POLICY, 0, _PRODUCER, profile.name,
            (), (), ("artifact_budget_exceeded",),
        )
    if total > policy.max_total_bytes:
        return ArmConfigurationTextImportFlowResult(
            CoverageStatus.SKIPPED_BY_POLICY, 0, _PRODUCER, profile.name,
            (), (), ("byte_budget_exceeded",),
        )
    try:
        for item in artifacts:
            _verify_source(item)
    except ValueError:
        return ArmConfigurationTextImportFlowResult(
            CoverageStatus.FAILED, total, _PRODUCER, profile.name,
            (), (), ("source_mismatch",),
        )

    by_path = {item.source.canonical_path: item for item in artifacts}
    document = next((
        item for path, item in by_path.items()
        if path.endswith(profile.source_document_suffix)
    ), None)
    startup = next((
        item for path, item in by_path.items()
        if path.endswith(profile.startup_script_suffix)
    ), None)
    parsed = []
    diagnostics = []
    for item in artifacts:
        if not item.content.startswith(b"\x7fELF"):
            continue
        try:
            parsed.append(_parse(ArmCrossElfArtifact(item.source, item.content)))
        except (KeyError, TypeError, ValueError, struct.error) as exc:
            diagnostics.append("artifact_parse_failed:{}:{}".format(
                item.source.canonical_path, exc
            ))
    upload = next(((item, _symbol(item, profile.upload_symbol)) for item in parsed
                   if _symbol(item, profile.upload_symbol) is not None), None)
    restore = next(((item, _symbol(item, profile.restore_symbol)) for item in parsed
                    if _symbol(item, profile.restore_symbol) is not None), None)
    if upload is None:
        diagnostics.append("upload_owner_missing")
    if restore is None:
        diagnostics.append("restore_owner_missing")
    if document is None:
        diagnostics.append("configuration_document_missing")
    if startup is None:
        diagnostics.append("runtime_materialization_missing")
    if upload is None or restore is None or document is None or startup is None:
        return ArmConfigurationTextImportFlowResult(
            CoverageStatus.PARTIAL, total, _PRODUCER, profile.name,
            (), (), tuple(sorted(set(diagnostics))),
        )

    ipc_result = discover_arm_configuration_blob_flows(tuple(
        ArmConfigurationBlobArtifact(item.source, item.content)
        for item in artifacts if item.content.startswith(b"\x7fELF")
    ))
    matching_ipc = tuple(
        item for item in ipc_result.flows
        if item.state_writer_symbol == profile.restore_symbol
    )
    if len(matching_ipc) != 1:
        diagnostics.append(
            "configuration_ipc_{}".format(
                "missing" if not matching_ipc else "ambiguous"
            )
        )

    upload_parsed, upload_export = upload
    restore_parsed, restore_export = restore
    upload_end = _function_end(
        upload_parsed, upload_export.address, profile.maximum_function_bytes
    )
    upload_calls = _calls(upload_parsed, upload_export.address, upload_end)
    upload_symbols = {item[1] for item in upload_calls}
    upload_literals = _pic_literals(upload_parsed, upload_export.address, upload_end)
    restore_end = _function_end(
        restore_parsed, restore_export.address, profile.maximum_function_bytes
    )
    restore_calls = _calls(restore_parsed, restore_export.address, restore_end)
    restore_symbols = {item[1] for item in restore_calls}
    restore_literals = _pic_literals(
        restore_parsed, restore_export.address, restore_end
    )
    init_export = _symbol(restore_parsed, profile.init_symbol)
    load_export = _symbol(restore_parsed, profile.load_symbol)
    required_upload = {"fopen", "strstr", "fwrite", "doSystemCmd"}
    required_literals = {
        profile.primary_runtime_path, profile.secondary_runtime_path,
        profile.section_delimiter, profile.import_command,
    }
    if not required_upload.issubset(upload_symbols) or not required_literals.issubset(upload_literals):
        diagnostics.append("upload_split_contract_missing")
    if not {"SetCfmValue", "restore_config_type", "RestoreNvram", profile.init_symbol}.issubset(restore_symbols):
        diagnostics.append("restore_dispatch_contract_missing")
    if "default_mib" not in restore_literals:
        diagnostics.append("default_mib_selector_missing")
    if init_export is None or load_export is None:
        diagnostics.append("configuration_loader_missing")

    parser_address = 0
    parser_span = None
    parser_calls = ()
    if init_export is not None and load_export is not None:
        init_end = _function_end(
            restore_parsed, init_export.address, profile.maximum_function_bytes
        )
        init_calls = _calls(restore_parsed, init_export.address, init_end)
        if not any(name == profile.load_symbol for _, name, _ in init_calls):
            diagnostics.append("init_to_load_call_missing")
        load_end = _function_end(
            restore_parsed, load_export.address, profile.maximum_function_bytes
        )
        load_literals = _pic_literals(restore_parsed, load_export.address, load_end)
        if profile.primary_runtime_path not in load_literals:
            diagnostics.append("loader_path_missing")
        internal = [
            (address, target) for address, name, target
            in _calls(restore_parsed, load_export.address, load_end)
            if name is None and target < load_export.address
        ]
        parser_choices = []
        for callsite, target in internal:
            candidate_end = _function_end(
                restore_parsed, target, profile.maximum_function_bytes
            )
            candidate_calls = _calls(restore_parsed, target, candidate_end)
            candidate_symbols = {item[1] for item in candidate_calls}
            if {"strtok", "strdup"}.issubset(candidate_symbols):
                parser_choices.append((callsite, target, candidate_end, candidate_calls))
        if len(parser_choices) == 1:
            load_to_parser, parser_address, parser_end, parser_calls = parser_choices[0]
            parser_symbols = {item[1] for item in parser_calls}
            helper_targets = {target for _, name, target in parser_calls if name is None}
            helper_symbols = set()
            hash_insert_call = None
            for target in helper_targets:
                end = _function_end(restore_parsed, target, profile.maximum_function_bytes)
                for call in _calls(restore_parsed, target, end):
                    if call[1] is not None:
                        helper_symbols.add(call[1])
                    if call[1] == "hash_insert":
                        hash_insert_call = call
            if not {"strtok", "strdup"}.issubset(parser_symbols):
                diagnostics.append("line_tokenizer_missing")
            if "strchr" not in helper_symbols:
                diagnostics.append("key_value_splitter_missing")
            if "hash_insert" not in helper_symbols:
                diagnostics.append("hash_store_missing")
            splitter_call = next((
                call for target in helper_targets
                for call in _calls(
                    restore_parsed, target,
                    _function_end(restore_parsed, target, profile.maximum_function_bytes),
                )
                if call[1] == "strchr"
            ), None)
            parser_span = (
                load_to_parser, parser_address, parser_end,
                splitter_call, hash_insert_call,
            )
        else:
            diagnostics.append("key_value_parser_missing")

    rows = _key_rows(document.content)
    if len(rows) > policy.max_declared_keys:
        diagnostics.append("declared_key_budget_exceeded")
    if diagnostics:
        return ArmConfigurationTextImportFlowResult(
            CoverageStatus.PARTIAL, total, _PRODUCER, profile.name,
            (), (), tuple(sorted(set(diagnostics))),
        )

    flow_id = _stable_id(
        "native-configuration-text-import-flow",
        upload_parsed.artifact.source.canonical_path, upload_export.address,
        restore_parsed.artifact.source.canonical_path, restore_export.address,
        document.source.content_sha256, profile.state_scope,
    )
    atoms = []
    ipc_flow = matching_ipc[0]
    ipc_atoms = tuple(
        item for item in ipc_result.evidence_atoms
        if item.evidence_id in ipc_flow.evidence_ids
    )
    atoms.extend(ipc_atoms)
    atoms.append(capture_evidence(
        upload_parsed.artifact.source, upload_parsed.artifact.content,
        SpanSelection(SpanKind.BINARY, *upload_export.symbol_span),
        EvidenceClaim(
            flow_id, "resolves_upload_processor", profile.upload_symbol,
            ObservationKind.DETERMINISTIC_DERIVED,
            "resolves_configuration_upload_processor", 1.0,
        ), _PRODUCER,
    ))
    for literal, predicate, capability in (
        (profile.primary_runtime_path, "writes_primary_document", "writes_configuration_document"),
        (profile.secondary_runtime_path, "writes_secondary_document", "writes_configuration_document"),
        (profile.section_delimiter, "splits_uploaded_document", "splits_configuration_sections"),
        (profile.import_command, "invokes_import_command", "invokes_configuration_import"),
    ):
        atoms.append(_literal_atom(
            upload_parsed, flow_id, literal, upload_literals[literal],
            predicate, capability,
        ))
    atoms.append(capture_evidence(
        restore_parsed.artifact.source, restore_parsed.artifact.content,
        SpanSelection(SpanKind.BINARY, *restore_export.symbol_span),
        EvidenceClaim(
            flow_id, "resolves_restore_implementation", profile.restore_symbol,
            ObservationKind.DETERMINISTIC_DERIVED,
            "resolves_configuration_restore_implementation", 1.0,
        ), _PRODUCER,
    ))
    atoms.append(_literal_atom(
        restore_parsed, flow_id, "default_mib", restore_literals["default_mib"],
        "selects_configuration_store", "selects_default_mib_store",
    ))
    load_end = _function_end(
        restore_parsed, load_export.address, profile.maximum_function_bytes
    )
    load_literals = _pic_literals(restore_parsed, load_export.address, load_end)
    atoms.append(_literal_atom(
        restore_parsed, flow_id, profile.primary_runtime_path,
        load_literals[profile.primary_runtime_path], "loads_configuration_document",
        "loads_default_configuration_document",
    ))
    load_to_parser, parser_address, parser_end, splitter_call, hash_insert_call = parser_span
    atoms.append(_binary_atom(
        restore_parsed, flow_id, parser_address, parser_end,
        "tokenizes_configuration_document", "strtok->strdup",
        "tokenizes_configuration_key_value_document",
    ))
    atoms.append(_binary_atom(
        restore_parsed, flow_id, splitter_call[0], splitter_call[0] + 4,
        "splits_configuration_entry", "strchr('=')",
        "splits_configuration_key_value_entry",
    ))
    atoms.append(_binary_atom(
        restore_parsed, flow_id, hash_insert_call[0], hash_insert_call[0] + 4,
        "imports_configuration_state", "hash_insert",
        "imports_configuration_key_value_state",
    ))
    materialization = "cp -rf /webroot_ro/* /webroot/"
    materialization_start = startup.content.index(materialization.encode())
    atoms.append(capture_evidence(
        startup.source, startup.content,
        SpanSelection(
            SpanKind.TEXT_UTF8, materialization_start,
            materialization_start + len(materialization),
        ),
        EvidenceClaim(
            flow_id, "materializes_runtime_document", materialization,
            ObservationKind.DIRECT_STATIC,
            "materializes_webroot_configuration", 1.0,
        ), _PRODUCER,
    ))
    key_evidence = []
    for index, (key, start, end) in enumerate(rows):
        atom = capture_evidence(
            document.source, document.content,
            SpanSelection(SpanKind.TEXT_UTF8, start, end),
            EvidenceClaim(
                flow_id, "declares_configuration_key", key,
                ObservationKind.DIRECT_STATIC,
                "declares_configuration_state_key", 1.0,
            ), _PRODUCER,
        )
        atoms.append(atom)
        key_evidence.append((key, atom.evidence_id))
    flow = ArmConfigurationTextImportFlow(
        flow_id,
        upload_parsed.artifact.source.canonical_path,
        "{}@0x{:08x}".format(
            upload_parsed.artifact.source.canonical_path, upload_export.address
        ),
        restore_parsed.artifact.source.canonical_path,
        "{}@0x{:08x}".format(
            restore_parsed.artifact.source.canonical_path, restore_export.address
        ),
        ipc_flow.client_identity,
        ipc_flow.dispatcher_identity,
        ipc_flow.request_opcode,
        ipc_flow.payload_literal,
        "{}@0x{:08x}".format(
            restore_parsed.artifact.source.canonical_path, parser_address
        ),
        profile.primary_runtime_path, profile.secondary_runtime_path,
        document.source.canonical_path, profile.section_delimiter,
        profile.import_command, profile.state_scope, "key_value_document",
        tuple(item[0] for item in rows),
        tuple(item.evidence_id for item in atoms),
        tuple(key_evidence),
    )
    return ArmConfigurationTextImportFlowResult(
        CoverageStatus.COMPLETED, total, _PRODUCER, profile.name,
        (flow,), tuple(sorted(atoms, key=lambda item: item.evidence_id)), (),
    )
