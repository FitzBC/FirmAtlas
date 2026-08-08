import hashlib
from dataclasses import replace
from pathlib import Path
import struct
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    NativeDeepPolicy,
    NativeRouteAnchor,
    NativeRouteTableProfile,
    ObservationKind,
    ObligationStatus,
    SchedulerObligation,
    SourceArtifactEntry,
    discover_native_route_bindings,
    discover_frontend_requests,
    discover_native_hints,
    correlate_frontend_native,
    assemble_discovery_catalog,
    native_deep_scheduler_analyzer,
    replay_evidence,
    run_obligation_scheduler,
)
from firmatlas.mapping.repository import DiscoveryCatalogRepository


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        canonical_path=path,
        original_path=path,
        kind="file",
        size=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
    )


def _route_table_elf(handler_address: int = 0x1000, include_entry: bool = True) -> bytes:
    shstrtab = b"\x00.shstrtab\x00.text\x00.rodata\x00.routes\x00"
    text = b"\x00\x00\xa0\xe1" * 4
    route = b"SetOnlineDevName\x00"
    routes = struct.pack("<II", 0x2000, handler_address) if include_entry else b"\x00" * 8
    header_size = 52
    payload = bytearray(b"\x00" * header_size)
    offsets = []
    for value in (shstrtab, text, route, routes):
        while len(payload) % 4:
            payload.append(0)
        offsets.append(len(payload))
        payload.extend(value)
    while len(payload) % 4:
        payload.append(0)
    section_offset = len(payload)
    sections = [struct.pack("<IIIIIIIIII", *([0] * 10))]
    sections.append(struct.pack(
        "<IIIIIIIIII", 1, 3, 0, 0, offsets[0], len(shstrtab), 0, 0, 1, 0,
    ))
    sections.append(struct.pack(
        "<IIIIIIIIII", 11, 1, 0x6, 0x1000, offsets[1], len(text), 0, 0, 4, 0,
    ))
    sections.append(struct.pack(
        "<IIIIIIIIII", 17, 1, 0x2, 0x2000, offsets[2], len(route), 0, 0, 1, 0,
    ))
    sections.append(struct.pack(
        "<IIIIIIIIII", 25, 1, 0x3, 0x3000, offsets[3], len(routes), 0, 0, 4, 0,
    ))
    for section in sections:
        payload.extend(section)
    ident = b"\x7fELF" + bytes((1, 1, 1, 0)) + b"\x00" * 8
    header = ident + struct.pack(
        "<HHIIIIIHHHHHH", 2, 40, 1, 0x1000, 0, section_offset, 0,
        header_size, 0, 0, 40, len(sections), 1,
    )
    payload[:header_size] = header
    return bytes(payload)


def _anchor() -> NativeRouteAnchor:
    return NativeRouteAnchor(
        target_ref="frontend-native-association:online-name",
        route_token="SetOnlineDevName",
    )


def _obligation(capability: str) -> SchedulerObligation:
    return SchedulerObligation(
        obligation_id="obligation:" + capability,
        target_ref=_anchor().target_ref,
        required_capability=capability,
        reason="candidate evidence is insufficient",
        priority=90,
        candidate_analyzers=("native-deep",),
        status=ObligationStatus.OPEN,
    )


class NativeDeepRouteTableContractTests(unittest.TestCase):
    def test_named_route_table_proves_registration_and_handler_binding(self):
        content = _route_table_elf()
        source = _source("bin/httpd", content)

        result = discover_native_route_bindings(source, content, (_anchor(),))

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.bindings))
        binding = result.bindings[0]
        self.assertEqual("SetOnlineDevName", binding.route_token)
        self.assertEqual("bin/httpd@0x00001000", binding.handler_identity)
        self.assertEqual(0x3000, binding.registration_address)
        self.assertEqual(
            {"mentions_endpoint", "registers_route", "binds_handler"},
            {atom.capability for atom in result.evidence_atoms},
        )
        for atom in result.evidence_atoms:
            self.assertTrue(replay_evidence(atom, source, content))

    def test_scheduler_only_closes_exact_capability_for_exact_target(self):
        content = _route_table_elf()
        result = discover_native_route_bindings(
            _source("bin/httpd", content), content, (_anchor(),)
        )
        scheduled = run_obligation_scheduler(
            (_obligation("registers_route"), _obligation("binds_handler")),
            (native_deep_scheduler_analyzer(result),),
        )

        self.assertEqual(2, len(scheduled.resolved_obligations))
        self.assertEqual(0, len(scheduled.open_obligations))
        self.assertTrue(all(attempt.evidence_ids for attempt in scheduled.attempts))

    def test_tampered_worker_proof_is_rejected_before_scheduler_use(self):
        content = _route_table_elf()
        result = discover_native_route_bindings(
            _source("bin/httpd", content), content, (_anchor(),)
        )
        handler_atom = next(
            atom for atom in result.evidence_atoms if atom.capability == "binds_handler"
        )
        with self.assertRaisesRegex(ValueError, "handler binding proof is invalid"):
            replace(
                result,
                evidence_atoms=tuple(
                    replace(atom, observation_kind=ObservationKind.DIRECT_STATIC)
                    if atom.evidence_id == handler_atom.evidence_id else atom
                    for atom in result.evidence_atoms
                ),
            )

    def test_handler_pointer_outside_executable_section_cannot_close_obligations(self):
        content = _route_table_elf(handler_address=0x2000)
        result = discover_native_route_bindings(
            _source("bin/httpd", content), content, (_anchor(),)
        )
        scheduled = run_obligation_scheduler(
            (_obligation("binds_handler"),),
            (native_deep_scheduler_analyzer(result),),
        )

        self.assertEqual((), result.bindings)
        self.assertEqual("handler_target_not_executable", result.diagnostics[0].code)
        self.assertEqual(1, len(scheduled.open_obligations))
        self.assertEqual("unchanged", scheduled.attempts[0].status.value)

    def test_string_without_profiled_table_entry_remains_only_a_hint(self):
        content = _route_table_elf(include_entry=False) + b"formSetDeviceName\x00"
        result = discover_native_route_bindings(
            _source("bin/httpd", content), content, (_anchor(),)
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual((), result.bindings)
        self.assertEqual((), result.evidence_atoms)

    def test_untrusted_table_section_is_not_scanned_by_default_profile(self):
        content = _route_table_elf().replace(b".routes\x00", b".data__\x00")
        result = discover_native_route_bindings(
            _source("bin/httpd", content), content, (_anchor(),)
        )
        self.assertEqual((), result.bindings)

    def test_policy_and_source_failures_are_explicit(self):
        content = _route_table_elf()
        source = _source("bin/httpd", content)
        skipped = discover_native_route_bindings(
            source, content, (_anchor(),), policy=NativeDeepPolicy(max_source_bytes=16)
        )
        malformed = discover_native_route_bindings(
            _source("bin/bad", b"not-elf"), b"not-elf", (_anchor(),)
        )
        self.assertEqual(CoverageStatus.SKIPPED_BY_POLICY, skipped.coverage_status)
        self.assertEqual(CoverageStatus.UNSUPPORTED, malformed.coverage_status)

    def test_profile_is_part_of_the_result_contract(self):
        content = _route_table_elf()
        profile = NativeRouteTableProfile(
            name="vendor-named-pair/v1", table_section_names=(".routes",),
            entry_pointer_slots=2, route_pointer_slot=0, handler_pointer_slot=1,
        )
        result = discover_native_route_bindings(
            _source("bin/httpd", content), content, (_anchor(),), profile=profile,
        )
        self.assertEqual("vendor-named-pair/v1", result.profile)
        self.assertEqual(
            "firmatlas.mapping.native-deep-result/v1alpha1", result.schema_version,
        )

    def test_actual_ac9_has_no_named_route_table_proof_under_conservative_profile(self):
        path = (
            Path(__file__).resolve().parents[2]
            / "iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root/bin/httpd"
        )
        if not path.exists():
            self.skipTest("local AC9 representative sample is unavailable")
        content = path.read_bytes()
        result = discover_native_route_bindings(
            _source("bin/httpd", content), content, (_anchor(),)
        )
        self.assertEqual((), result.bindings)
        self.assertEqual((), result.evidence_atoms)

    def test_deep_bindings_close_catalog_obligations_and_remain_queryable(self):
        frontend_content = b'''var pageModel = R.pageModel({
          setUrl: "/goform/SetOnlineDevName"
        });'''
        frontend = discover_frontend_requests(
            _source("webroot/js/online.js", frontend_content), frontend_content
        )
        native_content = _route_table_elf()
        native_source = _source("bin/httpd", native_content)
        shallow = discover_native_hints(native_source, native_content)
        correlation = correlate_frontend_native((frontend,), (shallow,))
        self.assertEqual(1, len(correlation.associations))
        deep = discover_native_route_bindings(
            native_source, native_content,
            (NativeRouteAnchor(
                correlation.associations[0].association_id, "SetOnlineDevName"
            ),),
        )
        scheduler = run_obligation_scheduler(
            correlation.obligations, (native_deep_scheduler_analyzer(deep),)
        )

        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64, "2" * 64,
            (
                DiscoveryProducerBatch.frontend((frontend,), "webroot/**/*.js"),
                DiscoveryProducerBatch.native((shallow,), "bin/httpd"),
                DiscoveryProducerBatch.native_deep((deep,), "bin/httpd:.routes"),
            ), correlation, scheduler,
        ))

        self.assertEqual(0, len(catalog.open_obligations))
        self.assertEqual(
            {"native_route_binding", "native_handler"},
            {item.candidate_kind.value for item in catalog.candidates
             if item.candidate_kind.value.startswith("native_")
             and item.candidate_kind.value != "native_hint"},
        )
        repository = DiscoveryCatalogRepository(":memory:")
        try:
            repository.publish(catalog)
            detail = repository.get_candidate(
                catalog.catalog_id, correlation.associations[0].association_id
            )
            self.assertEqual(1, len(detail["associations"]))
            self.assertEqual(2, len(detail["related_candidates"]))
            self.assertEqual(
                {"mentions_endpoint", "registers_route", "binds_handler"},
                {atom["capability"] for atom in detail["evidence_atoms"]
                 if atom["producer"] == "native-deep-route-table"},
            )
            binding_candidate = next(
                item for item in catalog.candidates
                if item.candidate_kind.value == "native_route_binding"
            )
            binding_detail = repository.get_candidate(
                catalog.catalog_id, binding_candidate.candidate_id
            )
            self.assertEqual(
                correlation.associations[0].association_id,
                binding_detail["associations"][0]["association_id"],
            )
            self.assertEqual(
                {"native_handler"},
                {item["candidate_kind"] for item in binding_detail["related_candidates"]},
            )
        finally:
            repository.close()


if __name__ == "__main__":
    unittest.main()
