import hashlib
import struct
import unittest
from dataclasses import replace
from types import SimpleNamespace

from firmatlas.mapping import (
    ArmFeaturePivotAnchor,
    ArmLiteralXrefPolicy,
    CoverageStatus,
    DiscoveryCatalogInput,
    DiscoveryCandidateKind,
    DiscoveryProducerBatch,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    discover_arm_feature_pivots,
    discover_arm_pic_registrar_bindings,
)
from tests.test_mapping_native_callsite import _arm32_pic_fixture


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )


def _feature_pivot_fixture() -> bytes:
    payload = bytearray(_arm32_pic_fixture())
    section_table_offset = struct.unpack_from("<I", payload, 32)[0]
    text_offset = struct.unpack_from(
        "<I", payload, section_table_offset + 2 * 40 + 16
    )[0]

    def put(address: int, value: int) -> None:
        struct.pack_into(
            "<I", payload, text_offset + address - 0x1000, value & 0xFFFFFFFF
        )

    put(0x1100, 0xE92D4010)  # push {r4, lr}
    put(0x1104, 0xE59F4034)  # PIC delta literal at 0x1140
    put(0x1108, 0xE08F4004)  # r4 = GOT
    put(0x110C, 0xE59F0030)  # feature literal delta at 0x1144
    put(0x1110, 0xE0840000)  # r0 = "SetOnlineDevName"
    put(0x1114, 0xE8BD8010)  # pop {r4, pc}
    put(0x1140, 0x3000 - 0x1110)
    put(0x1144, 0x2000 - 0x3000)
    return bytes(payload)


class NativeFeaturePivotContractTests(unittest.TestCase):
    def test_feature_literal_is_joined_to_verified_registered_handler(self):
        content = _feature_pivot_fixture()
        source = _source("bin/httpd", content)
        registrar = discover_arm_pic_registrar_bindings(source, content)

        result = discover_arm_feature_pivots(
            source,
            content,
            (ArmFeaturePivotAnchor("feature:online", "online"),),
            registrar,
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.pivots))
        pivot = result.pivots[0]
        self.assertEqual("online", pivot.feature_token)
        self.assertEqual("SetOnlineDevName", pivot.literal_value)
        self.assertEqual(0x1100, pivot.function_start_address)
        self.assertEqual("SetOnlineDevName", pivot.route_token)
        self.assertEqual("formSetDeviceName", pivot.handler_symbol)
        self.assertTrue(pivot.route_binding_ref)

    def test_unrelated_feature_token_does_not_create_a_pivot(self):
        content = _feature_pivot_fixture()
        source = _source("bin/httpd", content)
        registrar = discover_arm_pic_registrar_bindings(source, content)

        result = discover_arm_feature_pivots(
            source,
            content,
            (ArmFeaturePivotAnchor("feature:dlna", "dlna"),),
            registrar,
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual((), result.pivots)

    def test_feature_pivot_is_queryable_with_route_binding_reference(self):
        content = _feature_pivot_fixture()
        source = _source("bin/httpd", content)
        registrar = discover_arm_pic_registrar_bindings(source, content)
        pivots = discover_arm_feature_pivots(
            source,
            content,
            (ArmFeaturePivotAnchor("feature:online", "online"),),
            registrar,
        )

        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            firmware_artifact_sha256="1" * 64,
            source_inventory_sha256="2" * 64,
            batches=(
                DiscoveryProducerBatch.native_deep(
                    (registrar,), "native:registrar"
                ),
                DiscoveryProducerBatch.arm_feature_pivot(
                    (pivots,), "native:feature-pivot"
                ),
            ),
        ))

        candidate = next(
            item for item in catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.ARM_FEATURE_PIVOT
        )
        attributes = dict(candidate.attributes)
        self.assertEqual("candidate", candidate.claim_status.value)
        self.assertEqual("online", attributes["feature_token"])
        self.assertEqual("SetOnlineDevName", attributes["literal_value"])
        self.assertEqual("SetOnlineDevName", attributes["route_token"])
        self.assertEqual("formSetDeviceName", attributes["handler_symbol"])
        self.assertTrue(attributes["route_binding_ref"])

    def test_multiple_route_joins_respect_the_pivot_budget(self):
        content = _feature_pivot_fixture()
        source = _source("bin/httpd", content)
        registrar = discover_arm_pic_registrar_bindings(source, content)
        primary, secondary = registrar.bindings
        shared_handler = replace(
            secondary,
            handler_address=primary.handler_address,
            handler_identity=primary.handler_identity,
            handler_symbol=primary.handler_symbol,
        )
        third_shared_handler = replace(
            shared_handler, binding_id="binding:shared-handler-third-route"
        )
        expanded_registrar = SimpleNamespace(
            source_path=registrar.source_path,
            coverage_status=registrar.coverage_status,
            bindings=(primary, shared_handler, third_shared_handler),
            evidence_atoms=registrar.evidence_atoms,
        )

        result = discover_arm_feature_pivots(
            source,
            content,
            (ArmFeaturePivotAnchor("feature:online", "online"),),
            expanded_registrar,
            policy=ArmLiteralXrefPolicy(max_xrefs=2),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual(2, len(result.pivots))
        self.assertIn(
            "arm_feature_pivot.pivot_budget_exhausted", result.diagnostics
        )


if __name__ == "__main__":
    unittest.main()
