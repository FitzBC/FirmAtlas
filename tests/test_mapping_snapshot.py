import json
from pathlib import Path
import subprocess
import sys
import unittest

from firmatlas.mapping import (
    AnalyzerIdentity,
    ClaimStatus,
    CoverageEntry,
    CoverageStatus,
    DiagnosticSeverity,
    EvidenceAtom,
    EvidenceSpan,
    FirmwareMappingSnapshot,
    MappingBudget,
    MappingDiagnostic,
    MappingEntity,
    MappingMode,
    MappingPolicy,
    ObservationKind,
    ObligationStatus,
    SemanticRelation,
    SnapshotStatus,
    UnresolvedObligation,
)


class FirmwareMappingSnapshotContractTests(unittest.TestCase):
    def setUp(self):
        self.evidence = EvidenceAtom(
            evidence_id="ev-frontend-static-route",
            subject_ref="interface:goform-set-static-route",
            predicate="constructs_request",
            object_value="goform/SetStaticRouteCfg",
            source_span=EvidenceSpan(
                artifact_path="webroot_ro/js/static_route.js",
                artifact_sha256="9bd1ff64ac59189812d29fefe565984c7f58ac68358003e15a1e3fa71a15482b",
                locator="lines:18-19",
            ),
            producer="frontend-javascript",
            producer_version="0.1.0",
            observation_kind=ObservationKind.DIRECT_STATIC,
            capability="constructs_request",
            confidence=1.0,
        )
        self.entity = MappingEntity(
            entity_id="interface:goform-set-static-route",
            entity_kind="exposed_interface",
            canonical_identity="http|/goform/SetStaticRouteCfg|POST|form",
            claim_status=ClaimStatus.SUPPORTED,
            evidence_ids=(self.evidence.evidence_id,),
        )
        self.snapshot_values = dict(
            schema_version="firmatlas.mapping.snapshot/v1alpha1",
            snapshot_id="mapping:tenda-ac9:m1-contract",
            firmware_artifact_sha256="981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296",
            source_inventory_sha256="84747a51473b826ea2207396f5677dc39786cfc5bd0603f515ae135c923513f0",
            status=SnapshotStatus.PARTIAL_SUCCESS,
            policy=MappingPolicy(name="m1-contract", mode=MappingMode.DISCOVER),
            budget=MappingBudget(
                max_files=10000,
                max_bytes=268435456,
                max_seconds=300,
                max_deep_targets=0,
            ),
            analyzers=(AnalyzerIdentity(name="frontend-javascript", version="0.1.0"),),
            evidence_atoms=(self.evidence,),
            entities=(self.entity,),
            relations=(),
            coverage=(
                CoverageEntry(
                    scope="webroot_ro/**/*.js",
                    capability="constructs_request",
                    status=CoverageStatus.COMPLETED,
                    producer="frontend-javascript",
                    producer_version="0.1.0",
                    required=True,
                ),
                CoverageEntry(
                    scope="bin/httpd",
                    capability="binds_handler",
                    status=CoverageStatus.UNSUPPORTED,
                    producer="native-decompiler",
                    producer_version="not-run",
                    required=False,
                    diagnostic="M1 contract example does not perform Native binding",
                ),
            ),
            unresolved_obligations=(
                UnresolvedObligation(
                    obligation_id="obl-bind-static-route-handler",
                    target_ref=self.entity.entity_id,
                    required_capability="binds_handler",
                    reason="Frontend request construction does not prove a backend handler binding",
                    priority=90,
                    candidate_analyzers=("native-route-binding",),
                    status=ObligationStatus.OPEN,
                ),
            ),
        )

    def test_partial_snapshot_serializes_evidence_coverage_and_obligations(self):
        snapshot = FirmwareMappingSnapshot(**self.snapshot_values)

        payload = snapshot.to_dict()

        self.assertEqual("partial_success", payload["status"])
        self.assertEqual("discover", payload["policy"]["mode"])
        self.assertEqual("direct_static", payload["evidence_atoms"][0]["observation_kind"])
        self.assertEqual("unsupported", payload["coverage"][1]["status"])
        self.assertEqual("open", payload["unresolved_obligations"][0]["status"])
        self.assertNotIn("api_key", str(payload).lower())

    def test_snapshot_rejects_entity_with_dangling_evidence_reference(self):
        entity = MappingEntity(
            entity_id=self.entity.entity_id,
            entity_kind=self.entity.entity_kind,
            canonical_identity=self.entity.canonical_identity,
            claim_status=ClaimStatus.SUPPORTED,
            evidence_ids=("ev-does-not-exist",),
        )

        with self.assertRaisesRegex(ValueError, "unknown evidence ev-does-not-exist"):
            FirmwareMappingSnapshot(**{**self.snapshot_values, "entities": (entity,)})

    def test_model_suggestion_cannot_be_the_only_support_for_an_entity(self):
        evidence = EvidenceAtom(
            evidence_id=self.evidence.evidence_id,
            subject_ref=self.evidence.subject_ref,
            predicate=self.evidence.predicate,
            object_value=self.evidence.object_value,
            source_span=self.evidence.source_span,
            producer="minimax-adjudicator",
            producer_version="future",
            observation_kind=ObservationKind.MODEL_SUGGESTED,
            capability=self.evidence.capability,
            confidence=0.99,
        )

        with self.assertRaisesRegex(ValueError, "only model-suggested evidence"):
            FirmwareMappingSnapshot(
                **{**self.snapshot_values, "evidence_atoms": (evidence,)}
            )

    def test_success_rejects_incomplete_required_coverage(self):
        coverage = CoverageEntry(
            scope="webroot_ro/**/*.js",
            capability="constructs_request",
            status=CoverageStatus.PARTIAL,
            producer="frontend-javascript",
            producer_version="0.1.0",
            required=True,
            diagnostic="file budget exhausted",
        )

        with self.assertRaisesRegex(ValueError, "success requires completed coverage"):
            FirmwareMappingSnapshot(
                **{
                    **self.snapshot_values,
                    "status": SnapshotStatus.SUCCESS,
                    "coverage": (coverage,),
                }
            )

    def test_relation_rejects_unknown_target_entity(self):
        relation = SemanticRelation(
            relation_id="rel-interface-handler",
            source_ref=self.entity.entity_id,
            predicate="binds_to",
            target_ref="handler:not-published",
            claim_status=ClaimStatus.SUPPORTED,
            evidence_ids=(self.evidence.evidence_id,),
        )

        with self.assertRaisesRegex(ValueError, "unknown target handler:not-published"):
            FirmwareMappingSnapshot(
                **{**self.snapshot_values, "relations": (relation,)}
            )

    def test_snapshot_rejects_noncanonical_artifact_digest(self):
        with self.assertRaisesRegex(ValueError, "firmware_artifact_sha256"):
            FirmwareMappingSnapshot(
                **{**self.snapshot_values, "firmware_artifact_sha256": "NOT-A-SHA256"}
            )

    def test_snapshot_round_trips_through_versioned_dictionary(self):
        snapshot = FirmwareMappingSnapshot(**self.snapshot_values)

        restored = FirmwareMappingSnapshot.from_dict(snapshot.to_dict())

        self.assertEqual(snapshot, restored)

    def test_snapshot_rejects_duplicate_evidence_identity(self):
        with self.assertRaisesRegex(ValueError, "duplicate evidence_id"):
            FirmwareMappingSnapshot(
                **{
                    **self.snapshot_values,
                    "evidence_atoms": (self.evidence, self.evidence),
                }
            )

    def test_snapshot_rejects_out_of_range_evidence_confidence(self):
        evidence = EvidenceAtom(
            evidence_id=self.evidence.evidence_id,
            subject_ref=self.evidence.subject_ref,
            predicate=self.evidence.predicate,
            object_value=self.evidence.object_value,
            source_span=self.evidence.source_span,
            producer=self.evidence.producer,
            producer_version=self.evidence.producer_version,
            observation_kind=self.evidence.observation_kind,
            capability=self.evidence.capability,
            confidence=1.01,
        )

        with self.assertRaisesRegex(ValueError, "confidence must be between 0 and 1"):
            FirmwareMappingSnapshot(
                **{**self.snapshot_values, "evidence_atoms": (evidence,)}
            )

    def test_tenda_ac9_worked_example_preserves_unknown_handler_bindings(self):
        fixture = (
            Path(__file__).parent
            / "fixtures"
            / "mapping"
            / "tenda_ac9_m1_snapshot.json"
        )

        snapshot = FirmwareMappingSnapshot.from_dict(
            json.loads(fixture.read_text(encoding="utf-8"))
        )

        self.assertEqual(SnapshotStatus.PARTIAL_SUCCESS, snapshot.status)
        self.assertEqual(7, len(snapshot.entities))
        self.assertEqual(3, len(snapshot.relations))
        self.assertEqual(3, len(snapshot.unresolved_obligations))
        self.assertNotIn("binds_to", {relation.predicate for relation in snapshot.relations})
        self.assertEqual(
            {"SetStaticRouteCfg", "SetOnlineDevName"},
            {
                evidence.object_value
                for evidence in snapshot.evidence_atoms
                if evidence.capability == "mentions_handler_name"
            },
        )

    def test_mapping_cli_explains_the_worked_snapshot(self):
        fixture = (
            Path(__file__).parent
            / "fixtures"
            / "mapping"
            / "tenda_ac9_m1_snapshot.json"
        )

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "firmatlas.mapping",
                "validate-snapshot",
                str(fixture),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        summary = json.loads(completed.stdout)
        self.assertEqual("mapping:tenda-ac9:m1-manual-replay", summary["snapshot_id"])
        self.assertEqual(2, summary["interface_count"])
        self.assertEqual(3, summary["parameter_count"])
        self.assertEqual(3, summary["open_obligation_count"])

    def test_failed_snapshot_requires_a_structured_diagnostic(self):
        values = {
            **self.snapshot_values,
            "status": SnapshotStatus.FAILED,
            "entities": (),
            "evidence_atoms": (),
            "unresolved_obligations": (),
        }

        with self.assertRaisesRegex(ValueError, "failed snapshot requires diagnostics"):
            FirmwareMappingSnapshot(**values)

        snapshot = FirmwareMappingSnapshot(
            **{
                **values,
                "diagnostics": (
                    MappingDiagnostic(
                        code="INVENTORY_UNREADABLE",
                        severity=DiagnosticSeverity.ERROR,
                        message="The extracted root could not be read",
                        producer="artifact-inventory",
                    ),
                ),
            }
        )
        self.assertEqual("INVENTORY_UNREADABLE", snapshot.diagnostics[0].code)

    def test_obligation_rejects_unknown_target_entity(self):
        obligation = UnresolvedObligation(
            obligation_id="obl-unknown-target",
            target_ref="interface:not-published",
            required_capability="binds_handler",
            reason="A scheduler cannot resolve an obligation without a target entity",
            priority=50,
            candidate_analyzers=("native-route-binding",),
            status=ObligationStatus.OPEN,
        )

        with self.assertRaisesRegex(ValueError, "unknown target interface:not-published"):
            FirmwareMappingSnapshot(
                **{**self.snapshot_values, "unresolved_obligations": (obligation,)}
            )

    def test_incomplete_coverage_requires_a_diagnostic(self):
        coverage = CoverageEntry(
            scope="bin/httpd",
            capability="binds_handler",
            status=CoverageStatus.UNSUPPORTED,
            producer="native-decompiler",
            producer_version="not-run",
            required=False,
        )

        with self.assertRaisesRegex(ValueError, "unsupported coverage requires diagnostic"):
            FirmwareMappingSnapshot(
                **{**self.snapshot_values, "coverage": (coverage,)}
            )

    def test_model_suggestion_cannot_be_the_only_support_for_a_relation(self):
        evidence = EvidenceAtom(
            evidence_id="ev-model-relation",
            subject_ref=self.evidence.subject_ref,
            predicate=self.evidence.predicate,
            object_value=self.evidence.object_value,
            source_span=self.evidence.source_span,
            producer="minimax-adjudicator",
            producer_version="future",
            observation_kind=ObservationKind.MODEL_SUGGESTED,
            capability="accepts_parameter",
            confidence=0.99,
        )
        parameter = MappingEntity(
            entity_id="parameter:static-route:list",
            entity_kind="parameter_identity",
            canonical_identity="interface:goform-set-static-route|form|list|request",
            claim_status=ClaimStatus.UNKNOWN,
            evidence_ids=(evidence.evidence_id,),
        )
        relation = SemanticRelation(
            relation_id="rel-static-route-list",
            source_ref=self.entity.entity_id,
            predicate="accepts",
            target_ref=parameter.entity_id,
            claim_status=ClaimStatus.SUPPORTED,
            evidence_ids=(evidence.evidence_id,),
        )

        with self.assertRaisesRegex(ValueError, "only model-suggested evidence"):
            FirmwareMappingSnapshot(
                **{
                    **self.snapshot_values,
                    "evidence_atoms": (self.evidence, evidence),
                    "entities": (self.entity, parameter),
                    "relations": (relation,),
                }
            )


if __name__ == "__main__":
    unittest.main()
