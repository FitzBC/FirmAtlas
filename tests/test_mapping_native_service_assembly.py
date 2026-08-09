import hashlib
from dataclasses import replace
import json
from pathlib import Path
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    DiscoveryCatalogInput,
    DiscoveryCandidateKind,
    DiscoveryProducerBatch,
    MipsServiceAssemblyAnchor,
    MipsServiceAssemblyPolicy,
    ServiceAssemblyArtifact,
    StaticAssemblyStatus,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    discover_frontend_requests,
    discover_mips_service_assembly,
    replay_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
X5000R_ROOT = ROOT / (
    "var/mapping-work/x5000r-v9.1.0u.6118/extractions/firmware.bin.extracted/"
    "1004C/C8343R-6118.bin.extracted/184C70/squashfs-root"
)
PATHS = (
    "sbin/rc",
    "usr/sbin/lighttpd",
    "lighttp/lighttpd.conf",
    "www/cgi-bin/cstecgi.cgi",
)


def _artifact(path: str, content: bytes) -> ServiceAssemblyArtifact:
    return ServiceAssemblyArtifact(
        SourceArtifactEntry(
            canonical_path=path,
            original_path=path,
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        ),
        content,
    )


class MipsServiceAssemblyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contents = {
            path: (X5000R_ROOT / path).read_bytes() for path in PATHS
        }
        cls.artifacts = tuple(
            _artifact(path, cls.contents[path]) for path in PATHS
        )

    def test_actual_x5000r_proves_static_launch_to_cgi_artifact_chain(self) -> None:
        result = discover_mips_service_assembly(
            self.artifacts,
            (MipsServiceAssemblyAnchor(
                "nested:setUploadSetting", "/cgi-bin/cstecgi.cgi"
            ),),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.assemblies))
        assembly = result.assemblies[0]
        self.assertEqual(StaticAssemblyStatus.PROVED, assembly.assembly_status)
        self.assertEqual("init_router", assembly.bootstrap_symbol)
        self.assertEqual("sbin/rc@0x0040850c", assembly.bootstrap_identity)
        self.assertEqual(0x00408F1C, assembly.bootstrap_callsite)
        self.assertEqual("sbin/rc@0x0040b644", assembly.service_group_identity)
        self.assertEqual("start_services_once", assembly.service_group_symbol)
        self.assertEqual(0x0040B6B0, assembly.service_group_callsite)
        self.assertEqual("sbin/rc@0x0040aadc", assembly.launcher_identity)
        self.assertEqual("start_httpd", assembly.launcher_symbol)
        self.assertEqual(0x00457314, assembly.argument_table_address)
        self.assertEqual(0x0040AB24, assembly.launch_callsite)
        self.assertEqual("usr/sbin/lighttpd", assembly.server_artifact_path)
        self.assertEqual("lighttp/lighttpd.conf", assembly.config_artifact_path)
        self.assertEqual((80, 8080), assembly.listeners)
        self.assertEqual("/www/", assembly.document_root)
        self.assertEqual("/cgi-bin/", assembly.cgi_namespace)
        self.assertEqual(
            "www/cgi-bin/cstecgi.cgi", assembly.target_artifact_path
        )
        self.assertFalse(assembly.runtime_reachability_verified)
        self.assertEqual(11, len(assembly.evidence_ids))
        by_path = {artifact.source.canonical_path: artifact for artifact in self.artifacts}
        atoms = {
            atom.evidence_id: atom for atom in result.evidence_atoms
        }
        self.assertTrue(all(
            replay_evidence(
                atoms[evidence_id],
                by_path[atoms[evidence_id].source_span.artifact_path].source,
                by_path[atoms[evidence_id].source_span.artifact_path].content,
            )
            for evidence_id in assembly.evidence_ids
        ))

    def test_documented_x5000r_static_assembly_is_exactly_replayable(self) -> None:
        from scripts.build_x5000r_service_assembly_report import build_summary

        documented = json.loads((
            ROOT / "docs/firmware-mapping/samples/"
            "m1-22-x5000r-service-assembly.json"
        ).read_text(encoding="utf-8"))

        self.assertEqual(documented, build_summary(X5000R_ROOT))

    def test_cgi_namespace_must_cover_the_request_path(self) -> None:
        config = self.contents["lighttp/lighttpd.conf"].replace(
            b"/cgi-bin/", b"/xgi-bin/", 1
        )
        artifacts = tuple(
            _artifact(path, config if path == "lighttp/lighttpd.conf" else content)
            for path, content in self.contents.items()
        )

        result = discover_mips_service_assembly(
            artifacts,
            (MipsServiceAssemblyAnchor("target", "/cgi-bin/cstecgi.cgi"),),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual((), result.assemblies)
        self.assertEqual("cgi_configuration_not_proven", result.diagnostics[0].code)

    def test_missing_target_and_source_failures_remain_explicit(self) -> None:
        missing = discover_mips_service_assembly(
            tuple(
                item for item in self.artifacts
                if item.source.canonical_path != "www/cgi-bin/cstecgi.cgi"
            ),
            (MipsServiceAssemblyAnchor("target", "/cgi-bin/cstecgi.cgi"),),
        )
        mismatch_artifact = self.artifacts[0]
        mismatch = discover_mips_service_assembly(
            (
                ServiceAssemblyArtifact(
                    mismatch_artifact.source,
                    mismatch_artifact.content + b"x",
                ),
                *self.artifacts[1:],
            ),
            (MipsServiceAssemblyAnchor("target", "/cgi-bin/cstecgi.cgi"),),
        )

        self.assertEqual(CoverageStatus.PARTIAL, missing.coverage_status)
        self.assertEqual("request_artifact_not_proven", missing.diagnostics[0].code)
        self.assertEqual(CoverageStatus.FAILED, mismatch.coverage_status)
        self.assertEqual("source_mismatch", mismatch.diagnostics[0].code)

    def test_argv_table_and_instruction_budget_fail_closed(self) -> None:
        baseline = discover_mips_service_assembly(
            self.artifacts,
            (MipsServiceAssemblyAnchor("target", "/cgi-bin/cstecgi.cgi"),),
        )
        table_atom = next(
            atom for atom in baseline.evidence_atoms
            if atom.capability == "orders_service_arguments"
        )
        launcher = bytearray(self.contents["sbin/rc"])
        start = table_atom.source_span.start_byte
        launcher[start:start + 4] = b"\0" * 4
        mutated = tuple(
            _artifact(path, bytes(launcher) if path == "sbin/rc" else content)
            for path, content in self.contents.items()
        )
        argv = discover_mips_service_assembly(
            mutated,
            (MipsServiceAssemblyAnchor("target", "/cgi-bin/cstecgi.cgi"),),
        )
        budget = discover_mips_service_assembly(
            self.artifacts,
            (MipsServiceAssemblyAnchor("target", "/cgi-bin/cstecgi.cgi"),),
            policy=MipsServiceAssemblyPolicy(max_instructions=10),
        )

        self.assertEqual(CoverageStatus.PARTIAL, argv.coverage_status)
        self.assertIn(argv.diagnostics[0].code, {
            "launch_argv_not_terminated", "launch_argument_not_proven"
        })
        self.assertEqual(CoverageStatus.PARTIAL, budget.coverage_status)
        self.assertEqual("instruction_budget", budget.diagnostics[0].code)

    def test_initialization_call_chain_must_be_present(self) -> None:
        baseline = discover_mips_service_assembly(
            self.artifacts,
            (MipsServiceAssemblyAnchor("target", "/cgi-bin/cstecgi.cgi"),),
        )
        bootstrap_atom = next(
            atom for atom in baseline.evidence_atoms
            if atom.capability == "enters_service_bootstrap"
        )
        launcher = bytearray(self.contents["sbin/rc"])
        span = bootstrap_atom.source_span
        launcher[span.start_byte:span.end_byte] = b"\0" * (
            span.end_byte - span.start_byte
        )
        mutated = tuple(
            _artifact(path, bytes(launcher) if path == "sbin/rc" else content)
            for path, content in self.contents.items()
        )

        result = discover_mips_service_assembly(
            mutated,
            (MipsServiceAssemblyAnchor("target", "/cgi-bin/cstecgi.cgi"),),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual(
            "initialization_chain_not_proven", result.diagnostics[0].code
        )

    def test_static_result_cannot_be_tampered_into_runtime_verification(self) -> None:
        result = discover_mips_service_assembly(
            self.artifacts,
            (MipsServiceAssemblyAnchor("target", "/cgi-bin/cstecgi.cgi"),),
        )

        with self.assertRaisesRegex(ValueError, "runtime reachability"):
            replace(
                result,
                assemblies=(replace(
                    result.assemblies[0], runtime_reachability_verified=True
                ),),
            )

    def test_result_relation_cannot_be_changed_without_matching_evidence(self) -> None:
        result = discover_mips_service_assembly(
            self.artifacts,
            (MipsServiceAssemblyAnchor("target", "/cgi-bin/cstecgi.cgi"),),
        )

        with self.assertRaisesRegex(ValueError, "proof object is inconsistent"):
            replace(
                result,
                assemblies=(replace(result.assemblies[0], listeners=(80,)),),
            )

    def test_validated_assembly_is_queryable_as_catalog_candidate(self) -> None:
        frontend_content = b'$.post("/cgi-bin/cstecgi.cgi", {topicurl: "x"});'
        frontend = discover_frontend_requests(
            SourceArtifactEntry(
                "www/request.js",
                "www/request.js",
                "file",
                len(frontend_content),
                hashlib.sha256(frontend_content).hexdigest(),
            ),
            frontend_content,
        )
        target_ref = frontend.candidates[0].candidate_id
        result = discover_mips_service_assembly(
            self.artifacts,
            (MipsServiceAssemblyAnchor(target_ref, "/cgi-bin/cstecgi.cgi"),),
        )
        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64,
            "2" * 64,
            (
                DiscoveryProducerBatch.frontend((frontend,), "www/request.js"),
                DiscoveryProducerBatch.native_service_assembly(
                    (result,), "X5000R:static-service-assembly"
                ),
            ),
        ))

        candidates = [
            item for item in catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.NATIVE_SERVICE_ASSEMBLY
        ]
        self.assertEqual(1, len(candidates))
        self.assertEqual(
            "sbin/rc -> usr/sbin/lighttpd -> /cgi-bin/cstecgi.cgi",
            candidates[0].canonical_identity,
        )


if __name__ == "__main__":
    unittest.main()
    assemble_discovery_catalog,
