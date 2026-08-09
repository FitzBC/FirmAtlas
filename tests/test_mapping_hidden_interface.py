from dataclasses import replace
import json
from pathlib import Path
import unittest

from firmatlas.mapping import (
    AttributionArtifact,
    AttributionArtifactRole,
    CoverageStatus,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    assemble_discovery_catalog,
    attribute_frontend_native_set_difference,
    build_potential_hidden_interface_index,
)
from tests.test_mapping_set_difference import _source, _upstreams


def _catalog(*, frontend_partial: bool = False):
    frontend, native = _upstreams(
        ("visibleOperation",),
        ("visibleOperation", "hiddenOperation", "scopedOperation"),
    )
    if frontend_partial:
        frontend = replace(frontend, coverage_status=CoverageStatus.PARTIAL)
    web = b"scopedOperation();"
    difference = attribute_frontend_native_set_difference(
        frontend,
        native,
        (
            AttributionArtifact(
                _source("www/feature.html", web),
                web,
                AttributionArtifactRole.WEB_AUXILIARY,
            ),
        ),
    )
    return assemble_discovery_catalog(DiscoveryCatalogInput(
        "1" * 64,
        "2" * 64,
        (
            DiscoveryProducerBatch.frontend(
                frontend.results, "www/static/js/*"
            ),
        ),
        set_difference=difference,
    ))


class PotentialHiddenInterfaceContractTests(unittest.TestCase):
    def test_documented_x5000r_hidden_interface_report_is_replayable(self):
        from scripts.build_x5000r_hidden_interface_report import (
            X5000R_ROOT,
            build_summary,
        )

        if not X5000R_ROOT.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        documented = json.loads(Path(
            "docs/firmware-mapping/samples/"
            "m1-23-x5000r-potential-hidden-interfaces.json"
        ).read_text(encoding="utf-8"))

        self.assertEqual(documented, build_summary(X5000R_ROOT))

    def test_actual_x5000r_preserves_all_ten_unreferenced_registrations(self):
        from scripts.build_mapping_corpus_report import X5000R_ROOT, _x5000r_catalog

        if not X5000R_ROOT.exists():
            self.skipTest("local X5000R representative sample is unavailable")

        index = build_potential_hidden_interface_index(
            _x5000r_catalog(X5000R_ROOT)
        )

        self.assertEqual(CoverageStatus.COMPLETED, index.coverage_status)
        self.assertEqual(10, len(index.items))
        self.assertEqual(10, len({item.operation_token for item in index.items}))
        self.assertTrue(all(item.handler_identities for item in index.items))
        self.assertTrue(all(
            item.registration_artifact_path == "www/cgi-bin/cstecgi.cgi"
            for item in index.items
        ))

    def test_complete_scope_projects_only_unreferenced_native_registration(self):
        catalog = _catalog()

        index = build_potential_hidden_interface_index(catalog)

        self.assertEqual(CoverageStatus.COMPLETED, index.coverage_status)
        self.assertEqual(1, len(index.items))
        item = index.items[0]
        self.assertEqual("hiddenOperation", item.operation_token)
        self.assertEqual("www/cgi-bin/cstecgi.cgi", item.registration_artifact_path)
        self.assertEqual(1, len(item.binding_ids))
        self.assertEqual(1, len(item.handler_identities))
        self.assertTrue(item.frontend_coverage_complete)
        self.assertFalse(item.runtime_reachability_verified)
        self.assertIn("hidden clients", item.open_obligation)
        self.assertEqual(4, len(item.evidence_ids))

    def test_scope_gap_is_not_a_potential_hidden_interface(self):
        index = build_potential_hidden_interface_index(_catalog())

        self.assertNotIn(
            "scopedOperation", {item.operation_token for item in index.items}
        )

    def test_incomplete_frontend_or_set_difference_coverage_fails_closed(self):
        index = build_potential_hidden_interface_index(
            _catalog(frontend_partial=True)
        )

        self.assertEqual(CoverageStatus.PARTIAL, index.coverage_status)
        self.assertEqual((), index.items)
        self.assertEqual(
            "set_difference_coverage_incomplete", index.diagnostics[0].code
        )

    def test_projection_rejects_runtime_reachability_tampering(self):
        index = build_potential_hidden_interface_index(_catalog())

        with self.assertRaisesRegex(ValueError, "runtime reachability"):
            replace(
                index,
                items=(replace(
                    index.items[0], runtime_reachability_verified=True
                ),),
            )


if __name__ == "__main__":
    unittest.main()
