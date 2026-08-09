import hashlib
import unittest

from firmatlas.mapping import (
    AttributionArtifact,
    AttributionArtifactRole,
    CoverageStatus,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    DifferenceAttributionKind,
    DifferenceSide,
    FrontendAssetInput,
    NativeRouteAnchor,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    attribute_frontend_native_set_difference,
    discover_frontend_asset_graph,
    discover_mips_inline_route_bindings,
    replay_evidence,
)
from tests.test_mapping_native_mips_inline import _mips_inline_table_fixture


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )


def _asset(path: str, content: bytes) -> FrontendAssetInput:
    return FrontendAssetInput(_source(path, content), content)


def _upstreams(frontend_tokens, native_tokens):
    config = b'var globalConfig = {cgiUrl: "/cgi-bin/cstecgi.cgi"};'
    methods = "\n".join(
        '''Dispatcher.prototype.{0} = function(data) {{
  return this.topicurl = "{0}", this.post(data);
}};'''.format(token)
        for token in frontend_tokens
    )
    wrapper = ('''
function Dispatcher() {
  this.srcUrl = globalConfig.cgiUrl;
  this.post = function(data) {
    data.topicurl = this.topicurl;
    data = JSON.stringify(data);
    $.ajax({url:this.srcUrl,type:"POST",dataType:"json",data:data});
  };
}
''' + methods).encode()
    frontend = discover_frontend_asset_graph((
        _asset("www/static/js/config.js", config),
        _asset("www/static/js/topicurl.js", wrapper),
    ))
    binary = _mips_inline_table_fixture(tuple(
        (token, 0x1100 + index * 0x20)
        for index, token in enumerate(native_tokens)
    ))
    native_source = _source("www/cgi-bin/cstecgi.cgi", binary)
    native = discover_mips_inline_route_bindings(
        native_source,
        binary,
        tuple(
            NativeRouteAnchor("native:{}".format(token), token)
            for token in native_tokens
        ),
    )
    return frontend, native


class FrontendNativeSetDifferenceContractTests(unittest.TestCase):
    def test_direct_frontend_operation_is_not_mislabeled_as_wrapper_declaration(self):
        content = b'''var page={importAction:
"/cgi-bin/cstecgi.cgi?action=upload&setting/setUploadSetting"};
upload.fileUpload({data:file,url:this.importAction});'''
        frontend = discover_frontend_asset_graph((
            _asset("www/advance/config.html", content),
        ))
        _, native = _upstreams((), ("setUploadSetting",))

        result = attribute_frontend_native_set_difference(
            frontend, native, ()
        )

        upload = next(item for item in result.attributions if item.token == "upload")
        self.assertEqual(
            DifferenceAttributionKind.FRONTEND_OPERATION_NATIVE_ABSENT,
            upload.kind,
        )
        self.assertIn("direct frontend request", upload.interpretation)

    def test_auxiliary_evidence_distinguishes_scope_gap_from_unreferenced_routes(self):
        frontend, native = _upstreams(
            ("wrapperOnly", "usedOnly"),
            ("nativeOnly", "scopedNative", "crossNative"),
        )
        page = b'usedOnly(); scopedNative();'
        auxiliary_binary = b'prefix\x00crossNative\x00suffix'

        result = attribute_frontend_native_set_difference(
            frontend,
            native,
            (
                AttributionArtifact(
                    _source("www/feature.html", page), page,
                    AttributionArtifactRole.WEB_AUXILIARY,
                ),
                AttributionArtifact(
                    _source("usr/sbin/lighttpd", auxiliary_binary),
                    auxiliary_binary,
                    AttributionArtifactRole.NATIVE_AUXILIARY,
                ),
            ),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(5, len(result.attributions))
        by_token = {item.token: item for item in result.attributions}
        self.assertEqual(
            DifferenceAttributionKind.FRONTEND_DECLARATION_NATIVE_ABSENT,
            by_token["wrapperOnly"].kind,
        )
        self.assertEqual(
            DifferenceAttributionKind.FRONTEND_CONSUMER_NATIVE_ABSENT,
            by_token["usedOnly"].kind,
        )
        self.assertEqual(
            DifferenceAttributionKind.FRONTEND_SCOPE_GAP,
            by_token["scopedNative"].kind,
        )
        self.assertEqual(
            DifferenceAttributionKind.CROSS_NATIVE_LITERAL,
            by_token["crossNative"].kind,
        )
        self.assertEqual(
            DifferenceAttributionKind.NATIVE_REGISTRATION_NO_FRONTEND_REFERENCE,
            by_token["nativeOnly"].kind,
        )
        self.assertEqual(DifferenceSide.FRONTEND_ONLY, by_token["usedOnly"].side)
        self.assertEqual(DifferenceSide.NATIVE_ONLY, by_token["nativeOnly"].side)
        self.assertEqual(3, len(result.evidence_atoms))
        sources = {
            "www/feature.html": (_source("www/feature.html", page), page),
            "usr/sbin/lighttpd": (
                _source("usr/sbin/lighttpd", auxiliary_binary), auxiliary_binary,
            ),
        }
        for atom in result.evidence_atoms:
            source, content = sources[atom.source_span.artifact_path]
            self.assertTrue(replay_evidence(atom, source, content))

    def test_native_suffix_variant_stays_an_open_candidate_not_an_exact_match(self):
        frontend, native = _upstreams(
            ("frontendOnly",), ("loginAuth", "nativeOther")
        )
        content = b"prefix\x00userloginAuth\x00suffix"
        source = _source("usr/sbin/lighttpd", content)

        result = attribute_frontend_native_set_difference(
            frontend,
            native,
            (AttributionArtifact(
                source, content, AttributionArtifactRole.NATIVE_AUXILIARY
            ),),
        )

        item = next(item for item in result.attributions if item.token == "loginAuth")
        self.assertEqual(
            DifferenceAttributionKind.CROSS_NATIVE_TOKEN_VARIANT, item.kind
        )
        self.assertIn("Validate whether", item.open_obligation)
        atom = next(atom for atom in result.evidence_atoms if atom.subject_ref == item.attribution_id)
        self.assertEqual("mentions_operation_variant", atom.capability)
        self.assertEqual("userloginAuth", atom.object_value)
        self.assertTrue(replay_evidence(atom, source, content))

    def test_catalog_projects_attribution_with_upstream_and_auxiliary_evidence(self):
        frontend, native = _upstreams(
            ("usedOnly",), ("nativeOne", "nativeTwo")
        )
        content = b"usedOnly();"
        source = _source("www/feature.html", content)
        attribution = attribute_frontend_native_set_difference(
            frontend,
            native,
            (AttributionArtifact(
                source, content, AttributionArtifactRole.WEB_AUXILIARY
            ),),
        )

        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64,
            "2" * 64,
            (DiscoveryProducerBatch.frontend(
                frontend.results, "www/static/js/*"
            ),),
            set_difference=attribution,
        ))

        candidates = [
            item for item in catalog.candidates
            if item.candidate_kind.value == "set_difference_attribution"
        ]
        self.assertEqual(3, len(candidates))
        candidate = next(
            item for item in candidates if item.canonical_identity == "usedOnly"
        )
        attributes = dict(candidate.attributes)
        self.assertEqual("frontend_only", attributes["difference_side"])
        self.assertEqual(
            "frontend_consumer_native_absent", attributes["attribution_kind"]
        )
        self.assertEqual("www/feature.html", candidate.source_path)
        self.assertEqual(3, len(candidate.evidence_ids))
        self.assertTrue(set(candidate.evidence_ids) <= {
            atom.evidence_id for atom in catalog.evidence_atoms
        })
        coverage = next(
            item for item in catalog.coverage
            if item.producer_kind.value == "set_difference"
        )
        self.assertEqual(CoverageStatus.COMPLETED, coverage.status)

    def test_mismatched_auxiliary_source_is_partial_and_cannot_create_a_consumer(self):
        frontend, native = _upstreams(
            ("usedOnly",), ("nativeOne", "nativeTwo")
        )
        content = b"usedOnly();"
        mismatched = _source("www/feature.html", b"different")

        result = attribute_frontend_native_set_difference(
            frontend,
            native,
            (AttributionArtifact(
                mismatched, content, AttributionArtifactRole.WEB_AUXILIARY
            ),),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual("source_mismatch", result.diagnostics[0].code)
        item = next(item for item in result.attributions if item.token == "usedOnly")
        self.assertEqual(
            DifferenceAttributionKind.FRONTEND_DECLARATION_NATIVE_ABSENT,
            item.kind,
        )
        self.assertEqual((), item.evidence_ids)

    def test_documented_x5000r_attribution_is_exactly_replayable(self):
        from scripts.build_x5000r_set_difference_report import X5000R_ROOT, build_summary
        from pathlib import Path
        import json

        if not X5000R_ROOT.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        documented = json.loads(Path(
            "docs/firmware-mapping/samples/m1-18-x5000r-set-difference.json"
        ).read_text())

        replayed = build_summary(X5000R_ROOT)

        self.assertEqual(documented, replayed)
        self.assertEqual({
            "frontend_consumer_native_absent": 38,
            "frontend_declaration_native_absent": 38,
            "frontend_scope_gap": 3,
            "cross_native_token_variant": 1,
            "native_registration_no_frontend_reference": 10,
        }, replayed["attribution_counts"])

    def test_documented_x5000r_expanded_scope_closes_all_scope_gaps(self):
        from scripts.build_x5000r_expanded_frontend_report import (
            X5000R_ROOT,
            build_summary,
        )
        from pathlib import Path
        import json

        if not X5000R_ROOT.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        documented = json.loads(Path(
            "docs/firmware-mapping/samples/"
            "m1-19-x5000r-expanded-frontend.json"
        ).read_text())

        replayed = build_summary(X5000R_ROOT)

        self.assertEqual(documented, replayed)
        self.assertEqual(203, replayed["frontend_scope"]["operation_count"])
        self.assertEqual(
            {"getWanIeCfg", "setWanIeCfg", "setUploadSetting", "upload"},
            {
                item["operation"]
                for item in replayed["scope_closure"]["recovered_operations"]
            },
        )
        self.assertNotIn(
            "frontend_scope_gap",
            replayed["difference"]["attribution_counts"],
        )
        self.assertEqual(
            {"frontend_only": 77, "native_only": 11},
            replayed["difference"]["side_counts"],
        )


if __name__ == "__main__":
    unittest.main()
