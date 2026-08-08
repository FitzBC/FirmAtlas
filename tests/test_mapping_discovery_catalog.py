import hashlib
import json
import unittest
from pathlib import Path
from dataclasses import replace

from firmatlas.mapping import (
    CoverageStatus,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    FrontendParameterNamespace,
    AnalyzerIdentity,
    NativeHint,
    NativeHintKind,
    NativeProducerResult,
    EvidenceAtom,
    EvidenceSpan,
    ObservationKind,
    correlate_frontend_native,
    run_obligation_scheduler,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    discover_frontend_requests,
    discover_script_backend,
    discover_web_configuration,
    discover_native_hints,
)


class DiscoveryCatalogContractTests(unittest.TestCase):
    @staticmethod
    def source(path, content):
        return SourceArtifactEntry(
            canonical_path=path, original_path=path, kind="file",
            size=len(content), content_sha256=hashlib.sha256(content).hexdigest(),
        )

    @staticmethod
    def native_evidence(identity, value):
        return EvidenceAtom(
            evidence_id=identity, subject_ref="hint:" + identity,
            predicate="mentions", object_value=value,
            source_span=EvidenceSpan(
                artifact_path="bin/httpd", artifact_sha256="3" * 64,
                locator="binary:bytes=0-1",
            ), producer="native-shallow-producer", producer_version="0.1.0",
            observation_kind=ObservationKind.DIRECT_STATIC,
            capability="mentions_endpoint", confidence=1.0,
        )

    def test_frontend_batch_publishes_evidence_backed_interface_and_parameters(self):
        content = b'''$.ajax({
  url: "/cgi-bin/cstecgi.cgi",
  type: "POST",
  contentType: "application/json",
  data: JSON.stringify({topicurl: "setting/setLanCfg", lanIp: lanIp})
});'''
        source = SourceArtifactEntry(
            canonical_path="www/js/lan.js", original_path="www/js/lan.js",
            kind="file", size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )
        frontend = discover_frontend_requests(source, content)
        result = assemble_discovery_catalog(DiscoveryCatalogInput(
            firmware_artifact_sha256="1" * 64,
            source_inventory_sha256="2" * 64,
            batches=(DiscoveryProducerBatch.frontend((frontend,), scope="www/**/*.js"),),
        ))

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.candidates))
        candidate = result.candidates[0]
        self.assertEqual("request_interface", candidate.candidate_kind.value)
        self.assertEqual("/cgi-bin/cstecgi.cgi", candidate.canonical_identity)
        self.assertEqual("candidate", candidate.claim_status.value)
        self.assertEqual("POST", dict(candidate.attributes)["method"])
        self.assertEqual("json", dict(candidate.attributes)["representation"])
        self.assertEqual(["topicurl", "lanIp"], [x.name for x in result.parameters])
        self.assertEqual(
            {FrontendParameterNamespace.JSON.value},
            {x.namespace for x in result.parameters},
        )
        self.assertEqual(candidate.candidate_id, result.parameters[0].owner_ref)
        self.assertTrue(result.parameters[0].is_operation_selector)
        self.assertEqual("setting/setLanCfg", result.parameters[0].literal_value)
        self.assertEqual(len(frontend.evidence_atoms), len(result.evidence_atoms))
        self.assertEqual(1, len(result.coverage))
        self.assertEqual("frontend-request-producer", result.coverage[0].producer)
        self.assertEqual("www/**/*.js", result.coverage[0].scope)
        payload = result.to_dict()
        self.assertEqual("firmatlas.mapping.discovery-catalog/v1alpha1", payload["schema_version"])
        self.assertEqual(0, payload["seed_input_count"])
        self.assertIsInstance(json.dumps(payload), str)

    def test_web_configuration_stays_a_separate_architecture_candidate(self):
        content = b'''server {
 listen 8180;
 root /webroot;
 location /cgi-bin/luci/ { fastcgi_pass 127.0.0.1:8188; }
}'''
        configured = discover_web_configuration(
            self.source("etc/nginx/nginx.conf", content), content
        )
        result = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64, "2" * 64,
            (DiscoveryProducerBatch.web_configuration(
                (configured,), scope="etc/nginx/*.conf"
            ),),
        ))

        self.assertEqual(3, len(result.candidates))
        self.assertEqual(
            {"web_configuration"},
            {x.candidate_kind.value for x in result.candidates},
        )
        self.assertEqual(
            {"8180", "/webroot", "127.0.0.1:8188"},
            {x.canonical_identity for x in result.candidates},
        )
        self.assertNotIn(
            "request_interface", {x.candidate_kind.value for x in result.candidates}
        )
        self.assertEqual("web-configuration-producer", result.coverage[0].producer)
        mapping = next(x for x in result.candidates if x.canonical_identity == "127.0.0.1:8188")
        self.assertEqual("/cgi-bin/luci/", dict(mapping.attributes)["namespace"])

    def test_script_parameters_attach_to_source_without_inventing_a_route(self):
        content = b'''<%
If Request_Form("button_type") = "1" Then
 TCWebApi_set("Account_Entry0", "web_passwd", "admPass1")
End If
%>'''
        backend = discover_script_backend(
            self.source("boaroot/cgi-bin/mt_admin.asp", content), content
        )
        result = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64, "2" * 64,
            (DiscoveryProducerBatch.script_backend(
                (backend,), scope="boaroot/cgi-bin/**/*"
            ),),
        ))

        kinds = {x.candidate_kind.value for x in result.candidates}
        self.assertEqual({"script_source", "state_access"}, kinds)
        self.assertNotIn("script_route", kinds)
        source_candidate = next(
            x for x in result.candidates if x.candidate_kind.value == "script_source"
        )
        self.assertEqual("boaroot/cgi-bin/mt_admin.asp", source_candidate.canonical_identity)
        self.assertEqual(source_candidate.candidate_id, result.parameters[0].owner_ref)
        self.assertEqual(("1",), result.parameters[0].selector_values)
        state = next(x for x in result.candidates if x.candidate_kind.value == "state_access")
        self.assertEqual("set|Account_Entry0|web_passwd|admPass1", state.canonical_identity)

    def test_native_hints_remain_candidates_and_never_become_routes(self):
        route_evidence = self.native_evidence("ev:route", "SetOnlineDevName")
        symbol_evidence = self.native_evidence("ev:symbol", "formSetDeviceName")
        native = NativeProducerResult(
            source_path="bin/httpd", coverage_status=CoverageStatus.COMPLETED,
            processed_bytes=100, producer=AnalyzerIdentity("native-shallow-producer", "0.1.0"),
            detected_format="elf", bitness=32, endianness="little", machine="ARM",
            hints=(
                NativeHint("hint:route", NativeHintKind.ROUTE_TOKEN, "SetOnlineDevName", "elf.printable", (route_evidence.evidence_id,)),
                NativeHint("hint:symbol", NativeHintKind.SYMBOL, "formSetDeviceName", "elf.dynsym", (symbol_evidence.evidence_id,)),
            ), evidence_atoms=(route_evidence, symbol_evidence),
        )
        result = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64, "2" * 64,
            (DiscoveryProducerBatch.native((native,), scope="bin/*"),),
        ))
        self.assertEqual({"native_hint"}, {x.candidate_kind.value for x in result.candidates})
        self.assertEqual({"candidate"}, {x.claim_status.value for x in result.candidates})
        self.assertNotIn("script_route", {x.candidate_kind.value for x in result.candidates})
        route = next(x for x in result.candidates if x.canonical_identity == "SetOnlineDevName")
        self.assertEqual("route_token", dict(route.attributes)["hint_kind"])
        self.assertEqual("ARM", dict(route.attributes)["machine"])

    def test_correlation_and_scheduler_publish_referentially_complete_open_work(self):
        content = b'var pageModel = R.pageModel({setUrl: "goform/SetOnlineDevName"});'
        frontend = discover_frontend_requests(self.source("www/name.js", content), content)
        native_evidence = self.native_evidence("ev:name", "SetOnlineDevName")
        native = NativeProducerResult(
            source_path="bin/httpd", coverage_status=CoverageStatus.COMPLETED,
            processed_bytes=100, producer=AnalyzerIdentity("native-shallow-producer", "0.1.0"),
            detected_format="elf", bitness=32, endianness="little", machine="ARM",
            hints=(NativeHint("hint:name", NativeHintKind.ROUTE_TOKEN, "SetOnlineDevName", "fixture", (native_evidence.evidence_id,)),),
            evidence_atoms=(native_evidence,),
        )
        correlation = correlate_frontend_native((frontend,), (native,))
        scheduler = run_obligation_scheduler(correlation.obligations, ())
        result = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64, "2" * 64,
            (
                DiscoveryProducerBatch.frontend((frontend,), "www/**/*.js"),
                DiscoveryProducerBatch.native((native,), "bin/*"),
            ), correlation=correlation, scheduler=scheduler,
        ))

        self.assertEqual(1, len(result.associations))
        association = result.associations[0]
        self.assertEqual(2, len(result.open_obligations))
        self.assertEqual({association.association_id}, {x.target_ref for x in result.open_obligations})
        self.assertEqual("fixed_point", result.scheduler_termination.value)
        self.assertEqual(
            {"request_interface", "native_hint", "candidate_association"},
            {x.candidate_kind.value for x in result.candidates},
        )
        self.assertEqual(4, len(result.coverage))

    def test_missing_required_batch_is_partial_not_an_empty_success(self):
        result = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64, "2" * 64,
            (DiscoveryProducerBatch.frontend((), "www/**/*.js"),),
        ))
        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual(CoverageStatus.FAILED, result.coverage[0].status)
        self.assertEqual("required_batch_has_no_results", result.coverage[0].diagnostic)

    def test_partial_source_inventory_caps_catalog_coverage_at_partial(self):
        content = b'''<?php
if ($ACTION_POST == "tool_admin") {
  set("/sys/systemName", $sysname);
}
?>'''
        backend = discover_script_backend(
            self.source("www/__action.php", content), content
        )

        result = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64,
            "2" * 64,
            (DiscoveryProducerBatch.script_backend(
                (backend,), scope="www/__action.php"
            ),),
            source_inventory_coverage_status=CoverageStatus.PARTIAL,
        ))

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual(
            CoverageStatus.PARTIAL, result.source_inventory_coverage_status
        )
        self.assertEqual(
            "partial", result.to_dict()["source_inventory_coverage_status"]
        )

    def test_actual_ac9_publishes_no_seed_cross_producer_catalog(self):
        root = Path("../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root")
        required = (
            "webroot_ro/js/static_route.js", "webroot_ro/js/online_list.js",
            "webroot_ro/simple_upgrade.asp", "etc_ro/nginx/conf/nginx.conf",
            "etc_ro/nginx/conf/nginx_init.sh", "bin/httpd", "bin/dhttpd",
        )
        if not all((root / path).exists() for path in required):
            self.skipTest("local AC9 representative sample is unavailable")

        def analyze(path, producer):
            content = (root / path).read_bytes()
            return producer(self.source(path, content), content)

        frontend = tuple(analyze(path, discover_frontend_requests) for path in required[:3])
        web = tuple(analyze(path, discover_web_configuration) for path in required[3:5])
        native = tuple(analyze(path, discover_native_hints) for path in required[5:])
        script = (analyze(required[2], discover_script_backend),)
        correlation = correlate_frontend_native(frontend, native)
        scheduler = run_obligation_scheduler(correlation.obligations, ())
        result = assemble_discovery_catalog(DiscoveryCatalogInput(
            "981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296",
            "f425a98b9b7f4143a3b6b979631abe0715e3fc03773a656e1ee4455716ca8b4d",
            (
                DiscoveryProducerBatch.frontend(frontend, "webroot_ro/**/*"),
                DiscoveryProducerBatch.web_configuration(web, "etc_ro/nginx/conf/*"),
                DiscoveryProducerBatch.script_backend(script, "webroot_ro/*.asp"),
                DiscoveryProducerBatch.native(native, "bin/{httpd,dhttpd}"),
            ), correlation, scheduler,
        ))

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(0, result.seed_input_count)
        self.assertEqual(395, len(result.candidates))
        self.assertEqual(6, len(result.parameters))
        self.assertEqual(398, len(result.evidence_atoms))
        self.assertEqual(8, len(result.associations))
        self.assertEqual(16, len(result.open_obligations))
        upgrade = next(x for x in frontend[2].candidates if x.endpoint == "/cgi-bin/upgrade")
        self.assertEqual("multipart_form", upgrade.representation)
        published_upgrade = next(
            x for x in result.candidates
            if x.candidate_kind.value == "request_interface"
            and x.canonical_identity == "/cgi-bin/upgrade"
        )
        self.assertEqual("multipart_form", dict(published_upgrade.attributes)["representation"])
        self.assertEqual({"bin/httpd"}, {
            item.native_source_path for item in correlation.associations
        })

    def test_required_partial_result_propagates_to_catalog_coverage(self):
        content = b'var pageModel = R.pageModel({setUrl: "goform/SetX"});'
        result = discover_frontend_requests(self.source("www/x.js", content), content)
        partial = replace(result, coverage_status=CoverageStatus.PARTIAL)
        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64, "2" * 64,
            (DiscoveryProducerBatch.frontend((partial,), "www/**/*.js"),),
        ))
        self.assertEqual(CoverageStatus.PARTIAL, catalog.coverage_status)
        self.assertEqual(CoverageStatus.PARTIAL, catalog.coverage[0].status)

    def test_input_batch_order_does_not_change_catalog(self):
        html = b'<form action="/goform/Login"><input name="user"></form>'
        nginx = b'server { listen 80; }'
        frontend = discover_frontend_requests(self.source("www/login.html", html), html)
        web = discover_web_configuration(self.source("etc/nginx.conf", nginx), nginx)
        batches = (
            DiscoveryProducerBatch.frontend((frontend,), "www/*"),
            DiscoveryProducerBatch.web_configuration((web,), "etc/*"),
        )
        forward = assemble_discovery_catalog(DiscoveryCatalogInput("1" * 64, "2" * 64, batches))
        reverse = assemble_discovery_catalog(DiscoveryCatalogInput("1" * 64, "2" * 64, tuple(reversed(batches))))
        self.assertEqual(forward.to_dict(), reverse.to_dict())

    def test_catalog_identity_changes_when_parameter_inventory_changes(self):
        first_content = b'<form action="/goform/Login"><input name="user"></form>'
        second_content = b'<form action="/goform/Login"><input name="password"></form>'
        first = discover_frontend_requests(self.source("www/login.html", first_content), first_content)
        second = discover_frontend_requests(self.source("www/login.html", second_content), second_content)
        first_catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64, "2" * 64, (DiscoveryProducerBatch.frontend((first,), "www/*"),)
        ))
        second_catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64, "2" * 64, (DiscoveryProducerBatch.frontend((second,), "www/*"),)
        ))
        self.assertNotEqual(first_catalog.catalog_id, second_catalog.catalog_id)

    def test_documented_ac9_catalog_summary_matches_contract_counts(self):
        payload = json.loads(Path(
            "docs/firmware-mapping/samples/m1-08-ac9-discovery-catalog-summary.json"
        ).read_text())
        self.assertEqual(0, payload["seed_input_count"])
        self.assertEqual(395, payload["result"]["candidate_count"])
        self.assertEqual(398, payload["result"]["evidence_atom_count"])
        self.assertEqual(16, payload["result"]["open_obligation_count"])
        self.assertEqual("multipart_form", payload["selected_architecture"]["upgrade_request"]["representation"])


if __name__ == "__main__":
    unittest.main()
