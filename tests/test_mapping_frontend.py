import hashlib
import json
from pathlib import Path
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    FrontendEndpointShape,
    FrontendParameterDirection,
    FrontendParameterNamespace,
    FrontendPolicy,
    FrontendRequestRole,
    SourceArtifactEntry,
    discover_frontend_requests,
)


class FrontendRequestProducerContractTests(unittest.TestCase):
    def test_page_model_urls_become_read_and_write_request_candidates(self):
        content = b"""var pageModel = R.pageModel({
    getUrl: \"goform/GetStaticRouteCfg\",
    setUrl: \"goform/SetStaticRouteCfg\",
    afterSubmit: callback
});
"""
        source = SourceArtifactEntry(
            canonical_path="webroot_ro/js/static_route.js",
            original_path="webroot_ro/js/static_route.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(len(content), result.processed_bytes)
        self.assertEqual([], list(result.diagnostics))
        self.assertEqual(
            {
                "R.pageModel",
                "R.moduleModel.getSubmitData",
                "jQuery.getJSON",
                "jQuery.post",
                "jQuery.ajax",
                "HTML.form",
            },
            set(result.supported_constructs),
        )
        self.assertEqual(
            [
                ("goform/GetStaticRouteCfg", FrontendRequestRole.READ),
                ("goform/SetStaticRouteCfg", FrontendRequestRole.WRITE),
            ],
            [(item.endpoint, item.request_role) for item in result.candidates],
        )
        self.assertEqual([None, None], [item.method for item in result.candidates])
        self.assertEqual(
            ["R.pageModel.getUrl", "R.pageModel.setUrl"],
            [item.source_construct for item in result.candidates],
        )
        self.assertEqual(2, len(result.evidence_atoms))
        self.assertEqual(
            {"constructs_request"},
            {item.capability for item in result.evidence_atoms},
        )
        self.assertEqual(
            {
                "text_utf8:bytes=43-67;lines=2:14-2:38",
                "text_utf8:bytes=83-107;lines=3:14-3:38",
            },
            {item.source_span.locator for item in result.evidence_atoms},
        )
        self.assertEqual(
            {item.evidence_id for item in result.evidence_atoms},
            {evidence_id for item in result.candidates for evidence_id in item.evidence_ids},
        )
        payload = result.to_dict()
        self.assertEqual(
            "firmatlas.mapping.frontend-result/v1alpha1",
            payload["schema_version"],
        )
        self.assertIsInstance(json.dumps(payload), str)

    def test_comments_and_unrelated_strings_do_not_become_requests(self):
        content = b"""// getUrl: \"goform/FakeFromComment\"
var example = 'setUrl: "goform/FakeFromString"';
var pageModel = R.pageModel({});
"""
        source = SourceArtifactEntry(
            canonical_path="webroot_ro/js/empty.js",
            original_path="webroot_ro/js/empty.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual((), result.candidates)
        self.assertEqual((), result.evidence_atoms)

    def test_jquery_post_preserves_method_and_form_representation(self):
        content = b"""function changeDevName(macAddress, newName) {
    var submitStr = "mac=" + macAddress + "&devName=" + encodeURIComponent(newName);
    $.post("goform/SetOnlineDevName", submitStr, callback);
}
"""
        source = SourceArtifactEntry(
            canonical_path="webroot_ro/js/online_list.js",
            original_path="webroot_ro/js/online_list.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual(1, len(result.candidates))
        candidate = result.candidates[0]
        self.assertEqual("goform/SetOnlineDevName", candidate.endpoint)
        self.assertEqual(FrontendRequestRole.WRITE, candidate.request_role)
        self.assertEqual("POST", candidate.method)
        self.assertEqual("form_urlencoded", candidate.representation)
        self.assertEqual("jQuery.post", candidate.source_construct)
        self.assertEqual(
            "text_utf8:bytes=143-166;lines=3:13-3:36",
            result.evidence_atoms[0].source_span.locator,
        )
        self.assertEqual(
            ["mac", "devName"],
            [item.name for item in result.parameters],
        )
        self.assertEqual(
            {FrontendParameterNamespace.FORM},
            {item.namespace for item in result.parameters},
        )
        self.assertEqual(
            {FrontendParameterDirection.REQUEST},
            {item.direction for item in result.parameters},
        )
        self.assertEqual(
            {candidate.candidate_id},
            {item.request_candidate_id for item in result.parameters},
        )
        self.assertEqual(
            {"constructs_request", "serializes_parameter"},
            {item.capability for item in result.evidence_atoms},
        )

    def test_get_json_keeps_dynamic_url_as_an_explicit_literal_prefix(self):
        content = b"""function getOnlineList() {
    $.getJSON("goform/getOnlineList?" + Math.random(), initValue);
}
"""
        source = SourceArtifactEntry(
            canonical_path="webroot_ro/js/online_list.js",
            original_path="webroot_ro/js/online_list.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual(1, len(result.candidates))
        candidate = result.candidates[0]
        self.assertEqual("goform/getOnlineList?", candidate.endpoint)
        self.assertEqual(FrontendEndpointShape.LITERAL_PREFIX, candidate.endpoint_shape)
        self.assertEqual(FrontendRequestRole.READ, candidate.request_role)
        self.assertEqual("GET", candidate.method)
        self.assertEqual("json", candidate.representation)
        self.assertEqual("jQuery.getJSON", candidate.source_construct)

    def test_hnap_ajax_preserves_soap_action_as_an_operation_selector(self):
        content = b"""$.ajax({
    url: "/HNAP1",
    type: "POST",
    contentType: "text/xml",
    headers: {"SOAPAction": "http://purenetworks.com/HNAP1/GetDeviceSettings"},
    data: soapEnvelope
});
"""
        source = SourceArtifactEntry(
            canonical_path="www/js/hnap.js",
            original_path="www/js/hnap.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual(1, len(result.candidates))
        candidate = result.candidates[0]
        self.assertEqual("/HNAP1", candidate.endpoint)
        self.assertEqual("POST", candidate.method)
        self.assertEqual("xml", candidate.representation)
        self.assertEqual("jQuery.ajax", candidate.source_construct)
        self.assertEqual(1, len(result.parameters))
        selector = result.parameters[0]
        self.assertEqual("SOAPAction", selector.name)
        self.assertEqual(FrontendParameterNamespace.HEADER, selector.namespace)
        self.assertEqual(
            "http://purenetworks.com/HNAP1/GetDeviceSettings",
            selector.literal_value,
        )
        self.assertTrue(selector.is_operation_selector)
        self.assertEqual(
            {"constructs_request", "serializes_parameter", "selects_operation"},
            {item.capability for item in result.evidence_atoms},
        )

    def test_shared_cgi_json_selector_stays_separate_from_ordinary_parameters(self):
        content = b"""$.ajax({
    url: "/cgi-bin/cstecgi.cgi",
    type: "POST",
    contentType: "application/json",
    data: JSON.stringify({topicurl: "setting/setLanCfg", lanIp: lanIp})
});
"""
        source = SourceArtifactEntry(
            canonical_path="www/js/lan.js",
            original_path="www/js/lan.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual(1, len(result.candidates))
        candidate = result.candidates[0]
        self.assertEqual("/cgi-bin/cstecgi.cgi", candidate.endpoint)
        self.assertEqual("json", candidate.representation)
        self.assertEqual(["topicurl", "lanIp"], [item.name for item in result.parameters])
        self.assertEqual(
            {FrontendParameterNamespace.JSON},
            {item.namespace for item in result.parameters},
        )
        selector, ordinary = result.parameters
        self.assertTrue(selector.is_operation_selector)
        self.assertEqual("setting/setLanCfg", selector.literal_value)
        self.assertFalse(ordinary.is_operation_selector)
        self.assertIsNone(ordinary.literal_value)
        changed = content.replace(b"setting/setLanCfg", b"setting/getLanCfg")
        changed_source = SourceArtifactEntry(
            canonical_path=source.canonical_path,
            original_path=source.original_path,
            kind=source.kind,
            size=len(changed),
            content_sha256=hashlib.sha256(changed).hexdigest(),
        )
        self.assertNotEqual(
            candidate.candidate_id,
            discover_frontend_requests(changed_source, changed).candidates[0].candidate_id,
        )

    def test_html_form_action_and_named_inputs_become_one_request_shape(self):
        content = b"""<form action="/goform/Login" method="post">
  <input name="username" type="text">
  <input type="password" name="password">
</form>
"""
        source = SourceArtifactEntry(
            canonical_path="webroot_ro/login.html",
            original_path="webroot_ro/login.html",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual(1, len(result.candidates))
        candidate = result.candidates[0]
        self.assertEqual("/goform/Login", candidate.endpoint)
        self.assertEqual("POST", candidate.method)
        self.assertEqual("form_urlencoded", candidate.representation)
        self.assertEqual("HTML.form", candidate.source_construct)
        self.assertEqual(
            ["username", "password"],
            [item.name for item in result.parameters],
        )
        self.assertEqual(
            {FrontendParameterNamespace.FORM},
            {item.namespace for item in result.parameters},
        )

    def test_html_multipart_form_preserves_upload_representation(self):
        content = b'''<form method="POST" action="/cgi-bin/upgrade" enctype="multipart/form-data">
<input type="file" name="upgradeFile">
</form>'''
        source = SourceArtifactEntry(
            canonical_path="webroot/simple_upgrade.asp",
            original_path="webroot/simple_upgrade.asp", kind="file",
            size=len(content), content_sha256=hashlib.sha256(content).hexdigest(),
        )
        result = discover_frontend_requests(source, content)

        self.assertEqual(1, len(result.candidates))
        self.assertEqual("/cgi-bin/upgrade", result.candidates[0].endpoint)
        self.assertEqual("multipart_form", result.candidates[0].representation)
        self.assertEqual(["upgradeFile"], [x.name for x in result.parameters])

    def test_invalid_utf8_is_failed_coverage_not_a_false_empty_result(self):
        content = b"var route = \xff;"
        source = SourceArtifactEntry(
            canonical_path="webroot_ro/js/broken.js",
            original_path="webroot_ro/js/broken.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual(CoverageStatus.FAILED, result.coverage_status)
        self.assertEqual(0, result.processed_bytes)
        self.assertEqual((), result.candidates)
        self.assertEqual(
            ["frontend.invalid_utf8"],
            [item.code for item in result.diagnostics],
        )

    def test_source_and_candidate_budgets_publish_explicit_coverage(self):
        content = b'R.pageModel({getUrl:"/read",setUrl:"/write"});'
        source = SourceArtifactEntry(
            canonical_path="www/js/routes.js",
            original_path="www/js/routes.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        skipped = discover_frontend_requests(
            source,
            content,
            FrontendPolicy(max_source_bytes=10),
        )
        partial = discover_frontend_requests(
            source,
            content,
            FrontendPolicy(max_candidates=1),
        )

        self.assertEqual(CoverageStatus.SKIPPED_BY_POLICY, skipped.coverage_status)
        self.assertEqual(0, skipped.processed_bytes)
        self.assertEqual(
            ["frontend.source_byte_budget_exceeded"],
            [item.code for item in skipped.diagnostics],
        )
        self.assertEqual(CoverageStatus.PARTIAL, partial.coverage_status)
        self.assertEqual(1, len(partial.candidates))
        self.assertEqual(
            ["frontend.candidate_budget_exceeded"],
            [item.code for item in partial.diagnostics],
        )

    def test_post_uses_the_nearest_preceding_data_assignment(self):
        content = b"""var payload = "first=" + first;
$.post("/goform/Apply", payload, callback);
payload = "later=" + later;
"""
        source = SourceArtifactEntry(
            canonical_path="www/js/apply.js",
            original_path="www/js/apply.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual(["first"], [item.name for item in result.parameters])

    def test_repeated_call_sites_merge_candidate_identity_but_keep_both_evidence(self):
        content = b"""$.getJSON("/goform/status", first);
$.getJSON("/goform/status", second);
"""
        source = SourceArtifactEntry(
            canonical_path="www/js/status.js",
            original_path="www/js/status.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual(1, len(result.candidates))
        self.assertEqual(2, len(result.candidates[0].evidence_ids))
        self.assertEqual(2, len(result.evidence_atoms))
        self.assertEqual(
            2,
            len({item.evidence_id for item in result.evidence_atoms}),
        )

    def test_page_model_write_uses_module_model_submit_parameter(self):
        content = b"""var pageModel = R.pageModel({setUrl: "goform/SetStaticRouteCfg"});
var moduleModel = R.moduleModel({
    getSubmitData: function () {
        var data = "";
        data = "list=" + data;
        return data;
    }
});
"""
        source = SourceArtifactEntry(
            canonical_path="www/js/static_route.js",
            original_path="www/js/static_route.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual(1, len(result.candidates))
        self.assertEqual(["list"], [item.name for item in result.parameters])
        self.assertEqual(
            result.candidates[0].candidate_id,
            result.parameters[0].request_candidate_id,
        )
        self.assertEqual(
            "R.moduleModel.getSubmitData",
            result.parameters[0].source_construct,
        )

    def test_documented_frontend_sample_summary_keeps_real_and_fixture_roles(self):
        fixture = (
            Path(__file__).parents[1]
            / "docs"
            / "firmware-mapping"
            / "samples"
            / "m1-04-frontend-producer-summary.json"
        )
        payload = json.loads(fixture.read_text(encoding="utf-8"))

        self.assertEqual(
            "firmatlas.mapping.frontend-sample/v1alpha1",
            payload["schema_version"],
        )
        self.assertEqual(
            ["real_firmware_source", "real_firmware_source"],
            [item["sample_kind"] for item in payload["results"][:2]],
        )
        self.assertEqual(
            [2, 5],
            [item["candidate_count"] for item in payload["results"][:2]],
        )
        self.assertEqual(
            ["synthetic_contract_fixture", "synthetic_contract_fixture"],
            [item["sample_kind"] for item in payload["results"][2:]],
        )


if __name__ == "__main__":
    unittest.main()
