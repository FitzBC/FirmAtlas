import hashlib
import json
from pathlib import Path
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    FrontendEndpointShape,
    FrontendAssetInput,
    FrontendParameterDirection,
    FrontendParameterNamespace,
    FrontendPolicy,
    FrontendRequestRole,
    SourceArtifactEntry,
    discover_frontend_requests,
    discover_frontend_asset_graph,
)


class FrontendRequestProducerContractTests(unittest.TestCase):
    def test_documented_x5000r_asset_graph_is_exactly_replayable(self):
        from scripts.build_x5000r_frontend_asset_graph import (
            X5000R_ROOT,
            build_summary,
        )

        if not X5000R_ROOT.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        documented = json.loads(Path(
            "docs/firmware-mapping/samples/"
            "m1-15-x5000r-frontend-asset-graph.json"
        ).read_text())

        replayed = build_summary(X5000R_ROOT)

        self.assertEqual(documented, replayed)
        self.assertEqual(199, replayed["operation_count"])
        self.assertEqual({"/cgi-bin/cstecgi.cgi"}, {
            item["endpoint"] for item in replayed["operations"]
        })
        self.assertEqual({"unresolved_dynamic"}, {
            item["method_status"] for item in replayed["operations"]
        })

    def test_asset_graph_resolves_cross_file_shared_cgi_with_two_source_evidence(self):
        config = b'var globalConfig={cgiUrl:"/cgi-bin/cstecgi.cgi"};'
        wrapper = b'''function Dispatcher(){
this.srcUrl=globalConfig.cgiUrl;
this.post=function(data){data.topicurl=this.topicurl;data=JSON.stringify(data);
$.ajax({url:this.srcUrl,type:"POST",dataType:"json",data:data});};}
Dispatcher.prototype.setLanCfg=function(data){
return this.topicurl="setLanCfg",this.post(data);};'''
        assets = tuple(
            FrontendAssetInput(
                SourceArtifactEntry(path, path, "file", len(content),
                                    hashlib.sha256(content).hexdigest()),
                content,
            )
            for path, content in (
                ("www/static/js/config.js", config),
                ("www/static/js/topicurl.js", wrapper),
            )
        )

        graph = discover_frontend_asset_graph(assets)

        self.assertEqual(CoverageStatus.COMPLETED, graph.coverage_status)
        self.assertEqual(1, len(graph.bindings))
        binding = graph.bindings[0]
        self.assertEqual("globalConfig.cgiUrl", binding.symbol)
        self.assertEqual("/cgi-bin/cstecgi.cgi", binding.value)
        self.assertEqual("www/static/js/config.js", binding.definition_source_path)
        self.assertEqual("www/static/js/topicurl.js", binding.consumer_source_path)
        candidates = [
            candidate for result in graph.results for candidate in result.candidates
        ]
        self.assertEqual(1, len(candidates))
        self.assertEqual("/cgi-bin/cstecgi.cgi", candidates[0].endpoint)
        self.assertEqual("shared-cgi.topicurl.cross-resource",
                         candidates[0].source_construct)
        atoms = [atom for result in graph.results for atom in result.evidence_atoms]
        self.assertEqual(
            {"www/static/js/config.js", "www/static/js/topicurl.js"},
            {atom.source_span.artifact_path for atom in atoms},
        )
        self.assertEqual(
            {"constructs_request", "resolves_endpoint_binding",
             "serializes_parameter", "selects_operation"},
            {atom.capability for atom in atoms},
        )

    def test_asset_graph_resolves_custom_request_default_and_payload_variable(self):
        transport = b'''function Transport(){}
Transport.prototype.request=function(options){
  var endpoint=options.url||"/cgi-bin/cstecgi.cgi";
  var payload=options.data||{};
};
window.kr=new Transport();'''
        consumer = b'''function save(mode){
  var payload={topicurl:"setWanIeCfg",wanMode:mode};
  kr.request({type:"POST",data:payload});
}'''
        assets = tuple(
            FrontendAssetInput(
                SourceArtifactEntry(
                    path, path, "file", len(content),
                    hashlib.sha256(content).hexdigest(),
                ),
                content,
            )
            for path, content in (
                ("www/static/js/kr.js", transport),
                ("www/wan_ie.html", consumer),
            )
        )

        graph = discover_frontend_asset_graph(assets)

        candidates = [
            item for result in graph.results for item in result.candidates
        ]
        self.assertEqual(1, len(candidates))
        self.assertEqual("/cgi-bin/cstecgi.cgi", candidates[0].endpoint)
        self.assertEqual("POST", candidates[0].method)
        self.assertEqual(
            "custom.request.cross-resource-default",
            candidates[0].source_construct,
        )
        parameters = [
            item for result in graph.results for item in result.parameters
        ]
        self.assertEqual({"topicurl", "wanMode"}, {item.name for item in parameters})
        selector = next(item for item in parameters if item.name == "topicurl")
        self.assertEqual("setWanIeCfg", selector.literal_value)
        self.assertTrue(selector.is_operation_selector)
        self.assertEqual(1, len(graph.bindings))
        self.assertEqual("kr.request.default_url", graph.bindings[0].symbol)
        atoms = [
            atom for result in graph.results for atom in result.evidence_atoms
        ]
        self.assertEqual(
            {"www/static/js/kr.js", "www/wan_ie.html"},
            {atom.source_span.artifact_path for atom in atoms},
        )

    def test_payload_variable_does_not_cross_function_scope(self):
        transport = b'''function Transport(){}
Transport.prototype.request=function(options){
  var endpoint=options.url||"/cgi-bin/cstecgi.cgi";
};window.kr=new Transport();'''
        consumer = b'''function unrelated(){
  var payload={topicurl:"wrongOperation"};
}
function save(){
  var payload={topicurl:"rightOperation"};
  kr.request({type:"POST",data:payload});
}'''
        assets = tuple(
            FrontendAssetInput(
                SourceArtifactEntry(
                    path, path, "file", len(content),
                    hashlib.sha256(content).hexdigest(),
                ), content,
            )
            for path, content in (
                ("www/static/js/kr.js", transport),
                ("www/page.html", consumer),
            )
        )

        graph = discover_frontend_asset_graph(assets)

        selectors = {
            item.literal_value
            for result in graph.results
            for item in result.parameters
            if item.is_operation_selector
        }
        self.assertEqual({"rightOperation"}, selectors)

    def test_file_upload_property_preserves_outer_and_inner_operation_selectors(self):
        content = b'''var page={data:function(){return{
  importAction:"/cgi-bin/cstecgi.cgi?action=upload&setting/setUploadSetting"
}},methods:{restore:function(file){
  upload.fileUpload({data:file,url:this.importAction});
}}};'''
        source = SourceArtifactEntry(
            "www/advance/config.html", "www/advance/config.html", "file",
            len(content), hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual(1, len(result.candidates))
        candidate = result.candidates[0]
        self.assertEqual("/cgi-bin/cstecgi.cgi", candidate.endpoint)
        self.assertEqual("POST", candidate.method)
        self.assertEqual("multipart_form", candidate.representation)
        self.assertEqual("custom.file-upload-property", candidate.source_construct)
        selectors = {
            (item.name, item.literal_value)
            for item in result.parameters if item.is_operation_selector
        }
        self.assertEqual(
            {("action", "upload"), ("setting", "setUploadSetting")},
            selectors,
        )
        self.assertEqual(
            {"constructs_request", "serializes_parameter", "selects_operation"},
            {atom.capability for atom in result.evidence_atoms},
        )

    def test_file_upload_without_payload_does_not_publish_a_request(self):
        content = b'''var page={importAction:
"/cgi-bin/cstecgi.cgi?action=upload&setting/setUploadSetting"};
upload.fileUpload({url:this.importAction});'''
        source = SourceArtifactEntry(
            "www/advance/config.html", "www/advance/config.html", "file",
            len(content), hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual((), result.candidates)
        self.assertEqual((), result.parameters)

    def test_asset_graph_keeps_conflicting_endpoint_definitions_unresolved(self):
        sources = (
            ("www/a.js", b'globalConfig={cgiUrl:"/cgi-bin/a.cgi"};'),
            ("www/b.js", b'globalConfig={cgiUrl:"/cgi-bin/b.cgi"};'),
            ("www/wrapper.js", b'''function D(){this.srcUrl=globalConfig.cgiUrl;
this.post=function(x){x.topicurl=this.topicurl;x=JSON.stringify(x);
$.ajax({url:this.srcUrl,type:"POST",dataType:"json",data:x});};}
D.prototype.run=function(x){return this.topicurl="run",this.post(x)};'''),
        )
        assets = tuple(FrontendAssetInput(
            SourceArtifactEntry(path, path, "file", len(content),
                                hashlib.sha256(content).hexdigest()), content,
        ) for path, content in sources)

        graph = discover_frontend_asset_graph(assets)

        self.assertEqual(CoverageStatus.PARTIAL, graph.coverage_status)
        self.assertEqual((), graph.bindings)
        self.assertEqual(
            ["frontend.asset_symbol_conflict"],
            [item.code for item in graph.diagnostics],
        )
        self.assertFalse(any(
            candidate.source_construct == "shared-cgi.topicurl.cross-resource"
            for result in graph.results for candidate in result.candidates
        ))

    def test_asset_graph_binds_consumed_symbol_not_another_symbol_with_same_url(self):
        config = b'''globalConfig={cgiUrl:"/cgi-bin/shared.cgi"};
otherConfig={cgiUrl:"/cgi-bin/shared.cgi"};'''
        wrapper = b'''function D(){this.srcUrl=globalConfig.cgiUrl;
this.post=function(x){x.topicurl=this.topicurl;x=JSON.stringify(x);
$.ajax({url:this.srcUrl,type:"POST",dataType:"json",data:x});};}
D.prototype.run=function(x){return this.topicurl="run",this.post(x)};'''
        assets = tuple(FrontendAssetInput(
            SourceArtifactEntry(path, path, "file", len(content),
                                hashlib.sha256(content).hexdigest()), content,
        ) for path, content in (("www/config.js", config),
                                ("www/topicurl.js", wrapper)))

        graph = discover_frontend_asset_graph(assets)

        self.assertEqual(CoverageStatus.COMPLETED, graph.coverage_status)
        self.assertEqual(1, len(graph.bindings))
        self.assertEqual("globalConfig.cgiUrl", graph.bindings[0].symbol)

    def test_asset_graph_marks_repeated_same_symbol_definition_ambiguous(self):
        sources = (
            ("www/a.js", b'globalConfig={cgiUrl:"/cgi-bin/a.cgi"};'),
            ("www/b.js", b'globalConfig={cgiUrl:"/cgi-bin/a.cgi"};'),
        )
        assets = tuple(FrontendAssetInput(
            SourceArtifactEntry(path, path, "file", len(content),
                                hashlib.sha256(content).hexdigest()), content,
        ) for path, content in sources)

        graph = discover_frontend_asset_graph(assets)

        self.assertEqual(CoverageStatus.PARTIAL, graph.coverage_status)
        self.assertEqual((), graph.bindings)
        self.assertEqual(
            ["frontend.asset_symbol_ambiguous"],
            [item.code for item in graph.diagnostics],
        )

    def test_asset_graph_ignores_assignment_shaped_comments_and_strings(self):
        config = b'''// globalConfig={cgiUrl:"/comment.cgi"};
var note='globalConfig={cgiUrl:"/string.cgi"}';
var pattern=/globalConfig={cgiUrl:"\/regex.cgi"}/;
var commentProperty={/* cgiUrl:"/property-comment.cgi" */};'''
        wrapper = b'''function D(){this.srcUrl=globalConfig.cgiUrl;
this.post=function(x){x.topicurl=this.topicurl;x=JSON.stringify(x);
$.ajax({url:this.srcUrl,type:"POST",dataType:"json",data:x});};}
D.prototype.run=function(x){return this.topicurl="run",this.post(x)};'''
        assets = tuple(FrontendAssetInput(
            SourceArtifactEntry(path, path, "file", len(content),
                                hashlib.sha256(content).hexdigest()), content,
        ) for path, content in (("www/config.js", config),
                                ("www/topicurl.js", wrapper)))

        graph = discover_frontend_asset_graph(assets)

        self.assertEqual(CoverageStatus.COMPLETED, graph.coverage_status)
        self.assertEqual((), graph.bindings)
        self.assertFalse(any(
            candidate.source_construct == "shared-cgi.topicurl.cross-resource"
            for result in graph.results for candidate in result.candidates
        ))

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
                "custom.request",
                "custom.file-upload-property",
                "shared-cgi.topicurl",
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

    def test_shared_cgi_wrapper_resolves_endpoint_and_prototype_operation(self):
        content = b'''var globalConfig = {cgiUrl: "/cgi-bin/cstecgi.cgi"};
function Dispatcher() {
    this.srcUrl = globalConfig.cgiUrl;
    this.topicurl = "";
    this.post = function(data) {
        (data = data || {}).topicurl = this.topicurl;
        data = JSON.stringify(data);
        $.ajax({url: this.srcUrl, type: "POST", dataType: "json", data: data});
    };
}
Dispatcher.prototype.getSysStatusCfg = function(data) {
    return this.topicurl = "getSysStatusCfg", this.url = "/data/sysinfo.json", this.post(data);
};
Dispatcher.prototype.setLanCfg = function(data) {
    return this.topicurl = "setLanCfg", this.post(data);
};'''
        source = SourceArtifactEntry(
            canonical_path="www/static/js/topicurl.js",
            original_path="www/static/js/topicurl.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(
            [
                ("/cgi-bin/cstecgi.cgi", "getSysStatusCfg"),
                ("/cgi-bin/cstecgi.cgi", "setLanCfg"),
            ],
            [
                (
                    candidate.endpoint,
                    next(
                        parameter.literal_value
                        for parameter in result.parameters
                        if parameter.request_candidate_id == candidate.candidate_id
                        and parameter.is_operation_selector
                    ),
                )
                for candidate in result.candidates
            ],
        )
        self.assertEqual({"POST"}, {item.method for item in result.candidates})
        self.assertEqual({"json"}, {item.representation for item in result.candidates})
        self.assertEqual(
            {"shared-cgi.topicurl"},
            {item.source_construct for item in result.candidates},
        )
        self.assertEqual(
            {"constructs_request", "serializes_parameter", "selects_operation"},
            {item.capability for item in result.evidence_atoms},
        )

    def test_custom_request_object_preserves_literal_json_selector(self):
        content = b'''transport.request({
  type: "POST",
  url: "/cgi-bin/cstecgi.cgi",
  async: false,
  data: {topicurl: "getInitCfg"}
});'''
        source = SourceArtifactEntry(
            canonical_path="www/static/js/config_ie.js",
            original_path="www/static/js/config_ie.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual(1, len(result.candidates))
        self.assertEqual("/cgi-bin/cstecgi.cgi", result.candidates[0].endpoint)
        self.assertEqual("custom.request", result.candidates[0].source_construct)
        self.assertEqual("json", result.candidates[0].representation)
        self.assertEqual("getInitCfg", result.parameters[0].literal_value)
        self.assertTrue(result.parameters[0].is_operation_selector)

    def test_shared_cgi_wrapper_does_not_borrow_endpoint_from_another_object(self):
        content = b'''var unrelated = {cgiUrl: "/cgi-bin/wrong.cgi"};
function Dispatcher() {
  this.srcUrl = globalConfig.cgiUrl;
  this.post = function(data) {
    data.topicurl = this.topicurl;
    data = JSON.stringify(data);
    $.ajax({url:this.srcUrl,type:"POST",dataType:"json",data:data});
  };
}
Dispatcher.prototype.setLanCfg = function(data) {
  return this.topicurl = "setLanCfg", this.post(data);
};'''
        source = SourceArtifactEntry(
            canonical_path="www/static/js/topicurl.js",
            original_path="www/static/js/topicurl.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        result = discover_frontend_requests(source, content)

        self.assertEqual((), result.candidates)

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
