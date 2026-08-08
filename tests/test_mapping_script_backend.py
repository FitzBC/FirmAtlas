import hashlib
import json
from pathlib import Path
import unittest

from firmatlas.mapping import (
    BackendEntryKind,
    CoverageStatus,
    ScriptBackendLanguage,
    ScriptBackendPolicy,
    ScriptParameterNamespace,
    SourceArtifactEntry,
    discover_script_backend,
)


def source_for(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        canonical_path=path,
        original_path=path,
        kind="file",
        size=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
    )


class ScriptBackendProducerContractTests(unittest.TestCase):
    def test_vendor_asp_request_form_and_selector_are_backend_facts(self):
        content = b'''<%
If Request_Form("button_type") = "1" Then
    If Request_Form("admPass1") <> "sentinel" Then
        TCWebApi_set("Account_Entry0","web_passwd","admPass1")
    End If
End If
%>'''

        result = discover_script_backend(source_for("boaroot/cgi-bin/mt_admin.asp", content), content)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(ScriptBackendLanguage.VENDOR_ASP, result.language)
        self.assertEqual(
            [("button_type", ScriptParameterNamespace.FORM, ("1",)),
             ("admPass1", ScriptParameterNamespace.FORM, ())],
            [(item.name, item.namespace, item.selector_values) for item in result.parameters],
        )
        self.assertEqual(1, len(result.state_accesses))
        access = result.state_accesses[0]
        self.assertEqual(("Account_Entry0", "web_passwd", "admPass1"),
                         (access.object_name, access.field_name, access.parameter_name))
        self.assertEqual((), result.routes)
        self.assertEqual((), result.entries)
        self.assertEqual(
            {"reads_parameter", "selects_operation", "writes_configuration"},
            {item.capability for item in result.evidence_atoms},
        )
        self.assertIsInstance(json.dumps(result.to_dict()), str)

    def test_inline_vendor_template_get_is_not_an_http_parameter_or_route(self):
        content = b'''<input value=<% if tcWebApi_get("Account_Entry0","LogoutTime","h") <> "N/A" then tcWebApi_get("Account_Entry0","LogoutTime","s") else asp_Write("5") end if %>>'''

        result = discover_script_backend(source_for("boaroot/cgi-bin/mt_admin.asp", content), content)

        self.assertEqual((), result.parameters)
        self.assertEqual((), result.routes)
        self.assertEqual(1, len(result.template_reads))
        self.assertEqual(("Account_Entry0", "LogoutTime"),
                         (result.template_reads[0].object_name, result.template_reads[0].field_name))
        self.assertEqual("reads_template_state", result.evidence_atoms[0].capability)

    def test_empty_asp_is_completed_without_inventing_an_entrypoint(self):
        result = discover_script_backend(source_for("boaroot/cgi-bin/hnap.asp", b""), b"")

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(ScriptBackendLanguage.VENDOR_ASP, result.language)
        self.assertEqual((), result.entries)
        self.assertEqual((), result.routes)
        self.assertEqual((), result.evidence_atoms)

    def test_shell_cgi_shebang_declares_program_but_not_route(self):
        content = b'''#!/bin/sh
echo "Content-Type: application/json"
name="$QUERY_STRING"
'''
        result = discover_script_backend(
            source_for("boaroot/cgi-bin/get/device.cgi", content), content
        )

        self.assertEqual(ScriptBackendLanguage.SHELL_CGI, result.language)
        self.assertEqual(1, len(result.entries))
        self.assertEqual(BackendEntryKind.CGI_PROGRAM, result.entries[0].kind)
        self.assertIsNone(result.entries[0].route)
        self.assertEqual((), result.routes)
        self.assertEqual(["QUERY_STRING"], [item.name for item in result.parameters])
        self.assertEqual(ScriptParameterNamespace.CGI_ENVIRONMENT,
                         result.parameters[0].namespace)

    def test_ordinary_shell_outside_cgi_path_is_not_a_cgi_program(self):
        content = b"#!/bin/sh\necho ok\n"
        result = discover_script_backend(source_for("etc/init.d/service", content), content)

        self.assertEqual(ScriptBackendLanguage.SHELL, result.language)
        self.assertEqual((), result.entries)
        self.assertEqual((), result.routes)

    def test_php_superglobals_and_slim_route_keep_namespaces_and_handler(self):
        content = b'''<?php
$app->post('/api/network/set', 'setNetwork');
$name = $_POST['name'];
$token = $_SERVER['HTTP_X_TOKEN'];
?>'''
        result = discover_script_backend(source_for("www/api.php", content), content)

        self.assertEqual(ScriptBackendLanguage.PHP, result.language)
        self.assertEqual([("/api/network/set", "POST", "setNetwork")],
                         [(x.route, x.method, x.handler) for x in result.routes])
        self.assertEqual(
            [("name", ScriptParameterNamespace.FORM),
             ("X-Token", ScriptParameterNamespace.HEADER)],
            [(x.name, x.namespace) for x in result.parameters],
        )

    def test_luci_entry_and_formvalue_are_explicit_route_and_parameter(self):
        content = b'''entry({"admin", "network", "lan"}, call("action_lan"), "LAN", 10)
local ip = luci.http.formvalue("ipaddr")
'''
        result = discover_script_backend(source_for("usr/lib/lua/luci/controller/network.lua", content), content)

        self.assertEqual(ScriptBackendLanguage.LUA, result.language)
        self.assertEqual([("/admin/network/lan", None, "action_lan")],
                         [(x.route, x.method, x.handler) for x in result.routes])
        self.assertEqual([("ipaddr", ScriptParameterNamespace.REQUEST)],
                         [(x.name, x.namespace) for x in result.parameters])

    def test_comments_do_not_publish_backend_facts(self):
        content = b'''<?php
// $_POST['fake']; $app->get('/fake', 'fake');
/* $_GET["also_fake"] */
?>'''
        result = discover_script_backend(source_for("www/empty.php", content), content)
        self.assertEqual((), result.parameters)
        self.assertEqual((), result.routes)

        asp = b'''<%
' Request_Form("fake")
Rem TCWebApi_set("Fake", "field", "parameter")
%>'''
        asp_result = discover_script_backend(
            source_for("www/empty.asp", asp), asp
        )
        self.assertEqual((), asp_result.parameters)
        self.assertEqual((), asp_result.state_accesses)

    def test_invalid_utf8_source_mismatch_and_budget_are_explicit(self):
        invalid = b"<?php \xff ?>"
        invalid_result = discover_script_backend(source_for("www/api.php", invalid), invalid)
        self.assertEqual(CoverageStatus.FAILED, invalid_result.coverage_status)
        self.assertEqual("invalid_utf8", invalid_result.diagnostics[0].code)

        content = b"<?php $_GET['a']; ?>"
        with self.assertRaisesRegex(ValueError, "source inventory"):
            discover_script_backend(source_for("www/api.php", content), content + b"x")

        limited = discover_script_backend(
            source_for("www/api.php", content), content,
            ScriptBackendPolicy(max_source_bytes=8, max_findings=100),
        )
        self.assertEqual(CoverageStatus.PARTIAL, limited.coverage_status)
        self.assertEqual(8, limited.processed_bytes)
        self.assertEqual("source_budget_exceeded", limited.diagnostics[0].code)

    def test_finding_budget_is_stable_and_reports_partial_coverage(self):
        content = b"<?php $_GET['a']; $_GET['b']; $_GET['c']; ?>"
        source = source_for("www/api.php", content)
        result = discover_script_backend(
            source, content, ScriptBackendPolicy(max_findings=2)
        )
        again = discover_script_backend(
            source, content, ScriptBackendPolicy(max_findings=2)
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual(["a", "b"], [item.name for item in result.parameters])
        self.assertEqual(result.to_dict(), again.to_dict())
        self.assertEqual("finding_budget_exceeded", result.diagnostics[0].code)

    def test_actual_firmware_samples_distinguish_backend_and_empty_placeholder(self):
        base = Path("../iot_seedintelligentanalysis/binwalk_result/类型9/BM-2024-00096/")
        roots = list(base.glob("*.bin.extracted/squashfs-root/boaroot/cgi-bin"))
        if not roots:
            self.skipTest("local extracted D-Link sample is unavailable")
        root = roots[0]
        admin_path = root / "MAINTENANCE/mt_admin.asp"
        empty_path = root / "hnap.asp"
        admin = admin_path.read_bytes()
        empty = empty_path.read_bytes()

        admin_result = discover_script_backend(
            source_for("boaroot/cgi-bin/MAINTENANCE/mt_admin.asp", admin), admin
        )
        empty_result = discover_script_backend(
            source_for("boaroot/cgi-bin/hnap.asp", empty), empty
        )

        self.assertIn("button_type", {x.name for x in admin_result.parameters})
        self.assertGreaterEqual(len(admin_result.state_accesses), 5)
        self.assertEqual((), empty_result.entries)
        self.assertEqual((), empty_result.parameters)

    def test_documented_real_replay_summary_preserves_conservative_boundaries(self):
        payload = json.loads(Path(
            "docs/firmware-mapping/samples/m1-06b-script-backend-summary.json"
        ).read_text())
        by_path = {item["path"]: item for item in payload["real_replays"]}

        admin = by_path["boaroot/cgi-bin/MAINTENANCE/mt_admin.asp"]
        self.assertEqual(2, admin["counts"]["parameters"])
        self.assertEqual(6, admin["counts"]["state_accesses"])
        self.assertEqual(0, admin["counts"]["routes"])
        self.assertEqual(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            by_path["boaroot/cgi-bin/hnap.asp"]["sha256"],
        )
        self.assertEqual(
            {"entries": 1, "routes": 0},
            {key: by_path["boaroot/cgi-bin/get/ADVANCED/ad_routing.cgi"]["counts"][key]
             for key in ("entries", "routes")},
        )


if __name__ == "__main__":
    unittest.main()
