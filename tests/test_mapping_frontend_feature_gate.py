import hashlib
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    FrontendAssetInput,
    FrontendFeatureGateStatus,
    SourceArtifactEntry,
    discover_frontend_asset_graph,
    discover_frontend_feature_gates,
)


def _asset(path: str, content: bytes) -> FrontendAssetInput:
    return FrontendAssetInput(
        SourceArtifactEntry(
            path,
            path,
            "file",
            len(content),
            hashlib.sha256(content).hexdigest(),
        ),
        content,
    )


class FrontendFeatureGateContractTests(unittest.TestCase):
    def test_disabled_feature_is_linked_to_page_requests_with_exact_evidence(self):
        assets = (
            _asset(
                "webroot_ro/js/macro_config.js",
                b'var CONFIG_DLNA_SERVER = "n";',
            ),
            _asset(
                "webroot_ro/js/main.js",
                b'''var modulesObj = {"usb_dlna": CONFIG_DLNA_SERVER}, prop;
for (prop in modulesObj) {
  if (modulesObj[prop] == "y") {
    $("#" + prop).removeClass("none");
  }
}
switch (id) {
case "usb_dlna":
  showIframe(_("DLNA"), "dlna.html", 620, 450);
  break;
}''',
            ),
            _asset(
                "webroot_ro/dlna.html",
                b'<script src="js/dlna.js?cache"></script>',
            ),
            _asset(
                "webroot_ro/js/dlna.js",
                b'''var pageModel=R.pageModel({
getUrl:"goform/GetDlnaCfg",setUrl:"goform/SetDlnaCfg"});
$.GetSetData.setData("goform/expandDlnaFile?" + Math.random(), data, cb);
$.post("/goform/refreshDLNA", "action=1", cb);''',
            ),
        )
        graph = discover_frontend_asset_graph(assets)

        result = discover_frontend_feature_gates(assets, graph)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.gates))
        gate = result.gates[0]
        self.assertEqual(FrontendFeatureGateStatus.DISABLED, gate.status)
        self.assertEqual("CONFIG_DLNA_SERVER", gate.feature_symbol)
        self.assertEqual("n", gate.configured_value)
        self.assertEqual("y", gate.enabled_value)
        self.assertEqual("usb_dlna", gate.ui_target_id)
        self.assertEqual("webroot_ro/dlna.html", gate.page_path)
        self.assertEqual(("webroot_ro/js/dlna.js",), gate.script_paths)
        self.assertEqual(
            {
                "/goform/refreshDLNA",
                "goform/GetDlnaCfg",
                "goform/SetDlnaCfg",
                "goform/expandDlnaFile?",
            },
            set(gate.request_endpoints),
        )
        self.assertEqual(
            {
                "declares_feature_value",
                "maps_feature_to_ui_target",
                "reveals_feature_target",
                "routes_feature_target_to_page",
                "loads_feature_script",
            },
            {item.capability for item in result.evidence_atoms},
        )

    def test_unrelated_object_does_not_impersonate_modules_feature_map(self):
        assets = (
            _asset("webroot_ro/js/macro_config.js", b'var CONFIG_X = "n";'),
            _asset(
                "webroot_ro/js/main.js",
                b'''var unrelated = {"usb_x": CONFIG_X};
var modulesObj = {}, prop;
for (prop in modulesObj) {
  if (modulesObj[prop] == "y") { $("#" + prop).removeClass("none"); }
}
case "usb_x": showIframe("X", "x.html");''',
            ),
            _asset("webroot_ro/x.html", b'<script src="js/x.js"></script>'),
            _asset("webroot_ro/js/x.js", b'$.get("goform/GetX");'),
        )

        result = discover_frontend_feature_gates(
            assets, discover_frontend_asset_graph(assets)
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual((), result.gates)


if __name__ == "__main__":
    unittest.main()
