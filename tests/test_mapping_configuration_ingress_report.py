import json
from pathlib import Path
import unittest


class Ac9ConfigurationIngressReportContractTests(unittest.TestCase):
    REPORT = (
        Path(__file__).resolve().parents[1]
        / "docs/firmware-mapping/samples/"
          "r2-22-vendor-tenda-ac9-configuration-ingress.json"
    )

    def test_report_preserves_automated_boundary_and_cross_binary_open_work(self):
        report = json.loads(self.REPORT.read_text(encoding="utf-8"))

        self.assertEqual(
            "firmatlas.mapping.vendor-tenda-ac9-r2-22/v1alpha1",
            report["schema_version"],
        )
        self.assertEqual("firmatlas.mapping.profile/auto-v14", report["profile_id"])
        chain = report["automated_chain"]
        self.assertEqual("/cgi-bin/UploadCfg", chain["interface_path"])
        self.assertEqual("POST", chain["method"])
        self.assertEqual("filename", chain["multipart_parameter"])
        self.assertEqual("form", chain["parameter_namespace"])
        self.assertEqual("bin/httpd@0x0003a9a0", chain["dispatcher_identity"])
        self.assertEqual(6, chain["dispatcher_entry_count"])
        self.assertEqual("bin/httpd@0x0003b850", chain["handler_identity"])
        self.assertEqual(
            {"dispatched_by", "binds_handler"},
            {item["edge_kind"] for item in chain["graph_edges"]},
        )
        self.assertEqual(
            {
                "matches_interface_suffix",
                "establishes_pic_base",
                "dispatches_cgi_token",
                "binds_handler",
                "constructs_request",
                "serializes_parameter",
            },
            {item["capability"] for item in chain["evidence"]},
        )
        continuation = report["manual_cross_binary_continuation"]
        self.assertEqual(10, len(continuation))
        self.assertEqual(
            {"bin/httpd", "lib/libtpi.so", "bin/cfm", "lib/libCfm.so"},
            {item["artifact_path"] for item in continuation},
        )
        self.assertIn(
            "automate handler-to-tpi-to-cfm cross-binary call chain",
            report["obligation_state"]["open_for_next_producer"],
        )
        self.assertIn(
            "security.ddos.map or sys.schedulereboot fields are HTTP parameters",
            report["not_claimed"],
        )


if __name__ == "__main__":
    unittest.main()
