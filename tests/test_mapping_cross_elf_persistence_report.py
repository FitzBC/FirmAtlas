import json
from pathlib import Path
import unittest


REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-23-vendor-tenda-ac9-cross-elf-persistence.json"
)


class Ac9CrossElfPersistenceReportTests(unittest.TestCase):
    def test_report_preserves_cross_elf_chain_and_unresolved_owner_boundary(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))

        self.assertEqual(
            "firmatlas.mapping.profile/auto-v15", report["profile_id"]
        )
        stages = {item["stage_name"]: item for item in report["stages"]}
        self.assertEqual(
            "completed", stages["native_pointer_command_binding"]["coverage_status"]
        )
        self.assertEqual(
            "completed", stages["native_cross_elf_call"]["coverage_status"]
        )
        command = next(
            item for item in report["selected_calls"]
            if item["callsite_address"] == "0x00009d68"
        )
        self.assertEqual(["cfm Upload"], command["argument_literals"])
        self.assertEqual(
            "unresolved_import_owner", command["target_resolution_status"]
        )
        self.assertIn(
            "doSystemCmd is owned by an arbitrary same-name export",
            report["not_claimed"],
        )


if __name__ == "__main__":
    unittest.main()
