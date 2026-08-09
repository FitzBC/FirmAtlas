import os
from io import BytesIO
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from firmatlas.mapping import CoverageStatus, InventoryPolicy, build_inventory


class SourceInventoryContractTests(unittest.TestCase):
    def test_absolute_symlink_is_resolved_inside_firmware_chroot(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            (root / "dev").mkdir()
            (root / "dev" / "null").write_bytes(b"firmware-null")
            (root / "etc").mkdir()
            (root / "etc" / "hosts").symlink_to("/dev/null")

            inventory = build_inventory(root, InventoryPolicy())

            link = next(item for item in inventory.entries if item.kind == "symlink")
            self.assertEqual("/dev/null", link.link_target)
            self.assertEqual("dev/null", link.resolved_path)
            self.assertEqual(
                "recorded_chroot_absolute_not_followed", link.expansion_status
            )
            self.assertIsNone(link.content_sha256)
            self.assertEqual(CoverageStatus.COMPLETED, inventory.coverage_status)
            self.assertEqual((), inventory.diagnostics)

    def test_relative_symlink_chain_can_cross_a_chroot_absolute_link(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            (root / "lib").mkdir()
            (root / "real").mkdir()
            (root / "real" / "libc-1.so").write_bytes(b"ELF")
            (root / "lib" / "libc.so.0").symlink_to("/real/libc-1.so")
            (root / "lib" / "libc.so").symlink_to("libc.so.0")

            inventory = build_inventory(root, InventoryPolicy())

            links = {
                item.canonical_path: item
                for item in inventory.entries
                if item.kind == "symlink"
            }
            self.assertEqual("real/libc-1.so", links["lib/libc.so"].resolved_path)
            self.assertEqual(
                "recorded_not_followed", links["lib/libc.so"].expansion_status
            )
            self.assertEqual(CoverageStatus.COMPLETED, inventory.coverage_status)

    def test_inventory_policy_rejects_nonpositive_resource_limits(self):
        for field_name in (
            "max_files",
            "max_total_bytes",
            "max_file_bytes",
            "max_expanded_bytes",
            "max_symlink_depth",
        ):
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(ValueError, field_name):
                    InventoryPolicy(**{field_name: 0})

    def test_inventory_rejects_missing_or_nondirectory_roots(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            file_root = base / "firmware.bin"
            file_root.write_bytes(b"firmware")
            for invalid_root in (base / "missing", file_root):
                with self.subTest(invalid_root=invalid_root):
                    with self.assertRaisesRegex(ValueError, "existing directory"):
                        build_inventory(invalid_root, InventoryPolicy())

    def test_inventory_is_content_stable_across_root_location_and_mtime(self):
        with tempfile.TemporaryDirectory() as first_dir, \
            tempfile.TemporaryDirectory() as second_dir:
            first = Path(first_dir)
            second = Path(second_dir)
            for root in (first, second):
                (root / "etc").mkdir()
                (root / "www").mkdir()
                (root / "etc" / "httpd.conf").write_text("port=80\n", encoding="utf-8")
                (root / "www" / "index.js").write_text(
                    "fetch('/goform/SetOnlineDevName')\n", encoding="utf-8"
                )
            os.utime(first / "etc" / "httpd.conf", (1, 1))
            os.utime(second / "etc" / "httpd.conf", (2_000_000_000, 2_000_000_000))

            first_inventory = build_inventory(first, InventoryPolicy())
            second_inventory = build_inventory(second, InventoryPolicy())

            self.assertEqual(
                first_inventory.inventory_sha256,
                second_inventory.inventory_sha256,
            )
            self.assertEqual(
                ["etc/httpd.conf", "www/index.js"],
                [entry.canonical_path for entry in first_inventory.entries],
            )
            self.assertEqual([8, 34], [entry.size for entry in first_inventory.entries])
            self.assertTrue(all(entry.content_sha256 for entry in first_inventory.entries))

    def test_inventory_records_but_never_reads_a_symlink_escape(self):
        with tempfile.TemporaryDirectory() as root_dir, \
            tempfile.TemporaryDirectory() as outside_dir:
            root = Path(root_dir)
            outside = Path(outside_dir) / "secret.txt"
            outside.write_text("must-not-be-hashed", encoding="utf-8")
            (root / "www").mkdir()
            relative_escape = os.path.relpath(outside, root / "www")
            (root / "www" / "escape").symlink_to(relative_escape)

            inventory = build_inventory(root, InventoryPolicy())

            self.assertEqual(1, len(inventory.entries))
            entry = inventory.entries[0]
            self.assertEqual("www/escape", entry.canonical_path)
            self.assertEqual("symlink", entry.kind)
            self.assertEqual(relative_escape, entry.link_target)
            self.assertEqual("rejected_escape", entry.expansion_status)
            self.assertIsNone(entry.resolved_path)
            self.assertIsNone(entry.content_sha256)
            self.assertEqual(CoverageStatus.PARTIAL, inventory.coverage_status)
            self.assertEqual(
                ["inventory.symlink_escape"],
                [diagnostic.code for diagnostic in inventory.diagnostics],
            )

    def test_intermediate_symlink_escape_is_rejected_before_host_traversal(self):
        with tempfile.TemporaryDirectory() as root_dir, \
            tempfile.TemporaryDirectory() as outside_dir:
            root = Path(root_dir)
            outside = Path(outside_dir)
            (outside / "secret").write_text("must-not-be-hashed", encoding="utf-8")
            (root / "safe").symlink_to(os.path.relpath(outside, root))
            (root / "entry").symlink_to("safe/secret")

            inventory = build_inventory(root, InventoryPolicy())

            links = {item.canonical_path: item for item in inventory.entries}
            self.assertEqual("rejected_escape", links["entry"].expansion_status)
            self.assertIsNone(links["entry"].resolved_path)
            self.assertIsNone(links["entry"].content_sha256)
            self.assertEqual(CoverageStatus.PARTIAL, inventory.coverage_status)

    def test_parent_segment_does_not_erase_a_preceding_symlink_hop(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            (root / "secret").write_bytes(b"inside")
            (root / "jump").symlink_to("../../outside")
            (root / "entry").symlink_to("jump/../secret")

            inventory = build_inventory(root, InventoryPolicy())

            links = {item.canonical_path: item for item in inventory.entries}
            self.assertEqual("rejected_escape", links["entry"].expansion_status)
            self.assertIsNone(links["entry"].resolved_path)
            self.assertEqual(CoverageStatus.PARTIAL, inventory.coverage_status)

    def test_missing_symlink_target_is_a_visible_coverage_gap(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            (root / "bin").mkdir()
            (root / "bin" / "tool").symlink_to("/missing/tool")

            inventory = build_inventory(root, InventoryPolicy())

            link = inventory.entries[0]
            self.assertEqual("missing_target", link.expansion_status)
            self.assertEqual("missing/tool", link.resolved_path)
            self.assertEqual(CoverageStatus.PARTIAL, inventory.coverage_status)
            self.assertEqual(
                ["inventory.symlink_target_missing"],
                [item.code for item in inventory.diagnostics],
            )

    def test_unmaterialized_runtime_device_target_is_not_a_source_coverage_gap(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            (root / "etc").mkdir()
            (root / "etc" / "hosts").symlink_to("/dev/null")

            inventory = build_inventory(root, InventoryPolicy())

            link = inventory.entries[0]
            self.assertEqual(
                "recorded_runtime_target_not_materialized",
                link.expansion_status,
            )
            self.assertEqual("dev/null", link.resolved_path)
            self.assertEqual(CoverageStatus.COMPLETED, inventory.coverage_status)
            self.assertEqual((), inventory.diagnostics)

    def test_target_under_declared_empty_runtime_tree_is_not_a_source_gap(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            (root / "usr" / "bin").mkdir(parents=True)
            (root / "tmp").mkdir()
            (root / "var").mkdir()
            (root / "usr" / "bin" / "dynamic-tool").symlink_to(
                "/var/dynamic-tool"
            )
            (root / "usr" / "bin" / "runtime-state").symlink_to(
                "/tmp/runtime-state"
            )

            inventory = build_inventory(root, InventoryPolicy())

            links = [item for item in inventory.entries if item.kind == "symlink"]
            self.assertEqual(
                [
                    "recorded_runtime_target_not_materialized",
                    "recorded_runtime_target_not_materialized",
                ],
                [item.expansion_status for item in links],
            )
            self.assertEqual(CoverageStatus.COMPLETED, inventory.coverage_status)
            self.assertEqual((), inventory.diagnostics)

    def test_dap3520_chroot_symlinks_replay_without_false_escape_gap(self):
        root = Path(
            "../iot_seedintelligentanalysis/binwalk_result/类型6/BM-2024-00027/"
            "_DAP-3520_REVA_FIRMWARE_PATCH_1.17.RC047.ZIP.extracted/"
            "_DAP-3520_FW_v117-rc047.bin.extracted/squashfs-root"
        )
        if not root.exists():
            self.skipTest("local DAP-3520 representative sample is unavailable")

        inventory = build_inventory(root, InventoryPolicy())
        symlink_statuses = {
            item.expansion_status
            for item in inventory.entries
            if item.kind == "symlink"
        }

        self.assertEqual(CoverageStatus.COMPLETED, inventory.coverage_status)
        self.assertEqual(
            118,
            sum(item.kind == "symlink" for item in inventory.entries),
        )
        self.assertEqual(
            {
                "recorded_not_followed",
                "recorded_runtime_target_not_materialized",
            },
            symlink_statuses,
        )
        self.assertEqual((), inventory.diagnostics)

    def test_symlink_cycle_is_recorded_without_crashing_inventory(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            (root / "a").symlink_to("b")
            (root / "b").symlink_to("a")

            inventory = build_inventory(root, InventoryPolicy())

            self.assertEqual(
                ["rejected_cycle", "rejected_cycle"],
                [item.expansion_status for item in inventory.entries],
            )
            self.assertEqual(CoverageStatus.PARTIAL, inventory.coverage_status)
            self.assertEqual(
                ["inventory.symlink_cycle", "inventory.symlink_cycle"],
                [item.code for item in inventory.diagnostics],
            )

    def test_symlink_depth_budget_limits_only_the_long_chain(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            (root / "target").write_bytes(b"target")
            (root / "c").symlink_to("target")
            (root / "b").symlink_to("c")
            (root / "a").symlink_to("b")

            inventory = build_inventory(
                root, InventoryPolicy(max_symlink_depth=2)
            )
            links = {item.canonical_path: item for item in inventory.entries}

            self.assertEqual("depth_limited", links["a"].expansion_status)
            self.assertEqual("recorded_not_followed", links["b"].expansion_status)
            self.assertEqual("target", links["b"].resolved_path)
            self.assertEqual(
                ["inventory.symlink_depth_exceeded"],
                [item.code for item in inventory.diagnostics],
            )

    def test_zip_members_are_inspected_without_extracting_path_traversal(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            archive = root / "firmware.bin"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("www/index.js", "fetch('/HNAP1')\n")
                bundle.writestr("../../outside.txt", "escape")
                bundle.writestr("/absolute.txt", "escape")
                bundle.writestr("..\\windows-escape.txt", "escape")

            inventory = build_inventory(root, InventoryPolicy())

            self.assertEqual(
                ["firmware.bin", "firmware.bin!www/index.js"],
                [entry.canonical_path for entry in inventory.entries],
            )
            self.assertEqual("archive", inventory.entries[0].kind)
            self.assertEqual("inspected", inventory.entries[0].expansion_status)
            self.assertEqual("archive_member", inventory.entries[1].kind)
            self.assertEqual("firmware.bin", inventory.entries[1].parent_path)
            self.assertEqual(16, inventory.entries[1].size)
            self.assertEqual(
                [
                    "inventory.archive_path_traversal",
                    "inventory.archive_path_traversal",
                    "inventory.archive_path_traversal",
                ],
                [diagnostic.code for diagnostic in inventory.diagnostics],
            )
            self.assertEqual(CoverageStatus.PARTIAL, inventory.coverage_status)
            self.assertFalse((root.parent / "outside.txt").exists())

    def test_file_count_budget_publishes_partial_coverage_instead_of_a_false_empty_result(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            (root / "a.conf").write_text("aaaa", encoding="utf-8")
            (root / "b.conf").write_text("bbbb", encoding="utf-8")
            (root / "c.conf").write_text("cccc", encoding="utf-8")

            inventory = build_inventory(root, InventoryPolicy(max_files=2))

            self.assertEqual(
                ["a.conf", "b.conf"],
                [entry.canonical_path for entry in inventory.entries],
            )
            self.assertEqual(CoverageStatus.PARTIAL, inventory.coverage_status)
            self.assertEqual(3, inventory.observed_count)
            self.assertEqual(2, inventory.processed_count)
            self.assertEqual(8, inventory.processed_bytes)
            self.assertEqual(
                ["inventory.file_count_budget_exceeded"],
                [diagnostic.code for diagnostic in inventory.diagnostics],
            )
            self.assertEqual("c.conf", inventory.diagnostics[0].path)

    def test_byte_budget_skips_content_before_hashing_and_reports_the_gap(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            (root / "a-small").write_bytes(b"1234")
            (root / "b-large").write_bytes(b"must-not-be-read")

            inventory = build_inventory(
                root,
                InventoryPolicy(max_total_bytes=4, max_file_bytes=8),
            )

            self.assertEqual(["a-small"], [item.canonical_path for item in inventory.entries])
            self.assertEqual(CoverageStatus.PARTIAL, inventory.coverage_status)
            self.assertEqual(2, inventory.observed_count)
            self.assertEqual(1, inventory.processed_count)
            self.assertEqual(4, inventory.processed_bytes)
            self.assertEqual(
                ["inventory.file_size_budget_exceeded"],
                [diagnostic.code for diagnostic in inventory.diagnostics],
            )
            self.assertEqual("b-large", inventory.diagnostics[0].path)

    def test_archive_expansion_budget_rejects_member_before_decompression(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            archive = root / "compressed.bin"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                bundle.writestr("rootfs/large.txt", "A" * 10_000)

            inventory = build_inventory(
                root,
                InventoryPolicy(max_expanded_bytes=128),
            )

            self.assertEqual(
                ["compressed.bin"],
                [item.canonical_path for item in inventory.entries],
            )
            self.assertEqual(CoverageStatus.PARTIAL, inventory.coverage_status)
            self.assertEqual(2, inventory.observed_count)
            self.assertEqual(1, inventory.processed_count)
            self.assertEqual(0, inventory.expanded_bytes)
            self.assertEqual(
                ["inventory.archive_expansion_budget_exceeded"],
                [diagnostic.code for diagnostic in inventory.diagnostics],
            )
            self.assertEqual(
                "compressed.bin!rootfs/large.txt", inventory.diagnostics[0].path
            )

    def test_nested_archive_stops_at_policy_depth_and_exposes_the_obligation(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            nested_bytes = BytesIO()
            with zipfile.ZipFile(nested_bytes, "w") as nested:
                nested.writestr("www/index.js", "fetch('/goform/Test')\n")
            with zipfile.ZipFile(root / "outer.bin", "w") as outer:
                outer.writestr("images/rootfs.bin", nested_bytes.getvalue())

            inventory = build_inventory(
                root,
                InventoryPolicy(max_archive_depth=1),
            )

            self.assertEqual(
                ["outer.bin", "outer.bin!images/rootfs.bin"],
                [item.canonical_path for item in inventory.entries],
            )
            nested_entry = inventory.entries[1]
            self.assertEqual("archive", nested_entry.kind)
            self.assertEqual("depth_limited", nested_entry.expansion_status)
            self.assertEqual(CoverageStatus.PARTIAL, inventory.coverage_status)
            self.assertEqual(
                ["inventory.archive_depth_exceeded"],
                [diagnostic.code for diagnostic in inventory.diagnostics],
            )

    def test_nested_archive_is_recursively_inventoried_within_policy_depth(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            nested_bytes = BytesIO()
            with zipfile.ZipFile(nested_bytes, "w") as nested:
                nested.writestr("www/index.js", "fetch('/goform/Test')\n")
            with zipfile.ZipFile(root / "outer.bin", "w") as outer:
                outer.writestr("images/rootfs.bin", nested_bytes.getvalue())

            inventory = build_inventory(
                root,
                InventoryPolicy(max_archive_depth=2),
            )

            self.assertEqual(
                [
                    "outer.bin",
                    "outer.bin!images/rootfs.bin",
                    "outer.bin!images/rootfs.bin!www/index.js",
                ],
                [item.canonical_path for item in inventory.entries],
            )
            self.assertEqual(CoverageStatus.COMPLETED, inventory.coverage_status)
            self.assertEqual(3, inventory.observed_count)
            self.assertEqual(3, inventory.processed_count)

    def test_zero_archive_depth_hashes_container_without_opening_members(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            with zipfile.ZipFile(root / "firmware.bin", "w") as archive:
                archive.writestr("rootfs/etc/config", "secret")

            inventory = build_inventory(
                root,
                InventoryPolicy(max_archive_depth=0),
            )

            self.assertEqual(["firmware.bin"], [item.canonical_path for item in inventory.entries])
            self.assertEqual("depth_limited", inventory.entries[0].expansion_status)
            self.assertEqual(CoverageStatus.PARTIAL, inventory.coverage_status)
            self.assertEqual(1, inventory.observed_count)
            self.assertEqual(1, inventory.processed_count)
            self.assertEqual(
                ["inventory.archive_depth_exceeded"],
                [item.code for item in inventory.diagnostics],
            )

    def test_hardlinks_keep_both_paths_but_hash_shared_content_once(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            original = root / "bin" / "busybox"
            original.parent.mkdir()
            original.write_bytes(b"ELF!")
            os.link(original, root / "bin" / "sh")

            inventory = build_inventory(
                root,
                InventoryPolicy(max_total_bytes=4),
            )

            self.assertEqual(
                ["bin/busybox", "bin/sh"],
                [item.canonical_path for item in inventory.entries],
            )
            self.assertEqual(["file", "hardlink"], [item.kind for item in inventory.entries])
            self.assertEqual("bin/busybox", inventory.entries[1].parent_path)
            self.assertEqual(
                inventory.entries[0].content_sha256,
                inventory.entries[1].content_sha256,
            )
            self.assertEqual(2, inventory.processed_count)
            self.assertEqual(4, inventory.processed_bytes)
            self.assertEqual(CoverageStatus.COMPLETED, inventory.coverage_status)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO fixtures require os.mkfifo")
    def test_special_files_are_recorded_without_opening_them(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            os.mkfifo(root / "event.pipe")

            inventory = build_inventory(root, InventoryPolicy())

            self.assertEqual(["event.pipe"], [item.canonical_path for item in inventory.entries])
            self.assertEqual("fifo", inventory.entries[0].kind)
            self.assertIsNone(inventory.entries[0].content_sha256)
            self.assertEqual("unsupported", inventory.entries[0].expansion_status)
            self.assertEqual(CoverageStatus.PARTIAL, inventory.coverage_status)
            self.assertEqual(
                ["inventory.unsupported_filesystem_node"],
                [item.code for item in inventory.diagnostics],
            )

    def test_archive_member_normalization_collision_is_not_published_twice(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            with zipfile.ZipFile(root / "collision.bin", "w") as archive:
                archive.writestr("./www/index.js", "first")
                archive.writestr("www/index.js", "second")

            inventory = build_inventory(root, InventoryPolicy())

            self.assertEqual(
                ["collision.bin", "collision.bin!www/index.js"],
                [item.canonical_path for item in inventory.entries],
            )
            self.assertEqual(CoverageStatus.PARTIAL, inventory.coverage_status)
            self.assertEqual(
                ["inventory.archive_member_collision"],
                [item.code for item in inventory.diagnostics],
            )

    def test_inventory_cli_emits_a_bounded_explainable_summary(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            (root / "www").mkdir()
            (root / "www" / "index.js").write_text(
                "fetch('/HNAP1')\n", encoding="utf-8"
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "firmatlas.mapping",
                    "inventory",
                    str(root),
                    "--sample-limit",
                    "1",
                ],
                cwd=Path(__file__).resolve().parents[1],
                env={**os.environ, "PYTHONPATH": "src"},
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            summary = json.loads(completed.stdout)
            self.assertEqual("completed", summary["coverage_status"])
            self.assertEqual(1, summary["observed_count"])
            self.assertEqual(1, summary["processed_count"])
            self.assertEqual([], summary["diagnostic_codes"])
            self.assertEqual(
                [
                    {
                        "kind": "file",
                        "path": "www/index.js",
                        "size": 16,
                        "content_sha256": (
                            "415ecfc6c9bab4eb66c79c6d5796ec247859aca5fe672913f8a9f5d506028edf"
                        ),
                    }
                ],
                summary["sample_entries"],
            )

    def test_inventory_serializes_as_a_versioned_replayable_contract(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            (root / "httpd.conf").write_text("port=80\n", encoding="utf-8")
            policy = InventoryPolicy(max_files=17, max_archive_depth=0)

            inventory = build_inventory(root, policy)
            payload = inventory.to_dict()

            self.assertEqual(
                "firmatlas.mapping.inventory/v1alpha2",
                payload["schema_version"],
            )
            self.assertEqual(inventory.inventory_sha256, payload["inventory_sha256"])
            self.assertEqual(17, payload["policy"]["max_files"])
            self.assertEqual(0, payload["policy"]["max_archive_depth"])
            self.assertEqual("completed", payload["coverage_status"])
            self.assertEqual("httpd.conf", payload["entries"][0]["canonical_path"])
            self.assertIsInstance(json.dumps(payload), str)

    def test_corrupt_archive_member_becomes_a_diagnostic_not_a_call_failure(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            archive_path = root / "corrupt.bin"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("rootfs/config", b"unique-payload")
            corrupted = bytearray(archive_path.read_bytes())
            payload_offset = corrupted.index(b"unique-payload")
            corrupted[payload_offset] ^= 0xFF
            archive_path.write_bytes(corrupted)

            inventory = build_inventory(root, InventoryPolicy())

            self.assertEqual(["corrupt.bin"], [item.canonical_path for item in inventory.entries])
            self.assertEqual(CoverageStatus.PARTIAL, inventory.coverage_status)
            self.assertEqual(
                ["inventory.archive_member_read_failed"],
                [item.code for item in inventory.diagnostics],
            )
            self.assertEqual("corrupt.bin!rootfs/config", inventory.diagnostics[0].path)


if __name__ == "__main__":
    unittest.main()
