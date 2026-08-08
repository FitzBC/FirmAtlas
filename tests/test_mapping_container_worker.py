import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

from firmatlas.mapping import (
    BinwalkExtractor,
    ContainerBinwalkConfig,
    ContainerBinwalkWorker,
    ExtractionPolicy,
    ExtractionRequest,
    ExtractionStatus,
    InventoryPolicy,
    ToolIdentity,
)


IMAGE_DIGEST = "sha256:" + "a" * 64


def _fake_runtime(root: Path) -> Path:
    script = root / "fake-docker"
    script.write_text(
        """#!{python}
import pathlib
import sys

args = sys.argv[1:]
if args[0] != "run":
    raise SystemExit(64)
if args[-1:] == ["--version"]:
    print("Binwalk v3.1.0")
    raise SystemExit(0)
output_mount = next(value for index, value in enumerate(args) if args[index - 1] == "--volume" and value.endswith(":/output:rw"))
output = pathlib.Path(output_mount.rsplit(":/output:rw", 1)[0])
target = output / "extractions" / "squashfs-root" / "www"
target.mkdir(parents=True)
(target / "index.js").write_text("fetch('/HNAP1')\\n", encoding="utf-8")
print("extracted squashfs")
""".format(python=sys.executable),
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _burst_runtime(root: Path) -> Path:
    script = root / "burst-docker"
    script.write_text(
        """#!{python}
import pathlib
import sys

args = sys.argv[1:]
if args[-1:] == ["--version"]:
    print("Binwalk v3.1.0")
    raise SystemExit(0)
output_mount = next(value for index, value in enumerate(args) if args[index - 1] == "--volume" and value.endswith(":/output:rw"))
output = pathlib.Path(output_mount.rsplit(":/output:rw", 1)[0])
output.mkdir(parents=True, exist_ok=True)
for index in range(5):
    (output / ("burst-" + str(index))).write_bytes(b"x" * 32)
""".format(python=sys.executable),
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _slow_runtime(root: Path) -> Path:
    script = root / "slow-docker"
    script.write_text(
        """#!{python}
import pathlib
import sys
import time

args = sys.argv[1:]
if args[-1:] == ["--version"]:
    print("Binwalk v3.1.0")
    raise SystemExit(0)
output_mount = next(value for index, value in enumerate(args) if args[index - 1] == "--volume" and value.endswith(":/output:rw"))
output = pathlib.Path(output_mount.rsplit(":/output:rw", 1)[0])
output.mkdir(parents=True, exist_ok=True)
(output / "partial.bin").write_bytes(b"partial")
time.sleep(10)
""".format(python=sys.executable),
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _slow_probe_runtime(root: Path) -> Path:
    script = root / "slow-probe-docker"
    script.write_text(
        """#!{python}
import time

time.sleep(10)
""".format(python=sys.executable),
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _verbose_runtime(root: Path) -> Path:
    script = root / "verbose-docker"
    script.write_text(
        """#!{python}
import pathlib
import sys
import time

args = sys.argv[1:]
if args[-1:] == ["--version"]:
    print("Binwalk v3.1.0")
    raise SystemExit(0)
output_mount = next(value for index, value in enumerate(args) if args[index - 1] == "--volume" and value.endswith(":/output:rw"))
output = pathlib.Path(output_mount.rsplit(":/output:rw", 1)[0])
output.mkdir(parents=True, exist_ok=True)
(output / "filesystem.bin").write_bytes(b"filesystem")
sys.stdout.write("x" * 4096)
sys.stderr.write("y" * 4096)
sys.stdout.flush()
sys.stderr.flush()
time.sleep(10)
""".format(python=sys.executable),
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _verbose_probe_runtime(root: Path) -> Path:
    script = root / "verbose-probe-docker"
    script.write_text(
        """#!{python}
import sys
import time

print("Binwalk v3.1.0")
sys.stdout.write("x" * 4096)
sys.stdout.flush()
time.sleep(10)
""".format(python=sys.executable),
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


class ContainerBinwalkWorkerContractTests(unittest.TestCase):
    def test_pinned_container_worker_attests_isolation_and_builds_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = _fake_runtime(root)
            artifact = root / "firmware.bin"
            artifact.write_bytes(b"firmware-image")
            destination = root / "derived"
            worker = ContainerBinwalkWorker(ContainerBinwalkConfig(
                runtime_path=runtime,
                image_ref="ghcr.io/firmatlas/binwalk@" + IMAGE_DIGEST,
                poll_interval_seconds=0.01,
            ))

            result = BinwalkExtractor(worker).extract(ExtractionRequest(
                artifact_path=artifact,
                artifact_sha256=hashlib.sha256(b"firmware-image").hexdigest(),
                destination=destination,
                policy=ExtractionPolicy(
                    max_seconds=30,
                    inventory_policy=InventoryPolicy(
                        max_files=20, max_expanded_bytes=1024 * 1024,
                    ),
                ),
            ))

            self.assertEqual(ExtractionStatus.SUCCESS, result.status)
            self.assertIsNone(result.execution.limit_exceeded)
            self.assertEqual(
                ToolIdentity("binwalk", "3.1.0", image_digest=IMAGE_DIGEST),
                result.tool,
            )
            self.assertEqual(
                ["extractions/squashfs-root/www/index.js"],
                [item.canonical_path for item in result.inventory.entries],
            )
            self.assertEqual(
                {"wall_time", "output_files", "output_bytes", "no_network"},
                set(result.execution.enforced_limits),
            )
            launcher = result.execution.launcher_argv
            self.assertIn("--network", launcher)
            self.assertIn("none", launcher)
            self.assertIn("--read-only", launcher)
            self.assertIn("--pull", launcher)
            self.assertIn("never", launcher)
            self.assertTrue(any(value.endswith(":/input/firmware.bin:ro") for value in launcher))
            self.assertTrue(any(value.endswith(":/output:rw") for value in launcher))
            self.assertEqual(IMAGE_DIGEST, result.to_dict()["tool"]["image_digest"])

    def test_fast_container_cannot_escape_output_file_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "firmware.bin"
            artifact.write_bytes(b"firmware-image")
            worker = ContainerBinwalkWorker(ContainerBinwalkConfig(
                runtime_path=_burst_runtime(root),
                image_ref="ghcr.io/firmatlas/binwalk@" + IMAGE_DIGEST,
                poll_interval_seconds=0.01,
            ))

            result = BinwalkExtractor(worker).extract(ExtractionRequest(
                artifact_path=artifact,
                artifact_sha256=hashlib.sha256(b"firmware-image").hexdigest(),
                destination=root / "derived",
                policy=ExtractionPolicy(
                    max_seconds=30,
                    inventory_policy=InventoryPolicy(
                        max_files=2, max_expanded_bytes=1024,
                    ),
                ),
            ))

            self.assertEqual(ExtractionStatus.PARTIAL_SUCCESS, result.status)
            self.assertNotEqual(0, result.execution.exit_code)
            self.assertEqual("output_files", result.execution.limit_exceeded)
            self.assertEqual(
                ["extraction.worker_failed"],
                [item.code for item in result.diagnostics],
            )

    def test_unpinned_container_image_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "immutable sha256"):
            ContainerBinwalkConfig(
                runtime_path=Path("/usr/bin/docker"), image_ref="binwalk:latest"
            )

    def test_invalid_runtime_resource_limits_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "memory limit"):
            ContainerBinwalkConfig(
                runtime_path=Path("/usr/bin/docker"),
                image_ref=IMAGE_DIGEST,
                memory_limit="--privileged",
            )
        with self.assertRaisesRegex(ValueError, "CPU limit"):
            ContainerBinwalkConfig(
                runtime_path=Path("/usr/bin/docker"),
                image_ref=IMAGE_DIGEST,
                cpu_limit="0",
            )

    def test_wall_time_budget_terminates_container_and_preserves_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "firmware.bin"
            artifact.write_bytes(b"firmware-image")
            worker = ContainerBinwalkWorker(ContainerBinwalkConfig(
                runtime_path=_slow_runtime(root),
                image_ref="ghcr.io/firmatlas/binwalk@" + IMAGE_DIGEST,
                poll_interval_seconds=0.01,
            ))

            result = BinwalkExtractor(worker).extract(ExtractionRequest(
                artifact_path=artifact,
                artifact_sha256=hashlib.sha256(b"firmware-image").hexdigest(),
                destination=root / "derived",
                policy=ExtractionPolicy(max_seconds=1),
            ))

            self.assertEqual(ExtractionStatus.PARTIAL_SUCCESS, result.status)
            self.assertTrue(result.execution.timed_out)
            self.assertEqual("wall_time", result.execution.limit_exceeded)
            self.assertEqual(
                ["partial.bin"],
                [item.canonical_path for item in result.inventory.entries],
            )

    def test_probe_timeout_is_reported_as_structured_tool_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "firmware.bin"
            artifact.write_bytes(b"firmware-image")
            worker = ContainerBinwalkWorker(ContainerBinwalkConfig(
                runtime_path=_slow_probe_runtime(root),
                image_ref="ghcr.io/firmatlas/binwalk@" + IMAGE_DIGEST,
                probe_seconds=1,
            ))

            result = BinwalkExtractor(worker).extract(ExtractionRequest(
                artifact_path=artifact,
                artifact_sha256=hashlib.sha256(b"firmware-image").hexdigest(),
                destination=root / "derived",
            ))

            self.assertEqual(ExtractionStatus.FAILED, result.status)
            self.assertEqual(
                ["extraction.tool_unavailable"],
                [item.code for item in result.diagnostics],
            )
            self.assertEqual("RuntimeError", result.execution.stderr)

    def test_worker_retains_bounded_log_and_attests_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "firmware.bin"
            artifact.write_bytes(b"firmware-image")
            worker = ContainerBinwalkWorker(ContainerBinwalkConfig(
                runtime_path=_verbose_runtime(root),
                image_ref="ghcr.io/firmatlas/binwalk@" + IMAGE_DIGEST,
                max_log_bytes=128,
                poll_interval_seconds=0.01,
            ))

            result = BinwalkExtractor(worker).extract(ExtractionRequest(
                artifact_path=artifact,
                artifact_sha256=hashlib.sha256(b"firmware-image").hexdigest(),
                destination=root / "derived",
            ))

            self.assertEqual(ExtractionStatus.PARTIAL_SUCCESS, result.status)
            self.assertEqual("log_bytes", result.execution.limit_exceeded)
            self.assertLessEqual(
                len(result.execution.stdout.encode("utf-8"))
                + len(result.execution.stderr.encode("utf-8")),
                128,
            )
            self.assertTrue(result.execution.stdout_truncated)
            self.assertTrue(result.execution.stderr_truncated)
            self.assertTrue(result.to_dict()["execution"]["stdout_truncated"])

    def test_probe_rejects_a_version_other_than_the_pinned_toolchain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "legacy-docker"
            runtime.write_text(
                "#!{}\nprint('Binwalk v2.2.1')\n".format(sys.executable),
                encoding="utf-8",
            )
            runtime.chmod(0o755)
            worker = ContainerBinwalkWorker(ContainerBinwalkConfig(
                runtime_path=runtime,
                image_ref="ghcr.io/firmatlas/binwalk@" + IMAGE_DIGEST,
            ))

            with self.assertRaisesRegex(RuntimeError, "version mismatch"):
                worker.probe()

    def test_probe_log_flood_is_terminated_at_the_log_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worker = ContainerBinwalkWorker(ContainerBinwalkConfig(
                runtime_path=_verbose_probe_runtime(root),
                image_ref="ghcr.io/firmatlas/binwalk@" + IMAGE_DIGEST,
                max_log_bytes=128,
                probe_seconds=5,
                poll_interval_seconds=0.01,
            ))

            with self.assertRaisesRegex(RuntimeError, "log budget"):
                worker.probe()


if __name__ == "__main__":
    unittest.main()
