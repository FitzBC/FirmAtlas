"""Production container Adapter for the firmware ExtractionWorker seam."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
from typing import Tuple

from .extraction import (
    ExtractionWorker,
    ToolIdentity,
    WorkerExecution,
    WorkerExtractionRequest,
)


_PINNED_IMAGE = re.compile(
    r"^(?:.+@)?(?P<digest>sha256:[0-9a-f]{64})$"
)
_VERSION = re.compile(r"(?i)binwalk\s+v?(?P<version>[0-9]+\.[0-9]+\.[0-9]+)")
_MEMORY_LIMIT = re.compile(r"^[1-9][0-9]*[bkmg]?$", re.IGNORECASE)
_CPU_LIMIT = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")
_REQUIRED_LIMITS = ("no_network", "output_bytes", "output_files", "wall_time")


@dataclass(frozen=True)
class ContainerBinwalkConfig:
    runtime_path: Path
    image_ref: str
    expected_version: str = "3.1.0"
    memory_limit: str = "2g"
    cpu_limit: str = "2.0"
    pids_limit: int = 128
    max_log_bytes: int = 1024 * 1024
    probe_seconds: int = 30
    poll_interval_seconds: float = 0.05

    def __post_init__(self) -> None:
        if not _PINNED_IMAGE.fullmatch(self.image_ref):
            raise ValueError("Binwalk container image must use an immutable sha256 digest")
        if not str(self.runtime_path):
            raise ValueError("container runtime path is required")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.expected_version):
            raise ValueError("expected Binwalk version must use major.minor.patch")
        if not _MEMORY_LIMIT.fullmatch(self.memory_limit):
            raise ValueError("container memory limit is invalid")
        if (
            not _CPU_LIMIT.fullmatch(self.cpu_limit)
            or float(self.cpu_limit) <= 0
        ):
            raise ValueError("container CPU limit must be positive")
        if self.pids_limit <= 0 or self.max_log_bytes <= 0 or self.probe_seconds <= 0:
            raise ValueError("container worker limits must be positive")
        if self.poll_interval_seconds <= 0:
            raise ValueError("poll_interval_seconds must be positive")

    @property
    def image_digest(self) -> str:
        match = _PINNED_IMAGE.fullmatch(self.image_ref)
        assert match is not None
        return match.group("digest")


def _output_usage(root: Path) -> Tuple[int, int]:
    files = 0
    size = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = tuple(os.scandir(str(current)))
        except FileNotFoundError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                else:
                    files += 1
                    size += entry.stat(follow_symlinks=False).st_size
            except FileNotFoundError:
                continue
    return files, size


def _read_logs_bounded(
    stdout_stream, stderr_stream, limit: int
) -> Tuple[str, str, bool, bool]:
    for stream in (stdout_stream, stderr_stream):
        stream.flush()
        stream.seek(0)
    stdout_bytes = stdout_stream.read(limit + 1)
    if len(stdout_bytes) > limit:
        stderr_truncated = bool(stderr_stream.read(1))
        return (
            stdout_bytes[:limit].decode("utf-8", errors="replace"),
            "",
            True,
            stderr_truncated,
        )
    remaining = limit - len(stdout_bytes)
    stderr_bytes = stderr_stream.read(remaining + 1)
    return (
        stdout_bytes.decode("utf-8", errors="replace"),
        stderr_bytes[:remaining].decode("utf-8", errors="replace"),
        False,
        len(stderr_bytes) > remaining,
    )


def _terminate_process_group(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


class ContainerBinwalkWorker(ExtractionWorker):
    """Run pinned Binwalk in a networkless, read-only-root container."""

    def __init__(self, config: ContainerBinwalkConfig):
        self._config = config

    def _hardening_argv(self) -> Tuple[str, ...]:
        return (
            str(self._config.runtime_path), "run", "--rm",
            "--pull", "never", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", str(self._config.pids_limit),
            "--memory", self._config.memory_limit,
            "--cpus", self._config.cpu_limit,
            "--user", "{}:{}".format(os.getuid(), os.getgid()),
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=268435456",
            "--env", "HOME=/tmp",
        )

    def _probe_command(self, argument: str) -> Tuple[int, str]:
        launcher = (
            *self._hardening_argv(), "--entrypoint", "binwalk",
            self._config.image_ref, argument,
        )
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process = subprocess.Popen(
                launcher,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
            exceeded = ""
            started = time.monotonic()
            while process.poll() is None:
                if time.monotonic() - started > self._config.probe_seconds:
                    exceeded = "wall_time"
                elif (
                    stdout_file.tell() + stderr_file.tell()
                    > self._config.max_log_bytes
                ):
                    exceeded = "log_bytes"
                if exceeded:
                    _terminate_process_group(process)
                    break
                time.sleep(self._config.poll_interval_seconds)
            return_code = process.wait()
            if (
                not exceeded
                and stdout_file.tell() + stderr_file.tell()
                > self._config.max_log_bytes
            ):
                exceeded = "log_bytes"
            if exceeded == "wall_time":
                _terminate_process_group(process)
                raise RuntimeError(
                    "pinned Binwalk container probe timed out"
                )
            if exceeded == "log_bytes":
                raise RuntimeError(
                    "pinned Binwalk container probe log budget exceeded"
                )
            stdout, stderr, _, _ = _read_logs_bounded(
                stdout_file, stderr_file, self._config.max_log_bytes
            )
        return return_code, stdout + "\n" + stderr

    def probe(self) -> ToolIdentity:
        return_code, rendered = self._probe_command("--version")
        match = _VERSION.search(rendered)
        # Binwalk 2.2.x treats --version as an input file. If that command did
        # not yield a version banner, the equally isolated -h invocation is the
        # compatibility probe; its banner must still exactly match the pin.
        if match is None:
            return_code, rendered = self._probe_command("-h")
            match = _VERSION.search(rendered)
        if return_code != 0 or match is None:
            raise RuntimeError("pinned Binwalk container probe failed")
        if match.group("version") != self._config.expected_version:
            raise RuntimeError("pinned Binwalk container version mismatch")
        return ToolIdentity(
            name="binwalk",
            version=match.group("version"),
            image_digest=self._config.image_digest,
        )

    def extract(self, request: WorkerExtractionRequest) -> WorkerExecution:
        launcher = (
            *self._hardening_argv(),
            "--volume", "{}:/input/firmware.bin:ro".format(request.artifact_path),
            "--volume", "{}:/output:rw".format(request.destination),
            "--workdir", "/output",
            "--entrypoint", "binwalk",
            self._config.image_ref,
            "-Me", "/input/firmware.bin",
        )
        request.destination.mkdir(parents=True, exist_ok=True)
        exceeded = ""
        started = time.monotonic()
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process = subprocess.Popen(
                launcher,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
            while process.poll() is None:
                elapsed = time.monotonic() - started
                files, output_bytes = _output_usage(request.destination)
                if elapsed > request.max_seconds:
                    exceeded = "wall_time"
                elif files > request.max_output_files:
                    exceeded = "output_files"
                elif output_bytes > request.max_output_bytes:
                    exceeded = "output_bytes"
                elif (
                    stdout_file.tell() + stderr_file.tell()
                    > self._config.max_log_bytes
                ):
                    exceeded = "log_bytes"
                if exceeded:
                    _terminate_process_group(process)
                    break
                time.sleep(self._config.poll_interval_seconds)
            return_code = process.wait()
            files, output_bytes = _output_usage(request.destination)
            if not exceeded and files > request.max_output_files:
                exceeded = "output_files"
            elif not exceeded and output_bytes > request.max_output_bytes:
                exceeded = "output_bytes"
            elif (
                not exceeded
                and stdout_file.tell() + stderr_file.tell()
                > self._config.max_log_bytes
            ):
                exceeded = "log_bytes"
            if exceeded and return_code == 0:
                return_code = 125
            stdout, stderr, stdout_truncated, stderr_truncated = _read_logs_bounded(
                stdout_file, stderr_file, self._config.max_log_bytes
            )
        return WorkerExecution(
            exit_code=return_code,
            timed_out=exceeded == "wall_time",
            argv=("binwalk", "-Me", "/input/firmware.bin"),
            stdout=stdout,
            stderr=stderr,
            enforced_limits=_REQUIRED_LIMITS,
            launcher_argv=launcher,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            limit_exceeded=exceeded or None,
        )
