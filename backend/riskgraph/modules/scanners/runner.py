"""Run a scanner (or ``git``) as a child process (ADR-0009).

Rules, all enforced here so adapters cannot get them wrong:
- argv is a sequence, never a string; no shell is ever involved.
- the binary is resolved to an absolute path from a fixed search path.
- the environment is an allow-list: nothing from the worker leaks in (database URL,
  secret key, Redis password), except proxy/CA variables for commands that need egress.
- stdin is closed; stdout/stderr go to files; the child gets its own process group and
  is killed as a group on timeout; core dumps are off and file sizes are capped.

Residual risk (documented in ADR-0009): the child runs as the worker's uid, so it is not
a sandbox. The blueprint's DockerRunner replaces this before any non-localhost use.
"""

from __future__ import annotations

import contextlib
import os
import resource
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from riskgraph.modules.scanners.base import Network
from riskgraph.modules.scanners.containers import Mount

SYSTEM_PATH = ("/usr/local/bin", "/usr/bin", "/bin")
EGRESS_ENV = (
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
)
STDERR_TAIL_BYTES = 4096
DEFAULT_FSIZE_LIMIT = 256 * 1024 * 1024
# argv[0] alias for RiskGraph's own interpreter (helpers such as the reachability
# extractor). It is the only name that resolves to something outside the search path.
SELF_PYTHON = "riskgraph-python"


@dataclass(frozen=True, slots=True)
class RunSpec:
    argv: Sequence[str]
    cwd: Path
    log_dir: Path
    timeout_s: int
    network: Network = "none"
    env: Mapping[str, str] = field(default_factory=dict)
    fsize_limit: int = DEFAULT_FSIZE_LIMIT
    log_name: str = "run"
    memory_limit: int | None = None  # RLIMIT_AS bytes (parsers of untrusted input)
    # Container runner only (ignored by SubprocessRunner): the image to run, the paths
    # to mount (same path inside, see containers.py), and labels for cancel and cleanup.
    image: str | None = None
    mounts: tuple[Mount, ...] = ()
    user: str | None = None  # container uid:gid; None means the scanner default (nobody)
    labels: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RunResult:
    exit_code: int | None
    timed_out: bool
    duration_ms: int
    stderr_tail: str
    missing_binary: bool = False


class ScannerRunner(Protocol):
    def run(self, spec: RunSpec) -> RunResult: ...


class SubprocessRunner:
    def __init__(self, bin_dir: Path, system_path: Sequence[str] = SYSTEM_PATH) -> None:
        self._search_path = os.pathsep.join([str(bin_dir), *system_path])

    def resolve(self, name: str) -> str | None:
        if name == SELF_PYTHON:
            return sys.executable
        if os.sep in name:
            return None  # only bare tool names; never a path chosen elsewhere
        return shutil.which(name, path=self._search_path)

    def build_env(self, spec: RunSpec) -> dict[str, str]:
        env = {"PATH": self._search_path, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        if spec.network == "egress":
            env.update({k: os.environ[k] for k in EGRESS_ENV if k in os.environ})
        env.update(spec.env)
        return env

    def run(self, spec: RunSpec) -> RunResult:
        if isinstance(spec.argv, str | bytes):
            raise TypeError("argv must be a sequence of arguments, never a string")
        argv = [str(a) for a in spec.argv]
        binary = self.resolve(argv[0])
        if binary is None:
            return RunResult(None, False, 0, f"{argv[0]}: binary not installed", True)
        argv[0] = binary

        spec.log_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = spec.log_dir / f"{spec.log_name}.stdout.log"
        stderr_path = spec.log_dir / f"{spec.log_name}.stderr.log"
        limits = _rlimits(spec.timeout_s, spec.fsize_limit, spec.memory_limit)
        started = time.monotonic()
        timed_out = False
        with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
            proc = subprocess.Popen(  # noqa: S603 - argv list, resolved binary, no shell
                argv,
                cwd=spec.cwd,
                env=self.build_env(spec),
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                close_fds=True,
                start_new_session=True,
                preexec_fn=limits,
            )
            try:
                exit_code: int | None = proc.wait(timeout=spec.timeout_s)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_group(proc)
                exit_code = None
        duration_ms = int((time.monotonic() - started) * 1000)
        return RunResult(exit_code, timed_out, duration_ms, _tail(stderr_path))


def _rlimits(timeout_s: int, fsize_limit: int, memory_limit: int | None):  # type: ignore[no-untyped-def]
    cpu = max(60, timeout_s * 2)

    def apply() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if memory_limit is not None:
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_limit, fsize_limit))

    return apply


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGKILL)
    proc.wait()


def _tail(path: Path) -> str:
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            fh.seek(max(0, size - STDERR_TAIL_BYTES))
            data = fh.read()
    except OSError:
        return ""
    text = data.decode("utf-8", "replace")
    return "".join(ch for ch in text if ch.isprintable() or ch in "\n\t")
