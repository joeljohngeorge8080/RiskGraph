"""Run scanners as hardened containers (blueprint §9.2-9.3, ADR-0014).

``DockerRunner`` implements the same ``ScannerRunner`` protocol as ``SubprocessRunner``,
so the pipeline does not change. The worker reaches the daemon only through
``docker-socket-proxy`` (blueprint §9.3, "Trusted side").

Path mapping: scanner paths are worker-side paths (``/var/lib/riskgraph/...``). The
daemon binds *host* paths, so each root is mapped to the host directory that backs it.
Roots are configured by the operator (``RISKGRAPH_HOST_DATA_DIR``), never derived from
scanner output.
"""

from __future__ import annotations

import contextlib
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

import docker
from docker.errors import APIError, DockerException, ImageNotFound, NotFound

from riskgraph.modules.scanners.containers import (
    SCAN_LABEL,
    SCANNER_LABEL,
    ContainerSpecError,
    Limits,
    Mount,
    build_create_kwargs,
)
from riskgraph.modules.scanners.runner import RunResult, RunSpec
from riskgraph.modules.scanners.slots import SlotLimiter, SlotTimeoutError
from riskgraph.shared.logging import get_logger

log = get_logger(__name__)
LOG_CAP_BYTES = 1024 * 1024
TAIL_BYTES = 4096
WAIT_POLL_S = 0.5


@dataclass(frozen=True, slots=True)
class PathRoot:
    """A worker-side directory tree and the host directory that backs it."""

    container_root: str  # the worker's view, also the path inside the scanner
    host_root: str  # the daemon's view


class _Containers(Protocol):
    def create(self, **kwargs: Any) -> Any: ...
    def list(self, **kwargs: Any) -> list[Any]: ...


class _Images(Protocol):
    def get(self, name: str) -> Any: ...


class DockerClient(Protocol):
    containers: _Containers
    images: _Images


class DockerRunner:
    def __init__(
        self,
        client: DockerClient,
        roots: Sequence[PathRoot],
        egress_network: str,
        slots: SlotLimiter | None = None,
        slot_wait_s: float = 600,
    ) -> None:
        self._client = client
        self._roots = sorted(roots, key=lambda r: len(r.container_root), reverse=True)
        self._egress_network = egress_network
        self._slots = slots
        self._slot_wait_s = slot_wait_s

    @classmethod
    def from_env(
        cls,
        roots: Sequence[PathRoot],
        egress_network: str,
        slots: SlotLimiter | None = None,
    ) -> DockerRunner:
        """Connect via ``DOCKER_HOST`` (the socket proxy in compose)."""
        return cls(docker.from_env(timeout=30), roots, egress_network, slots)

    def host_path(self, path: str) -> str:
        p = PurePosixPath(path)
        for root in self._roots:
            base = PurePosixPath(root.container_root)
            if p == base or base in p.parents:
                return str(PurePosixPath(root.host_root) / p.relative_to(base))
        raise ContainerSpecError(f"path is outside every configured root: {path}")

    def run(self, spec: RunSpec) -> RunResult:
        if spec.image is None:
            return RunResult(None, False, 0, "no scanner image configured", True)
        if isinstance(spec.argv, str | bytes):
            raise TypeError("argv must be a sequence of arguments, never a string")
        argv = [str(a) for a in spec.argv]
        try:
            self._client.images.get(spec.image)
        except ImageNotFound:
            return RunResult(None, False, 0, f"image {spec.image} is not built", True)
        except DockerException as exc:
            return RunResult(None, False, 0, f"docker unavailable: {type(exc).__name__}", True)

        try:
            host_sources = {m.path: self.host_path(m.path) for m in spec.mounts}
            kwargs = build_create_kwargs(
                image=spec.image,
                argv=argv,
                env=spec.env,
                working_dir=str(spec.cwd),
                mounts=spec.mounts,
                host_sources=host_sources,
                labels={**spec.labels, SCANNER_LABEL: spec.log_name},
                network=spec.network,
                egress_network=self._egress_network,
                limits=Limits(fsize_bytes=spec.fsize_limit),
                **({"user": spec.user} if spec.user else {}),
            )
        except ContainerSpecError as exc:
            return RunResult(None, False, 0, f"refused: {exc}", True)

        started = time.monotonic()
        spec.log_dir.mkdir(parents=True, exist_ok=True)
        try:
            if self._slots is None:
                return self._execute(kwargs, spec, started)
            with self._slots.slot(self._slot_wait_s):
                return self._execute(kwargs, spec, started)
        except SlotTimeoutError:
            return RunResult(None, False, 0, "no scanner slot became free in time")

    def _execute(self, kwargs: dict[str, Any], spec: RunSpec, started: float) -> RunResult:
        timed_out = False
        container = None
        try:
            container = self._client.containers.create(**kwargs)
            container.start()
            exit_code = self._wait(container, spec.timeout_s)
            if exit_code is None:
                timed_out = True
                with contextlib.suppress(APIError):
                    container.kill()
            stdout = container.logs(stdout=True, stderr=False)
            stderr = container.logs(stdout=False, stderr=True)
        except DockerException as exc:
            return RunResult(
                None,
                False,
                int((time.monotonic() - started) * 1000),
                f"docker error: {type(exc).__name__}: {str(exc)[:300]}",
                True,
            )
        finally:
            if container is not None:
                with contextlib.suppress(APIError, NotFound):
                    container.remove(force=True)

        _write_capped(spec.log_dir / f"{spec.log_name}.stdout.log", stdout)
        _write_capped(spec.log_dir / f"{spec.log_name}.stderr.log", stderr)
        tail = _printable(stderr[-TAIL_BYTES:])
        duration_ms = int((time.monotonic() - started) * 1000)
        return RunResult(exit_code, timed_out, duration_ms, tail)

    @staticmethod
    def _wait(container: Any, timeout_s: float) -> int | None:
        """Poll state instead of ``wait(timeout=)``: the SDK surfaces a read timeout as a
        generic ConnectionError, so polling is the only unambiguous way to time out."""
        deadline = time.monotonic() + timeout_s
        while True:
            container.reload()
            state = container.attrs.get("State", {})
            if state.get("Status") in {"exited", "dead"}:
                return int(state.get("ExitCode", -1))
            if time.monotonic() >= deadline:
                return None
            time.sleep(WAIT_POLL_S)

    def kill_scan(self, scan_id: uuid.UUID) -> int:
        """Kill every scanner container of one scan (cancel). Returns how many."""
        killed = 0
        for c in self._client.containers.list(filters={"label": f"{SCAN_LABEL}={scan_id}"}):
            with contextlib.suppress(APIError, NotFound):
                c.kill()
                killed += 1
        log.info("scan_containers_killed", scan_id=str(scan_id), count=killed)
        return killed


def _write_capped(path: Any, data: bytes) -> None:
    path.write_bytes(data[:LOG_CAP_BYTES])


def _printable(data: bytes) -> str:
    text = data.decode("utf-8", "replace")
    return "".join(ch for ch in text if ch.isprintable() or ch in "\n\t")


# Runs inside a scanner container as nobody (65534). Files a scanner wrote are owned by that
# uid, so only it can open their directories for deletion; widening modes here lets the
# worker (a different uid) remove the workspace afterwards. Errors are ignored: whatever
# cannot be changed is reported by the removal that follows.
MAKE_REMOVABLE = """
import os, sys
for d, dirs, files in os.walk(sys.argv[1]):
    for n in files:
        try:
            os.chmod(os.path.join(d, n), 0o666)
        except OSError:
            pass
    try:
        os.chmod(d, 0o777)
    except OSError:
        pass
"""


def make_removable(runner: DockerRunner, root: str, image: str, log_dir: Any) -> RunResult:
    """Widen the modes under ``root`` so the worker can delete it (see MAKE_REMOVABLE)."""
    return runner.run(
        RunSpec(
            ("python3", "-c", MAKE_REMOVABLE, root),
            cwd=Path(root),
            log_dir=log_dir,
            timeout_s=120,
            network="none",
            env={"HOME": f"{root}/.fixup"},
            log_name="fixup",
            image=image,
            mounts=(Mount(root),),
        )
    )
