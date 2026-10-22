"""DockerRunner against a fake daemon: the control flow, not Docker itself (ADR-0014).

The real daemon is exercised by ``test_docker_live.py`` (marker ``docker``).
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest
from docker.errors import ImageNotFound
from riskgraph.modules.scanners import RunSpec
from riskgraph.modules.scanners.containers import Mount
from riskgraph.modules.scanners.docker_runner import DockerRunner, PathRoot


class FakeContainer:
    def __init__(self, kwargs: dict[str, Any], exit_code: int, *, hang: bool = False) -> None:
        self.kwargs = kwargs
        self.attrs: dict[str, Any] = {"State": {"Status": "created"}}
        self._exit = exit_code
        self._hang = hang
        self.killed = False
        self.removed = False

    def start(self) -> None:
        self.attrs["State"] = {"Status": "running"}

    def reload(self) -> None:
        if not self._hang and self.attrs["State"]["Status"] == "running":
            self.attrs["State"] = {"Status": "exited", "ExitCode": self._exit}

    def kill(self) -> None:
        self.killed = True
        self.attrs["State"] = {"Status": "exited", "ExitCode": 137}

    def logs(self, stdout: bool = True, stderr: bool = False) -> bytes:
        return b"scan out\n" if stdout else b"scanner warning\n"

    def remove(self, force: bool = False) -> None:
        self.removed = True


class FakeContainers:
    def __init__(self, exit_code: int = 0, hang: bool = False) -> None:
        self.created: list[FakeContainer] = []
        self.exit_code = exit_code
        self.hang = hang
        self.listed_filters: list[dict[str, Any]] = []
        self.to_list: list[FakeContainer] = []

    def create(self, **kwargs: Any) -> FakeContainer:
        c = FakeContainer(kwargs, self.exit_code, hang=self.hang)
        self.created.append(c)
        return c

    def list(self, filters: dict[str, Any] | None = None, **_: Any) -> list[FakeContainer]:
        self.listed_filters.append(filters or {})
        return self.to_list


class FakeImages:
    def __init__(self, present: bool = True) -> None:
        self.present = present

    def get(self, name: str) -> object:
        if not self.present:
            raise ImageNotFound(f"no image {name}")
        return object()


class FakeClient:
    def __init__(
        self, *, images: FakeImages | None = None, exit_code: int = 0, hang: bool = False
    ) -> None:
        self.images = images or FakeImages()
        self.containers = FakeContainers(exit_code, hang)


ROOT = "/var/lib/riskgraph"
HOST = "/var/lib/docker/volumes/riskgraph-data/_data"


def _runner(client: FakeClient, slots: Any = None) -> DockerRunner:
    return DockerRunner(
        client,  # type: ignore[arg-type]
        [PathRoot(ROOT, HOST)],
        "riskgraph_egress",
        slots=slots,
    )


def _spec(
    tmp_path: Path,
    *,
    timeout_s: int = 30,
    env: dict[str, str] | None = None,
    image: str | None = "riskgraph/scanner-gitleaks:8.30.1",
) -> RunSpec:
    src = f"{ROOT}/workspaces/a/src"
    return RunSpec(
        ("gitleaks", "detect"),
        Path(src),
        tmp_path / "logs",
        timeout_s,
        "none",
        env if env is not None else {"HOME": f"{ROOT}/workspaces/a/home/gitleaks"},
        image=image,
        mounts=(Mount(src, read_only=True),),
        labels={"riskgraph.scan_id": "a"},
        log_name="scan",
    )


def test_paths_are_mapped_to_the_host_volume(tmp_path: Path) -> None:
    runner = _runner(FakeClient())
    assert runner.host_path(f"{ROOT}/workspaces/a/src") == f"{HOST}/workspaces/a/src"
    with pytest.raises(Exception, match="outside every configured root"):
        runner.host_path("/etc/passwd")


def test_a_successful_run_writes_logs_and_removes_the_container(tmp_path: Path) -> None:
    client = FakeClient()
    result = _runner(client).run(_spec(tmp_path))
    assert result.exit_code == 0 and not result.timed_out and not result.missing_binary
    (container,) = client.containers.created
    assert container.kwargs["network_mode"] == "none"
    assert container.kwargs["mounts"][0]["Source"] == f"{HOST}/workspaces/a/src"
    assert container.removed
    assert (tmp_path / "logs" / "scan.stdout.log").read_text() == "scan out\n"
    assert result.stderr_tail == "scanner warning\n"


def test_a_missing_image_is_a_failure_not_an_exception(tmp_path: Path) -> None:
    client = FakeClient(images=FakeImages(present=False))
    result = _runner(client).run(_spec(tmp_path))
    assert result.missing_binary and "is not built" in result.stderr_tail
    assert client.containers.created == []


def test_no_image_configured_is_refused(tmp_path: Path) -> None:
    result = _runner(FakeClient()).run(_spec(tmp_path, image=None))
    assert result.missing_binary


def test_a_hung_container_is_killed_at_the_timeout(tmp_path: Path) -> None:
    client = FakeClient(hang=True)
    result = _runner(client).run(_spec(tmp_path, timeout_s=0))
    assert result.timed_out and result.exit_code is None
    (container,) = client.containers.created
    assert container.killed and container.removed


def test_a_profile_violation_never_reaches_the_daemon(tmp_path: Path) -> None:
    client = FakeClient()
    spec = _spec(tmp_path, env={"RISKGRAPH_DATABASE_URL": "x"})
    result = _runner(client).run(spec)
    assert result.missing_binary and "refused" in result.stderr_tail
    assert client.containers.created == []


def test_kill_scan_filters_by_scan_label() -> None:
    client = FakeClient()
    victim = FakeContainer({}, 0)
    client.containers.to_list = [victim]
    scan_id = uuid.uuid4()
    assert _runner(client).kill_scan(scan_id) == 1
    assert client.containers.listed_filters == [{"label": f"riskgraph.scan_id={scan_id}"}]
    assert victim.killed is True
