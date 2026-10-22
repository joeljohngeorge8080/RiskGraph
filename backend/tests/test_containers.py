"""The isolation profile (blueprint §9.3, ADR-0014). Pure: no Docker needed."""

from __future__ import annotations

import pytest
from riskgraph.modules.scanners.containers import (
    SCANNER_USER,
    ContainerSpecError,
    Limits,
    Mount,
    build_create_kwargs,
    scanner_image,
    scanner_mounts,
)

SRC = "/var/lib/riskgraph/workspaces/x/src"
OUT = "/var/lib/riskgraph/workspaces/x/out/trivy"
HOME = "/var/lib/riskgraph/workspaces/x/home/trivy"
HOSTS = {
    SRC: "/host/data/workspaces/x/src",
    OUT: "/host/data/workspaces/x/out/trivy",
    HOME: "/host/home",
}


def _kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "image": scanner_image("trivy", "0.76.0"),
        "argv": ("trivy", "fs", "."),
        "env": {"HOME": HOME, "TMPDIR": HOME + "/tmp"},  # noqa: S108
        "working_dir": SRC,
        "mounts": (Mount(SRC, read_only=True), Mount(OUT), Mount(HOME)),
        "host_sources": HOSTS,
        "labels": {"riskgraph.scan_id": "x"},
        "network": "none",
        "egress_network": "riskgraph_egress",
    }
    base.update(overrides)
    return base


def test_profile_is_the_blueprint_profile() -> None:
    kw = build_create_kwargs(**_kwargs())  # type: ignore[arg-type]
    assert kw["user"] == SCANNER_USER == "65534:65534"
    assert kw["read_only"] is True
    assert kw["cap_drop"] == ["ALL"]
    assert kw["security_opt"] == ["no-new-privileges:true"]
    assert kw["network_mode"] == "none"
    assert kw["mem_limit"] == "2g" and kw["pids_limit"] == 512
    assert kw["nano_cpus"] == 1_500_000_000
    assert kw["tmpfs"] == {"/tmp": "rw,noexec,nosuid,size=256m"}  # noqa: S108


def test_mounts_keep_the_worker_path_and_the_read_only_flag() -> None:
    kw = build_create_kwargs(**_kwargs())  # type: ignore[arg-type]
    by_target = {m["Target"]: m for m in kw["mounts"]}  # type: ignore[attr-defined,union-attr]
    assert by_target[SRC]["Source"] == HOSTS[SRC]
    assert by_target[SRC]["ReadOnly"] is True
    assert by_target[OUT]["ReadOnly"] is False


def test_egress_uses_the_named_network_only() -> None:
    kw = build_create_kwargs(**_kwargs(network="egress"))  # type: ignore[arg-type]
    assert kw["network_mode"] == "riskgraph_egress"


def test_the_socket_is_never_mountable() -> None:
    hosts = {**HOSTS, "/var/run/docker.sock": "/var/run/docker.sock"}
    with pytest.raises(ContainerSpecError):
        build_create_kwargs(  # type: ignore[arg-type]
            **_kwargs(
                mounts=(Mount(SRC, read_only=True), Mount("/var/run/docker.sock")),
                host_sources=hosts,
            )
        )


@pytest.mark.parametrize("bad", ["relative/path", "/a/../etc", "/"])
def test_mount_paths_must_be_absolute_and_normalised(bad: str) -> None:
    with pytest.raises(ContainerSpecError):
        build_create_kwargs(**_kwargs(mounts=(Mount(bad),), working_dir=bad))  # type: ignore[arg-type]


def test_every_mount_needs_a_host_source() -> None:
    with pytest.raises(ContainerSpecError, match="no host source"):
        build_create_kwargs(**_kwargs(host_sources={SRC: HOSTS[SRC]}))  # type: ignore[arg-type]


def test_working_directory_must_be_mounted() -> None:
    with pytest.raises(ContainerSpecError, match="working directory"):
        build_create_kwargs(**_kwargs(working_dir="/usr"))  # type: ignore[arg-type]


def test_worker_secrets_are_not_forwarded() -> None:
    with pytest.raises(ContainerSpecError, match="not allowed"):
        build_create_kwargs(  # type: ignore[arg-type]
            **_kwargs(env={"RISKGRAPH_DATABASE_URL": "postgresql://leak", "HOME": HOME})
        )


def test_duplicate_targets_are_refused() -> None:
    with pytest.raises(ContainerSpecError, match="duplicate"):
        build_create_kwargs(**_kwargs(mounts=(Mount(SRC), Mount(SRC))))  # type: ignore[arg-type]


def test_argv_must_be_a_list_of_strings() -> None:
    with pytest.raises(ContainerSpecError):
        build_create_kwargs(**_kwargs(argv=()))  # type: ignore[arg-type]


def test_fetcher_user_override_and_fsize_limit() -> None:
    kw = build_create_kwargs(  # type: ignore[arg-type]
        **_kwargs(user="1000:1000", limits=Limits(fsize_bytes=1234))
    )
    assert kw["user"] == "1000:1000"
    fsize = next(u for u in kw["ulimits"] if u["Name"] == "fsize")  # type: ignore[attr-defined,union-attr]
    assert fsize["Soft"] == 1234


def test_scanner_mounts_give_trivy_the_cache_and_nobody_else() -> None:
    trivy = scanner_mounts("trivy", SRC, OUT, HOME, "/cache")
    assert [m.path for m in trivy] == [SRC, OUT, HOME, "/cache"]
    semgrep = scanner_mounts("semgrep", SRC, OUT, HOME, "/cache")
    assert [m.path for m in semgrep] == [SRC, OUT, HOME]
    assert semgrep[0].read_only is True


def test_working_directory_may_be_below_a_mount() -> None:
    kw = build_create_kwargs(**_kwargs(working_dir=SRC + "/nested/dir"))  # type: ignore[arg-type]
    assert kw["working_dir"] == SRC + "/nested/dir"


def test_working_directory_must_not_be_a_sibling_of_a_mount() -> None:
    with pytest.raises(ContainerSpecError, match="working directory"):
        build_create_kwargs(**_kwargs(working_dir=SRC + "x"))  # type: ignore[arg-type]
