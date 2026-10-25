"""Hardened container profile for scanner runs (blueprint §9.3, ADR-0014).

This module is the only place that decides mounts and security options for a scanner
container, so reviewing this file is reviewing the isolation profile. It is pure: it
returns keyword arguments for Docker's ``containers.create`` and never talks to Docker.

Paths: a scanner sees each directory at the *same absolute path* the worker uses, so the
adapters' argv and env work unchanged. The worker maps those paths to host paths when it
creates the bind mounts (``DockerRunner``), because the daemon only knows host paths.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, Literal

from docker.types import Mount as DockerMount
from docker.types import Ulimit

if TYPE_CHECKING:
    from riskgraph.modules.scanners.base import ScanPaths

SCANNER_USER = "65534:65534"  # nobody
SCANNER_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
TMP_TMPFS = {"/tmp": "rw,noexec,nosuid,size=256m"}  # noqa: S108 - tmpfs inside the container
SCANNER_LABEL = "riskgraph.scanner"
SCAN_LABEL = "riskgraph.scan_id"
IMAGE_PREFIX = "riskgraph/scanner"
# Only these variables reach a scanner. Adapters set HOME/TMPDIR and their own tool knobs;
# nothing from the worker's environment is forwarded (blueprint §9.3, "Secrets").
ALLOWED_ENV = frozenset(
    {
        "HOME",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "LANG",
        "LC_ALL",
        "GIT_TERMINAL_PROMPT",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_ASKPASS",
        "SEMGREP_SEND_METRICS",
        "SEMGREP_ENABLE_VERSION_CHECK",
        "BC_SKIP_MAPPING",
        "CHECKOV_RUN_SCA_PACKAGE_SCAN_V2",  # checkov tuning: turns off its SCA package scan
        "SYFT_CHECK_FOR_APP_UPDATE",
        "TRIVY_CACHE_DIR",  # so `trivy --version` reports the DB build time (ADR-0018)
    }
)


class ContainerSpecError(ValueError):
    """The requested container would break the isolation profile. Never retried."""


Network = Literal["none", "egress"]


@dataclass(frozen=True, slots=True)
class Mount:
    """A directory the scanner may see. ``path`` is the same inside and outside."""

    path: str
    read_only: bool = False


@dataclass(frozen=True, slots=True)
class Limits:
    memory: str = "2g"
    cpus: float = 1.5
    pids: int = 512
    fsize_bytes: int = 256 * 1024 * 1024


def scanner_image(name: str, tag: str) -> str:
    return f"{IMAGE_PREFIX}-{name}:{tag}"


def _checked_path(path: str) -> str:
    p = PurePosixPath(path)
    if not p.is_absolute() or ".." in p.parts:
        raise ContainerSpecError(f"mount path must be absolute and normalised: {path!r}")
    return str(p)


def _check_env(env: Mapping[str, str]) -> dict[str, str]:
    unknown = sorted(set(env) - ALLOWED_ENV)
    if unknown:
        raise ContainerSpecError(f"environment variables not allowed in scanners: {unknown}")
    return dict(env)


def build_create_kwargs(
    *,
    image: str,
    argv: Sequence[str],
    env: Mapping[str, str],
    working_dir: str,
    mounts: Sequence[Mount],
    host_sources: Mapping[str, str],
    labels: Mapping[str, str],
    network: Network,
    egress_network: str,
    limits: Limits | None = None,
    user: str = SCANNER_USER,
) -> dict[str, Any]:
    """Keyword arguments for ``client.containers.create`` (blueprint §9.3 table)."""
    if not argv or not all(isinstance(a, str) for a in argv):
        raise ContainerSpecError("argv must be a non-empty sequence of strings")
    wd = _checked_path(working_dir)
    limits = limits or Limits()

    docker_mounts: list[DockerMount] = []
    targets: set[str] = set()
    for m in mounts:
        target = _checked_path(m.path)
        if target in targets:
            raise ContainerSpecError(f"duplicate mount target {target}")
        if target in {"/", "/var/run", "/run"} or target.startswith(
            ("/var/run/docker", "/run/docker")
        ):
            raise ContainerSpecError(f"mount target not allowed: {target}")
        source = host_sources.get(target)
        if source is None:
            raise ContainerSpecError(f"no host source for mount {target}")
        targets.add(target)
        docker_mounts.append(
            DockerMount(
                target=target,
                source=_checked_path(source),
                type="bind",
                read_only=m.read_only,
            )
        )
    # The working directory may be any directory under a mount (git runs in the checkout,
    # which sits under the workspace mount).
    if not any(wd == t or wd.startswith(t + "/") for t in targets):
        raise ContainerSpecError("working directory must be inside a mounted path")

    if network == "none":
        network_mode = "none"
    elif network == "egress":
        network_mode = egress_network
    else:  # pragma: no cover - guarded by the Literal type
        raise ContainerSpecError(f"unknown network mode {network!r}")

    return {
        "image": image,
        "command": list(argv),
        "environment": _check_env(env),  # PATH comes from the image, not from the worker
        "working_dir": wd,
        "user": user,
        "mounts": docker_mounts,
        "network_mode": network_mode,
        "read_only": True,
        "tmpfs": dict(TMP_TMPFS),
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "mem_limit": limits.memory,
        "memswap_limit": limits.memory,
        "nano_cpus": int(limits.cpus * 1_000_000_000),
        "pids_limit": limits.pids,
        "ulimits": [
            Ulimit(name="core", soft=0, hard=0),
            Ulimit(name="fsize", soft=limits.fsize_bytes, hard=limits.fsize_bytes),
        ],
        "labels": dict(labels),
        "detach": True,
        "tty": False,
        "stdin_open": False,
        "auto_remove": False,
    }


def scanner_mounts(name: str, src: str, out: str, home: str, cache: str) -> tuple[Mount, ...]:
    """What a scanner container may see. Source is read-only; output and HOME are writable;
    only Trivy also gets the shared DB cache (blueprint §9.3). Nothing else is mounted."""
    mounts = [Mount(src, read_only=True), Mount(out), Mount(home)]
    if name == "trivy":
        mounts.append(Mount(cache))
    return tuple(mounts)


def container_fields(
    name: str, image_tag: str, paths: ScanPaths, labels: Mapping[str, str]
) -> dict[str, Any]:
    """Image, mounts and labels for a scanner RunSpec. The subprocess runner ignores them."""
    return {
        "image": scanner_image(name, image_tag),
        "mounts": scanner_mounts(
            name, str(paths.src), str(paths.out), str(paths.home), str(paths.cache)
        ),
        "labels": dict(labels),
    }
