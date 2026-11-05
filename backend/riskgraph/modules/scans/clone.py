"""Shallow, hook-free clone of a public GitHub repository (threats T-03, T-05, T-13)."""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from typing import Any, Protocol

from riskgraph.modules.scanners import RunSpec, ScannerRunner
from riskgraph.modules.scanners.containers import SCAN_LABEL, Mount
from riskgraph.modules.scans.workspace import ScanWorkspace, WorkspaceError
from riskgraph.shared.config import Settings

_SAFE_CONFIG = (
    "core.hooksPath=/dev/null",
    "core.symlinks=false",
    "core.fsmonitor=false",
    "protocol.allow=never",
    "protocol.https.allow=always",
    "credential.helper=",
    "http.followRedirects=false",
    "submodule.recurse=false",
)
_SHA = re.compile(r"^[0-9a-f]{40}$")
_NOT_FOUND_MARKERS = ("not found", "could not read username", "authentication failed")


class CloneError(Exception):
    """Clone failed; the message is safe to show to the user."""


@dataclass(frozen=True, slots=True)
class CloneResult:
    commit_sha: str
    bytes: int
    files: int


class Cloner(Protocol):
    def clone(self, ws: ScanWorkspace, clone_url: str, ref: str) -> CloneResult: ...


def build_clone_argv(clone_url: str, ref: str, dest: str) -> tuple[str, ...]:
    argv: list[str] = ["git"]
    for item in _SAFE_CONFIG:
        argv += ["-c", item]
    argv += ["clone", "--depth", "1", "--single-branch", "--no-recurse-submodules", "--quiet"]
    if ref:
        argv += ["--branch", ref]
    argv += ["--", clone_url, dest]
    return tuple(argv)


def git_env(home: str) -> dict[str, str]:
    return {
        "HOME": home,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ASKPASS": "/bin/false",
    }


class GitCloner:
    """Clones with git. With the container runner it runs in ``image`` (git-fetcher, the
    only egress container, ADR-0014) and writes only the scan workspace."""

    def __init__(self, runner: ScannerRunner, settings: Settings, image: str | None = None) -> None:
        self._runner = runner
        self._settings = settings
        self._image = image

    def _container_fields(self, ws: ScanWorkspace) -> dict[str, Any]:
        if self._image is None:
            return {}
        # The fetcher runs as the worker's uid so cleanup can remove what it wrote.
        return {
            "image": self._image,
            "mounts": (Mount(str(ws.path)),),
            "labels": {SCAN_LABEL: ws.path.name},
            "user": f"{os.getuid()}:{os.getgid()}",
        }

    def clone(self, ws: ScanWorkspace, clone_url: str, ref: str) -> CloneResult:
        ws.prepare_tool("git")
        env = git_env(str(ws.home("git")))
        fields = self._container_fields(ws)
        result = self._runner.run(
            RunSpec(
                build_clone_argv(clone_url, ref, str(ws.src)),
                cwd=ws.path,
                log_dir=ws.logs("git"),
                timeout_s=self._settings.clone_timeout_s,
                network="egress",
                env=env,
                fsize_limit=self._settings.clone_max_bytes,
                log_name="clone",
                **fields,
            )
        )
        if result.missing_binary:
            raise CloneError("git is not installed on the worker")
        if result.timed_out:
            raise CloneError("clone timed out")
        if result.exit_code != 0:
            tail = result.stderr_tail.lower()
            if any(m in tail for m in _NOT_FOUND_MARKERS):
                raise CloneError("repository not found or not public")
            if "remote branch" in tail and "not found" in tail:
                raise CloneError("branch or tag not found")
            raise CloneError(f"clone failed (git exit {result.exit_code})")

        rev = self._runner.run(
            RunSpec(
                ("git", "rev-parse", "HEAD"),
                cwd=ws.src,
                log_dir=ws.logs("git"),
                timeout_s=30,
                env=env,
                log_name="rev-parse",
                **fields,
            )
        )
        if rev.exit_code != 0 or rev.missing_binary:
            raise CloneError(f"could not determine the cloned commit: {rev.stderr_tail[-200:]}")
        sha = (ws.logs("git") / "rev-parse.stdout.log").read_text().strip()
        if not _SHA.match(sha):
            raise CloneError("could not determine the cloned commit")
        # Scanners never see git internals (hooks, config, packed history).
        shutil.rmtree(ws.src / ".git", ignore_errors=True)
        try:
            size, files = ws.measure(self._settings.clone_max_bytes, self._settings.clone_max_files)
        except WorkspaceError as exc:
            raise CloneError(str(exc)) from exc
        ws.make_readonly()
        return CloneResult(sha, size, files)
