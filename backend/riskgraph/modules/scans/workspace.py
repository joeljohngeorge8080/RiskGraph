"""Per-scan workspace on disk (blueprint §8, threat T-13).

    <workspace_root>/<scan_id>/src/                 the clone (read-only after cloning)
    <workspace_root>/<scan_id>/out/<scanner>/       raw scanner output (deleted by collect)
    <workspace_root>/<scan_id>/home/<scanner>/      HOME and TMPDIR for one tool
    <workspace_root>/<scan_id>/logs/<scanner>/      stdout/stderr of one tool

Every path is derived from settings and a validated UUID; nothing from a request or a
scanner report ever selects a directory.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import shutil
import stat
import uuid
from pathlib import Path

MAX_SNIPPET_FILE_BYTES = 2 * 1024 * 1024
_WS = re.compile(r"\s+")


class WorkspaceError(Exception):
    pass


class ScanWorkspace:
    def __init__(self, workspace_root: Path, scan_id: uuid.UUID) -> None:
        if not isinstance(scan_id, uuid.UUID):
            raise TypeError("scan_id must be a UUID")
        self.root_dir = workspace_root.resolve()
        self.path = self.root_dir / str(scan_id)

    @property
    def src(self) -> Path:
        return self.path / "src"

    def out(self, scanner: str) -> Path:
        return self.path / "out" / scanner

    def home(self, scanner: str) -> Path:
        return self.path / "home" / scanner

    def logs(self, scanner: str) -> Path:
        return self.path / "logs" / scanner

    def prepare_tool(self, tool: str) -> None:
        for d in (self.out(tool), self.home(tool) / "tmp", self.logs(tool)):
            d.mkdir(parents=True, exist_ok=True)
        # Writable by the scanner's uid (65534) in the container runner; see create().
        for d in (self.out(tool), self.home(tool), self.home(tool) / "tmp"):
            d.chmod(0o777)

    def create(self) -> None:
        if self.path.exists():
            self.cleanup()
        # 0711: the scanner runs as nobody (65534) and must traverse this directory; it can
        # enter it but not list it. Every scan path is a random UUID (blueprint §9.3).
        self.path.mkdir(parents=True, mode=0o711)
        self.path.chmod(0o711)

    def measure(self, max_bytes: int, max_files: int) -> tuple[int, int]:
        """Size and file count of ``src`` (symlinks are not followed)."""
        total = files = 0
        for dirpath, dirnames, filenames in os.walk(self.src, followlinks=False):
            if ".git" in dirnames and Path(dirpath) == self.src:
                dirnames.remove(".git")
            for name in filenames:
                files += 1
                try:
                    total += os.lstat(os.path.join(dirpath, name)).st_size
                except OSError:
                    continue
                if total > max_bytes or files > max_files:
                    raise WorkspaceError("repository exceeds the size or file-count limit")
        return total, files

    def make_readonly(self) -> None:
        for dirpath, dirnames, filenames in os.walk(self.src, followlinks=False):
            for name in filenames + dirnames:
                p = os.path.join(dirpath, name)
                if not os.path.islink(p):
                    mode = os.lstat(p).st_mode
                    os.chmod(p, mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        os.chmod(self.src, 0o555)  # noqa: S103 - read+traverse only; owner is the worker

    def safe_resolve(self, relative: str) -> Path | None:
        """Resolve a scanner-reported path inside ``src`` or return None (never raises)."""
        if not relative or relative.startswith("<") or "\x00" in relative:
            return None
        try:
            candidate = (self.src / relative).resolve(strict=True)
        except (OSError, RuntimeError):
            return None
        src = self.src.resolve()
        if not candidate.is_relative_to(src) or not candidate.is_file():
            return None
        return candidate

    def snippet_sha256(self, relative: str, start: int | None, end: int | None) -> str | None:
        """Hash of the whitespace-collapsed matched lines (SAST fingerprint, §10.2)."""
        if start is None:
            return None
        path = self.safe_resolve(relative)
        if path is None:
            return None
        try:
            if path.stat().st_size > MAX_SNIPPET_FILE_BYTES:
                return None
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None
        chunk = " ".join(lines[max(0, start - 1) : (end or start)])
        collapsed = _WS.sub(" ", chunk).strip()
        return hashlib.sha256(collapsed.encode()).hexdigest() if collapsed else None

    def remove_dir(self, path: Path) -> None:
        if path.exists() and path.resolve().is_relative_to(self.path):
            shutil.rmtree(path, onexc=_force_writable)

    def cleanup(self) -> None:
        target = self.path.resolve()
        if target.parent != self.root_dir:
            raise WorkspaceError("refusing to delete outside the workspace root")
        if target.exists():
            shutil.rmtree(target, onexc=_force_writable)


def _force_writable(func, path, _exc):  # type: ignore[no-untyped-def]
    """Make a read-only tree removable. Directories a scanner container wrote are already
    world-writable (discard_workspace widens them first) and belong to another uid, so a
    chmod there is refused; that is fine, the removal below still goes ahead."""
    parent = os.path.dirname(path)
    with contextlib.suppress(OSError):
        os.chmod(parent, 0o700)
    if os.path.isdir(path) and not os.path.islink(path):
        with contextlib.suppress(OSError):
            os.chmod(path, 0o700)
    if func not in (os.unlink, os.rmdir):
        raise _exc  # a failed open/scan cannot be fixed by retrying it: report it
    func(path)


def widen_own_directories(root: Path) -> None:
    """Worker-side pass: make every directory the worker owns world-writable, so a scanner
    uid can delete entries in it (blueprint §9.3, cleanup). Others' directories are left
    to the scanner's own fixup pass; a refusal there is not an error."""
    uid = os.getuid()
    for dirpath, dirnames, _filenames in os.walk(root, followlinks=False):
        for name in dirnames:
            full = os.path.join(dirpath, name)
            with contextlib.suppress(OSError):
                if os.lstat(full).st_uid == uid:
                    os.chmod(full, 0o777)  # noqa: S103 - the scanner uid must write here (UUID-scoped)
        with contextlib.suppress(OSError):
            if os.lstat(dirpath).st_uid == uid:
                os.chmod(dirpath, 0o777)  # noqa: S103 - as above
