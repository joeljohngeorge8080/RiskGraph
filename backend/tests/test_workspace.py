from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from riskgraph.modules.scans.storage import report_path
from riskgraph.modules.scans.workspace import ScanWorkspace, WorkspaceError
from riskgraph.shared.vocabulary import ScannerName


@pytest.fixture()
def ws(tmp_path: Path) -> ScanWorkspace:
    w = ScanWorkspace(tmp_path / "workspaces", uuid.uuid4())
    w.create()
    w.src.mkdir()
    (w.src / "app.py").write_text("a = 1\n  b   =  2\nc = 3\n")
    (tmp_path / "secret.txt").write_text("outside")
    (w.src / "link").symlink_to(tmp_path / "secret.txt")
    return w


def test_safe_resolve_stays_inside_src(ws: ScanWorkspace) -> None:
    assert ws.safe_resolve("app.py") == (ws.src / "app.py").resolve()
    for evil in ("../../secret.txt", "/etc/passwd", "link", "<invalid-path>", "", "a\x00b"):
        assert ws.safe_resolve(evil) is None


def test_snippet_hash_ignores_whitespace(ws: ScanWorkspace) -> None:
    first = ws.snippet_sha256("app.py", 2, 2)
    (ws.src / "app.py").write_text("a = 1\nb = 2\nc = 3\n")
    assert ws.snippet_sha256("app.py", 2, 2) == first
    assert ws.snippet_sha256("../../secret.txt", 1, 1) is None


def test_readonly_then_cleanup(ws: ScanWorkspace) -> None:
    ws.make_readonly()
    assert not (ws.src / "app.py").stat().st_mode & 0o222
    if os.geteuid() != 0:  # root ignores permission bits
        with pytest.raises(PermissionError):
            (ws.src / "new.txt").write_text("x")
    ws.cleanup()
    assert not ws.path.exists()


def test_measure_enforces_limits(ws: ScanWorkspace) -> None:
    assert ws.measure(10_000, 10)[1] == 2
    with pytest.raises(WorkspaceError):
        ws.measure(10_000, 1)


def test_workspace_requires_uuid(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        ScanWorkspace(tmp_path, "../../etc")  # type: ignore[arg-type]


def test_report_path_is_fixed(tmp_path: Path) -> None:
    sid = uuid.uuid4()
    assert (
        report_path(tmp_path, sid, ScannerName.TRIVY)
        == (tmp_path / str(sid) / "trivy.json").resolve()
    )
    with pytest.raises(ValueError):
        report_path(tmp_path, sid, "../../x")  # type: ignore[arg-type]
