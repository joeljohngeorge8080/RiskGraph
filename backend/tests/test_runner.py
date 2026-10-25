from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest
from riskgraph.modules.scanners import RunSpec, SubprocessRunner
from riskgraph.modules.scans.clone import build_clone_argv


@pytest.fixture()
def runner(tmp_path: Path) -> SubprocessRunner:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "py").symlink_to(sys.executable)
    return SubprocessRunner(bin_dir)


def _spec(tmp_path: Path, *argv: str, **kw: object) -> RunSpec:
    return RunSpec(argv, tmp_path, tmp_path / "logs", **kw)  # type: ignore[arg-type]


def test_string_argv_is_rejected(runner: SubprocessRunner, tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        runner.run(RunSpec("py -c 'print(1)'", tmp_path, tmp_path / "logs", 5))


def test_missing_binary_is_reported_not_raised(runner: SubprocessRunner, tmp_path: Path) -> None:
    result = runner.run(_spec(tmp_path, "no-such-tool", "--help", timeout_s=5))
    assert result.missing_binary and result.exit_code is None


def test_paths_are_never_executed_directly(runner: SubprocessRunner, tmp_path: Path) -> None:
    result = runner.run(_spec(tmp_path, sys.executable, "-c", "pass", timeout_s=5))
    assert result.missing_binary


def test_environment_is_an_allow_list(
    runner: SubprocessRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RISKGRAPH_DATABASE_URL", "postgresql+psycopg://leak")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    code = "import os,json; print(json.dumps(dict(os.environ)))"
    runner.run(_spec(tmp_path, "py", "-c", code, timeout_s=10, env={"HOME": "/h"}, log_name="a"))
    env = (tmp_path / "logs" / "a.stdout.log").read_text()
    assert "RISKGRAPH" not in env and "leak" not in env
    assert "HTTPS_PROXY" not in env  # network="none" gets no proxy
    assert '"HOME": "/h"' in env

    runner.run(_spec(tmp_path, "py", "-c", code, timeout_s=10, network="egress", log_name="b"))
    assert "proxy.invalid" in (tmp_path / "logs" / "b.stdout.log").read_text()


def test_timeout_kills_the_whole_process_group(runner: SubprocessRunner, tmp_path: Path) -> None:
    marker = tmp_path / "child-alive"
    grandchild = f"import time; time.sleep(3); open({str(marker)!r}, 'w').close()"
    code = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}])\n"
        "time.sleep(30)\n"
    )
    started = time.monotonic()
    result = runner.run(_spec(tmp_path, "py", "-c", code, timeout_s=1))
    assert result.timed_out and result.exit_code is None
    assert time.monotonic() - started < 10
    time.sleep(3.5)
    assert not marker.exists(), "grandchild survived the group kill"


def test_exit_code_and_stderr_tail(runner: SubprocessRunner, tmp_path: Path) -> None:
    code = "import sys; sys.stderr.write('boom\\x00\\n'); sys.exit(3)"
    result = runner.run(_spec(tmp_path, "py", "-c", code, timeout_s=10))
    assert result.exit_code == 3
    assert result.stderr_tail.strip() == "boom"


def test_stdin_is_closed(runner: SubprocessRunner, tmp_path: Path) -> None:
    code = "import sys; print(repr(sys.stdin.read()))"
    runner.run(_spec(tmp_path, "py", "-c", code, timeout_s=10, log_name="s"))
    assert (tmp_path / "logs" / "s.stdout.log").read_text().strip() == "''"


def test_clone_argv_is_hardened_and_ends_options() -> None:
    argv = build_clone_argv("https://github.com/o/r.git", "main", "/w/src")
    joined = " ".join(argv)
    for flag in ("core.hooksPath=/dev/null", "protocol.allow=never", "core.symlinks=false"):
        assert flag in joined
    assert "--depth" in argv and "--no-recurse-submodules" in argv
    assert argv[-3:] == ("--", "https://github.com/o/r.git", "/w/src")
    assert argv[argv.index("--branch") + 1] == "main"
    assert "--branch" not in build_clone_argv("https://github.com/o/r.git", "", "/w/src")


def test_runner_never_uses_a_shell() -> None:
    source = Path(os.path.dirname(__file__)).parent / "riskgraph/modules/scanners/runner.py"
    assert "shell=True" not in source.read_text()
