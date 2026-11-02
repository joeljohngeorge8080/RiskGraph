"""Joern spike runner (X4.0, L-2).

    uv run python docs/auto/spikes/joern/run_spike.py <suite dir> <out dir> [--lang py|js] [--only ID]

Runs Joern once per case directory in the ADR-0014 profile (no network, read-only source,
read-only root, no capabilities, memory cap) and writes, per case, the raw sink lines and
the wall time and peak memory. The summary is a Semgrep-shaped JSON (``results`` with
``check_id``, ``path``, ``start.line``) so ``evaluation.taint_suite score`` can score it.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

IMAGE = "ghcr.io/joernio/joern@sha256:f6b35cd1296f92070305fcc7cbdb2f113d26ea1920abcb303e1a6622c6b1ba2a"
HERE = Path(__file__).parent
MEMORY = "6g"
FRONTEND = {"py": "pythonsrc", "js": "jssrc"}


def peak_bytes(cid: str) -> int | None:
    for pattern in (
        f"/sys/fs/cgroup/system.slice/docker-{cid}.scope/memory.peak",
        f"/sys/fs/cgroup/docker/{cid}/memory.peak",
    ):
        try:
            return int(Path(pattern).read_text())
        except OSError:
            continue
    return None


def run_case(src: Path, out: Path, lang: str) -> dict[str, object]:
    out.mkdir(parents=True, exist_ok=True)
    out.chmod(0o777)
    name = f"joern-spike-{uuid.uuid4().hex[:8]}"
    script = (
        f"set -e; mkdir -p /work/tmp; joern-parse --language {FRONTEND[lang]} -o /work/cpg.bin /src >/work/parse.log 2>&1; "
        f"joern --script /q/taint.sc --param cpgFile=/work/cpg.bin --param out=/work/sinks.tsv "
        f"--param lang={lang} >/work/query.log 2>&1"
    )
    cmd = [
        "docker", "run", "--name", name, "--network", "none", "--user", "65534:65534",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--memory", MEMORY, "--pids-limit", "512",
        "--tmpfs", "/tmp:rw,nosuid,size=2g", "-e", "HOME=/tmp/home", "-e", "JAVA_TOOL_OPTIONS=-Djava.io.tmpdir=/work/tmp",
        "-v", f"{src}:/src:ro", "-v", f"{HERE}:/q:ro", "-v", f"{out}:/work",
        "-w", "/work", "--entrypoint", "sh", IMAGE, "-c", script,
    ]  # fmt: skip
    started = time.monotonic()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)  # noqa: S603
    # the cgroup is gone once the container exits, so the peak is read while it runs
    cid, peak = "", 0
    while proc.poll() is None:
        if time.monotonic() - started > 900:
            proc.kill()
            break
        if not cid:
            cid = subprocess.run(  # noqa: S603
                ["docker", "inspect", "--format", "{{.Id}}", name], capture_output=True, text=True
            ).stdout.strip()
        if cid:
            peak = max(peak, peak_bytes(cid) or 0)
        time.sleep(0.5)
    timed_out = proc.returncode not in (0, 1) and time.monotonic() - started > 900
    code = 124 if timed_out else proc.returncode
    err = "timeout 900 s" if timed_out else proc.communicate()[1][-400:]
    seconds = time.monotonic() - started
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)  # noqa: S603, S607
    tsv = out / "sinks.tsv"
    sinks = [ln.split("\t") for ln in tsv.read_text().splitlines() if ln] if tsv.exists() else []
    return {"exit": code, "seconds": round(seconds, 1), "peak_mb": peak and peak // 2**20,
            "sinks": sinks, "stderr": err}  # fmt: skip


def main() -> None:
    args = sys.argv[1:]
    lang = args[args.index("--lang") + 1] if "--lang" in args else "py"
    only = args[args.index("--only") + 1] if "--only" in args else None
    suite, out = Path(args[0]).resolve(), Path(args[1]).resolve()
    cases = sorted(p for p in suite.iterdir() if p.is_dir() and p.name.startswith("python-" if lang == "py" else "javascript-"))
    cases = [c for c in cases if only in (None, c.name)] if only else cases
    summary: dict[str, object] = {}
    results: list[dict[str, object]] = []
    for case in cases:
        r = run_case(case, out / case.name, lang)
        summary[case.name] = {k: v for k, v in r.items() if k != "sinks"} | {"n_sinks": len(r["sinks"])}  # type: ignore[arg-type]
        print(case.name, summary[case.name], flush=True)  # noqa: T201
        for cls, file, line, *_ in r["sinks"]:  # type: ignore[misc]
            results.append({"check_id": f"riskgraph.taint.{lang}.{cls}",
                            "path": f"{case.name}/{file}", "start": {"line": int(line)}})  # fmt: skip
    (out / "joern.json").write_text(json.dumps({"results": results}, indent=1))
    (out / "summary.json").write_text(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
