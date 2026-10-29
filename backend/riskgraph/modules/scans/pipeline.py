"""Scan pipeline stages: clone → run scanners → collect → analyze → finalize.

Each stage is a plain function of ``(scan_id, deps)`` so Celery tasks (``tasks.py``)
and the inline runner used by tests (``orchestration.run_pipeline_inline``) execute
exactly the same code. Stages:

- check the scan's state first and do nothing if it is not the expected one, so a
  redelivered or out-of-order message is harmless;
- never raise for domain failures: they record FAILED/TIMED_OUT and return, so the
  Celery chain and chord always reach ``finalize``.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import re
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from typing import Any

import redis
from sqlalchemy import update
from sqlalchemy.orm import Session

from riskgraph.modules.authz import (
    SENSITIVE_CATEGORIES,
    AuthzResult,
    Route,
    evidence_by_route,
    issue_findings,
    route_inventory,
)
from riskgraph.modules.authz import analyze as authz_analysis
from riskgraph.modules.authz import summary as routes_summary
from riskgraph.modules.context import (
    ContextResolver,
    FindingContext,
    IacAsset,
    IacResult,
    ManifestResult,
    Observed,
    extract_iac,
    load_manifest,
    persist_assets,
    refresh_intel,
)
from riskgraph.modules.evidence import Evidence, link_finding, persist_evidence
from riskgraph.modules.evidence import clear as clear_evidence
from riskgraph.modules.findings import apply_history, clear_scan, persist_merged
from riskgraph.modules.graph import GraphFinding, Topology, derive_topology
from riskgraph.modules.graph import analyze as attack_analysis
from riskgraph.modules.graph import clear as clear_graph
from riskgraph.modules.graph import persist as persist_graph
from riskgraph.modules.normalization import MergedFinding, RawFinding, fingerprint, merge
from riskgraph.modules.reachability import (
    NOT_APPLICABLE,
    ReachabilityRun,
    Verdict,
    persist_verdict,
    run_extractor,
)
from riskgraph.modules.reachability import clear as clear_reachability
from riskgraph.modules.repositories import Repository
from riskgraph.modules.risk import (
    MODEL_VERSION,
    ScoreInput,
    ScoreResult,
    input_for,
    persist_score,
    rescore,
    score,
)
from riskgraph.modules.runtime import (
    RUNTIME_ANALYZER,
    ImageRef,
    declarations,
    dockerfile_refs,
    image_refs,
    load_feeds,
    os_eol_finding,
    runtime_findings,
)
from riskgraph.modules.sbom import attach_findings, canonical_purl, persist_components
from riskgraph.modules.sbom.service import PackageSeen
from riskgraph.modules.scanners import (
    REDACTION_ORDER,
    ParseContext,
    RunResult,
    RunSpec,
    ScannerRunner,
    ScanPaths,
    SubprocessRunner,
    derive_key,
    get_scanner,
    scrub,
    trivy_dependency_graph,
)
from riskgraph.modules.scanners.containers import SCAN_LABEL, container_fields, scanner_image
from riskgraph.modules.scanners.docker_runner import DockerRunner, PathRoot, make_removable
from riskgraph.modules.scanners.slots import SlotLimiter
from riskgraph.modules.scanners.syft.parser import Component
from riskgraph.modules.scanners.syft.parser import components as syft_components
from riskgraph.modules.scanners.trivy import TrivyScanner
from riskgraph.modules.scanners.trivy.parser import parse_image
from riskgraph.modules.scans import repo
from riskgraph.modules.scans.clone import CloneError, Cloner, GitCloner
from riskgraph.modules.scans.finding_evidence import finding_evidence
from riskgraph.modules.scans.models import ScanJob, ScannerRun
from riskgraph.modules.scans.state import final_status
from riskgraph.modules.scans.storage import (
    ReportTooLargeError,
    read_image_index,
    read_image_report,
    read_json_capped,
    read_report,
    write_image_index,
    write_image_report,
    write_report,
)
from riskgraph.modules.scans.workspace import ScanWorkspace, widen_own_directories
from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.db import session_scope
from riskgraph.shared.http import OutboundClient
from riskgraph.shared.logging import get_logger
from riskgraph.shared.redis import get_redis
from riskgraph.shared.vocabulary import (
    ReachabilityTier,
    RunStatus,
    ScannerName,
    ScanStatus,
    SourceType,
)

log = get_logger(__name__)

TRIVY_LOCK_KEY = "riskgraph:lock:trivy"
TRIVY_LOCK_WAIT_S = 900
EXCERPT_LIMIT = 2000
EGRESS_FSIZE = 4 * 1024 * 1024 * 1024  # Trivy writes its vulnerability DB
DEFAULT_FSIZE = 512 * 1024 * 1024


@dataclass
class PipelineDeps:
    settings: Settings
    runner: ScannerRunner
    cloner: Cloner
    outbound: Callable[[], OutboundClient | None]
    kev_cache: Callable[[], redis.Redis | None]
    scanner_lock: Callable[[ScannerName, int], AbstractContextManager[bool]]


@contextmanager
def redis_scanner_lock(name: ScannerName, timeout_s: int) -> Iterator[bool]:
    """Serialize Trivy runs: concurrent scans would contend for its cache DB lock."""
    if name is not ScannerName.TRIVY:
        yield True
        return
    lock = get_redis().lock(
        TRIVY_LOCK_KEY, timeout=timeout_s + 120, blocking_timeout=TRIVY_LOCK_WAIT_S
    )
    acquired = bool(lock.acquire())
    try:
        yield acquired
    finally:
        if acquired:
            with contextlib.suppress(redis.exceptions.LockError):
                lock.release()


@contextmanager
def no_lock(_name: ScannerName, _timeout_s: int) -> Iterator[bool]:
    yield True


def _kev_cache() -> redis.Redis | None:
    try:
        return get_redis()
    except redis.RedisError:
        return None


def build_runner(s: Settings) -> ScannerRunner:
    """The MVP host runner, or the hardened container runner (ADR-0014)."""
    if s.scanner_runner == "subprocess":
        return SubprocessRunner(s.scanner_bin_dir)
    roots = [
        PathRoot(str(s.data_dir), str(s.host_data_dir)),
        PathRoot(str(s.trivy_cache_dir), str(s.host_trivy_cache_dir)),
    ]
    slots = SlotLimiter(get_redis(), s.scanner_max_slots, s.scanner_slot_lease_s)
    return DockerRunner.from_env(roots, s.scanner_egress_network, slots=slots)


def default_deps(settings: Settings | None = None) -> PipelineDeps:
    s = settings or get_settings()
    runner = build_runner(s)
    return PipelineDeps(
        settings=s,
        runner=runner,
        cloner=GitCloner(runner, s, image=fetcher_image()),
        outbound=lambda: OutboundClient() if s.enrichment_enabled else None,
        kev_cache=_kev_cache,
        scanner_lock=redis_scanner_lock,
    )


def fetcher_image() -> str:
    return "riskgraph/git-fetcher:bookworm"


def _container_fields(scan_id: uuid.UUID, name: ScannerName, paths: ScanPaths) -> dict[str, Any]:
    """Image, mounts and labels for a RunSpec. Ignored by the subprocess runner."""
    return container_fields(
        name.value, get_scanner(name).image_tag, paths, {SCAN_LABEL: str(scan_id)}
    )


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _workspace(deps: PipelineDeps, scan_id: uuid.UUID) -> ScanWorkspace:
    return ScanWorkspace(deps.settings.workspace_root, scan_id)


def _excerpt(text: str, ws: ScanWorkspace) -> str:
    cleaned = text.replace(str(ws.path), "<workspace>")
    return cleaned[-EXCERPT_LIMIT:]


def discard_workspace(deps: PipelineDeps, scan_id: uuid.UUID) -> None:
    """Remove a scan's workspace after its containers are stopped (cancel, reaper).

    With the container runner, files the scanners wrote belong to nobody (65534) and the
    worker cannot delete them, so a scanner image first widens their modes (ADR-0014)."""
    if deps.settings.keep_workspaces:
        return
    ws = _workspace(deps, scan_id)
    if isinstance(deps.runner, DockerRunner) and ws.path.is_dir():
        widen_own_directories(ws.path)
        make_removable(
            deps.runner,
            str(ws.path),
            scanner_image("checkov", get_scanner(ScannerName.CHECKOV).image_tag),
            ws.logs("cleanup"),
        )
    ws.cleanup()


def fail_scan(scan_id: uuid.UUID, reason: str) -> None:
    """Move a scan in any non-terminal state to FAILED (used on unexpected errors)."""
    with session_scope() as s:
        scan = s.get(ScanJob, scan_id)
        if scan is None or scan.status.is_terminal:
            return
        repo.cas_scan(s, scan_id, scan.status, ScanStatus.FAILED, reason, finished_at=_now())


# --- stage 1: clone ------------------------------------------------------------------


def clone(scan_id: uuid.UUID, deps: PipelineDeps) -> bool:
    with session_scope() as s:
        scan = s.get(ScanJob, scan_id)
        if scan is None:
            return False
        if not repo.cas_scan(s, scan_id, ScanStatus.QUEUED, ScanStatus.CLONING, started_at=_now()):
            return False
        repository = s.get(Repository, scan.repository_id)
        if repository is None:
            raise LookupError("scan references a missing repository")
        clone_url, ref = repository.clone_url, scan.requested_ref

    ws = _workspace(deps, scan_id)
    try:
        ws.create()
        result = deps.cloner.clone(ws, clone_url, ref)
    except CloneError as exc:
        reason = str(exc)
    except Exception:
        log.exception("clone_crashed", scan_id=str(scan_id))
        reason = "clone failed (internal error)"
    else:
        with session_scope() as s:
            repo.cas_scan(
                s, scan_id, ScanStatus.CLONING, ScanStatus.SCANNING, commit_sha=result.commit_sha
            )
        log.info("clone_done", scan_id=str(scan_id), files=result.files, bytes=result.bytes)
        return True

    with session_scope() as s:
        repo.cas_scan(s, scan_id, ScanStatus.CLONING, ScanStatus.FAILED, reason, finished_at=_now())
    ws.cleanup()
    return False


# --- stage 2: run one scanner --------------------------------------------------------


def _version(
    deps: PipelineDeps,
    ws: ScanWorkspace,
    name: ScannerName,
    env: Any,
    fields: dict[str, Any],
) -> str | None:
    scanner = get_scanner(name)
    result = deps.runner.run(
        RunSpec(
            scanner.version_argv(),
            ws.src,
            ws.logs(name),
            60,
            env=env,
            log_name="version",
            **fields,
        )
    )
    if result.exit_code != 0:
        return None
    try:
        text = (ws.logs(name) / "version.stdout.log").read_text(errors="replace")
    except OSError:
        return None
    for token in text.replace("Version:", " ").split():
        if token[:1].isdigit():
            return token[:64]
    return None


def _classify(
    result: RunResult, ok_codes: frozenset[int], output: Any, cap: int
) -> tuple[RunStatus, str | None]:
    if result.missing_binary:
        return RunStatus.FAILED, result.stderr_tail
    if result.timed_out:
        return RunStatus.TIMED_OUT, "scanner exceeded its time limit"
    if result.exit_code not in ok_codes:
        return RunStatus.FAILED, f"exit code {result.exit_code}: {result.stderr_tail}"
    if not output.is_file():
        return RunStatus.FAILED, f"no report produced: {result.stderr_tail}"
    if output.stat().st_size > cap:
        return RunStatus.FAILED, "report exceeds the size cap"
    return RunStatus.SUCCEEDED, None


def run_scanner(scan_id: uuid.UUID, name: ScannerName, deps: PipelineDeps) -> RunStatus:
    with session_scope() as s:
        scan = s.get(ScanJob, scan_id)
        run = repo.get_run(s, scan_id, name)
        if scan is None or run is None:
            return RunStatus.SKIPPED
        run_id = run.id
        if scan.status is not ScanStatus.SCANNING:
            repo.cas_run(s, run_id, RunStatus.QUEUED, RunStatus.SKIPPED)
            return RunStatus.SKIPPED
        if not repo.cas_run(s, run_id, RunStatus.QUEUED, RunStatus.RUNNING, started_at=_now()):
            return run.status

    settings = deps.settings
    scanner = get_scanner(name)
    ws = _workspace(deps, scan_id)
    status, excerpt, version, result = RunStatus.FAILED, None, None, None
    try:
        ws.prepare_tool(name)
        if name is ScannerName.TRIVY:
            settings.trivy_cache_dir.mkdir(parents=True, exist_ok=True)
        paths = ScanPaths(ws.src, ws.out(name), ws.home(name), settings.trivy_cache_dir)
        cmd = scanner.command(paths, settings)
        fields = _container_fields(scan_id, name, paths)
        version = _version(deps, ws, name, cmd.env, fields)
        timeout = scanner.timeout_s(settings)
        with deps.scanner_lock(name, timeout) as acquired:
            if not acquired:
                status, excerpt = RunStatus.TIMED_OUT, "waited too long for the trivy cache lock"
            else:
                result = deps.runner.run(
                    RunSpec(
                        cmd.argv,
                        ws.src,
                        ws.logs(name),
                        timeout,
                        scanner.network,
                        cmd.env,
                        EGRESS_FSIZE if scanner.network == "egress" else DEFAULT_FSIZE,
                        log_name="scan",
                        **fields,
                    )
                )
                status, excerpt = _classify(
                    result,
                    scanner.ok_exit_codes,
                    paths.out / scanner.output_name,
                    settings.raw_report_max_bytes,
                )
    except Exception:
        log.exception("scanner_crashed", scan_id=str(scan_id), scanner=name.value)
        status, excerpt = RunStatus.FAILED, "scanner failed (internal error)"

    with session_scope() as s:
        repo.cas_run(
            s,
            run_id,
            RunStatus.RUNNING,
            status,
            finished_at=_now(),
            scanner_version=version,
            exit_code=result.exit_code if result else None,
            duration_ms=result.duration_ms if result else None,
            error_excerpt=_excerpt(excerpt, ws) if excerpt else None,
        )
    log.info("scanner_done", scan_id=str(scan_id), scanner=name.value, status=status.value)
    return status


# --- stage 3: collect, redact, store -------------------------------------------------


def collect(scan_id: uuid.UUID, deps: PipelineDeps) -> None:
    settings = deps.settings
    ws = _workspace(deps, scan_id)
    with session_scope() as s:
        scan = s.get(ScanJob, scan_id)
        if scan is None or scan.status is not ScanStatus.SCANNING:
            return
        runs = {r.scanner: (r.id, r.status) for r in repo.runs_for(s, scan_id)}

    key = derive_key(settings)
    docs: dict[ScannerName, Any] = {}
    secrets: set[str] = set()
    rejected: dict[ScannerName, str] = {}
    for name in REDACTION_ORDER:
        if name not in runs or runs[name][1] is not RunStatus.SUCCEEDED:
            continue
        scanner = get_scanner(name)
        try:
            doc = read_json_capped(
                ws.out(name) / scanner.output_name, settings.raw_report_max_bytes
            )
            docs[name], found = scanner.redact(doc, key)
            secrets |= found
        except (OSError, ValueError, ReportTooLargeError) as exc:
            rejected[name] = f"report unreadable: {type(exc).__name__}"

    stored: dict[ScannerName, tuple[str, str, int, int]] = {}
    for name, doc in docs.items():
        clean = scrub(doc, secrets)
        rel, sha, size = write_report(settings.scan_output_root, scan_id, name, clean)
        stored[name] = (rel, sha, size, get_scanner(name).count(clean))
    secrets.clear()
    ws.remove_dir(ws.path / "out")

    with session_scope() as s:
        for name, (rel, sha, size, count) in stored.items():
            s.execute(
                update(ScannerRun)
                .where(ScannerRun.id == runs[name][0])
                .values(
                    output_path=rel, output_sha256=sha, output_bytes=size, raw_findings_count=count
                )
            )
        for name, reason in rejected.items():
            repo.cas_run(
                s, runs[name][0], RunStatus.SUCCEEDED, RunStatus.FAILED, error_excerpt=reason
            )
        repo.cas_scan(s, scan_id, ScanStatus.SCANNING, ScanStatus.ANALYZING)


# --- stage 3b: images the repository names (X2, ADR-0018) --------------------------

IMAGE_TOOL = "trivy-image"
IMAGE_WARNING_LIMIT = 300


def image_stage_budget_s(settings: Settings) -> int:
    """No image is started after this many seconds (one lock wait plus every image)."""
    return settings.image_scan_max_refs * settings.timeout_trivy_image_s + TRIVY_LOCK_WAIT_S


def image_stage_time_limit_s(settings: Settings) -> int:
    """Celery's soft limit for the stage: the budget, plus one image started at its end."""
    return image_stage_budget_s(settings) + settings.timeout_trivy_image_s + TRIVY_LOCK_WAIT_S


def _touch(scan_id: uuid.UUID) -> bool:
    """Record progress, so the reaper does not take a long image stage for a dead one.
    False when the scan has left ANALYZING (cancelled, reaped): stop pulling images."""
    with session_scope() as s:
        result = s.execute(
            update(ScanJob)
            .where(ScanJob.id == scan_id, ScanJob.status == ScanStatus.ANALYZING)
            .values(updated_at=_now())
        )
        return bool(getattr(result, "rowcount", 0))


def _image_entry(ref: ImageRef, k: int, status: str, warning: str | None) -> dict[str, Any]:
    return {
        "index": k,
        "ref": ref.canonical,
        "file": ref.file,
        "line": ref.line,
        "origin": ref.origin,
        "status": status,  # scanned | failed | skipped
        "warning": warning[:IMAGE_WARNING_LIMIT] if warning else None,
    }


def _scan_one_image(
    deps: PipelineDeps, scan_id: uuid.UUID, ws: ScanWorkspace, ref: ImageRef, k: int
) -> dict[str, Any]:
    settings = deps.settings
    scanner = TrivyScanner()
    tool = f"{IMAGE_TOOL}-{k}"
    ws.prepare_tool(tool)
    paths = ScanPaths(ws.src, ws.out(tool), ws.home(tool), settings.trivy_cache_dir)
    output = paths.out / scanner.output_name
    cmd = scanner.image_command(paths, settings, ref.canonical, str(output))
    fields = container_fields(
        ScannerName.TRIVY.value, scanner.image_tag, paths, {SCAN_LABEL: str(scan_id)}
    )
    timeout = settings.timeout_trivy_image_s
    try:
        with deps.scanner_lock(ScannerName.TRIVY, timeout) as acquired:
            if not acquired:
                return _image_entry(ref, k, "failed", "waited too long for the trivy cache lock")
            result = deps.runner.run(
                RunSpec(
                    cmd.argv,
                    ws.src,
                    ws.logs(tool),
                    timeout,
                    "egress",  # the pull needs the registry; nothing else is mounted writable
                    cmd.env,
                    EGRESS_FSIZE,
                    log_name="scan",
                    **fields,
                )
            )
        status, excerpt = _classify(
            result, scanner.ok_exit_codes, output, settings.raw_report_max_bytes
        )
        if status is not RunStatus.SUCCEEDED:
            return _image_entry(ref, k, "failed", _excerpt(excerpt or status.value, ws))
        doc, _ = scanner.redact(
            read_json_capped(output, settings.raw_report_max_bytes), derive_key(settings)
        )
        size = (doc.get("Metadata") or {}).get("Size") if isinstance(doc, dict) else None
        if isinstance(size, int) and size > settings.image_scan_max_bytes:
            return _image_entry(ref, k, "skipped", "image is larger than the size cap")
        write_image_report(settings.scan_output_root, scan_id, k, doc)
        entry = _image_entry(ref, k, "scanned", None)
        entry["duration_ms"] = result.duration_ms
        return entry
    except (OSError, ValueError, ReportTooLargeError) as exc:
        return _image_entry(ref, k, "failed", f"report unreadable: {type(exc).__name__}")
    finally:
        ws.remove_dir(ws.out(tool))


def scan_images(scan_id: uuid.UUID, deps: PipelineDeps) -> None:
    """``trivy image`` for each allowed reference, at most ``image_scan_max_refs``.

    Runs after collect and before analyze. A pull failure, a rate limit, the size cap or
    a missing Trivy DB is a warning in the index, never a failed scan. Writes the index
    last, so a redelivered message finds it and does nothing.
    """
    settings = deps.settings
    root = settings.scan_output_root
    with session_scope() as s:
        scan = s.get(ScanJob, scan_id)
        if scan is None or scan.status is not ScanStatus.ANALYZING:
            return
        trivy = repo.get_run(s, scan_id, ScannerName.TRIVY)
        trivy_ok = trivy is not None and trivy.status is RunStatus.SUCCEEDED
    if read_image_index(root, scan_id) is not None:
        return
    ws = _workspace(deps, scan_id)
    entries: list[dict[str, Any]] = []
    warnings: list[str] = []
    try:
        if not ws.src.is_dir():
            warnings.append("checkout no longer on disk")
            refs: list[ImageRef] = []
        else:
            refs = sorted(
                (i for i in image_refs(ws.src, extract_iac(ws.src).assets) if i.allowed),
                key=lambda i: i.canonical,
            )
        deadline = _now() + dt.timedelta(seconds=image_stage_budget_s(settings))
        active = True
        for k, ref in enumerate(refs):
            if not active:
                entries.append(_image_entry(ref, k, "skipped", "the scan stopped"))
            elif k >= settings.image_scan_max_refs:
                reason = f"more than {settings.image_scan_max_refs} images; not scanned"
                entries.append(_image_entry(ref, k, "skipped", reason))
            elif not trivy_ok:
                entries.append(
                    _image_entry(ref, k, "skipped", "trivy did not run cleanly in this scan")
                )
            elif _now() > deadline:
                entries.append(_image_entry(ref, k, "skipped", "the image stage ran out of time"))
            else:
                try:
                    entries.append(_scan_one_image(deps, scan_id, ws, ref, k))
                except Exception:
                    log.exception("image_scan_crashed", scan_id=str(scan_id), index=k)
                    entries.append(
                        _image_entry(ref, k, "failed", "image scan failed (internal error)")
                    )
                active = _touch(scan_id)
    except Exception:
        log.exception("image_stage_crashed", scan_id=str(scan_id))
        warnings.append("image stage failed (internal error)")
    write_image_index(root, scan_id, {"images": entries, "warnings": warnings})
    log.info(
        "images_done",
        scan_id=str(scan_id),
        scanned=sum(1 for e in entries if e["status"] == "scanned"),
        total=len(entries),
    )


# --- stage 4: normalize, merge, enrich, score ----------------------------------------


def _parse_all(
    deps: PipelineDeps, scan_id: uuid.UUID, scanners: list[ScannerName], repository: str
) -> list[RawFinding]:
    ws = _workspace(deps, scan_id)
    has_src = ws.src.is_dir()
    ctx = ParseContext(repository)
    seen: set[tuple[str, str]] = set()
    out: list[RawFinding] = []
    for name in scanners:
        doc = read_report(
            deps.settings.scan_output_root, scan_id, name, deps.settings.raw_report_max_bytes
        )
        for f in get_scanner(name).parse(doc, ctx):
            if f.source_type is SourceType.SAST and has_src:
                loc = f.location
                f.attrs["snippet_sha256"] = ws.snippet_sha256(
                    loc.file, loc.line_start, loc.line_end
                )
            f.fingerprint = fingerprint(f, repository)
            if (f.scanner.value, f.fingerprint) in seen:
                continue  # the same native result reported twice by one tool
            seen.add((f.scanner.value, f.fingerprint))
            out.append(f)
    return out


def _own_run(session: Session, scan_id: uuid.UUID) -> None:
    """The run that RiskGraph's own findings (runtime EOL) belong to (ADR-0018)."""
    if repo.get_run(session, scan_id, ScannerName.RISKGRAPH) is None:
        now = _now()
        session.add(
            ScannerRun(
                scan_job_id=scan_id,
                scanner=ScannerName.RISKGRAPH,
                status=RunStatus.SUCCEEDED,
                scanner_version=RUNTIME_ANALYZER,
                started_at=now,
                finished_at=now,
            )
        )
        session.flush()


def _runtime(
    deps: PipelineDeps, scan_id: uuid.UUID, iac: IacResult
) -> tuple[list[ImageRef], list[Any]]:
    ws = _workspace(deps, scan_id)
    if not ws.src.is_dir():
        return [], []
    images = image_refs(ws.src, iac.assets)
    return images, declarations(ws.src, images)


def _image_assets(images: list[ImageRef]) -> list[IacAsset]:
    return [
        IacAsset(
            "container_image",
            (i.canonical if i.repository else i.raw)[:160],
            i.file,
            {
                "raw": i.raw,
                "registry": i.registry,
                "repository": i.repository,
                "tag": i.tag,
                "digest": i.digest,
                "line": i.line,
                "origin": i.origin,
                "allowed": i.allowed,
                "reason": i.reason,
            },
        )
        for i in images
    ]


_DB_UPDATED = re.compile(r"^\s*UpdatedAt:\s*(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")


def _trivy_db_time(deps: PipelineDeps, scan_id: uuid.UUID) -> dt.datetime | None:
    """Advisory freshness: Trivy's DB build time, from this scan's own version log."""
    log_file = _workspace(deps, scan_id).logs(ScannerName.TRIVY) / "version.stdout.log"
    try:
        text = log_file.read_text(errors="replace")[:4096]
    except OSError:
        return None
    for line in text.splitlines():
        if m := _DB_UPDATED.match(line):
            return dt.datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}+00:00")
    return None


def _iac(deps: PipelineDeps, scan_id: uuid.UUID) -> IacResult:
    ws = _workspace(deps, scan_id)
    if not ws.src.is_dir():
        return IacResult((), ("checkout no longer on disk",), 0)
    return extract_iac(ws.src)


def _manifest(deps: PipelineDeps, scan_id: uuid.UUID) -> ManifestResult:
    ws = _workspace(deps, scan_id)
    if not ws.src.is_dir():
        return ManifestResult("unavailable", warnings=("checkout no longer on disk",))
    result = load_manifest(ws)
    log.info("manifest_loaded", scan_id=str(scan_id), status=result.status, file=result.file)
    return result


def _sbom_documents(
    deps: PipelineDeps, scan_id: uuid.UUID, succeeded: list[ScannerName]
) -> list[Component]:
    if ScannerName.SYFT not in succeeded:
        return []
    doc = read_report(
        deps.settings.scan_output_root,
        scan_id,
        ScannerName.SYFT,
        deps.settings.raw_report_max_bytes,
    )
    return syft_components(doc)


def _trivy_dependencies(
    deps: PipelineDeps, scan_id: uuid.UUID, succeeded: list[ScannerName]
) -> dict[str, dict[str, Any]]:
    if ScannerName.TRIVY not in succeeded:
        return {}
    doc = read_report(
        deps.settings.scan_output_root,
        scan_id,
        ScannerName.TRIVY,
        deps.settings.raw_report_max_bytes,
    )
    return trivy_dependency_graph(doc)


def _reachability(
    deps: PipelineDeps,
    scan_id: uuid.UUID,
    dependency_graph: dict[str, dict[str, Any]],
    manifest: ManifestResult,
) -> ReachabilityRun:
    ws = _workspace(deps, scan_id)
    entrypoints = (
        [e for s in manifest.manifest.services for e in s.entrypoints] if manifest.manifest else []
    )
    try:
        # The extractor is RiskGraph's own code, run in its own process (ADR-0012). It has no
        # scanner image, so it always uses the subprocess runner, whatever runner scans use.
        run = run_extractor(
            SubprocessRunner(deps.settings.scanner_bin_dir),
            ws.src,
            ws.path / "reachability",
            dependency_graph,
            entrypoints,
        )
    except Exception:
        log.exception("reachability_crashed", scan_id=str(scan_id))
        return ReachabilityRun("failed", detail="reachability failed (internal error)")
    log.info("reachability_done", scan_id=str(scan_id), status=run.status, **run.stats)
    return run


def _routes(
    scan_id: uuid.UUID, reach: ReachabilityRun, extra_guards: tuple[str, ...] = ()
) -> tuple[list[Route], dict[str, Any]]:
    """The route inventory from the extractor's output (X5, ADR-0022). Pure and capped; a
    failure here is logged and reported in the summary, and the scan goes on without it."""
    if reach.status != "ok":
        return [], {"status": "unavailable", "routes": 0}
    try:
        routes = route_inventory(reach.extracted, extra_guards=extra_guards)
    except Exception:
        log.exception("route_inventory_crashed", scan_id=str(scan_id))
        return [], {"status": "failed", "routes": 0}
    return routes, {"status": "ok", **routes_summary(routes)}


def _authz(
    scan_id: uuid.UUID, routes: list[Route], manifest: ManifestResult, raw: list[RawFinding]
) -> tuple[AuthzResult, dict[str, Any]]:
    """Authorization issues from the routes (X5 part 2, ADR-0023); like the inventory, a
    failure is reported and the scan goes on without them."""
    authz = manifest.manifest.authz if manifest.manifest is not None else None
    rules = authz.rules if authz is not None else ()
    code: dict[str, list[int]] = {}
    for f in raw:
        if f.source_type is SourceType.SAST and f.category in SENSITIVE_CATEGORIES:
            code.setdefault(f.location.file, []).append(f.location.line_start or 0)
    try:
        result = authz_analysis(routes, rules, code)
    except Exception:
        log.exception("authz_analysis_crashed", scan_id=str(scan_id))
        return AuthzResult([], {}), {"status": "failed", "findings": 0}
    by_rule: dict[str, int] = {}
    for issue in result.issues:
        by_rule[issue.rule] = by_rule.get(issue.rule, 0) + 1
    return result, {
        "status": "ok" if routes else "no_routes",
        "findings": len(result.issues),
        "by_rule": dict(sorted(by_rule.items())),
        "hypotheses": sum(1 for i in result.issues if i.assurance.value == "hypothesis"),
        "policy_rules": len(rules),
        "policy_unchecked_routes": len(result.unchecked),
    }


def _image_of(m: MergedFinding) -> str | None:
    image = (m.representative.package or {}).get("image")
    return str(image) if image and m.source_type is SourceType.SCA else None


def _topology(deps: PipelineDeps, scan_id: uuid.UUID, iac: IacResult) -> Topology:
    """Services from Compose and Kubernetes; the graph uses them only without a manifest."""
    ws = _workspace(deps, scan_id)
    return derive_topology(iac.assets, dockerfile_refs(ws.src) if ws.src.is_dir() else [])


def _graph_label(m: MergedFinding) -> str:
    """Short node label: credentials read as '<family> credential · file:line'."""
    if m.source_type is SourceType.SECRET:
        loc = m.location
        where = f"{loc.file}:{loc.line_start}" if loc.line_start else loc.file
        return f"{m.attrs.get('secret_family', 'generic')} credential · {where}"[:120]
    return m.representative.title[:120]


@dataclass
class _Scored:
    merged: MergedFinding
    context: FindingContext
    verdict: Verdict
    score_input: ScoreInput
    result: ScoreResult


def _persist_sbom(
    session: Session,
    scan_id: uuid.UUID,
    inventory: list[Component],
    scored: list[_Scored],
    finding_ids: dict[int, uuid.UUID],
    image_packages: list[PackageSeen],
) -> dict[str, int]:
    """Write the SBOM and attach each SCA finding to its package (blueprint §10.2).

    Image inventories (X2) come before the findings' packages, so a component keeps the
    file Trivy read it from rather than the file that names the image."""
    seen: list[PackageSeen] = list(image_packages)
    wanted: dict[int, tuple[str, str | None]] = {}
    for i, x in enumerate(scored):
        pkg = x.merged.representative.package
        if x.merged.source_type is not SourceType.SCA or not pkg or not pkg.get("purl"):
            continue
        purl = str(pkg["purl"])
        image = str(pkg["image"]) if pkg.get("image") else None
        wanted[i] = (canonical_purl(purl), image)
        seen.append(
            PackageSeen(
                purl=purl,
                name=str(pkg.get("name") or ""),
                version=str(pkg.get("version") or ""),
                location=x.merged.location.file,
                image=image,
            )
        )
    ids = persist_components(session, scan_id, inventory, seen)
    links = {finding_ids[i]: ids[key] for i, key in wanted.items() if key in ids}
    attached = attach_findings(session, scan_id, links)
    syft_keys = {(canonical_purl(x.purl), None) for x in inventory}
    return {
        "components": len(ids),
        "syft": len(inventory),
        "trivy_only": sum(1 for c in ids if c not in syft_keys and c[1] is None),
        "image_packages": sum(1 for c in ids if c[1] is not None),
        "findings_attached": attached,
    }


@dataclass
class _ImageResults:
    """What the image stage left for the analysis (X2): findings, inventory, the index."""

    entries: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    findings: list[RawFinding] = field(default_factory=list)
    eol: list[RawFinding] = field(default_factory=list)
    packages: list[PackageSeen] = field(default_factory=list)

    @property
    def scanned(self) -> set[str]:
        return {str(e["ref"]) for e in self.entries if e.get("status") == "scanned"}

    def summary(self) -> dict[str, Any]:
        return {
            "scanned": sorted(self.scanned),
            "results": [
                {k: e.get(k) for k in ("ref", "file", "origin", "status", "warning")}
                for e in self.entries
            ],
            "warnings": [
                *self.warnings,
                *(str(e["warning"]) for e in self.entries if e.get("warning")),
            ],
            "findings": len(self.findings),
            "eol_findings": len(self.eol),
        }


def _image_results(deps: PipelineDeps, scan_id: uuid.UUID, repository: str) -> _ImageResults:
    out = _ImageResults()
    root, cap = deps.settings.scan_output_root, deps.settings.raw_report_max_bytes
    try:
        index = read_image_index(root, scan_id)
    except (OSError, ValueError, ReportTooLargeError):
        index = None
        out.warnings.append("image index unreadable")
    if not isinstance(index, dict):
        return out
    out.warnings.extend(str(w)[:IMAGE_WARNING_LIMIT] for w in index.get("warnings") or [])
    seen: set[str] = set()
    for e in index.get("images") or []:
        if not isinstance(e, dict) or not isinstance(e.get("ref"), str):
            continue
        out.entries.append(e)
        if e.get("status") != "scanned" or not isinstance(e.get("index"), int):
            continue
        ref, file = e["ref"], str(e.get("file") or "")
        line = e.get("line") if isinstance(e.get("line"), int) else None
        try:
            doc = read_image_report(root, scan_id, e["index"], cap)
        except (OSError, ValueError, ReportTooLargeError):
            e["status"], e["warning"] = "failed", "image report unreadable"
            continue
        report = parse_image(doc, ref, file, line)
        for f in report.findings:
            f.fingerprint = fingerprint(f, repository)
            if f.fingerprint not in seen:  # one package at two paths in the same image
                seen.add(f.fingerprint)
                out.findings.append(f)
        out.packages.extend(
            PackageSeen(p.purl, p.name, p.version, p.location, ref) for p in report.packages
        )
        if report.eosl and report.os_family and report.os_name:
            f = os_eol_finding(ref, report.os_family, report.os_name, file, line, report.created_at)
            f.fingerprint = fingerprint(f, repository)
            out.eol.append(f)
    return out


def analyze(scan_id: uuid.UUID, deps: PipelineDeps) -> None:
    with session_scope() as s:
        scan = s.get(ScanJob, scan_id)
        if scan is None or scan.status is not ScanStatus.ANALYZING:
            return
        repository = s.get(Repository, scan.repository_id)
        if repository is None:
            raise LookupError("scan references a missing repository")
        repo_id, repo_name, ref = repository.id, repository.full_name, scan.requested_ref
        _own_run(s, scan_id)
        runs = repo.runs_for(s, scan_id)
        run_ids = {r.scanner.value: r.id for r in runs}
        versions = {r.scanner.value: r.scanner_version for r in runs}
        succeeded = [r.scanner for r in runs if r.status is RunStatus.SUCCEEDED and r.output_path]

    try:
        raw = _parse_all(deps, scan_id, succeeded, repo_name)
        iac = _iac(deps, scan_id)
        # X2: images and runtimes the repository declares; EOL from the stored feed only
        images, decls = _runtime(deps, scan_id, iac)
        with session_scope() as s:
            feeds = load_feeds(s)
        own = runtime_findings(decls, feeds, _now().date())
        for f in own:
            f.fingerprint = fingerprint(f, repo_name)
        # X2 part 2: what the image stage found (sca, marked with the image) and EOSL
        image_scan = _image_results(deps, scan_id, repo_name)
        own = [*own, *image_scan.eol]
        manifest = _manifest(deps, scan_id)
        reach = _reachability(
            deps, scan_id, _trivy_dependencies(deps, scan_id, succeeded), manifest
        )
        # X5: routes and their authorization issues, which are findings like any other
        now = _now()
        authz_decl = manifest.manifest.authz if manifest.manifest is not None else None
        routes, routes_info = _routes(
            scan_id, reach, authz_decl.guards if authz_decl is not None else ()
        )
        authz, authz_info = _authz(scan_id, routes, manifest, raw)
        routes_ev, route_ids = evidence_by_route(routes, now, authz.unchecked)
        authz_findings = issue_findings(authz.issues, route_ids)
        for f in authz_findings:
            f.fingerprint = fingerprint(f, repo_name)
        merged = merge([*raw, *image_scan.findings, *own, *authz_findings])
        syft_inventory = _sbom_documents(deps, scan_id, succeeded)
        trivy_db = _trivy_db_time(deps, scan_id)
        eol_as_of = min(
            (c.fetched_at for cycles in feeds.values() for c in cycles.values()), default=None
        )
        # MVP scans only public github.com repositories (ADR-0010)
        resolver = ContextResolver(manifest, public_repository=True, iac=iac.assets)

        cvss_by_id: dict[str, dict[str, Any] | None] = {}
        for m in merged:
            vid = m.representative.vulnerability_id
            if m.source_type is SourceType.SCA and vid:
                cvss_by_id[vid] = cvss_by_id.get(vid) or m.representative.cvss
        client = deps.outbound()
        try:
            with session_scope() as s:
                intel = refresh_intel(s, cvss_by_id, deps.settings, client, deps.kev_cache())
        finally:
            if client is not None:
                client.close()

        # Pass 1: base scores with context and reachability (pure).
        scored: list[_Scored] = []
        for m in merged:
            context = resolver.for_finding(m.location.file, m.source_type)
            # the code that uses an image's packages is not analysed: not assessable
            verdict = (
                NOT_APPLICABLE
                if (m.representative.package or {}).get("image")
                else reach.classify(
                    m.source_type,
                    m.location.file,
                    m.representative.package,
                    m.representative.vulnerability_id,
                    m.location.line_start,
                )
            )
            observed = (
                None
                if verdict.tier is ReachabilityTier.NOT_APPLICABLE
                else Observed(
                    verdict.tier.value, "reachability", verdict.confidence, verdict.evidence
                )
            )
            inp = input_for(
                m, intel.get(m.representative.vulnerability_id or ""), context, observed
            )
            scored.append(_Scored(m, context, verdict, inp, score(inp)))

        # Each finding's own evidence (ADR-0017): edges built from a finding rest on it. An
        # authorization finding rests on the route and guard evidence it names (ADR-0023).
        routes_by_id = {e.id: e for e in routes_ev}
        evidence: list[list[Evidence]] = [
            [
                *finding_evidence(x.merged, x.verdict, run_ids, versions, now, {"trivy": trivy_db}),
                *(
                    routes_by_id[i]
                    for i in x.merged.attrs.get("evidence_ids") or []
                    if x.merged.source_type is SourceType.AUTHZ and i in routes_by_id
                ),
            ]
            for x in scored
        ]

        # Attack paths, then pass 2: effective impact for findings on paths (§14.4).
        analysis = attack_analysis(
            manifest.manifest,
            [
                GraphFinding(
                    index=i,
                    service=x.context.service,
                    source_type=x.merged.source_type,
                    exploit_p=x.result.exploit_likelihood,
                    tier=x.verdict.tier.value,
                    secret_family=x.merged.attrs.get("secret_family"),
                    credential_p=(x.result.factor("E").value if x.result.factor("E") else 0.0),  # type: ignore[union-attr]
                    public_secret=x.merged.source_type is SourceType.SECRET,
                    title=_graph_label(x.merged),
                    evidence=tuple(e.id for e in evidence[i]),
                    file=x.merged.location.file,
                    line=x.merged.location.line_start,
                    image=_image_of(x.merged),
                    kev=bool(
                        (hit := intel.get(x.merged.representative.vulnerability_id or ""))
                        and hit.kev
                    ),
                )
                for i, x in enumerate(scored)
            ],
            manifest_file=manifest.file or "riskgraph.yaml",
            observed_at=now,
            topology=_topology(deps, scan_id, iac),
        )
        for i, effective in analysis.effective.items():
            scored[i].result = rescore(scored[i].score_input, effective)

        by_priority: dict[str, int] = {}
        by_source: dict[str, int] = {}
        by_scanner: dict[str, int] = {}
        tiers: dict[str, int] = {}
        multi = 0
        max_score = 0.0
        with session_scope() as s:
            clear_scan(s, scan_id)
            clear_graph(s, scan_id)
            clear_evidence(s, scan_id)
            clear_reachability(s, scan_id)
            persist_evidence(s, scan_id, routes_ev)
            finding_ids: dict[int, uuid.UUID] = {}
            for i, x in enumerate(scored):
                m, result = x.merged, x.result
                finding_id = persist_merged(
                    s, repository_id=repo_id, scan_id=scan_id, run_ids=run_ids, merged=m, now=now
                )
                finding_ids[i] = finding_id
                persist_evidence(s, scan_id, evidence[i])
                link_finding(s, scan_id, finding_id, [e.id for e in evidence[i]])
                persist_score(s, scan_id, finding_id, result)
                if x.verdict.tier is not ReachabilityTier.NOT_APPLICABLE:
                    persist_verdict(s, scan_id, finding_id, x.verdict)
                    tiers[x.verdict.tier.value] = tiers.get(x.verdict.tier.value, 0) + 1
                by_priority[result.priority.value] = by_priority.get(result.priority.value, 0) + 1
                by_source[m.source_type.value] = by_source.get(m.source_type.value, 0) + 1
                for sc in m.detected_by:
                    by_scanner[sc] = by_scanner.get(sc, 0) + 1
                multi += len(m.detected_by) > 1
                max_score = max(max_score, result.score)
            persist_graph(s, scan_id, analysis, finding_ids)
            assets_written = persist_assets(s, scan_id, [*iac.assets, *_image_assets(images)])
            sbom_summary = _persist_sbom(
                s, scan_id, syft_inventory, scored, finding_ids, image_scan.packages
            )
            s.flush()
            history = apply_history(
                s,
                scan_id=scan_id,
                repository_id=repo_id,
                ref=ref,
                succeeded_scanners={sc.value for sc in succeeded} | {ScannerName.RISKGRAPH.value},
                scanned_images=image_scan.scanned,
                now=now,
            )
            intel_status = sorted(
                {i.epss_status for i in intel.values()} | {i.kev_status for i in intel.values()}
            )
            summary = {
                "raw_findings": len(raw),
                "findings": len(merged),
                # scanner results plus RiskGraph's own (image, runtime, authz) before merging
                "merged_away": len(raw)
                + len(image_scan.findings)
                + len(own)
                + len(authz_findings)
                - len(merged),
                "cross_scanner": multi,
                "by_priority": by_priority,
                "by_source_type": by_source,
                "by_scanner": by_scanner,
                "max_score": max_score,
                "intel": {
                    "vulnerabilities": len(intel),
                    "epss_scored": sum(1 for i in intel.values() if i.epss is not None),
                    "kev_listed": sum(1 for i in intel.values() if i.kev),
                    "statuses": intel_status,
                },
                "context": resolver.summary(),
                "reachability": reach.summary(tiers),
                "routes": routes_info,
                "authz": authz_info,
                "graph": analysis.summary(),
                "sbom": sbom_summary,
                "iac": {
                    "assets": assets_written,
                    "files": iac.files_read,
                    "warnings": list(iac.warnings),
                },
                "history": history,
                "runtime": {
                    "images": len(images),
                    "images_allowed": sum(1 for i in images if i.allowed),
                    "declarations": len(decls),
                    "eol_findings": len(own),
                    "eol_data": sorted(feeds),
                },
                "images": image_scan.summary(),
                "freshness": {
                    "trivy_db": trivy_db.isoformat() if trivy_db else None,
                    "eol": eol_as_of.isoformat() if eol_as_of else None,
                },
            }
            s.execute(
                update(ScanJob)
                .where(ScanJob.id == scan_id)
                .values(summary=summary, risk_model_version=MODEL_VERSION)
            )
    except Exception:
        log.exception("analysis_crashed", scan_id=str(scan_id))
        with session_scope() as s:
            repo.cas_scan(
                s,
                scan_id,
                ScanStatus.ANALYZING,
                ScanStatus.FAILED,
                "analysis failed (internal error)",
                finished_at=_now(),
            )


# --- stage 5: finalize ---------------------------------------------------------------


def finalize(scan_id: uuid.UUID, deps: PipelineDeps) -> ScanStatus | None:
    with session_scope() as s:
        scan = s.get(ScanJob, scan_id)
        if scan is None:
            return None
        runs = repo.runs_for(s, scan_id)
        for r in runs:
            if r.status is RunStatus.QUEUED:
                repo.cas_run(s, r.id, RunStatus.QUEUED, RunStatus.SKIPPED)
        if scan.status is ScanStatus.ANALYZING:
            # the riskgraph run is RiskGraph's own analysis, not a scanner: it never makes
            # a scan whose scanners all failed look partial
            status, reason = final_status(
                r.status for r in runs if r.scanner is not ScannerName.RISKGRAPH
            )
            repo.cas_scan(s, scan_id, ScanStatus.ANALYZING, status, reason, finished_at=_now())
        elif not scan.status.is_terminal:
            repo.cas_scan(
                s,
                scan_id,
                scan.status,
                ScanStatus.FAILED,
                "pipeline ended early",
                finished_at=_now(),
            )
        s.flush()
        s.refresh(scan)
        final = scan.status

    discard_workspace(deps, scan_id)
    log.info("scan_finished", scan_id=str(scan_id), status=final.value)
    return final
