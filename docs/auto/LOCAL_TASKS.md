# Local tasks: work that needs the owner's machine

The cloud runs have no Docker daemon, no real scanners, no Ollama, and cannot reach `endoflife.date` or `api.first.org`. Everything that needs one of those is listed here, with what depends on it. Status: `TODO`, `DONE <date>`.

| Id | Task | Needed by | Status |
|---|---|---|---|
| L-1 | Record `trivy image` reports for `python:3.8-slim` and `node:14` (`backend/tests/fixtures/images/`) | Day 1 (X2 part 2) | DONE 2026-10-25 |
| L-2 | **Joern spike** (X4.0): run Joern in a hardened container on a 20-case Python/JS source-to-sink suite plus the scenario repos; measure recall, precision, peak RAM, time; write `docs/auto/spikes/joern/RESULT.md` (`GO` or `NO-GO`, with the numbers) and record Joern's output as fixtures under `backend/tests/fixtures/joern/` | before Day 3 (28 Oct, 05:00 IST) | TODO |
| L-3 | Run the real `trivy image` stage end to end in the container runner (egress network, 5 images, 2 GB cap); measure the overhead per image with a warm cache (target ≤ +90 s) | after Day 1 | TODO |
| L-4 | Run the generated tier-1 taint rules with the real Semgrep against the 40-case suite; record recall and precision. Steps: `uv run python -m evaluation.taint_suite write /tmp/taint-suite`; `semgrep scan --config backend/riskgraph/modules/scanners/semgrep/taint_rules.yaml --json --metrics=off -o /tmp/taint.json /tmp/taint-suite` (it must load all 10 rules without errors); `uv run python -m evaluation.taint_suite score /tmp/taint-suite /tmp/taint.json`. Also check that `extra.dataflow_trace` in `/tmp/taint.json` has the shape `parser.taint_steps` expects (`taint_source`/`intermediate_vars`/`taint_sink` with `path` + `start.line`). Then answer F-2-1 | after Day 2 | TODO |
| L-5 | Run the Joern container for real through the runner (`deep` profile, one slot); check RAM and time on NodeGoat | after Day 3 | TODO |
| L-6 | Live-model check (`make test-llm`) of the explanation prompt after the new path and taint evidence | after Day 6 | TODO |
| L-7 | `make dev`: apply the new migrations to the dev database and click through the new API fields | after Day 6 | TODO |
| L-8 | Check that Trivy 0.76.0 accepts `--max-image-size 2147MB` with `--image-src remote`. If it rejects the flag, every image run fails with a warning: take the flag out of `TrivyScanner.image_command` (the `Metadata.Size` check stays). Same run as L-3 | Day 1 follow-up (with L-3) | TODO |
| L-9 | Run one normal scan with `RISKGRAPH_SCANNER_RUNNER=docker` and check that the Trivy run SUCCEEDED. Before `1f6f069`, every Trivy run in a container failed: `TRIVY_CACHE_DIR` was not on the container env allow-list. Only the subprocess runner was tested, and still is in the cloud | Day 1 follow-up | TODO |

The cloud runs may append rows (next id L-10, …). Do not edit another row's status.
