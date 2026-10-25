# Local tasks: work that needs the owner's machine

The cloud runs have no Docker daemon, no real scanners, no Ollama, and cannot reach `endoflife.date` or `api.first.org`. Everything that needs one of those is listed here, with what depends on it. Status: `TODO`, `DONE <date>`.

| Id | Task | Needed by | Status |
|---|---|---|---|
| L-1 | Record `trivy image` reports for `python:3.8-slim` and `node:14` (`backend/tests/fixtures/images/`) | Day 1 (X2 part 2) | DONE 2026-10-25 |
| L-2 | **Joern spike** (X4.0): run Joern in a hardened container on a 20-case Python/JS source-to-sink suite plus the scenario repos; measure recall, precision, peak RAM, time; write `docs/auto/spikes/joern/RESULT.md` (`GO` or `NO-GO`, with the numbers) and record Joern's output as fixtures under `backend/tests/fixtures/joern/` | before Day 3 (28 Oct, 05:00 IST) | TODO |
| L-3 | Run the real `trivy image` stage end to end in the container runner (egress network, 5 images, 2 GB cap); measure the overhead per image with a warm cache (target ≤ +90 s) | after Day 1 | TODO |
| L-4 | Run the generated tier-1 taint rules with the real Semgrep against the 40-case suite; record recall and precision | after Day 2 | TODO |
| L-5 | Run the Joern container for real through the runner (`deep` profile, one slot); check RAM and time on NodeGoat | after Day 3 | TODO |
| L-6 | Live-model check (`make test-llm`) of the explanation prompt after the new path and taint evidence | after Day 6 | TODO |
| L-7 | `make dev`: apply the new migrations to the dev database and click through the new API fields | after Day 6 | TODO |

The cloud runs may append rows (next id L-8, …). Do not edit another row's status.
