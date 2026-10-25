# PHASE 12: AI explanation (evidence-grounded, validated, cached)

**Status:** done (2026-10-25). Decision: ADR-0016 (implements blueprint §15). Migration `e1b7d3a9c2f4`.

## A. Objective
Roadmap P12 definition of done:
- an explanation generated for a Critical finding, validated and cached;
- validator golden tests;
- the fallback verified with the model unavailable.

The deliverables: adapter protocol, Ollama adapter, prompt, validator, template fallback. The Anthropic adapter is a stretch item and is not built.

## B. Why
The score already says *what*; developers need *why here*. The rule from §1 holds: AI never decides risk. The score is computed first, and the model only words evidence that a mechanical validator checks.

## C. Architecture
```
finding detail + score + factors + attack paths  (already stored)
   └─ build_pack ─▶ EvidencePack { FINDING, SCORE, F1…Fn, P1…P3, S1…S3 (untrusted, ≤5 lines) }
                      │ sha256 = cache key (ai_explanations: finding_id + evidence_hash)
                      ▼
   generate(pack, adapter):  attempt 1 ─ valid ─▶ validated
                               │ invalid → feedback = validator messages
                             attempt 2 ─ valid ─▶ validated
                               │ invalid / model unreachable
                             template ──────────▶ fallback (always validates)
API:  GET|POST /findings/{id}/explanation?scan_id=[&refresh=true]
Beat/worker: after a COMPLETED/PARTIAL scan → riskgraph.explain.top_findings (top 10 Critical)
UI:   drawer "Explanation" panel, plain text, evidence-id chips with labels
```

## D. Components
| Component | File |
|---|---|
| EvidencePack, ids, number spellings | `backend/riskgraph/modules/explain/evidence.py` |
| Draft schema (structured output) | `modules/explain/draft.py` |
| Validator | `modules/explain/validator.py` |
| Prompt (snippets labelled as data) | `modules/explain/prompt.py` |
| Adapters: protocol, Ollama, Null | `modules/explain/adapters.py` |
| Retry and fallback | `modules/explain/generate.py` |
| Template explainer | `modules/explain/template.py` |
| Pack from rows, cache, upsert, top-N | `modules/explain/service.py` |
| Model, router, task | `modules/explain/{models,router,tasks}.py` |
| Migration | `backend/alembic/versions/20261025_1000_ai_explanations.py` |
| UI | `frontend/src/features/findings/ExplanationPanel.tsx`, `lib/level2.ts` (`explanationSource`) |

## E. Technical decisions
See ADR-0016. In short:
- **The validator is stricter than the blueprint.** A reason needs a trusted id (repository snippets alone never carry a claim). A number must match the evidence's own spellings, never be rounded to fit. Error messages never quote the draft.
- **Raw model output is never stored.**
- **`qwen3:4b` by default** (installed here, fits the host); thinking off, temperature 0.
- **Synchronous POST**, bounded by a 60 s timeout. With the model down, the template answers at once.

## G. Database
`ai_explanations`:
- `finding_id` and `scan_job_id` (FK cascade); `evidence_hash`; `prompt_version`; `generator`; `status` (CHECK `validated|fallback`);
- `draft`, `evidence_ids` (id → label) and `validation_errors` (JSONB); `attempts`, `latency_ms`, `created_at`;
- unique on (finding_id, evidence_hash); index on `scan_job_id`.

Reviewed by hand; the round trip is in the db suite; `alembic check` reports no drift.

## H. API
| Method & path | Notes |
|---|---|
| `GET /findings/{id}/explanation?scan_id=` | The stored explanation for the current evidence; 404 until one exists |
| `POST /findings/{id}/explanation?scan_id=&refresh=` | Generate or return the cached one. `refresh` regenerates a template fallback only |

## L. Configuration
- `RISKGRAPH_LLM_PROVIDER` (`ollama` | `none`, default `ollama`);
- `RISKGRAPH_OLLAMA_URL` (default `http://127.0.0.1:11434`; Compose `http://host.docker.internal:11434`);
- `RISKGRAPH_OLLAMA_MODEL` (`qwen3:4b`), `RISKGRAPH_OLLAMA_TIMEOUT_S` (60), `RISKGRAPH_EXPLAIN_TOP_N` (10; 0 = off).

- `RISKGRAPH_OLLAMA_KEEP_ALIVE` (`10m`; the stack sets `-1`) and `RISKGRAPH_OLLAMA_SOCKET` (empty = use the URL; the stack sets `/run/ollama/ollama.sock`).

Tests force `none`.

**Model lifecycle (added 2026-10-25).** `make dev` and `make dev-detached` run `infrastructure/scripts/llm.sh up`; `make down`, `make nuke` and Ctrl-C of `make dev` run `llm.sh down`; `make llm-status` shows the state.
- `up` loads `qwen3:4b` in the background and keeps it loaded (`keep_alive` -1, sent as a number: Ollama rejects the string `"-1"`). Ollama splits the model between GPU and CPU by itself: on this laptop (GTX 1650, 4 GB) it loads 82 % GPU and 18 % CPU, 2.8 GB VRAM.
- `down` cancels a preload still in flight, then unloads until Ollama no longer lists the model (an early Ctrl-C otherwise left it loaded), and stops the forwarder. The Ollama service itself keeps running, idle.
- Containers reach it through a socket file, not TCP: `socat` publishes `.data/ollama/ollama.sock`, mounted read-only into `api` and `worker`, and the adapter speaks HTTP over it with `Host: localhost` (Ollama answers 403 to any other host). TCP to the host does not work here: `ufw` is active and drops container-to-host traffic, so a forwarder on the Docker bridge timed out.
- Missing Ollama, model or `socat` is never fatal: the script says so and explanations use the template.

## M. Testing
- **`test_explain.py` (33, unit, no network):**
  - pack digest stability; snippet clipping;
  - golden validator cases: a grounded draft passes. These are rejected: no reasons, unknown id, no id, S-only reason, invented `92`, invented `0.31` (it does not round to fit), a foreign URL, an 81-word summary;
  - ids such as `F2`/`L3`/`CWE-918` are not numbers; errors never quote the draft;
  - the template always validates and never repeats repository text;
  - generate: validated first time; retry carries the feedback; two bad answers → template; unreachable → template without retry; malformed JSON; no adapter;
  - Ollama wire format (`think: false`, `format`, temperature 0); 500, invalid JSON, missing content, oversize body, redirect and connection errors → `AdapterError`; non-http URLs refused.
- **`test_explain_db.py` (6, db):**
  - without a model: template, cached (same row, `created_at`, hash), one row;
  - a grounded model reply is validated;
  - an **injection** reply (claims only on S1, a foreign URL, an invented number, a marker string) is rejected twice → template. The marker and the URL appear nowhere in the stored row, and the finding's priority is unchanged;
  - `refresh` replaces a fallback with a validated answer (still one row);
  - the top-N task explains exactly 10 of the 11 Criticals;
  - 404/422.
- **`tests/e2e/test_explain_ollama.py` (`make test-llm`, opt-in, real model):** the live run below.
- **Frontend:** `explanationSource` test (10 Vitest tests in total).

## O. Validation
```
uv run ruff check . && uv run mypy                         → clean (177 files)
pytest -m "not db and not docker and not e2e and not perf"  → 306 passed
make test-db                                               → 56 passed, 2 skipped
alembic upgrade head && alembic check                      → e1b7d3a9c2f4 (head); no new operations
npm run lint/typecheck, vitest, build                      → clean, 10 passed, built
make test-llm  (Ollama 0.32.9, qwen3:4b, this machine)     → 2 passed
  first: status=validated generator=ollama:qwen3:4b attempts=1 latency_ms=17707
  summary: "A private key was found in a public repository. … The risk score is 93.92 with
            critical priority due to high likelihood (0.9487) and impact (0.9)."
  second call: cached (same row, < 2 s)
  unreachable (port 9): status=fallback generator=template 0.01s ['attempt 1: ollama unreachable: ConnectError']
```
- **The fallback was verified with an unreachable endpoint, not by stopping your Ollama service.** Both trigger the same `ConnectError` path.
- **Latency:** 17.7 s, within the blueprint's 20 s budget.

## Q. Known limits
- The validator checks ids, numbers and URLs, not meaning. The live summary's "can be used to decrypt sensitive data" is plausible but not stated by the evidence; it passes because it invents no number or id. The evidence chips beside each claim let a reader check.
- One local model, one user: no queueing or rate limit on POST before Phase 2 auth.
- The socket is mode 0666 because the container user (uid 10001) is not the host user. Ollama has no authentication and already answers every local user on 127.0.0.1, so the socket adds no new exposure.
- The dev database was not migrated in this session (the stack was not running); `make dev` runs `alembic upgrade head`.
