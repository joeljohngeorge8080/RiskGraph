# ADR-0016: Evidence-grounded explanations with a local model and a template fallback

Status: accepted · Date: 2026-10-25 · Implements: roadmap Phase 12 (blueprint §15)

## Context
Blueprint §15 fixes the shape:
- an EvidencePack;
- an LLM adapter protocol (Ollama by default);
- a validator;
- one retry with feedback;
- a template fallback;
- a cache by `sha256(EvidencePack)`;
- top-N Critical findings explained per scan.

This ADR records the choices the blueprint left open and the places where the implementation is stricter.

## Decision
- **Model:** default `qwen3:4b` (Q4_K_M, about 2.5 GB), the model installed on the development machine. It is configurable (`RISKGRAPH_OLLAMA_MODEL`).
  - The blueprint's suggestion was a 7–8B model; 4B fits the 15 GB host next to the stack.
  - Requests use structured output (the draft's JSON schema), `temperature 0`, `think: false` and an output cap of 900 tokens.
- **Validator is stricter than §15:**
  - every reason must cite at least one *trusted* id (F, P, SCORE, FINDING). A reason resting only on `S*` repository snippets is rejected, so injected text cannot carry a claim;
  - a number in the draft must equal a spelling the evidence supports (its decimals, two and one places, rounded, or a percentage of a 0–1 value). The draft's own numbers are never rounded to fit;
  - error messages never quote the draft.
- **Raw model output is never stored.** A rejected reply may carry injected repository text. Only the validated draft (or the template) and the validator's messages are kept.
- **Cache:** one row per (finding, evidence hash) in `ai_explanations` (migration `e1b7d3a9c2f4`).
  - The same evidence in a later scan reuses the explanation.
  - `refresh=true` regenerates only a template fallback, because re-wording a validated one adds nothing.
- **API:**
  - `GET /findings/{id}/explanation?scan_id=` returns the stored explanation for the current evidence, or 404;
  - `POST` generates it synchronously, bounded by the model timeout (60 s). The template answers at once when the model is down.
- **Background:** after a scan completes, `riskgraph.explain.top_findings` explains its top `RISKGRAPH_EXPLAIN_TOP_N` (10) Critical findings, excluding triaged noise, one transaction per finding.
- **Anthropic adapter: not built.** It is a blueprint stretch item; the adapter protocol leaves room for it.

## Alternatives considered
- **Free-text answers checked by a second model:** rejected. They are not mechanical and not reproducible.
- **Storing rejected replies for debugging:** rejected for the injection reason above. The validator's messages say why a reply failed.
- **Asynchronous POST (202 plus polling):** deferred. For one local user a bounded synchronous call is simpler; revisit with Phase 2 auth and multiple users.

## Consequences
- (+) The score is computed before the model runs and is never read back from it. A model that misbehaves can only lose its own explanation to the template.
- (−) The validator checks ids, numbers and URLs, not meaning. A fluent but loose sentence ("the key can decrypt sensitive data") passes if it cites real evidence and invents no number. The UI shows each claim's evidence chips so a reader can check it.
- (−) Containers reach the host's Ollama only if it listens on a reachable address (for example `OLLAMA_HOST=172.17.0.1`). Otherwise the stack works with template explanations.
  - *Addendum 2026-10-25 (implementation, not a new decision):* `make dev` now publishes Ollama to the containers as a socket file and loads and unloads the model with the stack; see `PHASE_12.md` §L. No change to the decision above.
