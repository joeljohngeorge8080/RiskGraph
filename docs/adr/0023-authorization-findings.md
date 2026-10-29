# ADR-0023: Authorization findings, the manifest `authz:` section, an interim score, and non-traversable authz edges

Status: accepted · Date: 2026-10-29 · Implements: expansion phase X5 part 2 (`docs/proposals/EXPANSION_A-D.md` §3.B, §3.D (UNGUARDED, BOLA_SUSPECT), §4 X5, §6; `docs/auto/SCHEDULE.md` day 5, done on day 4) · Builds on: ADR-0017 (evidence and assurance), ADR-0018 (RiskGraph's own producer, interim EOL score), ADR-0020 (two-pass search), ADR-0022 (route inventory)

## Context
X5 part 1 (ADR-0022) gives every route a guard status. Only `none_found` means "every place a guard could come from was resolved and none was found". Part 2 turns that into findings, a manifest policy and graph edges, with the plan's honesty rules:
- a catalogued guard is at most inferred;
- BOLA is always a hypothesis and never above Low;
- an undecided route is never called unguarded.

Three things the plan leaves open had to be settled here:
- the shape of the manifest section;
- how authz findings score before risk v2 (X6);
- what the new edges mean for path search.

## Decision
**Extractor `ts-imports.5`** (additive, same sandbox and caps).
- Each route whose handler code is in the same file gets a `body`:
  - its line `span`;
  - the route parameters passed into a call (`loads`), not counting calls that only format or answer (`str`, `jsonify`, `res.json`, …);
  - `ownership`: whether a comparison or keyword argument mentions an owner or the current user (`owner`, `user_id`, `current_user`, `request.user`, `req.user`, …).
  These are words, not semantics. Only the BOLA hypothesis reads them.
- JavaScript files also record two things:
  - plain-function call sites with name arguments (`routes(app, db)`, `require("./r")(app)`);
  - the parameter names of exported functions.

**Passed-in Express apps.** A route registered on a parameter of an exported function is bound to the receiver that the first call site passes in that position. The caller's `use()` calls before that call count, and so do `use()` calls inside the module before the route. With several call sites, the route says that the first one was used. An export nobody calls stays `unresolved`.

**Manifest `authz:`** (optional, strict, additive).
```yaml
authz:
  guards: [team_member_required]          # the repository's own guard names, counted as catalogued
  rules:
    - path: /admin/**                     # * one segment, ** any number (also none)
      methods: [DELETE]                   # optional; empty = every method
      require: [require_admin]            # or: authenticated (any guard, custom included)
```
- The plan writes `authz: [{path, requires}]` and, separately, `authz.guards:`. Both together need a mapping, so the rules sit under `rules:`, and the key is `require` (singular, like the other manifest verbs).
- The matcher is the iterative wildcard walk: worst case pattern × path steps, never exponential.

**Rules** (`authz/analysis.py`, pure; every issue keeps the route keys it rests on).
| Rule | When | Assurance | Severity |
|---|---|---|---|
| `inconsistent` | A `none_found` route on a resource (full path without trailing parameters) where: for a write, most of at least two siblings are guarded, or a read is; for a read, most of the other reads are guarded | inferred | high for a write, medium for a read |
| `unguarded-sensitive` | `none_found` and (a mutating method, or an injection-like SAST finding inside the handler span). Routes whose path or handler has a `public_hints` word (login, signup, callback, health, webhook, …) are not sensitive for writing alone. An inconsistent route is reported only as inconsistent | inferred | high with a code finding, else medium |
| `policy` | A manifest rule matches and the route lacks the required guard. A route that is `unresolved` or `unknown_framework` is listed as "not checked" | inferred (the guards are) | high |
| `bola` | A path parameter is in `loads`, `ownership` is false, and the handler code was seen | **hypothesis** | low |

- "Compare reads with reads" came from the labelled suite: a public post list next to guarded writes is the usual design.
- The "data store the manifest marks ≥ confidential" signal of plan §3.B is not used: nothing states which store a handler touches.

**Findings.**
- `source_type = authz`, producer `riskgraph`, rule ids `authz:<rule>`, CWE-862 (CWE-639 for BOLA).
- The location is the route's file and line, with `METHOD full path` as the resource. The fingerprint and merge key survive the route moving.
- A finding stores no evidence of its own. It links the route and guard evidence it rests on; an inconsistency also links its guarded siblings' route evidence.
- The occurrence keeps the route, guard status, assurance and missing evidence for display.

**Interim score (model `v1-ctx.4`, replaced by X6).**
- Factors: E from `E_SAST[severity]` without the confidence bonus, T from `T_SAST["auth"]`, context as usual.
- **Every authz finding is capped just under the Medium band, priority Low.** The override is `authz_interim_ceiling_low`, or `hypothesis_ceiling_low` for BOLA.
- Without the cap, two inferred findings landed in the X0 M4 top ten, at ranks 6 and 9, above labelled findings. Pooled nDCG@10 went from 0.991 to 0.902. How an inferred authz finding ranks against scanner findings is the factor-table decision X6 owns ("authz (E for inferred unguarded; hypotheses not above Low)"), so until then authz findings are listed but do not compete. BOLA stays Low in v2 too.
- No other finding's score changes. A test checks that `assurance` has no effect outside `authz`.

**Evaluation.**
- The X0 replay leaves `authz` findings out (`OUTSIDE_X0` in `evaluation/run.py`) and says so in the report. The X0 labels were written before any ranking; labelling a new class after seeing its ranks would break that rule.
- Authz findings get labels with their own scenarios: X6 or later, F-4-1.

**Graph edges.**
- UNGUARDED: internet → endpoint, inferred. It is built for an unguarded-sensitive or inconsistent finding on a route of a service with an EXPOSES edge.
- BOLA_SUSPECT: endpoint → data store, hypothesis. It is built for a BOLA finding, to every data store the route's manifest service connects to.
- Both rest on the finding's route evidence. They are stored **without a probability**, like RUNS_IMAGE, so they are not traversable: no path, effective impact or score can change. This is checked by a property test over random authz findings, and in a db test.
- Endpoint nodes exist only where such an edge does.

**Manual verification list.** `GET /scans/{id}/authz/manual?kind=` returns:
- every open BOLA hypothesis with the checks that would settle it;
- every route a manifest rule could not be checked against;
- every `unresolved`, `unknown_framework` and `custom` route.

## Consequences
- (+) Only a fully resolved "no guard" ever becomes an unguarded or inconsistent finding. A property test over random inventories checks that.
- (+) Labelled suite (three apps, 36 routes):
  - inconsistency 4 TP, 0 FP, 0 FN;
  - unguarded-sensitive 3 TP, 2 FP (a contact form and a feedback form), 0 FN;
  - policy 1/1;
  - BOLA 6 TP and 1 FP (a public catalogue), all low hypotheses.
- (+) NodeGoat at `c5cb68a`: all 20 routes resolve (8 were `unresolved`). No authz issue is raised: its unguarded routes are login, signup, logout and the tutorial.
- (−) Unguarded-sensitive precision is 0.6 on the suite, below plan §6's 0.8. A public form looks like any other unguarded write. The manifest has no "public" declaration yet; that would be a new field, so it is left to the owner.
- (−) BOLA needs the handler's code in the route's file. NodeGoat's documented IDOR (`/allocations/:userId`, handler `allocationsHandler.displayAllocations` in another file) is therefore not raised: a recall gap until handlers are resolved across files.
- (−) The ownership words are a heuristic. A comparison against `owner` on an unrelated object suppresses a hypothesis.
- (−) Until X6, an authz finding never ranks above Low, however real.

## Rejected
- **Scoring inferred authz findings by the SAST table without a cap.** It moves the frozen X0 ranking before risk v2 has decided authz factors (plan §8: no weight tuning against the baseline).
- **Labelling the new findings in the X0 scenarios.** The labels would be written after seeing the ranks.
- **A probability for UNGUARDED / BOLA_SUSPECT now.** A new attack-transition probability is a factor-table decision (X6). A hypothesis edge would not change scores anyway (ADR-0020), but an inferred UNGUARDED edge would.
- **A `routes` or `authz_findings` table.** Findings, occurrences and evidence already hold everything; no migration.
