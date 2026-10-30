# ADR-0024: Risk model v2: factor tables for image packages, taint, runtime end-of-life and authorization findings

Status: accepted · Date: 2026-10-30 · Implements: expansion phase X6 (`docs/proposals/EXPANSION_A-D.md` §4 X6 row, §6 scenarios F–H, §8; `docs/auto/SCHEDULE.md` day 6, done on day 5) · Builds on: ADR-0011 (manifest context scoring), ADR-0013 (paths and effective impact), ADR-0017 (assurance), ADR-0018 (interim EOL score), ADR-0021 (tier-1 taint), ADR-0023 (interim authz score) · Replaces: the interim factors of ADR-0018 and ADR-0023

## Context
X2 to X5 added four kinds of input the v1 model scores with stand-ins:
- packages installed in a container image (X2): reachability "unknown" (0.6), and no context, because their file is the Compose or Kubernetes file that names the image;
- tier-1 taint flows (X4): scored as the generic SAST pattern they merge with;
- runtime end-of-life (X2): a flat interim E 0.5, T 0.6;
- authorization findings (X5): the SAST `auth` row, every one capped under Medium.

The X6 row asks for factor tables for each, model `v2`, the reduction property kept, and scenarios F–H. The plan gives one number (R = 0.5 for image packages). The others are set here, each with its reasoning, **before** the X0 re-run and not adjusted after it (plan §8).

## Decision
Model `v2.1` (`risk/tables.py`, `risk/model.py`). `ScoreInput` gets four fields; each defaults to "absent", and absent means the v1 factor applies.

| Input (`ScoreInput`) | From (`risk/service.input_for`) | Factor |
|---|---|---|
| `image_package` | `package.image` is set | **R = 0.5**, source `not_assessable`. The code that uses the package is not analysed. An observation cannot apply. |
| `taint_cwe`, `taint_confidence` | the best tier-1 member of the merged finding (members, not the representative: after a merge the generic rule usually leads) | **E = max(SAST row, `E_TAINT[cwe][confidence]`)** |
| `eol_age_days` | `data_as_of − eol_date` of a runtime finding (the feed snapshot, never the clock) | **E by age**: < 1 year 0.4, 1–3 years 0.5, ≥ 3 years 0.6; no date (or a date after the snapshot) 0.5, the interim value. T stays 0.6. |
| `assurance` (authz) | as in ADR-0023 | **E = `E_AUTHZ_INFERRED[severity]`**, T = SAST `auth` (0.8). **No interim cap.** A hypothesis keeps `hypothesis_ceiling_low` (≤ 19.99, Low). |

**Taint table** (tier 1, inferred):

| CWE class | HIGH rule | MEDIUM rule |
|---|---|---|
| CWE-89 (SQL), CWE-78 (OS command) | 0.85 | 0.75 |
| CWE-502 (deserialization) | 0.8 | 0.7 |
| CWE-22 (path), CWE-918 (SSRF) | 0.75 | 0.65 |

- A flow traced from an HTTP source to the sink shows the attacker controls the argument; a pattern match only suggests it.
- Query and shell injection with attacker input are directly exploitable. Deserialization needs a gadget chain. Path traversal and SSRF need a useful file or endpoint behind them.
- A MEDIUM-confidence rule (less certain sanitizer coverage) is 0.1 lower. A LOW-confidence rule, or a CWE outside the catalogue, adds nothing.
- The max means a flow never lowers E. For a high-severity, HIGH-confidence SAST hit (0.8) the CWE-22/502/918 rows add nothing. Tier 2 (Joern, F-3-1) would add a verified column.

**End-of-life by age.** An unsupported release gets no fixes, so advisories against it pile up unpatched. The first year is below the interim 0.5 because few have piled up yet. The age is read from the feed's own dates, so replaying the same data gives the same score.

**Authorization table.** High/critical 0.6, medium 0.35, low/info 0.15: 0.1 under the SAST row for High and Medium, 0.05 for Low.
- An unguarded route needs nothing but a request.
- But "no guard" is inferred from a catalogue that can miss a custom guard. The labelled suite's unguarded-sensitive precision is 0.6 (ADR-0023).
- Without manifest context, an inferred high authz finding scores 31.5 (Medium). With full context and a path it can reach Critical.

**Image packages take the context of the services that run them** (`graph/topology.py`, `Topology.image_contexts`, `fill_unknown`).
- An image finding's file names the image but maps to no service, so before this its exposure, privilege and data were "unknown". A KEV CVE on an internet-facing, cluster-admin workload therefore scored like one with nothing known.
- Now the derived services that run the image give its exposure (`internet_noauth` if any of them is exposed) and its privilege (the highest bound). Source `topology`, confidence low, evidence: the image and the services.
- This is the worst case over those services, like a service's most sensitive store (ADR-0011).
- Only factors the finding's own file leaves unknown are filled, so precedence manifest > Kubernetes > Compose is kept.
- The index is built once per scan.
- The base OS end-of-life finding (`runtime-eol:os:*`) carries the image too and gets the same context. It is not on the graph (only `sca` image packages are).

**Reduction property.** Without the four inputs, v2.1 equals v1-ctx.3 for every non-authz finding:
- a Hypothesis property over random v1 inputs checks that only v1 factor sources appear and that the score is the §14 formula over them;
- a second property checks that explicit "absent" values change nothing;
- the A–E table and every earlier pinned score pass unchanged.

**Monotonicity** (Hypothesis): an older end of support, a taint rule going from absent to MEDIUM to HIGH, and authz from hypothesis to inferred never lower score or priority. The §14.7 property over the v1 ladders is unchanged.

**Scenarios F–H** (`tests/test_risk_scenarios_v2.py`). They run the pipeline's order: context, pass 1, graph, pass 2. Labels were written in `DAY_5_PLAN.md` before the first run:
- F: tier-1 SSRF in an internet API that runs as an admin role with access to instance metadata. The SSRF is on verified paths to both sinks and is Critical.
- G: KEV CVE in an image package of a LoadBalancer workload whose ServiceAccount is bound to `cluster-admin`. It is on an inferred path to the account and is Critical. Without KEV the path is a hypothesis and no score moves.
- H: co-located findings in an isolated service: **0 paths**.
- Pooled, both important findings rank above every other.
- G's sink is the ServiceAccount, not a database: data stores from Compose are F-1-1 (OPEN), and Kubernetes declares none.

`MODEL_VERSION = "v2.1"`.

## Consequences
- (+) X0 re-run: the pooled table and the M4 top 10 are **identical** to the day-4 run, apart from the model line. The X0 scenarios have no image, taint or EOL findings, and authz findings stay outside the set (F-4-1).
- (+) The interim factors of ADR-0018 and ADR-0023 are gone; each new kind of finding has a reasoned table and a source in its factor provenance (`not_assessable`, `taint_tier1`, `runtime_eol`, `authz`, `topology`).
- (−) Image packages without service context drop slightly (R 0.6 → 0.5). With an exposed service they rise, often a lot (X 0.5 → 1.0).
- (−) An inferred authz finding can now outrank scanner findings. That is the point of X6, but it has not been checked against labels yet (F-4-1 proposes an authz scenario with labels written first).
- (−) **Found by scenario F, not changed here (F-5-1):** every code finding of an exposed service is evidence on its EXPLOIT edge and takes the path's effective impact. A weak hash next to the SSRF is Critical (71.1). So are an L1 CVE (a hypothesis-level finding on its own) and a non-KEV image CVE next to a KEV one. The rule predates v2 (§14.4, ADR-0013). Restricting it changes how effective impact is attributed, so it is the owner's call; the measured effect of each option on X0 is in the flag.
- (−) The taint and EOL numbers are reasoned, not measured. L-4 (real Semgrep on the 40-case suite) is the first measurement of tier-1 precision.

## Rejected
- **Scaling E by a confidence multiplier** (e.g. × 0.9 for inferred) instead of a table. The plan asks for "E by CWE and confidence"; a table shows each number and its reason.
- **Adding the taint E to the SAST E** (or a bonus) instead of max. It would let one flow push E past 1 for every severity and break the "a flow never lowers, never doubles" reading.
- **Keeping the authz cap until F-4-1 is answered.** F-4-1 is about the evaluation's labels, not the product's scores, and the X6 row names authz factors as v2's job.
- **A probability for UNGUARDED / BOLA_SUSPECT edges.** The X6 row does not name it, and it would create new inferred paths through endpoints. They stay non-traversable (ADR-0023); a follow-up.
- **Using the clock for EOL age.** A replay of the same snapshot would score differently every day.
