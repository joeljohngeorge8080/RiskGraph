# Commit SHA map (history rewrite, 2026-11-05)

The branch history was rewritten on 2026-11-05 so that no commit names an AI tool as author, committer or co-author. File contents did not change: the tree of the new tip is identical to the old one, and the 102 commits have the same order and subjects. Every commit after the first MVP commit got a new SHA.

Older notes, session reports and `HISTORY.md` quote **old** SHAs. Look them up here. `STATE.md`, `HANDOFF.md` and the run book were updated to the new ones.

| Old | New | Subject |
|---|---|---|
| `d8b2abc` | `367d9f8` | Add MVP: scan a GitHub repo with four scanners, merge and prioritize |
| `3c44f97` | `ed61cfa` | Merge cloud session MVP work (cloud MVP branch) |
| `1ccaa41` | `b8ba378` | Score findings with deployment context from riskgraph.yaml |
| `392e68f` | `e9fb382` | Extend MVP level 2 with reachability, attack paths, triage and history |
| `d253adc` | `3b42f3a` | Fix CI action pin, local db test ports and test-client warnings |
| `e708cbb` | `ee4972b` | Bump certifi to 2026.10.19 for GHSA-6q48-6c7w-9gw2 |
| `74b40f3` | `987ac1a` | Add a graphify knowledge graph of the repo |
| `8e8c4db` | `154d085` | Housekeeping: commit graph, ignore graphify hook outputs, localise tool settings |
| `f86a986` | `78c207d` | Run scanners as hardened containers with pinned images |
| `e92d6f4` | `77ab646` | Store the SBOM per scan and attach SCA findings to their packages |
| `0793048` | `6dd38e2` | Refresh NVD scores in the background and read Kubernetes and Compose assets |
| `a56c7be` | `d045959` | Add L3 reachability for Python: vulnerable calls reached from entry points |
| `47c2c20` | `fa4cb90` | Cancel scans, recover dead workers and clean workspaces after container runs |
| `5def368` | `3f6b723` | Update tests, phase notes and handoff for the container runner, SBOM and L3 |
| `c031943` | `081aa54` | Rebuild the graphify graph for the new modules |
| `08d5181` | `30b78c1` | Join Kubernetes Services, Ingress and RBAC per workload and score its privilege |
| `8ecdf63` | `73a9a7c` | Propose the A-D expansion architecture and phased plan; update handoff |
| `bc34f75` | `bbb36f0` | Map Semgrep findings to their enclosing function and type Semgrep secrets as secrets |
| `43c03e3` | `592fa4b` | Enforce security-graph invariants and add the "what can reach X" query |
| `91d5219` | `94e361c` | Pre-filter attack-path search by hop distance and add scenario E |
| `e9fa0f6` | `87e1b72` | Add GET /risks and test the risk model against the blueprint scenarios |
| `4862bbd` | `5cab7a6` | Make the expansion plan phase-based only and move closed items out of X0 |
| `943be49` | `ac52710` | Explain findings from their evidence with a local model and a template fallback |
| `9a66703` | `5ca4e2a` | Rebuild the graphify graph after P7-P12 |
| `3d16a7c` | `d3e4039` | Update handoff for P7-P12 |
| `bd4e43c` | `1b9f593` | X0 part 1: evaluation scenarios A-E, recorder and recorded fixtures |
| `2d49092` | `17df38d` | X0: offline replay, baselines M1/M2, metrics and BASELINE.md |
| `e165f14` | `e03ddf5` | Load the explanation model with the stack and unload it on stop |
| `de9f218` | `9669c41` | Reinstall frontend packages when the lockfile changes |
| `d9c92b2` | `eef5262` | Rebuild the graphify graph after X0 and the model lifecycle work |
| `299d419` | `9885ff6` | X1: give every graph edge evidence and an assurance level |
| `d3bdb3d` | `46291e2` | Rebuild the graphify graph after X1 |
| `987836b` | `a90dcbc` | X2 part 1: flag end-of-life runtimes and record advisory freshness |
| `26afe03` | `b1e5123` | Rebuild the graphify graph after X2 part 1 |
| `4b8eeee` | `306c69e` | Check that scheduled runs can push this branch |
| `ce6ec33` | `e40bd61` | Record image scan fixtures and add the run book for the six-day build |
| `f056a4f` | `284f7a3` | Keep the graph output out of the nightly commits |
| `d701718` | `affcdd3` | Plan day 1: image scanning and a graph without a manifest |
| `1f6f069` | `250b022` | Allow Trivy's cache variable in scanner containers |
| `62e7c50` | `4ecac78` | Fix the type of the container profile test parameter |
| `e82138a` | `d55c4e3` | Parse trivy image reports into findings scoped by image |
| `86bb13c` | `2ac6bca` | Scan the public images a repository names |
| `78cc007` | `343d5ff` | Build the graph from Compose and Kubernetes when there is no manifest |
| `e657214` | `cefeabc` | Keep derived graph keys within their column |
| `10f3eb8` | `8caaadf` | Write up day 1: image scanning and the graph without a manifest |
| `ec6c1c9` | `d5f74ef` | Plan day 2: assurance-aware paths and tier-1 taint rules |
| `ccee5e9` | `2a6a331` | Keep hypothesis paths from crowding out the paths that set scores |
| `ea5a710` | `28cd95a` | List attack paths by assurance and say what each hypothesis lacks |
| `eb26c3b` | `107c60a` | Expect attack paths grouped by assurance in the level 2 test |
| `8aa9677` | `b9bafe9` | Measure graph build and search together at 5k nodes and 20k edges |
| `b1398fb` | `d9c6436` | Add tier-1 taint rules generated from RiskGraph's own catalogue |
| `68c25b5` | `938fbc7` | Build the 40-case taint suite as code, with a scorer |
| `f81b9cc` | `507290f` | Join taint hits to generic findings by line instead of pairwise |
| `6a822ab` | `651a763` | Write up day 2: assurance-aware paths and tier-1 taint |
| `bd8c075` | `e6978a7` | Plan day 3: Joern is gated, so tier-1 hardening and routes early |
| `1cc66af` | `99aa438` | Join a taint hit to the generic finding whose call spans its line |
| `0a068fa` | `25d2eaa` | Record routes and their possible guards in the extractor |
| `1de154c` | `0f0b15e` | Add the route inventory with a guard catalogue and a labelled suite |
| `ea01689` | `da7e4c7` | Serve each scan's route inventory at /scans/{id}/routes |
| `e821fe2` | `556f7fd` | Keep the route inventory linear in large repositories |
| `4aed1eb` | `4e9161d` | Keep Express routes whose path is a template literal |
| `51f7b15` | `6c6d7d9` | Write up day 3: Joern gated, tier-1 hardening and the route inventory |
| `805bd8f` | `fabd975` | Plan day 4: X5 part 2, since part 1 was finished a day early |
| `bd258f4` | `38fe24c` | Record handler bodies, call sites and exported functions in the extractor |
| `9d07ec7` | `f946cde` | Bind an Express app passed into a routes module to the caller's app |
| `7ea70cf` | `b11a300` | Add an optional authz section to the manifest |
| `1fd675c` | `673652d` | Find authorization issues in the route inventory |
| `fe25182` | `5fe702b` | Add the labelled authorization suite and compare reads with reads |
| `b7df109` | `8bce796` | Turn authorization issues into findings with an interim score |
| `f387139` | `e34aa54` | Serve the manual verification list at /scans/{id}/authz/manual |
| `c4a55df` | `fdd42de` | Add UNGUARDED and BOLA_SUSPECT edges to the security graph |
| `8996a79` | `2a57709` | Keep the authz analysis linear on large inputs |
| `484f686` | `217d403` | Write up day 4: X5 part 2, authorization findings |
| `70d4f6b` | `fd1f1ca` | Plan day 5: risk v2 |
| `be72147` | `333bf64` | Add risk model v2 factor tables |
| `a84ffb9` | `c61b9ee` | Score image packages in the context of their services; add scenarios F-H |
| `c6e0649` | `51870e7` | Build the image context once per scan |
| `0fae2cc` | `d8b4cde` | Record risk model v2 in ADR-0024 and the X6 chapter |
| `0716d64` | `f15da5b` | Write up day 5: risk v2 |
| `044affc` | `574b263` | Plan day 6: integration pass |
| `de027d7` | `2e1a802` | Teach the frontend the source types and producers added since the MVP |
| `f9a8e81` | `3515c8b` | Give runtime and authorization findings their own fallback steps |
| `43842f1` | `1e72460` | Bring the example manifest in line with credential links |
| `1a93885` | `0749eb6` | Write up day 6 and the six-day final report |
| `de0f3bc` | `71780e0` | Run the local tasks: image stage, taint rules, Joern spike, live model |
| `6329243` | `76f6be4` | Answer F-L-1 and F-L-2: tier-1 taint has no steps, explain.3 prompt |
| `19ba9e7` | `9a3dcb3` | Record the owner's answers to the open flags |
| `b94e31b` | `3a145c9` | Treat Compose database images as data stores |
| `11a3a9e` | `78471b9` | Read database connections from Compose environment URLs |
| `8d659f8` | `e656791` | Write the session 9 handoff: what is done and what is left |
| `04d0dc0` | `bf4827f` | Let the manifest declare routes public on purpose (F-4-2) |
| `4295244` | `c85c571` | Give effective impact only to findings that are an attack step (F-5-1) |
| `5333439` | `81333c2` | Keep the explanation cap test exercising the cap |
| `84f0183` | `3c9b750` | Add Joern as tier-2 taint in an opt-in deep scan profile (F-3-1) |
| `99ae3ca` | `e4a6e21` | Write the authorization scenario and its labels before running it (F-4-1) |
| `fd3dbb4` | `bafbc85` | Evaluate authorization findings on their own scenario (F-4-1) |
| `24dea05` | `4d96094` | Add the X8 evaluation harness and run book |
| `1c82fb3` | `05e12de` | Pin CI actions by commit and bring the tooling pins in line |
| `9fffd52` | `0592ac6` | Write the handover docs for collaborators |
| `1dfbd0a` | `f4ba3fa` | Rebuild the code graph for the handover |
| `05f22a9` | `d2f8e96` | Allowlist two gitleaks false positives that fail the PR scan |
| `c2ff288` | `eeb1c82` | Update the handover notes now that the branch is pushed |
