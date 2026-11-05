# HANDOFF: resume here (updated 2026-11-05, handover to collaborators)

The project moved from its original owner to collaborators on 2026-11-05. Start with **`docs/handover/README.md`**. Then:
- **`docs/handover/STATE.md`**: what is built and verified, owner items, gotchas.
- **`docs/handover/BACKLOG.md`**: everything left, plus the new scope.
- **`CONTRIBUTING.md`**: the rules.
- **`docs/handover/HISTORY.md`**: every earlier session, verbatim (this file's previous content).

New sessions add a section below, newest first.

## Session 10 (2026-11-05, branch `extended_phase_auto`, PR #3 to `main`): handover
- **Built:**
  - F-4-2 `authz.public` (`bf4827f`);
  - F-5-1 foothold-only effective impact (`c85c571`, `81333c2`);
  - F-3-1 the Joern adapter and the opt-in `deep` profile (`3c9b750`, ADR-0025, migration `d4e8b2c6f1a3`);
  - F-4-1 authz scenario I, labels first (`e4a6e21`, `bafbc85`);
  - the X8 harness and run book (`4d96094`);
  - CI SHA pins and tooling alignment (`05e12de`);
  - these handover docs.
- **Not built, on purpose:**
  - X7: there is no frontend work in the handover. It is in the backlog, and its backend parts (SARIF, `--assurance-min`) are X7-1 and X7-2.
  - The rest of X8 is NOT RUN, with exact steps in the run book.
  - P2 auth was not confirmed for this session, so it is backlog item AUTH-1.
- **Verified:**
  - `make test` 759, `make test-db` 86 (2 e2e skipped), plus 4 perf; `make lint` clean;
  - migration round trip on a fresh DB; `alembic check` clean;
  - X0 byte-identical with and without F-5-1;
  - L-5 through the DockerRunner: 13.1 s, 592 MB.
- **PR #3** is open to `main`; CI is green on all four jobs. A tier-2 E row (ADR-0025) and disabling the nightly routine are still open for the owner (see `STATE.md`).
