# Flags: things that need the owner

A run adds an entry here when the work needs a human decision or permission (RUNBOOK §3), then parks that item and carries on with everything that does not depend on it. **The owner answers by setting `Status: ANSWERED` and writing the answer under `Answer:`.** The next run continues from the resume steps. `OPEN` means: do not build on it.

## Template

```
### F-<day>-<k>: <short title>
- Status: OPEN | ANSWERED | WITHDRAWN
- Phase / step: <X3 part 2, step 2>
- Blocked: <what cannot be done until this is settled>
- Why it needs the owner: <hard stop it hit, or the choice that is the owner's>
- Done meanwhile: <what was built or skipped instead>
- Question: <the exact question, with the options and a recommendation>
- Resume: <exact steps to take once ANSWERED>
- Answer: <owner fills in>
```

## Entries

_None yet._
