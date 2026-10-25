"""Research evaluation (blueprint §25.2, §26; expansion phase X0).

Scenario repositories are generated from the templates in ``scenarios.py`` (never
committed: scenario C holds a fake credential), scanned once with the pinned scanner
images (``record.py``), and replayed offline with a frozen intel snapshot (``run.py``),
so every number in ``docs/evaluation/BASELINE.md`` is reproducible in one command.
"""
