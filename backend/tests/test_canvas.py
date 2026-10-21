from __future__ import annotations

import uuid
from typing import Any

from riskgraph.modules.scans.orchestration import build_canvas
from riskgraph.shared.config import Settings
from riskgraph.shared.vocabulary import ScannerName


def test_canvas_shape_and_queues(settings: Settings) -> None:
    """clone → chord(run_scanner x 4) → collect → analyze → finalize.

    Celery folds the tasks after a chord into the chord body; behaviour is identical.
    """
    sid = uuid.uuid4()
    canvas: Any = build_canvas(sid, list(ScannerName), settings)
    clone, chord = canvas.tasks
    assert clone.task == "riskgraph.scans.clone" and clone.args == (str(sid),)
    assert clone.options["queue"] == "scan"

    header = list(chord.tasks)
    assert {t.args[1] for t in header} == {s.value for s in ScannerName}
    assert all(t.task == "riskgraph.scans.run_scanner" for t in header)
    assert all(t.options["queue"] == "scan" and t.immutable for t in header)
    trivy = next(t for t in header if t.args[1] == "trivy")
    assert trivy.options["time_limit"] == settings.timeout_trivy_s + 120

    body = [t.task for t in chord.body.tasks]
    assert body == [
        "riskgraph.scans.collect",
        "riskgraph.scans.analyze",
        "riskgraph.scans.finalize",
    ]
    collect = chord.body.tasks[0]
    assert not collect.immutable  # receives the header results
    assert all(t.options["queue"] == "analysis" for t in chord.body.tasks)
