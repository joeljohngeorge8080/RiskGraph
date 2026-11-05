"""Reject explanations that say anything the evidence does not (blueprint §15).

A draft fails when it cites an unknown evidence id, rests a reason only on repository
text (``S*`` snippets are untrusted), states a number or a URL the evidence does not
contain, breaks a length limit, or gives no reason. The checks are
mechanical on purpose: they hold whatever the model, the prompt or the repository says.

Error messages are stored and fed back to the model, so they never quote the draft: a
rejected reply may carry text injected through the repository.
"""

from __future__ import annotations

import re

from riskgraph.modules.explain.draft import ExplanationDraft
from riskgraph.modules.explain.evidence import EvidencePack, norm

MAX_SUMMARY_WORDS = 80
MAX_CLAIM_WORDS = 40
MAX_TEXT_WORDS = 70
# A number not glued to a letter: "F1", "L3", "v1" and "CVE-2020-1747"'s letters are ids,
# but "2020" and "1747" after the hyphen are still checked against the evidence.
_NUMBER = re.compile(r"(?<![A-Za-z\d.])\d+(?:\.\d+)?(?!\d)")
_URL = re.compile(r"(?:https?://|www\.)[^\s)\"'>]+", re.IGNORECASE)


def _words(text: str) -> int:
    return len(text.split())


def _texts(d: ExplanationDraft) -> list[str]:
    return [d.summary, d.impact, d.caveats, *(r.claim for r in d.reasons), *d.remediation_steps]


def validate(draft: ExplanationDraft, pack: EvidencePack) -> list[str]:
    errors: list[str] = []
    known = pack.ids()
    if not draft.reasons:
        errors.append("at least one reason is required")
    for i, reason in enumerate(draft.reasons, 1):
        if not reason.evidence_ids:
            errors.append(f"reason {i} cites no evidence id")
        for eid in reason.evidence_ids:
            if eid not in known:
                errors.append(f"reason {i} cites an evidence id that does not exist")
        if reason.evidence_ids and all(e.startswith("S") for e in reason.evidence_ids):
            errors.append(f"reason {i} rests only on untrusted repository text (S ids)")
        if _words(reason.claim) > MAX_CLAIM_WORDS:
            errors.append(f"reason {i} is longer than {MAX_CLAIM_WORDS} words")
    if _words(draft.summary) > MAX_SUMMARY_WORDS:
        errors.append(f"summary is longer than {MAX_SUMMARY_WORDS} words")
    for name, text in (("impact", draft.impact), ("caveats", draft.caveats)):
        if _words(text) > MAX_TEXT_WORDS:
            errors.append(f"{name} is longer than {MAX_TEXT_WORDS} words")
    for i, step in enumerate(draft.remediation_steps, 1):
        if _words(step) > MAX_CLAIM_WORDS:
            errors.append(f"remediation step {i} is longer than {MAX_CLAIM_WORDS} words")

    allowed = pack.numbers()
    evidence_text = pack.canonical_json()
    unknown_numbers: set[str] = set()
    for text in _texts(draft):
        for raw in _NUMBER.findall(text):
            # the evidence side carries the rounded and percentage spellings; the draft's
            # number must equal one of them, never be rounded itself to fit
            if norm(float(raw)) not in allowed:
                unknown_numbers.add(raw)
        for url in _URL.findall(text):
            if url.rstrip(".,;:") not in evidence_text:
                errors.append("a URL that is not in the evidence")
    if unknown_numbers:
        # digits only (the regex guarantees it), so listing them carries no injected text
        listed = ", ".join(sorted(unknown_numbers, key=float)[:5])
        errors.append(f"numbers not in the evidence: {listed}")
    return errors
