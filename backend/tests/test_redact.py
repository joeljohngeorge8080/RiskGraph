from __future__ import annotations

from riskgraph.modules.scanners import SCANNERS, scrub
from riskgraph.modules.scanners.redact import MASK, derive_key, mask, secret_hmac
from riskgraph.shared.config import Settings
from riskgraph.shared.vocabulary import ScannerName

KEY = b"k" * 32
RAW = "AKIA" + "ZZZZ5HHHFPZAM2QY"


def test_gitleaks_redaction_removes_every_raw_field() -> None:
    doc = [
        {
            "RuleID": "aws-access-token",
            "Secret": RAW,
            "Match": f"key = {RAW}",
            "Line": f"x={RAW}",
            "File": "a",
        }
    ]
    clean, secrets = SCANNERS[ScannerName.GITLEAKS].redact(doc, KEY)
    assert secrets == {RAW}
    assert RAW not in repr(clean)
    assert clean[0]["SecretHMAC"] == secret_hmac(KEY, RAW)
    assert clean[0]["SecretMasked"].startswith("AKIA")


def test_hmac_is_keyed_and_deterministic(settings: Settings) -> None:
    key = derive_key(settings)
    assert secret_hmac(key, RAW) == secret_hmac(key, RAW)
    assert secret_hmac(key, RAW) != secret_hmac(b"other-key", RAW)


def test_snippet_fields_are_dropped() -> None:
    trivy = {"Results": [{"Secrets": [{"RuleID": "x", "Code": {"Lines": [RAW]}, "Match": RAW}]}]}
    clean, _ = SCANNERS[ScannerName.TRIVY].redact(trivy, KEY)
    assert RAW not in repr(clean)
    semgrep = {
        "results": [{"extra": {"lines": RAW, "metavars": {"$X": {"abstract_content": RAW}}}}]
    }
    assert RAW not in repr(SCANNERS[ScannerName.SEMGREP].redact(semgrep, KEY)[0])
    checkov = [{"results": {"failed_checks": [{"code_block": [[1, RAW]], "file_abs_path": "/w"}]}}]
    assert RAW not in repr(SCANNERS[ScannerName.CHECKOV].redact(checkov, KEY)[0])


def test_scrub_removes_secrets_from_any_report() -> None:
    doc = {"a": [f"prefix {RAW} suffix", {"b": RAW}], "n": 1, "short": "abc"}
    clean = scrub(doc, {RAW, "abc"})  # too-short "secrets" are ignored
    assert RAW not in repr(clean)
    assert clean["a"][0] == f"prefix {MASK} suffix"
    assert clean["short"] == "abc" and clean["n"] == 1


def test_mask_never_shows_short_secrets() -> None:
    assert "hunter2" not in mask("hunter2")
    assert mask("x" * 40).endswith("(40 chars)")
