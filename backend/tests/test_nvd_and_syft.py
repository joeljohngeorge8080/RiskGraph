"""NVD CVSS parsing (P7) and Syft inventory parsing (P5). Pure; no network."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from riskgraph.modules.context.feeds import parse_nvd_cvss
from riskgraph.modules.scanners.syft.parser import components, count


def _nvd(metrics: dict[str, Any]) -> dict[str, Any]:
    return {"vulnerabilities": [{"cve": {"id": "CVE-2021-44228", "metrics": metrics}}]}


def test_prefers_v31_primary_over_other_entries() -> None:
    body = _nvd(
        {
            "cvssMetricV31": [
                {
                    "type": "Secondary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                        "baseScore": 1.0,
                    },
                },
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseScore": 10.0,
                    },
                },
            ]
        }
    )
    found = parse_nvd_cvss(body)
    assert found is not None
    assert found.version == "3.1" and found.base == Decimal("10.0")
    assert found.vector.startswith("CVSS:3.1/AV:N")


def test_falls_back_to_v30_then_v40() -> None:
    v30 = _nvd(
        {
            "cvssMetricV30": [
                {
                    "cvssData": {
                        "version": "3.0",
                        "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "baseScore": 7.5,
                    }
                }
            ]
        }
    )
    assert parse_nvd_cvss(v30) is not None and parse_nvd_cvss(v30).version == "3.0"  # type: ignore[union-attr]
    v40_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    v40 = _nvd(
        {
            "cvssMetricV40": [
                {"cvssData": {"version": "4.0", "vectorString": v40_vector, "baseScore": 9.3}}
            ]
        }
    )
    assert parse_nvd_cvss(v40) is not None and parse_nvd_cvss(v40).version == "4.0"  # type: ignore[union-attr]


def test_malformed_responses_yield_none_not_exceptions() -> None:
    assert parse_nvd_cvss(None) is None
    assert parse_nvd_cvss({"vulnerabilities": []}) is None
    assert parse_nvd_cvss(_nvd({"cvssMetricV31": "nope"})) is None
    assert (
        parse_nvd_cvss(
            _nvd({"cvssMetricV31": [{"cvssData": {"vectorString": "x", "baseScore": 11}}]})
        )
        is None
    )
    assert (
        parse_nvd_cvss(
            _nvd({"cvssMetricV31": [{"cvssData": {"vectorString": "x" * 300, "baseScore": 5}}]})
        )
        is None
    )


def test_syft_components_are_deduplicated_and_capped_text() -> None:
    doc = {
        "components": [
            {
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
                "properties": [{"name": "syft:location:0:path", "value": "requirements.txt"}],
            },
            {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
            {"name": "", "purl": "pkg:npm/x@1"},
            "not a dict",
            {"name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"},
        ]
    }
    parsed = components(doc)
    assert [c.name for c in parsed] == ["requests", "express"]
    assert parsed[0].location == "requirements.txt"
    assert parsed[0].ecosystem == "pypi" and parsed[1].ecosystem == "npm"
    assert count(doc) == 2


def test_syft_tolerates_garbage() -> None:
    assert components(None) == [] and components({"components": "x"}) == []
    long = components({"components": [{"name": "a", "purl": "p" * 9000}]})
    assert len(long[0].purl) == 512  # text is capped before it is stored
