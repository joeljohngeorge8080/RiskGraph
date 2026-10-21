from __future__ import annotations

import json
from decimal import Decimal

import httpx
import pytest
from riskgraph.modules.context import subscores
from riskgraph.modules.context.feeds import EPSS_BATCH, fetch_epss, fetch_kev
from riskgraph.shared.http import OutboundClient, OutboundError


@pytest.mark.parametrize(
    ("vector", "impact", "expl"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 5.9, 3.9),  # 9.8
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 1.4, 3.9),  # 5.3
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 2.7, 2.8),  # 6.1 (XSS)
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, 0.3),
    ],
)
def test_cvss_subscores(vector: str, impact: float, expl: float) -> None:
    sub = subscores(vector)
    assert sub is not None
    assert (sub.impact, sub.exploitability) == (impact, expl)


def test_cvss_rejects_v2_and_garbage() -> None:
    assert subscores("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None
    assert subscores("CVSS:3.1/AV:X") is None


def _client(handler: httpx.MockTransport) -> OutboundClient:
    return OutboundClient(transport=handler)


def test_epss_batches_and_parses() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        cves = request.url.params["cve"].split(",")
        calls.append(request.url.host)
        data = [{"cve": c, "epss": "0.05", "percentile": "0.9", "date": "2026-10-20"} for c in cves]
        data.append({"cve": "CVE-9999-0001", "epss": "0.9"})  # not requested: ignored
        return httpx.Response(200, json={"data": data})

    ids = [f"CVE-2020-{i:05d}" for i in range(EPSS_BATCH + 5)] + ["GHSA-xxxx"]
    out = fetch_epss(_client(httpx.MockTransport(handler)), ids)
    assert len(calls) == 2 and len(out) == EPSS_BATCH + 5
    assert out["CVE-2020-00000"].epss == Decimal("0.05")
    assert "CVE-9999-0001" not in out


def test_kev_falls_back_to_mirror() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "www.cisa.gov":
            return httpx.Response(503)
        body = {"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]}
        return httpx.Response(200, content=json.dumps(body))

    assert fetch_kev(_client(httpx.MockTransport(handler))) == {"CVE-2021-44228": "2021-12-10"}


def test_outbound_refuses_redirects_and_foreign_hosts() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://evil.example/"})

    client = _client(httpx.MockTransport(handler))
    with pytest.raises(OutboundError):
        client.get_json("https://api.first.org/data/v1/epss")
    for url in (
        "https://evil.example/data/",
        "http://api.first.org/data/",
        "https://raw.githubusercontent.com/attacker/repo/x.json",
        "https://api.first.org:8443/data/",
    ):
        with pytest.raises(OutboundError):
            client.get_json(url)


def test_outbound_caps_body_size() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"[" + b"1," * 2000 + b"1]")

    client = OutboundClient(transport=httpx.MockTransport(handler), max_body_bytes=100)
    with pytest.raises(OutboundError):
        client.get_json("https://api.first.org/data/v1/epss")
