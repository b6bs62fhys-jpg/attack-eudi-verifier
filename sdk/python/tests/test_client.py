import json
from typing import Dict, List, Mapping, Optional, Tuple

import pytest

from eudi_verify_sdk import (
    ApiError,
    AttackClient,
    CreateRequestInput,
    DirectPostEnvelope,
    LivenessResponse,
    ReadinessResponse,
)
from eudi_verify_sdk.client import HttpResponse, Transport


class FakeTransport:
    def __init__(self, response: HttpResponse) -> None:
        self.response = response
        self.calls: List[Tuple[str, str, Dict[str, str], Optional[bytes]]] = []

    def __call__(self, method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
        self.calls.append((method, url, dict(headers), body))
        return self.response


def response(status: int, body: object) -> HttpResponse:
    return HttpResponse(status, json.dumps(body).encode("utf-8"))


def test_creates_request_with_bearer() -> None:
    transport = FakeTransport(response(201, {
        "sessionId": "vs_test",
        "state": "vs_test",
        "expiresAt": 1768320000,
        "requestObject": "eyJ.test",
        "responseUri": "https://verifier.example/direct_post",
        "requestObjectUri": "https://verifier.example/request",
    }))
    client = AttackClient("https://verifier.example", "test-key", transport)

    result = client.create_presentation_request(CreateRequestInput(claims=["age_over_18"]))

    assert result.session_id == "vs_test"
    assert transport.calls[0][2]["authorization"] == "Bearer test-key"


def test_submits_presentation() -> None:
    transport = FakeTransport(response(200, {"ok": True, "valid": True}))
    client = AttackClient("https://verifier.example", transport=transport)

    result = client.submit_presentation(response="compact-jwe")

    assert result.valid is True


def test_liveness_readiness_and_metrics_cover_the_operational_routes() -> None:
    # Die drei Betriebsrouten fehlten im Client, obwohl die Spec sie seit
    # Paket 1 fuehrt. generate:check bewacht nur generated.ts, nicht von
    # Hand geschriebene Clients, deshalb steht hier die Abdeckung.
    live = FakeTransport(response(200, {"ok": True, "status": "live", "app": "attack-service"}))
    client = AttackClient("https://verifier.example", transport=live)
    liveness = client.liveness()
    assert liveness == LivenessResponse(ok=True, status="live", app="attack-service")
    assert live.calls[-1][1] == "https://verifier.example/live"
    # Betriebsrouten sind oeffentlich, es darf kein Authorization-Header laufen.
    assert "authorization" not in live.calls[-1][2]

    ready = FakeTransport(response(200, {"ok": True, "status": "ready", "checks": {"config": "ok"}}))
    client = AttackClient("https://verifier.example", transport=ready)
    readiness = client.readiness()
    assert readiness == ReadinessResponse(ok=True, status="ready", checks={"config": "ok"})

    metrics = FakeTransport(HttpResponse(200, b"# HELP attack_http_requests_total x\n"))
    client = AttackClient("https://verifier.example", transport=metrics)
    assert client.metrics().startswith("# HELP attack_http_requests_total")


def test_readiness_treats_503_as_an_answer_not_an_error() -> None:
    # not_ready ist eine gueltige Antwort auf genau diese Frage. Der Dienst
    # antwortet dafuer mit 503; ein Aufrufer darf daran kein ApiError sehen.
    transport = FakeTransport(response(503, {
        "ok": False,
        "status": "not_ready",
        "checks": {"issuer_trust": "failed", "ocsp": "degraded"},
    }))
    client = AttackClient("https://verifier.example", transport=transport)

    readiness = client.readiness()

    assert readiness.ok is False
    assert readiness.status == "not_ready"
    assert readiness.checks["issuer_trust"] == "failed"


def test_direct_post_422_is_a_result_not_an_error() -> None:
    # /direct_post ist die oeffentliche Wallet-Route: es gab dort nichts zu
    # authentifizieren. Eine abgelehnte Praesentation traegt 422 und den
    # konkreten Grund im Body, also ein Ergebnis und kein Fehler.
    client = AttackClient(
        "https://verifier.example",
        transport=FakeTransport(response(422, {"ok": False, "valid": False, "error": "unknown_state"})),
    )

    result = client.submit_presentation(response="compact-jwe")

    assert result.ok is False
    assert result.valid is False
    assert result.error == "unknown_state"


def test_direct_post_still_raises_for_request_errors() -> None:
    # Gegenprobe: 422 ist der einzige Fehlerstatus, der eine Ablehnung traegt.
    # 401 und 413 sind Fehler der Anfrage und muessen eine Ausnahme loesen.
    # Vorher liess allow_error_response jeden Status durch, auch 500.
    for status, code in ((401, "unauthorized"), (413, "payload_too_large"), (500, "internal_error")):
        client = AttackClient(
            "https://verifier.example",
            transport=FakeTransport(response(status, {"error": code})),
        )
        with pytest.raises(ApiError) as error:
            client.submit_presentation(response="compact-jwe")
        assert error.value.status == status
        assert error.value.code == code


def test_maps_api_error() -> None:
    client = AttackClient("https://verifier.example", transport=FakeTransport(response(401, {"error": "unauthorized"})))

    with pytest.raises(ApiError) as error:
        client.get_result("missing")

    assert error.value.status == 401
    assert error.value.code == "unauthorized"
