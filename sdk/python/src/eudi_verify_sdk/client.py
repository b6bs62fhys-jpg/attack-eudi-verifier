"""Small, typed, dependency-free client for the Attack verifier API."""

from dataclasses import dataclass, field as dataclasses_field
import json
from typing import Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple, Union, cast
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

JsonValue = Union[None, bool, int, float, str, List["JsonValue"], Dict[str, "JsonValue"]]
JsonObject = Dict[str, JsonValue]
VpValue = Union[str, Mapping[str, JsonValue]]
Transport = Callable[[str, str, Mapping[str, str], Optional[bytes]], "HttpResponse"]

# HTTP 422: die Praesentation kam an, wurde aber nicht angenommen. Der
# Ablehnungsgrund steht im Body, deshalb ist das ein Ergebnis und kein Fehler.
# 401 bleibt exklusiv fuer den API-Schluessel, 413 fuer die Groessengrenze.
REJECTED_PRESENTATION = 422

# HTTP 503: /ready antwortet bei nicht bereitem Dienst so. Es ist eine Antwort
# auf die Frage, kein Fehler, deshalb wird sie hier nicht als Ausnahme geworfen.
NOT_READY = 503


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes


class ApiError(Exception):
    """HTTP/API failure with a stable server error code when available."""

    def __init__(self, status: int, code: Optional[str] = None) -> None:
        self.status = status
        self.code = code
        super().__init__(code or "http_" + str(status))


@dataclass(frozen=True)
class CreateRequestInput:
    claims: Optional[Sequence[str]] = None
    vct: Optional[str] = None
    registration_ref: Optional[Mapping[str, str]] = None

    def as_json(self) -> JsonObject:
        result: JsonObject = {}
        if self.claims is not None:
            result["claims"] = list(self.claims)
        if self.vct is not None:
            result["vct"] = self.vct
        if self.registration_ref is not None:
            result["registration_ref"] = dict(self.registration_ref)
        return result


@dataclass(frozen=True)
class CreateRequestOutput:
    session_id: str
    state: str
    expires_at: int
    request_object: str
    response_uri: str
    request_object_uri: str

    @classmethod
    def from_json(cls, value: Mapping[str, JsonValue]) -> "CreateRequestOutput":
        return cls(
            session_id=_required_str(value, "sessionId"),
            state=_required_str(value, "state"),
            expires_at=_required_int(value, "expiresAt"),
            request_object=_required_str(value, "requestObject"),
            response_uri=_required_str(value, "responseUri"),
            request_object_uri=_required_str(value, "requestObjectUri"),
        )


@dataclass(frozen=True)
class LivenessResponse:
    """Antwort von ``GET /live``. Betriebsroute, nicht rate-limitiert."""

    ok: bool
    status: str
    app: Optional[str] = None

    @classmethod
    def from_json(cls, value: Mapping[str, JsonValue]) -> "LivenessResponse":
        return cls(
            ok=_required_bool(value, "ok"),
            status=_required_str(value, "status"),
            app=cast(Optional[str], value.get("app")),
        )


@dataclass(frozen=True)
class ReadinessResponse:
    """Antwort von ``GET /ready``.

    ``not_ready`` ist eine gueltige Antwort und kein Fehler, deshalb wird der
    Status 503 hier nicht als Ausnahme behandelt.
    """

    ok: bool
    status: str
    checks: Mapping[str, str] = dataclasses_field(default_factory=dict)

    @classmethod
    def from_json(cls, value: Mapping[str, JsonValue]) -> "ReadinessResponse":
        checks = cast(Optional[Mapping[str, JsonValue]], value.get("checks"))
        return cls(
            ok=_required_bool(value, "ok"),
            status=_required_str(value, "status"),
            checks=cast(Mapping[str, str], checks) if checks is not None else {},
        )


@dataclass(frozen=True)
class ResultStatus:
    status: str
    result: Optional[Mapping[str, JsonValue]] = None

    @classmethod
    def from_json(cls, value: Mapping[str, JsonValue]) -> "ResultStatus":
        result = value.get("result")
        return cls(status=_required_str(value, "status"), result=cast(Optional[Mapping[str, JsonValue]], result))


@dataclass(frozen=True)
class PresentationResponse:
    ok: bool
    valid: bool
    error: Optional[str] = None

    @classmethod
    def from_json(cls, value: Mapping[str, JsonValue]) -> "PresentationResponse":
        ok = value.get("ok")
        valid = value.get("valid")
        if not isinstance(ok, bool) or not isinstance(valid, bool):
            raise ValueError("PresentationResponse requires boolean ok and valid")
        error = value.get("error")
        return cls(ok=ok, valid=valid, error=error if isinstance(error, str) else None)


@dataclass(frozen=True)
class DirectPostEnvelope:
    vp_token: Mapping[str, Sequence[VpValue]]
    state: str

    def as_json(self) -> JsonObject:
        token: Dict[str, JsonValue] = {
            key: cast(JsonValue, list(values)) for key, values in self.vp_token.items()
        }
        return {"vp_token": token, "state": self.state}


class AttackClient:
    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        transport: Optional[Transport] = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._transport = transport or _urlopen_transport

    def liveness(self) -> LivenessResponse:
        """``GET /live``: Prozess laeuft, ohne API-Schluessel."""
        return LivenessResponse.from_json(_as_object(self._request("GET", "/live", authenticated=False)))

    def health(self) -> Mapping[str, JsonValue]:
        return cast(Mapping[str, JsonValue], self._request("GET", "/health", authenticated=False))

    def readiness(self) -> ReadinessResponse:
        """``GET /ready``: Abhaengigkeiten einzeln.

        Der Dienst antwortet bei ``not_ready`` mit HTTP 503. Das ist eine
        gueltige Antwort auf genau diese Frage und kein Fehler, deshalb wird
        503 hier nicht als Ausnahme geworfen.
        """
        value = self._request(
            "GET",
            "/ready",
            authenticated=False,
            tolerated_statuses=frozenset({NOT_READY}),
        )
        return ReadinessResponse.from_json(_as_object(value))

    def metrics(self) -> str:
        """``GET /metrics``: Prometheus-Text, kein JSON."""
        response = self._transport("GET", self._base_url + "/metrics", {"accept": "text/plain"}, None)
        if not 200 <= response.status < 300:
            raise ApiError(response.status, _error_code(_decode_json(response.body)))
        return response.body.decode("utf-8")

    def create_presentation_request(self, request: Optional[CreateRequestInput] = None) -> CreateRequestOutput:
        body = request.as_json() if request is not None else {}
        value = self._request("POST", "/v1/verification-requests", body=body)
        return CreateRequestOutput.from_json(_as_object(value))

    def get_request_object(self, session_id: str) -> str:
        headers = {"accept": "application/oauth-authz-req+jwt"}
        response = self._transport(
            "GET",
            self._base_url + "/v1/verification-requests/" + _quote(session_id),
            headers,
            None,
        )
        if not 200 <= response.status < 300:
            raise ApiError(response.status)
        return response.body.decode("utf-8")

    def submit_presentation(
        self,
        *,
        response: Optional[str] = None,
        envelope: Optional[DirectPostEnvelope] = None,
    ) -> PresentationResponse:
        if (response is None) == (envelope is None):
            raise ValueError("provide exactly one of response or envelope")
        body: JsonObject
        if response is not None:
            body = {"response": response}
        else:
            assert envelope is not None
            body = envelope.as_json()
        value = self._request(
            "POST",
            "/direct_post",
            body=body,
            authenticated=False,
            tolerated_statuses=frozenset({REJECTED_PRESENTATION}),
        )
        return PresentationResponse.from_json(_as_object(value))

    def get_result(self, session_id: str) -> ResultStatus:
        value = self._request("GET", "/v1/verification-requests/" + _quote(session_id))
        data = _as_object(value)
        result = data.get("result")
        return ResultStatus(_required_str(data, "status"), cast(Optional[Mapping[str, JsonValue]], result))

    def delete_session(self, session_id: str) -> None:
        self._request("DELETE", "/v1/verification-requests/" + _quote(session_id))

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[JsonObject] = None,
        authenticated: bool = True,
        tolerated_statuses: FrozenSet[int] = frozenset(),
    ) -> JsonValue:
        headers: Dict[str, str] = {"accept": "application/json"}
        if authenticated and self._api_key:
            headers["authorization"] = "Bearer " + self._api_key
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        if payload is not None:
            headers["content-type"] = "application/json"
        response = self._transport(method, self._base_url + path, headers, payload)
        decoded = _decode_json(response.body)
        # `tolerated_statuses` nennt die Fehlerstatus, die ein Ergebnis tragen
        # statt eines Fehlers. Ohne diese Ausnahme wurde jede Antwort
        # ausserhalb 2xx als ApiError geworfen, wodurch eine abgelehnte
        # Praesentation fuer den Aufrufer nicht lesbar war.
        if not 200 <= response.status < 300 and response.status not in tolerated_statuses:
            raise ApiError(response.status, _error_code(decoded))
        return decoded


def _urlopen_transport(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
    request = Request(url, method=method, headers=dict(headers), data=body)
    try:
        with urlopen(request, timeout=10) as response:
            return HttpResponse(response.status, response.read())
    except HTTPError as error:
        return HttpResponse(error.code, error.read())
    except URLError as error:
        raise ApiError(0, "network_error") from error


def _decode_json(body: bytes) -> JsonValue:
    if not body:
        return None
    return cast(JsonValue, json.loads(body.decode("utf-8")))


def _as_object(value: JsonValue) -> Mapping[str, JsonValue]:
    if not isinstance(value, dict):
        raise ValueError("API response is not a JSON object")
    return value


def _error_code(value: JsonValue) -> Optional[str]:
    if isinstance(value, dict):
        error = value.get("error")
        if isinstance(error, str):
            return error
    return None


def _required_bool(value: Mapping[str, JsonValue], key: str) -> bool:
    raw = value.get(key)
    if not isinstance(raw, bool):
        raise ValueError("expected boolean at " + key)
    return raw


def _required_str(value: Mapping[str, JsonValue], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise ValueError("missing string field: " + key)
    return item


def _required_int(value: Mapping[str, JsonValue], key: str) -> int:
    item = value.get(key)
    if not isinstance(item, int) or isinstance(item, bool):
        raise ValueError("missing integer field: " + key)
    return item


def _quote(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")
