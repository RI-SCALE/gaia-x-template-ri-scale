"""HTTP contracts of gx/gxdch.py, with the network replaced by a scripted session."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest
import requests

from gx.errors import StepError
from gx.gxdch import NOTARY_RETRY_DELAYS, Gxdch

from .conftest import Deployment


@dataclass
class Response:
    status_code: int
    text: str = ""
    content: bytes = b""

    def json(self) -> Any:
        import json
        return json.loads(self.text)


@dataclass
class Session:
    """Answers requests from a list (or a function) and records them."""

    answers: list[Response] | Callable[..., Response]
    calls: list[dict[str, Any]] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)

    def request(self, method: str, url: str, **kwargs: Any) -> Response:
        self.calls.append({"method": method, "url": url, **kwargs})
        if callable(self.answers):
            return self.answers(method, url, **kwargs)
        return self.answers.pop(0)


def client(deployment: Deployment, answers) -> tuple[Gxdch, Session, list[float]]:
    slept: list[float] = []
    http = Gxdch(deployment.config(), sleep=slept.append)
    session = Session(answers)
    http.session = session
    return http, session, slept


LRN = "eyJhbGciOiJQUzI1NiJ9.e30.c2ln"


def test_notary_request(deployment: Deployment) -> None:
    http, session, _ = client(deployment, [Response(200, LRN)])
    assert http.registration_number_vc("https://gx.test/gaia-x/lrn.jwt", "https://gx.test/gaia-x/lrn.jwt#cs") == LRN
    call = session.calls[0]
    assert call["url"].endswith("/development/registration-numbers/vat-id/NL000000000B01")
    assert call["params"] == {"vcId": "https://gx.test/gaia-x/lrn.jwt", "subjectId": "https://gx.test/gaia-x/lrn.jwt#cs"}


def test_notary_retries_transient_errors(deployment: Deployment) -> None:
    busy = Response(502, '{"message":"rate limiting in the VAT API"}')
    http, session, slept = client(deployment, [busy, Response(503), Response(200, LRN)])
    assert http.registration_number_vc("v", "s") == LRN
    assert slept == list(NOTARY_RETRY_DELAYS[:2]) and len(session.calls) == 3


def test_notary_gives_up(deployment: Deployment) -> None:
    http, session, slept = client(deployment, lambda *a, **k: Response(502, "still busy"))
    with pytest.raises(StepError, match="HTTP 502.*still busy"):
        http.registration_number_vc("v", "s")
    assert slept == list(NOTARY_RETRY_DELAYS)


def test_notary_refusal_is_not_retried(deployment: Deployment) -> None:
    http, session, slept = client(deployment, [Response(400, '{"message":"invalid VAT ID"}')])
    with pytest.raises(StepError, match="invalid VAT ID"):
        http.registration_number_vc("v", "s")
    assert slept == [] and len(session.calls) == 1


def test_network_errors_become_step_errors(deployment: Deployment) -> None:
    def fail(*args: Any, **kwargs: Any) -> Response:
        raise requests.ConnectionError("no route to host")

    http, _, _ = client(deployment, fail)
    with pytest.raises(StepError, match="no route to host"):
        http.fetch("https://gx.test/cert.pem")


def test_registry_reads(deployment: Deployment) -> None:
    config_json = '{"schema:name":"evsslonly","https://w3id.org/okn/o/sd#hasFixedValue":"true"}'
    shapes = ('gx:IssuerShape a sh:NodeShape ; sh:property [ sh:in ( "' + "a" * 64 + '" "' + "b" * 64
              + '" ) ] ; sh:targetClass gx:Issuer .\ngx:Other "' + "c" * 64 + '"')
    http, session, _ = client(deployment, [Response(200, content=config_json.encode()),
                                           Response(200, content=shapes.encode()),
                                           Response(200, '{"result":true}'),
                                           Response(409, '{"message":"Root certificate is not self-signed"}')])
    assert http.ev_only() is True
    assert http.accepted_tandc_hashes() == {"a" * 64, "b" * 64}
    assert session.calls[1]["url"].endswith("/development/shapes/development")
    assert http.chain_accepted("https://gx.test/cert.pem") == (True, 'HTTP 200: {"result":true}')
    ok, detail = http.chain_accepted("https://gx.test/cert.pem")
    assert not ok and "not self-signed" in detail


def test_unreadable_registry_values(deployment: Deployment) -> None:
    http, _, _ = client(deployment, lambda *a, **k: Response(500))
    assert http.ev_only() is None
    assert http.accepted_tandc_hashes() == set()


def test_submit(deployment: Deployment) -> None:
    http, session, _ = client(deployment, [Response(201, "eyJ.compliance.vc"), Response(409, '{"message":"x"}')])
    assert http.submit("vp.jwt", "https://gx.test/gaia-x/compliance-vc.jwt") == "eyJ.compliance.vc"
    call = session.calls[0]
    assert call["params"] == {"vcid": "https://gx.test/gaia-x/compliance-vc.jwt"}
    assert call["headers"]["Content-Type"] == "application/vp+jwt"
    assert call["url"].endswith("/development/api/credential-offers/standard-compliance")
    with pytest.raises(StepError, match="HTTP 409"):
        http.submit("vp.jwt", "v")


@pytest.mark.parametrize("did, url", [
    ("did:web:gx.test", "https://gx.test/.well-known/did.json"),
    ("did:web:compliance.lab.gaia-x.eu:development", "https://compliance.lab.gaia-x.eu/development/did.json"),
    ("did:web:localhost%3A8443", "https://localhost:8443/.well-known/did.json"),
])
def test_did_web_resolution(deployment: Deployment, did: str, url: str) -> None:
    http, session, _ = client(deployment, [Response(200, '{"id": "x"}')])
    assert http.resolve_did_web(did) == {"id": "x"}
    assert session.calls[0]["url"] == url


def test_did_web_rejects_other_methods(deployment: Deployment) -> None:
    http, _, _ = client(deployment, [])
    with pytest.raises(StepError):
        http.resolve_did_web("did:key:z6Mk")
