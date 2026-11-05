"""HTTP calls to the GXDCH (Notary, Registry, Compliance, CES) and to public URLs.

Every network failure surfaces as StepError with the service's own message, so
the operator sees why Gaia-X refused something without reading a traceback.
Request/response contracts verified against the lab services on 2026-10-27.
"""

import re
import time
from collections.abc import Callable
from typing import Any, Final
from urllib.parse import quote, unquote

import requests

from gx import __version__
from gx.config import Config
from gx.constants import (
    CES_EVENTS,
    CLOUDEVENTS_JSON,
    COMPLIANCE_SUBMIT,
    DID_DOCUMENT,
    DID_WEB_PREFIX,
    NOTARY_REGISTRATION_NUMBER,
    REGISTRY_CHAIN_CHECK,
    REGISTRY_CREDENTIALS_CONFIG,
    REGISTRY_SHAPES,
    VC_JWT,
    VP_JWT,
    WELL_KNOWN,
)
from gx.errors import StepError

USER_AGENT: Final[str] = f"gx-automation/{__version__}"

# Seconds per request. The Compliance Service fetches every credential and the
# certificate chain while it validates, so it gets the longest.
TIMEOUT: Final[int] = 30
NOTARY_TIMEOUT: Final[int] = 60
COMPLIANCE_TIMEOUT: Final[int] = 180

# The Notary answers 502 when its upstream register is busy, e.g. "could not be
# validated due to rate limiting in the VAT API" (VIES, seen 2026-11-02); a retry
# moments later succeeds. Seconds to wait before each retry:
NOTARY_RETRY_DELAYS: Final[tuple[int, ...]] = (10, 30, 60)
NOTARY_TRANSIENT_STATUSES: Final[frozenset[int]] = frozenset({429, 502, 503, 504})


def _snippet(response: requests.Response, limit: int = 2000) -> str:
    return response.text.strip()[:limit] or "<empty body>"


class Gxdch:
    def __init__(self, cfg: Config, sleep: Callable[[float], None] = time.sleep) -> None:
        self.cfg = cfg
        self.sleep = sleep
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT

    def _request(self, method: str, url: str, timeout: int = TIMEOUT, **kwargs: Any) -> requests.Response:
        try:
            return self.session.request(method, url, timeout=timeout, **kwargs)
        except requests.RequestException as e:
            raise StepError(f"{method} {url} failed: {e}") from None

    def fetch(self, url: str) -> bytes:
        response = self._request("GET", url)
        if response.status_code != 200:
            raise StepError(f"GET {url} returned HTTP {response.status_code}")
        return response.content

    def fetch_text(self, url: str) -> str:
        return self.fetch(url).decode("utf-8", errors="replace")

    # ── Notary ────────────────────────────────────────────────────────────────

    def registration_number_vc(self, vc_id: str, subject_id: str) -> str:
        """GET /registration-numbers/{type}/{value}: 200 application/vc+jwt, 400 JSON on refusal.

        Transient upstream failures (NOTARY_TRANSIENT_STATUSES) are retried after NOTARY_RETRY_DELAYS.
        """
        legal = self.cfg.legal
        path = NOTARY_REGISTRATION_NUMBER.format(
            type=legal["registration_type"], value=quote(str(legal["registration_number"]), safe="")
        )
        for delay in (*NOTARY_RETRY_DELAYS, None):
            response = self._request("GET", f"{self.cfg.gxdch['notary']}{path}", timeout=NOTARY_TIMEOUT,
                                     params={"vcId": vc_id, "subjectId": subject_id})
            if response.status_code not in NOTARY_TRANSIENT_STATUSES or delay is None:
                break
            print(f"   the Notary answered HTTP {response.status_code} ({_snippet(response, 200)}); "
                  f"retrying in {delay} s")
            self.sleep(delay)
        body = response.text.strip()
        if response.status_code != 200 or not body.startswith("eyJ"):
            raise StepError(f"the Notary refused the registration number (HTTP {response.status_code}): "
                            f"{_snippet(response)}")
        return body

    # ── Registry ──────────────────────────────────────────────────────────────

    def chain_accepted(self, cert_url: str) -> tuple[bool, str]:
        """POST /api/trustAnchor/chain/file — success is exactly {"result": true}."""
        response = self._request("POST", f"{self.cfg.gxdch['registry']}{REGISTRY_CHAIN_CHECK}",
                                 json={"uri": cert_url})
        try:
            ok = response.status_code == 200 and response.json().get("result") is True
        except ValueError:
            ok = False
        return ok, f"HTTP {response.status_code}: {_snippet(response, 500)}"

    def ev_only(self) -> bool | None:
        """The registry's `evsslonly` flag (true on every production GXDCH), or None if unreadable."""
        try:
            text = self.fetch_text(f"{self.cfg.gxdch['registry']}{REGISTRY_CREDENTIALS_CONFIG}")
        except StepError:
            return None
        match = re.search(r'"evsslonly"\s*,\s*"[^"]*hasFixedValue"\s*:\s*"(true|false)"', text)
        return None if match is None else match.group(1) == "true"

    def accepted_tandc_hashes(self) -> set[str]:
        """Hashes allowed by gx:IssuerShape in the registry's SHACL shapes (empty if unreadable).

        The Registry has no "current T&C hash" endpoint, but its shapes list every
        accepted value, which is exactly what the Compliance shape validation checks.
        """
        path = REGISTRY_SHAPES.format(version=self.cfg.credentials.get("shapes_version", "development"))
        try:
            text = self.fetch_text(f"{self.cfg.gxdch['registry']}{path}")
        except StepError:
            return set()
        start = text.find("gx:IssuerShape a sh:NodeShape")
        if start < 0:
            return set()
        end = text.find("sh:targetClass gx:Issuer", start)
        return set(re.findall(r'"([0-9a-f]{64})"', text[start:end]))

    # ── Compliance ────────────────────────────────────────────────────────────

    def submit(self, vp_jwt: str, vc_id: str) -> str:
        """POST the VP; the 201 response body IS the Compliance VC (one JWT string)."""
        response = self._request(
            "POST",
            f"{self.cfg.gxdch['compliance']}{COMPLIANCE_SUBMIT}",
            timeout=COMPLIANCE_TIMEOUT,
            params={"vcid": vc_id},
            data=vp_jwt.encode("ascii"),
            headers={"Content-Type": VP_JWT, "Accept": VC_JWT},
        )
        body = response.text.strip()
        if response.status_code != 201 or not body.startswith("eyJ"):
            raise StepError(f"the Compliance Service refused the presentation (HTTP {response.status_code}): "
                            f"{_snippet(response)}")
        return body

    # ── CES ───────────────────────────────────────────────────────────────────

    def push_event(self, event: dict[str, Any]) -> None:
        response = self._request("POST", f"{self.cfg.gxdch['ces']}{CES_EVENTS}", json=event,
                                 headers={"Content-Type": CLOUDEVENTS_JSON})
        if response.status_code != 201:
            raise StepError(f"CES refused the event (HTTP {response.status_code}): {_snippet(response)}")

    # ── DIDs ──────────────────────────────────────────────────────────────────

    def resolve_did_web(self, did: str) -> dict[str, Any]:
        """did:web:host[:path...] -> the DID document (W3C did:web method), or {} if unavailable."""
        if not did.startswith(DID_WEB_PREFIX):
            raise StepError(f"not a did:web identifier: {did}")
        host, *path = did[len(DID_WEB_PREFIX):].split(":")
        location = "/".join(unquote(p) for p in path) or WELL_KNOWN
        response = self._request("GET", f"https://{unquote(host)}/{location}/{DID_DOCUMENT}")
        try:
            return response.json() if response.status_code == 200 else {}
        except ValueError:
            return {}
