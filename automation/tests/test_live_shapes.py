"""Our credentials against the lab's SHACL shapes, validated the way gx-compliance does it.

Mirrors gx-compliance src/vp-validation/service/shacl.service.ts (development, 2026-11-02):
each credentialSubject gets its VC's @context and type = VC types + subject types; all
subjects go into one @graph; JSON-LD contexts come from gx-compliance's bundled copies;
RDFS inference with the Gaia-X ontology; then SHACL with the Registry's shapes.

Run with: pip install -e ".[test,shacl]" && pytest --live
"""

import copy
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
import requests

from gx import credentials, jws
from gx.gxdch import Gxdch

from .test_live_lab import EGI_LEGAL

pytestmark = pytest.mark.live
rdflib = pytest.importorskip("rdflib")
pyshacl = pytest.importorskip("pyshacl")

GAIA_X = "https://w3id.org/gaia-x/development#"
GX_COMPLIANCE_CONTEXTS = ("https://gitlab.com/api/v4/projects/gaia-x%2Flab%2Fcompliance%2Fgx-compliance"
                          "/repository/files/src%2Fcontexts%2F{name}.json/raw?ref=development")
BUNDLED = {   # gx-compliance src/common/providers/document-loader.provider.ts
    "http://schema.org/": "schema_context",
    "https://schema.org/": "schema_context",
    "https://www.w3.org/ns/credentials/v2": "credentials_v2_context",
    GAIA_X: "development_context",
}


def get(url: str, accept: str) -> str:
    return requests.get(url, headers={"Accept": accept}, timeout=120).text


@pytest.fixture(scope="module")
def lab_rdf() -> dict[str, Any]:
    contexts = {name: requests.get(GX_COMPLIANCE_CONTEXTS.format(name=name), timeout=60).json()["@context"]
                for name in set(BUNDLED.values())}
    return {
        "shapes": rdflib.Graph().parse(data=get(GAIA_X, "text/turtle"), format="turtle"),
        "ontology": rdflib.Graph().parse(data=get(GAIA_X, "application/rdf+xml"), format="turtle"),
        "contexts": {url: contexts[name] for url, name in BUNDLED.items()},
    }


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def subject_graph(vcs: list[dict[str, Any]], contexts: dict[str, Any]) -> dict[str, Any]:
    subjects = []
    for vc in vcs:
        for cs in as_list(vc["credentialSubject"]):
            ctx = [contexts.get(c, c) for c in as_list(vc["@context"]) + as_list(cs.get("@context", []))]
            types = as_list(vc.get("type", [])) + as_list(cs.get("type", []))
            subjects.append({**cs, "@context": ctx, "type": types})
    return {"@graph": subjects}


def rdfs_closure(graph: Any, ontology: Any) -> None:
    """The RDFS rules Jena's `riot --rdfs` applies that matter here: subproperty, domain, range, subclass."""
    RDF, RDFS = rdflib.RDF, rdflib.RDFS
    size = -1
    while size != len(graph):
        size = len(graph)
        for s, p, o in list(graph):
            for parent in ontology.objects(p, RDFS.subPropertyOf):
                graph.add((s, parent, o))
            for cls in ontology.objects(p, RDFS.domain):
                graph.add((s, RDF.type, cls))
            if not isinstance(o, rdflib.Literal):
                for cls in ontology.objects(p, RDFS.range):
                    graph.add((o, RDF.type, cls))
        for s, cls in list(graph.subject_objects(RDF.type)):
            for parent in ontology.objects(cls, RDFS.subClassOf):
                graph.add((s, RDF.type, parent))


def conforms(vcs: list[dict[str, Any]], lab_rdf: dict[str, Any]) -> tuple[bool, str]:
    graph = rdflib.Graph().parse(data=json.dumps(subject_graph(vcs, lab_rdf["contexts"])), format="json-ld")
    rdfs_closure(graph, lab_rdf["ontology"])
    ok, _, text = pyshacl.validate(graph, shacl_graph=lab_rdf["shapes"], inference="none", allow_warnings=True)
    return ok, text


@pytest.fixture(scope="module")
def egi_credentials(tmp_path_factory, pki) -> list[dict[str, Any]]:
    from .conftest import Deployment

    root = tmp_path_factory.mktemp("lab")
    deployment = Deployment(root, pki, pki.keys["rsa"])
    deployment.write_config(legal=EGI_LEGAL)
    deployment.install_certificate()
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("GX_HOSTING_DIR", str(root))
        cfg = deployment.config()
    now = datetime.now(timezone.utc)
    lrn = Gxdch(cfg).registration_number_vc(cfg.url("lrn"), credentials.registration_number_subject(cfg))
    return [jws.decode(lrn)[1],
            credentials.legal_person(cfg, now, now + timedelta(days=90)),
            credentials.terms_and_conditions(cfg, now, now + timedelta(days=90))]


def test_egi_credentials_conform(egi_credentials, lab_rdf) -> None:
    ok, report = conforms(egi_credentials, lab_rdf)
    assert ok, report


@pytest.mark.parametrize("index, path, value", [
    (1, ("gx:legalAddress", "gx:countrySubdivisionCode"), "NL-NH"),   # closed shape
    (1, ("gx:legalAddress", "vcard:region"), "NL-NH"),                # not a NUTS-2 code
    (2, ("gaiaxTermsAndConditions",), "0" * 64),                      # not an accepted T&C hash
])
def test_broken_credentials_are_rejected(egi_credentials, lab_rdf, index: int, path: tuple[str, ...],
                                         value: str) -> None:
    vcs = copy.deepcopy(egi_credentials)
    target = vcs[index]["credentialSubject"]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert not conforms(vcs, lab_rdf)[0]
