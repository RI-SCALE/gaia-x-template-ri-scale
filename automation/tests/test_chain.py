from cryptography.hazmat.primitives import serialization

from gx.chain import (
    check_chain,
    complete_chain,
    covers_domain,
    did_document,
    has_ev_oid,
    load_chain,
    normalize_domain,
    order_chain,
    to_pem,
)

from .conftest import DOMAIN, ROOT_URL, Pki, make_cert, pem


def offline(url: str) -> bytes:
    raise OSError("offline")


def test_complete_chain_follows_aia(pki: Pki) -> None:
    leaf = pki.leaf(pki.keys["rsa"])
    fetched = []

    def fetch(url: str) -> bytes:
        fetched.append(url)
        return pki.root.public_bytes(serialization.Encoding.DER)

    chain = complete_chain([leaf, pki.intermediate], fetch)
    assert chain == [leaf, pki.intermediate, pki.root]
    assert fetched == [ROOT_URL]
    assert check_chain(chain) == []


def test_complete_chain_falls_back_to_extra_roots(pki: Pki) -> None:
    leaf = pki.leaf(pki.keys["rsa"])

    def fetch(url: str) -> bytes:
        if url == "https://roots.test/root.pem":
            return pem(pki.root).encode()
        raise OSError("unreachable")

    chain = complete_chain([leaf, pki.intermediate], fetch, ["https://roots.test/other.pem", "https://roots.test/root.pem"])
    assert chain[-1] == pki.root


def test_complete_chain_ignores_a_root_that_did_not_sign(pki: Pki) -> None:
    impostor_key = pki.keys["rsa2"]
    impostor = make_cert("Test Root", "Test Root", impostor_key.public_key(), impostor_key, ca=True)
    chain = complete_chain([pki.leaf(pki.keys["rsa"]), pki.intermediate],
                           lambda url: impostor.public_bytes(serialization.Encoding.DER))
    assert len(chain) == 2
    assert "NOT self-signed" in check_chain(chain)[0]


def test_check_chain_problems(pki: Pki) -> None:
    leaf = pki.leaf(pki.keys["rsa"])
    assert "only one certificate" in check_chain([leaf])[0]
    problems = check_chain([leaf, pki.root])  # intermediate missing
    assert any("broken chain at position 0" in p for p in problems)


def test_order_chain_puts_the_leaf_first(pki: Pki) -> None:
    """A .p12 export may list the CA certificates before the leaf."""
    leaf = pki.leaf(pki.keys["rsa"])
    other = make_cert("Unrelated", "Unrelated", pki.keys["ec"].public_key(), pki.keys["ec"], ca=True)
    assert order_chain([pki.root, other, pki.intermediate, leaf]) == [leaf, pki.intermediate, pki.root]
    assert order_chain([pki.intermediate, leaf]) == [leaf, pki.intermediate]


def test_pem_round_trip(pki: Pki) -> None:
    chain = [pki.leaf(pki.keys["ec"]), pki.intermediate, pki.root]
    assert load_chain(to_pem(chain)) == chain


def test_covers_domain(pki: Pki) -> None:
    leaf = pki.leaf(pki.keys["rsa"])
    assert covers_domain(leaf, DOMAIN)
    assert not covers_domain(leaf, "other.test")
    key = pki.keys["rsa"]
    wildcard = make_cert("w", "Test Intermediate", key.public_key(), pki.intermediate_key,
                         ca=False, san=["*.example.eu"])
    assert covers_domain(wildcard, "gaia-x.example.eu")
    assert not covers_domain(wildcard, "a.gaia-x.example.eu")
    assert not covers_domain(wildcard, "example.eu")


def test_ev_oid(pki: Pki) -> None:
    assert not has_ev_oid(pki.leaf(pki.keys["rsa"]))
    assert has_ev_oid(pki.leaf(pki.keys["rsa"], ev=True))


def test_did_document(pki: Pki) -> None:
    doc = did_document(DOMAIN, pki.leaf(pki.keys["rsa"]), alg="RS256")
    method = doc["verificationMethod"][0]
    assert doc["id"] == f"did:web:{DOMAIN}"
    assert method["id"] == doc["assertionMethod"][0] == f"did:web:{DOMAIN}#key-1"
    assert method["publicKeyJwk"]["alg"] == "RS256"
    assert method["publicKeyJwk"]["x5u"] == f"https://{DOMAIN}/cert.pem"


def test_normalize_domain() -> None:
    assert normalize_domain(" https://gx.test/ ") == "gx.test"
    assert normalize_domain("http://gx.test") == "gx.test"
