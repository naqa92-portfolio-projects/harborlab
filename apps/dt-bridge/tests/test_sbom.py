"""SBOM extraction from the Sigstore bundle build-image.yml attaches to each image as an OCI referrer."""

import json
from pathlib import Path

import pytest

from dt_bridge.sbom import AttestationError, extract_cyclonedx_sbom

FIXTURES = Path(__file__).parent / "fixtures"


def test_extracts_cyclonedx_predicate_from_attestation():
    bundle = (FIXTURES / "cyclonedx-attestation.sigstore.json").read_bytes()
    attested_sbom = json.loads((FIXTURES / "cyclonedx-sbom.json").read_text())

    sbom = extract_cyclonedx_sbom(bundle)

    assert sbom == attested_sbom


def test_rejects_non_cyclonedx_predicate():
    bundle = (FIXTURES / "spdx-attestation.sigstore.json").read_bytes()

    with pytest.raises(AttestationError, match="https://spdx.dev/Document"):
        extract_cyclonedx_sbom(bundle)


@pytest.mark.parametrize(
    "bundle",
    [
        pytest.param(b"not json", id="not-json"),
        pytest.param(
            b'{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}', id="no-dsse-envelope"
        ),
        pytest.param(
            b'{"dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": "%%%"}}',
            id="payload-not-base64",
        ),
        pytest.param(
            b'{"dsseEnvelope": {"payloadType": "text/plain", "payload": "e30=", "signatures": []}}',
            id="payload-not-in-toto",
        ),
    ],
)
def test_rejects_malformed_attestation(bundle):
    with pytest.raises(AttestationError):
        extract_cyclonedx_sbom(bundle)
