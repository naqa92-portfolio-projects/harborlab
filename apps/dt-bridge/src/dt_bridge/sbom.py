"""In-toto predicates of the Sigstore bundles that build-image.yml attaches to each image as OCI referrers."""

import base64
import binascii
import json

INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
CYCLONEDX_PREDICATE_TYPE = "https://cyclonedx.org/bom"


class AttestationError(ValueError):
    """The bundle is not a well-formed in-toto attestation of the expected predicate type."""


def intoto_statement(bundle: bytes) -> dict:
    """Returns the in-toto statement of the DSSE envelope of a Sigstore bundle (signature not checked)."""
    try:
        document = json.loads(bundle)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AttestationError(f"attestation bundle is not JSON: {error}") from error
    envelope = document.get("dsseEnvelope") if isinstance(document, dict) else None
    if not isinstance(envelope, dict):
        raise AttestationError("attestation bundle has no dsseEnvelope")
    payload_type = envelope.get("payloadType")
    if payload_type != INTOTO_PAYLOAD_TYPE:
        raise AttestationError(f"DSSE payloadType is {payload_type!r}, expected {INTOTO_PAYLOAD_TYPE}")
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        raise AttestationError("DSSE envelope has no payload")
    try:
        statement = json.loads(base64.b64decode(payload, validate=True))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AttestationError(f"DSSE payload is not base64-encoded JSON: {error}") from error
    if not isinstance(statement, dict):
        raise AttestationError("DSSE payload is not an in-toto statement")
    return statement


def is_cyclonedx_predicate_type(predicate_type: object) -> bool:
    return isinstance(predicate_type, str) and (
        predicate_type == CYCLONEDX_PREDICATE_TYPE
        or predicate_type.startswith(CYCLONEDX_PREDICATE_TYPE + "/v1.")
    )


def extract_cyclonedx_sbom(bundle: bytes) -> dict:
    """Returns the CycloneDX SBOM attested in a Sigstore bundle, unchanged."""
    statement = intoto_statement(bundle)
    predicate_type = statement.get("predicateType")
    if not is_cyclonedx_predicate_type(predicate_type):
        raise AttestationError(f"attestation predicateType is {predicate_type!r}, not a CycloneDX BOM")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise AttestationError("CycloneDX attestation has no predicate object")
    return predicate
