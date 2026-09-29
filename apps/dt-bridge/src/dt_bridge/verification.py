"""Sigstore signer policy of the governed images (the build workflow identity, run from this repository),
and the checks dt-bridge runs on an attestation or a DHI OpenVEX before using it."""

import base64
import binascii
import json
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509 import Certificate, SubjectAlternativeName, UniformResourceIdentifier
from sigstore.errors import Error as SigstoreError
from sigstore.errors import VerificationError
from sigstore.models import Bundle
from sigstore.verify import Verifier
from sigstore.verify.policy import AllOf, OIDCIssuerV2, OIDCSourceRepositoryURI, VerificationPolicy

from dt_bridge.sbom import INTOTO_PAYLOAD_TYPE, AttestationError


@dataclass(frozen=True)
class Identities:
    """Signer identity (certificate SAN regexp, matched in full) per Harbor project, the OIDC issuer, and
    the `<owner>/<name>` GitHub repository the build must run from."""

    issuer: str
    by_project: dict[str, str]
    repository: str


class SanMatches:
    """Verification policy: a certificate URI SAN matches the regular expression."""

    def __init__(self, pattern: str) -> None:
        self._pattern = re.compile(pattern)

    def verify(self, cert: Certificate) -> None:
        extension = cert.extensions.get_extension_for_class(SubjectAlternativeName).value
        sans = extension.get_values_for_type(UniformResourceIdentifier)
        if not any(self._pattern.fullmatch(san) for san in sans):
            raise VerificationError(f"no certificate SAN matches {self._pattern.pattern}")


def signer_policy(identities: Identities, project: str) -> VerificationPolicy:
    """Issuer, SAN and source repository of the images of Harbor project `project`. The SAN names the
    reusable build workflow whoever calls it; the source repository extension names the caller."""
    return AllOf(
        [
            OIDCIssuerV2(identities.issuer),
            SanMatches(identities.by_project[project]),
            OIDCSourceRepositoryURI(f"https://github.com/{identities.repository}"),
        ]
    )


def verified_statement(verifier: Verifier, bundle: bytes, policy: VerificationPolicy, digest: str) -> dict:
    """The in-toto statement of a Sigstore bundle whose signature, signer and subject all verify: signed
    under the trust root by a certificate `policy` accepts, about the image of digest `digest`."""
    try:
        payload_type, payload = verifier.verify_dsse(Bundle.from_json(bundle), policy)
    except (SigstoreError, ValueError) as error:
        raise AttestationError(f"Sigstore bundle not verified: {str(error)[:200]}") from None
    if payload_type != INTOTO_PAYLOAD_TYPE:
        raise AttestationError(f"DSSE payloadType is {payload_type!r}, expected {INTOTO_PAYLOAD_TYPE}")
    try:
        statement = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AttestationError(f"DSSE payload is not JSON: {error}") from None
    if not isinstance(statement, dict):
        raise AttestationError("DSSE payload is not an in-toto statement")
    if digest not in statement_subjects(statement):
        raise AttestationError(f"attestation subject is not {digest}")
    return statement


def statement_subjects(statement: dict) -> set[str]:
    return {
        f"sha256:{(subject.get('digest') or {}).get('sha256')}"
        for subject in statement.get("subject") or []
        if isinstance(subject, dict)
    }


def cosign_signature_valid(
    public_key_pem: bytes, payload: bytes, signature: str, manifest_digest: str
) -> bool:
    """Whether a cosign simple-signing payload is signed by the ECDSA key and names `manifest_digest`."""
    key = load_pem_public_key(public_key_pem)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("the DHI public key is not an ECDSA key")
    try:
        key.verify(base64.b64decode(signature, validate=True), payload, ec.ECDSA(hashes.SHA256()))
        document = json.loads(payload)
    except (InvalidSignature, binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        return False
    image = ((document.get("critical") or {}).get("image") or {}) if isinstance(document, dict) else {}
    return image.get("docker-manifest-digest") == manifest_digest
