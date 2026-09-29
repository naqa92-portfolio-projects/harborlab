"""Sigstore verification of what dt-bridge reads from the registries before it reaches Dependency-Track.

The golden/python bundles in fixtures/golden-python are the public Sigstore bundles build-image.yml attached
to that image (Rekor-logged, no secret): they pass the offline public-good trust root, so a rejection below
comes from the identity or subject check under test, never from a broken chain. The DHI signing keys are
generated per test run; the DHI signature format mirrors the cosign simple-signing referrer dhi.io serves.
"""

import base64
import datetime
import gzip
import hashlib
import importlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import certifi
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sigstore.errors import VerificationError

from dt_bridge.pipeline import Bridge, ImageRef
from dt_bridge.registry import Registry
from dt_bridge.sbom import AttestationError

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN = FIXTURES / "golden-python"

ISSUER = "https://token.actions.githubusercontent.com"
REPOSITORY = "naqa92-portfolio-projects/harborlab"
FOREIGN_REPOSITORY = "attacker-example/harborlab-copy"
BUILD_IDENTITY_MAIN = (
    r"^https://github\.com/naqa92-portfolio-projects/harborlab/\.github/workflows/build-image\.yml"
    r"@refs/heads/main$"
)
# The identity the fixture bundles were signed with (a PRD branch run of build-image.yml).
BUILD_IDENTITY_FIXTURES = (
    r"^https://github\.com/naqa92-portfolio-projects/harborlab/\.github/workflows/build-image\.yml"
    r"@refs/heads/prd-1-prd-1-harborlab-image-governance-platform$"
)
BUILD_SAN_MAIN = (
    "https://github.com/naqa92-portfolio-projects/harborlab/.github/workflows/build-image.yml@refs/heads/main"
)

IMAGE = ImageRef("golden", "python", "sha-b9fdf902347ed3e77985c9b3c6f7a6a63fa439ff")
IMAGE_DIGEST = "sha256:44440011a75ee28d9bbf977929288e1d9f907a2bc17ab2a1c67cd0e1fc7ad696"
DHI_REPOSITORY = "python"
DHI_INDEX_DIGEST = "sha256:be3c790e05dd0a4b9f15c76846a2146a75833b3ed4d1fe11e7828fd27446cedd"
DHI_PLATFORM_DIGEST = "sha256:7a77aea21e53d7bf55709791e521291c3587ced0c90d23b21844e08e22081c56"

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_EMPTY = {"mediaType": "application/vnd.oci.empty.v1+json", "digest": "", "size": 2, "data": "e30="}
BUNDLE_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
INTOTO_TYPE = "application/vnd.in-toto+json"
COSIGN_SIG_TYPE = "application/vnd.dev.cosign.artifact.sig.v1+json"
SIMPLE_SIGNING_TYPE = "application/vnd.dev.cosign.simplesigning.v1+json"
OPENVEX_PREDICATE = "https://openvex.dev/ns/v0.2.0"
BOM_PROCESSING_UUID = "00000000-0000-4000-8000-000000000001"
VEX_PROCESSING_UUID = "00000000-0000-4000-8000-000000000002"

# Sigstore certificate extensions (github.com/sigstore/fulcio docs/oid-info.md).
OID_ISSUER_V1 = "1.3.6.1.4.1.57264.1.1"
OID_WORKFLOW_REPOSITORY_V1 = "1.3.6.1.4.1.57264.1.5"
OID_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8"
OID_SOURCE_REPOSITORY_URI = "1.3.6.1.4.1.57264.1.12"


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical(document: dict) -> bytes:
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


@dataclass
class FakeRegistry:
    """OCI distribution endpoints of one registry, from memory; manifests and blobs are content-addressed."""

    manifests: dict[tuple[str, str], bytes] = field(default_factory=dict)
    blobs: dict[tuple[str, str], bytes] = field(default_factory=dict)
    referrers: dict[tuple[str, str], list[dict]] = field(default_factory=dict)

    def add_blob(self, repository: str, data: bytes) -> dict:
        digest = sha256_digest(data)
        self.blobs[(repository, digest)] = data
        return {"digest": digest, "size": len(data)}

    def add_manifest(self, repository: str, body: bytes, *tags: str) -> dict:
        digest = sha256_digest(body)
        for reference in (digest, *tags):
            self.manifests[(repository, reference)] = body
        document = json.loads(body)
        return {"mediaType": document.get("mediaType", OCI_MANIFEST), "digest": digest, "size": len(body)}

    def add_referrer(self, repository: str, subject_digest: str, descriptor: dict) -> None:
        self.referrers.setdefault((repository, subject_digest), []).append(descriptor)

    def handler(self, request: httpx.Request) -> httpx.Response:
        match = re.fullmatch(r"/v2/(.+)/(manifests|referrers|blobs)/([^/]+)", request.url.path)
        if not match:
            return httpx.Response(404)
        repository, kind, reference = match.groups()
        if kind == "manifests" and (repository, reference) in self.manifests:
            body = self.manifests[(repository, reference)]
            return httpx.Response(
                200,
                content=body,
                headers={
                    "docker-content-digest": sha256_digest(body),
                    "content-type": json.loads(body).get("mediaType", OCI_MANIFEST),
                },
            )
        if kind == "referrers":
            index = {
                "schemaVersion": 2,
                "mediaType": OCI_INDEX,
                "manifests": self.referrers.get((repository, reference), []),
            }
            return httpx.Response(200, json=index, headers={"content-type": OCI_INDEX})
        if kind == "blobs" and (repository, reference) in self.blobs:
            return httpx.Response(200, content=self.blobs[(repository, reference)])
        return httpx.Response(404)

    def client(self, base_url: str) -> Registry:
        return Registry(
            base_url, None, None, ca_file=certifi.where(), transport=httpx.MockTransport(self.handler)
        )


@dataclass
class FakeDependencyTrack:
    """Records what would reach Dependency-Track."""

    boms: list[tuple[str, str]] = field(default_factory=list)
    vexes: list[tuple[str, str]] = field(default_factory=list)

    def upload_bom(self, name: str, version: str, sbom: dict) -> str:
        self.boms.append((name, version))
        return BOM_PROCESSING_UUID

    def upload_vex(self, name: str, version: str, vex: dict) -> dict:
        self.vexes.append((name, version))
        return {"token": VEX_PROCESSING_UUID}

    def project_uuid(self, name: str, version: str) -> None:
        return None

    def token_status(self, token: str) -> str:
        return "COMPLETED"

    def findings(self, uuid: str) -> list:
        return []


def bundle_referrer(harbor: FakeRegistry, subject: dict, bundle: bytes, predicate_type: str, created: str):
    layer = {"mediaType": BUNDLE_TYPE, **harbor.add_blob("golden/python", bundle)}
    empty = {**OCI_EMPTY, **harbor.add_blob("golden/python", b"{}")}
    annotations = {
        "dev.sigstore.bundle.content": "dsse-envelope",
        "dev.sigstore.bundle.predicateType": predicate_type,
        "org.opencontainers.image.created": created,
    }
    manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "artifactType": BUNDLE_TYPE,
        "config": empty,
        "layers": [layer],
        "subject": subject,
        "annotations": annotations,
    }
    descriptor = harbor.add_manifest("golden/python", canonical(manifest))
    return {**descriptor, "artifactType": BUNDLE_TYPE, "annotations": annotations}


def golden_harbor(*, image_manifest: bytes | None = None) -> tuple[FakeRegistry, str]:
    """Harbor serving golden/python at IMAGE.tag with its real attestation bundles as referrers.

    With `image_manifest`, the tag serves that manifest instead, still carrying the bundles whose statement
    subject is IMAGE_DIGEST: another image dressed with the golden image's attestations."""
    harbor = FakeRegistry()
    real_manifest = (GOLDEN / "image-manifest.json").read_bytes()
    harbor.add_blob("golden/python", (GOLDEN / "image-config.json").read_bytes())
    image = harbor.add_manifest("golden/python", image_manifest or real_manifest, IMAGE.tag)
    bundles = [
        ("signature.sigstore.json", "https://sigstore.dev/cosign/sign/v1", "2026-09-26T14:32:44Z"),
        ("cyclonedx.sigstore.json.gz", "https://cyclonedx.org/bom", "2026-09-26T14:32:47Z"),
        ("slsa-provenance.sigstore.json", "https://slsa.dev/provenance/v1", "2026-09-26T14:32:54Z"),
    ]
    for name, predicate_type, created in bundles:
        raw = (GOLDEN / name).read_bytes()
        bundle = gzip.decompress(raw) if name.endswith(".gz") else raw
        harbor.add_referrer(
            "golden/python", image["digest"], bundle_referrer(harbor, image, bundle, predicate_type, created)
        )
    return harbor, image["digest"]


def dhi_registry(signing_key: ec.EllipticCurvePrivateKey | None) -> FakeRegistry:
    """dhi.io serving the golden image's DHI base with one OpenVEX attestation on its linux/amd64 manifest,
    signed with `signing_key` the way dhi.io signs it (cosign simple signing referrer), or unsigned."""
    dhi = FakeRegistry()
    dhi.add_manifest(DHI_REPOSITORY, (GOLDEN / "dhi-python-index.json").read_bytes())
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": OPENVEX_PREDICATE,
        "subject": [
            {"name": "dhi/python", "digest": {"sha256": DHI_PLATFORM_DIGEST.removeprefix("sha256:")}}
        ],
        "predicate": json.loads((FIXTURES / "openvex-document.json").read_text()),
    }
    annotations = {"in-toto.io/predicate-type": OPENVEX_PREDICATE}
    attestation = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "artifactType": INTOTO_TYPE,
        "config": {**OCI_EMPTY, **dhi.add_blob(DHI_REPOSITORY, b"{}")},
        "layers": [
            {
                "mediaType": INTOTO_TYPE,
                "annotations": annotations,
                **dhi.add_blob(DHI_REPOSITORY, canonical(statement)),
            }
        ],
        "subject": {"mediaType": OCI_MANIFEST, "digest": DHI_PLATFORM_DIGEST, "size": 2678},
        "annotations": annotations,
    }
    attestation_descriptor = dhi.add_manifest(DHI_REPOSITORY, canonical(attestation))
    dhi.add_referrer(
        DHI_REPOSITORY,
        DHI_PLATFORM_DIGEST,
        {**attestation_descriptor, "artifactType": INTOTO_TYPE, "annotations": annotations},
    )
    if signing_key is None:
        return dhi

    payload = canonical(
        {
            "critical": {
                "identity": {"docker-reference": "registry.scout.docker.com/dhi/python"},
                "image": {"docker-manifest-digest": attestation_descriptor["digest"]},
                "type": "cosign container image signature",
            },
            "optional": {
                "predicateType": OPENVEX_PREDICATE,
                "subject": f"dhi/python@{DHI_PLATFORM_DIGEST}",
                "type": "https://in-toto.io/Statement/v0.1",
            },
        }
    )
    signature = base64.b64encode(signing_key.sign(payload, ec.ECDSA(hashes.SHA256()))).decode()
    payload_blob = dhi.add_blob(DHI_REPOSITORY, payload)
    config = canonical(
        {
            "architecture": "",
            "config": {},
            "created": "0001-01-01T00:00:00Z",
            "os": "",
            "rootfs": {"type": "layers", "diff_ids": [payload_blob["digest"]]},
        }
    )
    signature_manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "artifactType": COSIGN_SIG_TYPE,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            **dhi.add_blob(DHI_REPOSITORY, config),
        },
        "layers": [
            {
                "mediaType": SIMPLE_SIGNING_TYPE,
                "annotations": {"dev.cosignproject.cosign/signature": signature},
                **payload_blob,
            }
        ],
        "subject": attestation_descriptor,
    }
    signature_descriptor = dhi.add_manifest(DHI_REPOSITORY, canonical(signature_manifest))
    dhi.add_referrer(
        DHI_REPOSITORY,
        attestation_descriptor["digest"],
        {**signature_descriptor, "artifactType": COSIGN_SIG_TYPE},
    )
    return dhi


@pytest.fixture(scope="module")
def dhi_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def other_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def public_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def verification():
    """The verification module, imported per test so that each test reports its own failure."""
    return importlib.import_module("dt_bridge.verification")


def identities(golden_identity: str):
    return verification().Identities(
        issuer=ISSUER,
        by_project={"golden": golden_identity, "apps": BUILD_IDENTITY_MAIN},
        repository=REPOSITORY,
    )


def make_bridge(
    harbor: FakeRegistry, dt: FakeDependencyTrack, dhi: FakeRegistry, *, golden_identity: str, dhi_key
):
    return Bridge(
        harbor.client("https://harbor.example.invalid"),
        dt,
        dhi.client("https://dhi.io"),
        identities=identities(golden_identity),
        dhi_public_key=public_pem(dhi_key),
    )


# Webhook path ------------------------------------------------------------------------------------------


def test_webhook_path_uploads_sbom_and_returns_dhi_vex_when_everything_verifies(dhi_key):
    harbor, _ = golden_harbor()
    dt = FakeDependencyTrack()
    bridge = make_bridge(
        harbor, dt, dhi_registry(dhi_key), golden_identity=BUILD_IDENTITY_FIXTURES, dhi_key=dhi_key
    )

    pending = bridge.process(IMAGE)

    assert dt.boms == [("golden/python", IMAGE.tag)]
    assert pending is not None
    assert pending.image == IMAGE


def test_webhook_path_rejects_sbom_signed_by_a_foreign_identity(dhi_key):
    harbor, _ = golden_harbor()
    dt = FakeDependencyTrack()
    bridge = make_bridge(
        harbor, dt, dhi_registry(dhi_key), golden_identity=BUILD_IDENTITY_MAIN, dhi_key=dhi_key
    )

    with pytest.raises(AttestationError):
        bridge.process(IMAGE)

    assert dt.boms == []


def test_webhook_path_rejects_attestations_whose_subject_is_another_digest(dhi_key):
    real = json.loads((GOLDEN / "image-manifest.json").read_text())
    other_image = canonical({**real, "annotations": {"org.example.variant": "not-the-attested-image"}})
    harbor, served_digest = golden_harbor(image_manifest=other_image)
    assert served_digest != IMAGE_DIGEST
    dt = FakeDependencyTrack()
    bridge = make_bridge(
        harbor, dt, dhi_registry(dhi_key), golden_identity=BUILD_IDENTITY_FIXTURES, dhi_key=dhi_key
    )

    with pytest.raises(AttestationError):
        bridge.process(IMAGE)

    assert dt.boms == []


# DHI VEX path ------------------------------------------------------------------------------------------


def process_ignoring_rejection(bridge: Bridge):
    try:
        return bridge.process(IMAGE)
    except AttestationError:
        return None


def test_dhi_vex_path_ignores_an_unsigned_openvex(dhi_key):
    harbor, _ = golden_harbor()
    dt = FakeDependencyTrack()
    bridge = make_bridge(
        harbor, dt, dhi_registry(None), golden_identity=BUILD_IDENTITY_FIXTURES, dhi_key=dhi_key
    )

    pending = process_ignoring_rejection(bridge)

    assert dt.boms == [("golden/python", IMAGE.tag)]
    assert pending is None


def test_dhi_vex_path_ignores_an_openvex_signed_by_another_key(dhi_key, other_key):
    harbor, _ = golden_harbor()
    dt = FakeDependencyTrack()
    bridge = make_bridge(
        harbor, dt, dhi_registry(other_key), golden_identity=BUILD_IDENTITY_FIXTURES, dhi_key=dhi_key
    )

    pending = process_ignoring_rejection(bridge)

    assert dt.boms == [("golden/python", IMAGE.tag)]
    assert pending is None


# Kubescape path ----------------------------------------------------------------------------------------


def test_kubescape_path_rejects_sbom_signed_by_a_foreign_identity(dhi_key):
    harbor, digest = golden_harbor()
    dt = FakeDependencyTrack()
    bridge = make_bridge(
        harbor, dt, dhi_registry(dhi_key), golden_identity=BUILD_IDENTITY_MAIN, dhi_key=dhi_key
    )
    document = json.loads((FIXTURES / "kubescape-openvex.json").read_text())

    with pytest.raises(AttestationError):
        bridge.forward_kubescape(IMAGE, digest, "runtime-demo/replicaset-x", 1, document)

    assert dt.boms == []
    assert dt.vexes == []


def test_kubescape_path_rejects_attestations_whose_subject_is_another_digest(dhi_key):
    real = json.loads((GOLDEN / "image-manifest.json").read_text())
    other_image = canonical({**real, "annotations": {"org.example.variant": "not-the-attested-image"}})
    harbor, served_digest = golden_harbor(image_manifest=other_image)
    dt = FakeDependencyTrack()
    bridge = make_bridge(
        harbor, dt, dhi_registry(dhi_key), golden_identity=BUILD_IDENTITY_FIXTURES, dhi_key=dhi_key
    )
    document = json.loads((FIXTURES / "kubescape-openvex.json").read_text())

    with pytest.raises(AttestationError):
        bridge.forward_kubescape(IMAGE, served_digest, "runtime-demo/replicaset-x", 1, document)

    assert dt.boms == []
    assert dt.vexes == []


# Signer identity bound to this repository --------------------------------------------------------------


def der_utf8(value: str) -> bytes:
    data = value.encode()
    if len(data) < 0x80:
        length = bytes([len(data)])
    else:
        size = len(data).to_bytes((len(data).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(size)]) + size
    return b"\x0c" + length + data


def build_certificate(repository: str | None) -> x509.Certificate:
    """A Fulcio-shaped leaf for build-image.yml@refs/heads/main, called from `repository` (None: no
    repository extension). Self-signed: only the identity policy reads it."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime(2026, 9, 28, 12, 0, tzinfo=datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-only-fulcio")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(minutes=10))
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(BUILD_SAN_MAIN)]), True)
        .add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(OID_ISSUER_V1), ISSUER.encode()), False
        )
        .add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(OID_ISSUER_V2), der_utf8(ISSUER)), False
        )
    )
    if repository is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(OID_WORKFLOW_REPOSITORY_V1), repository.encode()
            ),
            False,
        ).add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(OID_SOURCE_REPOSITORY_URI), der_utf8(f"https://github.com/{repository}")
            ),
            False,
        )
    return builder.sign(key, hashes.SHA256())


def test_signer_policy_accepts_build_image_called_from_this_repository():
    policy = verification().signer_policy(identities(BUILD_IDENTITY_MAIN), "apps")

    policy.verify(build_certificate(REPOSITORY))


def test_signer_policy_rejects_build_image_called_from_another_repository():
    policy = verification().signer_policy(identities(BUILD_IDENTITY_MAIN), "apps")

    with pytest.raises(VerificationError):
        policy.verify(build_certificate(FOREIGN_REPOSITORY))


def test_signer_policy_rejects_a_certificate_without_repository_binding():
    policy = verification().signer_policy(identities(BUILD_IDENTITY_MAIN), "apps")

    with pytest.raises(VerificationError):
        policy.verify(build_certificate(None))
