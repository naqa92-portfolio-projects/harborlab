"""Kubescape runtime VEX documents: image references normalised, documents read from the storage API.

Only the documents of a container instance (relevancy) are read; image-level ones state every match affected.
"""

import ssl
from dataclasses import dataclass
from pathlib import Path

import httpx

from dt_bridge.vex import Purl

DOCKER_HUB = "docker.io"
DOCKER_HUB_ALIASES = {"docker.io", "index.docker.io", "registry-1.docker.io"}
VEX_API = "/apis/spdx.softwarecomposition.kubescape.io/v1beta1"
VEX_RESOURCE = "openvulnerabilityexchangecontainers"
INSTANCE_ID_ANNOTATION = "kubescape.io/instance-id"
IMAGE_ID_ANNOTATION = "kubescape.io/image-id"
SERVICE_ACCOUNT_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
TIMEOUT_SECONDS = 30.0


@dataclass(frozen=True)
class ImageReference:
    registry: str
    repository: str
    tag: str | None
    digest: str | None


def _oci_purl_reference(value: str) -> str:
    try:
        purl = Purl(value)
    except ValueError as error:
        raise ValueError(f"not an image reference: {value!r}") from error
    if purl.type != "oci":
        raise ValueError(f"package URL of type {purl.type!r} is not an image: {value!r}")
    location = purl.qualifiers.get("repository_url", "").strip("/")
    if not location:
        location = f"{DOCKER_HUB}/{purl.name}"
    elif location.rsplit("/", 1)[-1] != purl.name:
        location = f"{location}/{purl.name}"
    tag = purl.qualifiers.get("tag")
    return location + (f":{tag}" if tag else "") + (f"@{purl.version}" if purl.version else "")


def image_reference(value: str) -> ImageReference:
    """Parses an image reference or a `pkg:oci` package URL; Docker Hub spellings all give `docker.io`."""
    value = value.strip()
    if not value:
        raise ValueError("empty image reference")
    if value.startswith("pkg:"):
        value = _oci_purl_reference(value)
    value = value.split("://", 1)[-1]
    name, _, digest = value.partition("@")
    segments = name.split("/")
    first = segments[0]
    if len(segments) > 1 and ("." in first or ":" in first or first == "localhost"):
        registry, segments = first, segments[1:]
    else:
        registry = DOCKER_HUB
    last, _, tag = segments[-1].partition(":")
    segments[-1] = last
    if registry in DOCKER_HUB_ALIASES:
        registry = DOCKER_HUB
        if len(segments) == 1:
            segments = ["library", *segments]
    repository = "/".join(segments)
    if not repository:
        raise ValueError(f"image reference without repository: {value!r}")
    return ImageReference(registry, repository, tag or None, digest or None)


class KubescapeError(Exception):
    """A Kubernetes API request for Kubescape documents failed."""


class VexDocuments:
    """Reads the Kubescape VEX documents of one namespace with the pod's projected ServiceAccount token."""

    def __init__(
        self,
        namespace: str,
        api_url: str,
        *,
        service_account_dir: Path = SERVICE_ACCOUNT_DIR,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._namespace = namespace
        self._token_file = service_account_dir / "token"
        context = ssl.create_default_context(cafile=str(service_account_dir / "ca.crt"))
        self._client = httpx.Client(
            base_url=api_url.rstrip("/"), timeout=TIMEOUT_SECONDS, transport=transport, verify=context
        )

    def _get(self, path: str) -> dict:
        url = f"{VEX_API}/namespaces/{self._namespace}/{VEX_RESOURCE}{path}"
        # The kubelet rotates the projected token: it is re-read on every request.
        headers = {"Authorization": f"Bearer {self._token_file.read_text().strip()}"}
        try:
            response = self._client.get(url, headers=headers)
        except httpx.HTTPError as error:
            raise KubescapeError(f"GET {url} failed: {type(error).__name__}") from None
        if response.status_code != 200:
            raise KubescapeError(f"GET {url} answered HTTP {response.status_code}")
        return response.json()

    def instance_documents(self) -> list[dict]:
        """The documents of container instances, each with its `spec`."""
        documents = []
        for item in self._get("").get("items") or []:
            metadata = item.get("metadata") or {}
            if not (metadata.get("annotations") or {}).get(INSTANCE_ID_ANNOTATION):
                continue
            documents.append(
                item if isinstance(item.get("spec"), dict) else self._get(f"/{metadata['name']}")
            )
        return documents
