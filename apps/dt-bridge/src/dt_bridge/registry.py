"""Read-only OCI distribution client (manifests, referrers, blobs) with the registry token flow."""

import re
import ssl

import httpx

MANIFEST_MEDIA_TYPES = ",".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)
INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
IMAGE_CONFIG_MEDIA_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
TIMEOUT_SECONDS = 60.0


class RegistryError(Exception):
    """A registry request failed."""


class Registry:
    """One registry host; credentials only reach its token endpoint, never error messages."""

    def __init__(
        self,
        base_url: str,
        username: str | None,
        password: str | None,
        *,
        ca_file: str,
        relax_x509_strict: bool = False,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = (username, password) if username and password else None
        context = ssl.create_default_context(cafile=ca_file)
        if relax_x509_strict:
            context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        self._client = httpx.Client(
            timeout=TIMEOUT_SECONDS, transport=transport, follow_redirects=True, verify=context
        )
        self._tokens: dict[str, str] = {}

    def _token(self, repository: str, challenge: str) -> str:
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = params.pop("realm", None)
        if not realm:
            raise RegistryError(f"{self._base_url} sent no token realm")
        params["scope"] = f"repository:{repository}:pull"
        try:
            response = self._client.get(realm, params=params, auth=self._auth)
        except httpx.HTTPError as error:
            raise RegistryError(f"token request to {realm} failed: {type(error).__name__}") from None
        if response.status_code != 200:
            raise RegistryError(f"token request for {repository} refused (HTTP {response.status_code})")
        body = response.json()
        return body.get("token") or body["access_token"]

    def _get(self, repository: str, path: str, **kwargs) -> httpx.Response:
        url = f"{self._base_url}/v2/{repository}/{path}"
        for _ in range(2):
            headers = dict(kwargs.pop("headers", {}))
            if repository in self._tokens:
                headers["Authorization"] = f"Bearer {self._tokens[repository]}"
            try:
                response = self._client.get(url, headers=headers, **kwargs)
            except httpx.HTTPError as error:
                raise RegistryError(f"GET {url} failed: {type(error).__name__}") from None
            challenge = response.headers.get("www-authenticate", "")
            if response.status_code != 401 or not challenge.lower().startswith("bearer"):
                break
            self._tokens[repository] = self._token(repository, challenge)
            kwargs["headers"] = headers
        if response.status_code != 200:
            raise RegistryError(f"GET {url} answered HTTP {response.status_code}")
        return response

    def manifest(self, repository: str, reference: str) -> tuple[str, dict]:
        """Returns the digest and the manifest of a tag or digest."""
        response = self._get(repository, f"manifests/{reference}", headers={"Accept": MANIFEST_MEDIA_TYPES})
        digest = response.headers.get("docker-content-digest") or reference
        return digest, response.json()

    def referrers(self, repository: str, digest: str, artifact_type: str | None = None) -> list[dict]:
        params = {"artifactType": artifact_type} if artifact_type else {}
        response = self._get(
            repository,
            f"referrers/{digest}",
            params=params,
            headers={"Accept": "application/vnd.oci.image.index.v1+json"},
        )
        return response.json().get("manifests", [])

    def blob(self, repository: str, digest: str) -> bytes:
        return self._get(repository, f"blobs/{digest}").content
