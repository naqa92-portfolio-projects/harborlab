"""Dependency-Track v1 REST client (API key authentication). Errors never carry the API key."""

import base64
import json

import httpx

DEFAULT_TIMEOUT_SECONDS = 60.0


class DependencyTrackError(Exception):
    """A Dependency-Track request failed."""


class DependencyTrackUnauthorized(DependencyTrackError):
    """Dependency-Track rejected the API key (401) or its permissions (403)."""


class DependencyTrackServerError(DependencyTrackError):
    """Dependency-Track answered with a 5xx status."""

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


class DependencyTrackTimeout(DependencyTrackError):
    """Dependency-Track did not answer in time."""


def _encoded(document: dict) -> str:
    return base64.b64encode(json.dumps(document).encode()).decode()


class DependencyTrackClient:
    def __init__(self, base_url: str, api_key: str, *, transport: httpx.BaseTransport | None = None) -> None:
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"X-Api-Key": api_key, "Accept": "application/json"},
            timeout=DEFAULT_TIMEOUT_SECONDS,
            transport=transport,
        )

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        description = f"{method} {path}"
        try:
            response = self._client.request(method, path, **kwargs)
        except httpx.TimeoutException:
            raise DependencyTrackTimeout(f"Dependency-Track {description} timed out") from None
        except httpx.HTTPError as error:
            raise DependencyTrackError(
                f"Dependency-Track {description} failed: {type(error).__name__}"
            ) from None
        if response.status_code in (401, 403):
            raise DependencyTrackUnauthorized(
                f"Dependency-Track {description} refused (HTTP {response.status_code})"
            )
        if response.status_code >= 500:
            raise DependencyTrackServerError(
                f"Dependency-Track {description} failed (HTTP {response.status_code})", response.status_code
            )
        return response

    def _expect(self, response: httpx.Response, *statuses: int) -> httpx.Response:
        if response.status_code not in statuses:
            raise DependencyTrackError(
                f"Dependency-Track {response.request.method} {response.request.url.path} "
                f"answered HTTP {response.status_code}: {response.text[:200]}"
            )
        return response

    def upload_bom(self, project_name: str, project_version: str, bom: dict) -> str:
        """Uploads a CycloneDX BOM into the project version, created when absent; returns its token."""
        body = {
            "projectName": project_name,
            "projectVersion": project_version,
            "autoCreate": True,
            "bom": _encoded(bom),
        }
        response = self._expect(self._request("PUT", "/api/v1/bom", json=body), 200)
        return response.json()["token"]

    def upload_vex(self, project_name: str, project_version: str, vex: dict) -> str | None:
        """Uploads a CycloneDX VEX onto the existing findings of the project version."""
        body = {"projectName": project_name, "projectVersion": project_version, "vex": _encoded(vex)}
        response = self._expect(self._request("PUT", "/api/v1/vex", json=body), 200)
        return response.json().get("token") if response.content else None

    def token_status(self, token: str) -> str | None:
        """PENDING, RUNNING, COMPLETED or FAILED; None while no processing is associated with the token."""
        response = self._expect(self._request("GET", f"/api/v1/event/token/{token}"), 200)
        return response.json().get("status")

    def project_uuid(self, project_name: str, project_version: str) -> str | None:
        response = self._request(
            "GET", "/api/v1/project/lookup", params={"name": project_name, "version": project_version}
        )
        if response.status_code == 404:
            return None
        return self._expect(response, 200).json()["uuid"]

    def findings(self, project_uuid: str) -> list[dict]:
        response = self._request(
            "GET", f"/api/v1/finding/project/{project_uuid}", params={"suppressed": "true"}
        )
        return self._expect(response, 200).json()
