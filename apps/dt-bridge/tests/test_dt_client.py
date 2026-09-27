"""Dependency-Track REST client, exercised through httpx.MockTransport at the transport boundary."""

import base64
import json
from pathlib import Path

import httpx
import pytest

from dt_bridge.dt_client import (
    DependencyTrackClient,
    DependencyTrackError,
    DependencyTrackServerError,
    DependencyTrackTimeout,
    DependencyTrackUnauthorized,
)

FIXTURES = Path(__file__).parent / "fixtures"
BASE_URL = "http://dependency-track.example.invalid"
API_KEY = "fake-dt-api-key-for-tests"
PROJECT_NAME = "golden/python"
PROJECT_VERSION = "sha-b9fdf902347ed3e77985c9b3c6f7a6a63fa439ff"
PROCESSING_UUID = "3c0f6d1e-8a4b-4f2e-9c7d-5b6a4e3d2c1b"


def load_sbom():
    return json.loads((FIXTURES / "cyclonedx-sbom.json").read_text())


def client_answering(handler):
    return DependencyTrackClient(BASE_URL, api_key=API_KEY, transport=httpx.MockTransport(handler))


def test_upload_sends_bom_to_project_version():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"token": PROCESSING_UUID})

    token = client_answering(handler).upload_bom(PROJECT_NAME, PROJECT_VERSION, load_sbom())

    assert token == PROCESSING_UUID
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "PUT"
    assert request.url == f"{BASE_URL}/api/v1/bom"
    assert request.headers["X-Api-Key"] == API_KEY
    body = json.loads(request.content)
    assert body["projectName"] == PROJECT_NAME
    assert body["projectVersion"] == PROJECT_VERSION
    assert body["autoCreate"] is True
    assert json.loads(base64.b64decode(body["bom"])) == load_sbom()


def test_upload_vex_sends_vex_to_project_version():
    vex = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "vulnerabilities": [
            {
                "id": "CVE-2010-0928",
                "analysis": {"state": "not_affected", "detail": "Example Vendor <vex@example.invalid>"},
                "affects": [{"ref": "pkg:deb/debian/openssl@3.5.7-1~deb13u2%2Bdhi1"}],
            }
        ],
    }
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"token": PROCESSING_UUID})

    client_answering(handler).upload_vex(PROJECT_NAME, PROJECT_VERSION, vex)

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "PUT"
    assert request.url == f"{BASE_URL}/api/v1/vex"
    assert request.headers["X-Api-Key"] == API_KEY
    body = json.loads(request.content)
    assert body["projectName"] == PROJECT_NAME
    assert body["projectVersion"] == PROJECT_VERSION
    assert json.loads(base64.b64decode(body["vex"])) == vex


def test_upload_raises_on_unauthorized():
    def handler(request):
        return httpx.Response(401, text="Unauthorized")

    with pytest.raises(DependencyTrackUnauthorized) as excinfo:
        client_answering(handler).upload_bom(PROJECT_NAME, PROJECT_VERSION, load_sbom())

    assert isinstance(excinfo.value, DependencyTrackError)
    assert API_KEY not in str(excinfo.value)


def test_upload_raises_on_server_error():
    def handler(request):
        return httpx.Response(503, text="Service Unavailable")

    with pytest.raises(DependencyTrackServerError) as excinfo:
        client_answering(handler).upload_bom(PROJECT_NAME, PROJECT_VERSION, load_sbom())

    assert isinstance(excinfo.value, DependencyTrackError)
    assert excinfo.value.status_code == 503
    assert API_KEY not in str(excinfo.value)


def test_upload_raises_on_timeout():
    def handler(request):
        raise httpx.ReadTimeout("timed out", request=request)

    with pytest.raises(DependencyTrackTimeout) as excinfo:
        client_answering(handler).upload_bom(PROJECT_NAME, PROJECT_VERSION, load_sbom())

    assert isinstance(excinfo.value, DependencyTrackError)
