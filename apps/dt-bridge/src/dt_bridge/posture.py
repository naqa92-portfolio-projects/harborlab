"""Image posture metrics per golden image, in the Prometheus text format VictoriaMetrics scrapes.

- `harborlab_image_vulnerabilities`: Harbor Trivy report entries and Dependency-Track findings of each catalog
  golden image and running governed image, before and after the VEX documents applied to it.
- `harborlab_running_containers`: running containers of governed images, with their Sigstore verdicts.
- `harborlab_admission_violations` and `harborlab_runtime_alerts`: admission denials (API server audit log)
  and Kubescape runtime alerts of the last 24 hours, read from VictoriaLogs.

An image belongs to the golden image named by its image config label `io.harborlab.golden.name`.
"""

import json
import logging
import re
import ssl
import time
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

import httpx
from sigstore.errors import Error as SigstoreError
from sigstore.models import Bundle
from sigstore.verify import Verifier

from dt_bridge.dt_client import DependencyTrackClient, DependencyTrackError
from dt_bridge.kubescape import IMAGE_ID_ANNOTATION, ImageReference, KubescapeError, image_reference
from dt_bridge.pipeline import SLSA_PREDICATE_TYPE, Bridge, ImageRef, is_image_tag
from dt_bridge.registry import RegistryError
from dt_bridge.sbom import AttestationError, extract_cyclonedx_sbom, is_cyclonedx_predicate_type
from dt_bridge.verification import Identities, signer_policy
from dt_bridge.vex import VexConversionError, openvex_to_cyclonedx

log = logging.getLogger(__name__)

GOLDEN_LABEL = "io.harborlab.golden.name"
HARBOR_REPORT_TYPE = "application/vnd.security.vulnerability.report; version=1.1"
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
NO_GOLDEN = "none"
SIGN_PREDICATE_TYPE = "https://sigstore.dev/cosign/sign/v1"
ATTESTATION_PREDICATE_TYPES = (
    "https://cyclonedx.org/bom",
    "https://spdx.dev/Document",
    SLSA_PREDICATE_TYPE,
)
BUNDLE_PREDICATE_ANNOTATION = "dev.sigstore.bundle.predicateType"
IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
LOGS_WINDOW = "24h"
LOGS_LIMIT = 5000
DENIED_POLICY = re.compile(r"Policy ([A-Za-z0-9.-]+) failed")
SERVICE_ACCOUNT_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
TIMEOUT_SECONDS = 30.0


def severity_of(value: object) -> str:
    severity = str(value or "").lower()
    return severity if severity in SEVERITIES[:-1] else "unknown"


def label_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render(name: str, help_text: str, samples: Iterable[tuple[dict[str, str], float]]) -> str:
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} gauge"]
    for labels, value in samples:
        rendered = ",".join(f'{key}="{label_value(val)}"' for key, val in sorted(labels.items()))
        lines.append(f"{name}{{{rendered}}} {value:g}")
    return "\n".join(lines) + "\n"


class PostureError(Exception):
    """A source of the posture metrics could not be read."""


# Failures of one source: reported, and the metrics it feeds keep their previous values.
POSTURE_ERRORS = (
    PostureError,
    RegistryError,
    DependencyTrackError,
    KubescapeError,
    AttestationError,
    VexConversionError,
    SigstoreError,
    httpx.HTTPError,
    OSError,
    KeyError,
    ValueError,
    TimeoutError,
)


class KubernetesApi:
    """Read-only Kubernetes API client with the pod's projected ServiceAccount token."""

    def __init__(self, api_url: str, *, service_account_dir: Path = SERVICE_ACCOUNT_DIR) -> None:
        self._token_file = service_account_dir / "token"
        context = ssl.create_default_context(cafile=str(service_account_dir / "ca.crt"))
        self._client = httpx.Client(base_url=api_url.rstrip("/"), timeout=TIMEOUT_SECONDS, verify=context)

    def get(self, path: str) -> dict:
        try:
            headers = {"Authorization": f"Bearer {self._token_file.read_text().strip()}"}
            response = self._client.get(path, headers=headers)
        except (httpx.HTTPError, OSError) as error:
            raise PostureError(f"GET {path} failed: {type(error).__name__}") from None
        if response.status_code != 200:
            raise PostureError(f"GET {path} answered HTTP {response.status_code}")
        return response.json()


class HarborApi:
    """Harbor v2.0 REST API with the dt-bridge read-only robot."""

    def __init__(self, base_url: str, username: str, password: str, *, ca_file: str) -> None:
        context = ssl.create_default_context(cafile=ca_file)
        self._client = httpx.Client(
            base_url=base_url.rstrip("/") + "/api/v2.0",
            auth=(username, password),
            timeout=TIMEOUT_SECONDS,
            verify=context,
        )

    def get(self, path: str, **params) -> object | None:
        """The JSON body, or None when Harbor holds no such object."""
        try:
            response = self._client.get(path, params=params)
        except httpx.HTTPError as error:
            raise PostureError(f"Harbor GET {path} failed: {type(error).__name__}") from None
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise PostureError(f"Harbor GET {path} answered HTTP {response.status_code}")
        return response.json()

    def artifact(self, project: str, repository: str, reference: str) -> dict | None:
        return self.get(
            f"/projects/{project}/repositories/{repository.replace('/', '%252F')}/artifacts/{reference}",
            with_tag="true",
        )

    def vulnerabilities(self, project: str, repository: str, digest: str) -> list[dict]:
        report = self.get(
            f"/projects/{project}/repositories/{repository.replace('/', '%252F')}"
            f"/artifacts/{digest}/additions/vulnerabilities"
        )
        return ((report or {}).get(HARBOR_REPORT_TYPE) or {}).get("vulnerabilities") or []

    def repositories(self, project: str) -> list[str]:
        items = self.get(f"/projects/{project}/repositories", page_size="100") or []
        return [item["name"].split("/", 1)[1] for item in items]


class VictoriaLogs:
    def __init__(self, base_url: str) -> None:
        self._client = httpx.Client(base_url=base_url.rstrip("/"), timeout=TIMEOUT_SECONDS)

    def query(self, logsql: str) -> list[dict]:
        try:
            response = self._client.post(
                "/select/logsql/query", data={"query": logsql, "limit": str(LOGS_LIMIT)}
            )
        except httpx.HTTPError as error:
            raise PostureError(f"VictoriaLogs query failed: {type(error).__name__}") from None
        if response.status_code != 200:
            raise PostureError(f"VictoriaLogs query answered HTTP {response.status_code}")
        return [json.loads(line) for line in response.text.splitlines() if line.strip()]


@dataclass(frozen=True)
class GovernedImage:
    project: str
    repository: str
    digest: str

    @property
    def path(self) -> str:
        return f"{self.project}/{self.repository}"


class SigstoreVerdicts:
    """Whether an image's cosign signature and its CycloneDX, SPDX and SLSA attestations verify, as
    `cosign verify` and `cosign verify-attestation` would: Sigstore public-good trust root, signer identity
    and issuer, statement subject equal to the image digest."""

    def __init__(self, identities: Identities) -> None:
        # The public-good trust root shipped with sigstore-python: its TUF client would use the process's
        # default TLS trust, which holds only the local CA here (SSL_CERT_FILE).
        self._verifier = Verifier.production(offline=True)
        self._policies = {project: signer_policy(identities, project) for project in identities.by_project}

    def verdict(self, bridge: Bridge, image: GovernedImage) -> tuple[bool, bool]:
        """(signed, attested), each verified against the build identity of the image's project."""
        policy = self._policies[image.project]
        verified: set[str] = set()
        for referrer in bridge.harbor.referrers(image.path, image.digest):
            predicate_type = (referrer.get("annotations") or {}).get(BUNDLE_PREDICATE_ANNOTATION)
            if predicate_type not in (SIGN_PREDICATE_TYPE, *ATTESTATION_PREDICATE_TYPES):
                continue
            if predicate_type in verified:
                continue
            _, manifest = bridge.harbor.manifest(image.path, referrer["digest"])
            raw = bridge.harbor.blob(image.path, manifest["layers"][0]["digest"])
            try:
                payload_type, payload = self._verifier.verify_dsse(Bundle.from_json(raw), policy)
            except (SigstoreError, ValueError) as error:
                log.info(
                    "Sigstore bundle not verified",
                    extra={"image": image.path, "digest": image.digest, "error": str(error)[:200]},
                )
                continue
            statement = json.loads(payload) if payload_type == IN_TOTO_PAYLOAD_TYPE else {}
            subjects = {
                f"sha256:{(subject.get('digest') or {}).get('sha256')}"
                for subject in statement.get("subject") or []
                if isinstance(subject, dict)
            }
            if statement.get("predicateType") == predicate_type and image.digest in subjects:
                verified.add(predicate_type)
        return SIGN_PREDICATE_TYPE in verified, all(t in verified for t in ATTESTATION_PREDICATE_TYPES)


@dataclass
class ImageFacts:
    golden: str
    tag: str | None


class Posture:
    """Collects the posture metrics; `refresh` is called periodically, `metrics` serves the last result."""

    def __init__(
        self,
        bridge: Bridge,
        dt: DependencyTrackClient,
        harbor_api: HarborApi,
        kube: KubernetesApi,
        logs: VictoriaLogs,
        *,
        harbor_host: str,
        governed_projects: set[str],
        catalog_configmap: tuple[str, str],
        kubescape_documents: Callable[[], list[dict]],
        verdicts: Callable[[], SigstoreVerdicts],
        vulnerabilities_ttl_seconds: float = 300.0,
    ) -> None:
        self._bridge = bridge
        self._dt = dt
        self._harbor = harbor_api
        self._kube = kube
        self._logs = logs
        self._harbor_host = harbor_host
        self._governed = governed_projects
        self._catalog_configmap = catalog_configmap
        self._kubescape_documents = kubescape_documents
        self._verdicts_factory = verdicts
        self._verdicts: SigstoreVerdicts | None = None
        self._ttl = vulnerabilities_ttl_seconds
        self._facts: dict[GovernedImage, ImageFacts] = {}
        self._vulnerabilities: dict[GovernedImage, tuple[float, list[tuple[dict, float]]]] = {}
        self._signatures: dict[GovernedImage, tuple[bool, bool]] = {}
        self._sections: dict[str, str] = {}

    # Image identity -----------------------------------------------------------------------------------

    def governed_image(self, reference: str) -> GovernedImage | None:
        """The Harbor golden/apps image of a reference to Harbor or to its GHCR source (same digests)."""
        try:
            parsed: ImageReference = image_reference(reference)
        except ValueError:
            return None
        path = parsed.repository
        if parsed.registry == "ghcr.io":
            parts = path.split("/")
            if len(parts) < 4:
                return None
            path = "/".join(parts[2:])
        elif parsed.registry != self._harbor_host:
            return None
        project, _, repository = path.partition("/")
        if project not in self._governed or not repository:
            return None
        digest = parsed.digest
        if digest is None and parsed.tag:
            artifact = self._harbor.artifact(project, repository, parsed.tag)
            digest = (artifact or {}).get("digest")
        return GovernedImage(project, repository, digest) if digest else None

    def facts(self, image: GovernedImage) -> ImageFacts | None:
        """Golden label and image tag of a Harbor artifact; None when Harbor does not hold it."""
        if image not in self._facts:
            artifact = self._harbor.artifact(image.project, image.repository, image.digest)
            if artifact is None:
                return None
            labels = ((artifact.get("extra_attrs") or {}).get("config") or {}).get("Labels") or {}
            tags = [t["name"] for t in artifact.get("tags") or [] if is_image_tag(t.get("name", ""))]
            self._facts[image] = ImageFacts(labels.get(GOLDEN_LABEL, ""), tags[0] if tags else None)
        return self._facts[image]

    def golden_of(self, reference: str) -> str:
        image = self.governed_image(reference)
        facts = self.facts(image) if image else None
        return (facts.golden if facts else "") or NO_GOLDEN

    # Sources ------------------------------------------------------------------------------------------

    def catalog_images(self) -> list[GovernedImage]:
        namespace, name = self._catalog_configmap
        data = self._kube.get(f"/api/v1/namespaces/{namespace}/configmaps/{name}").get("data") or {}
        digests = {key.replace(".", ":", 1) for key in data if key.startswith("sha256.")}
        images = []
        for repository in self._harbor.repositories("golden"):
            for digest in digests:
                if self._harbor.artifact("golden", repository, digest) is not None:
                    images.append(GovernedImage("golden", repository, digest))
        return images

    def running_containers(self) -> list[tuple[str, str, str, GovernedImage]]:
        """(namespace, pod, container, image) of every running container of a governed digest reference."""
        pattern = re.compile(
            rf"^{re.escape(self._harbor_host)}/(?:{'|'.join(map(re.escape, sorted(self._governed)))})"
            r"/[^@]+@sha256:[0-9a-f]{64}$"
        )
        running = []
        for pod in self._kube.get("/api/v1/pods").get("items") or []:
            metadata = pod.get("metadata") or {}
            if metadata.get("deletionTimestamp"):
                continue
            images = {c["name"]: c.get("image", "") for c in (pod.get("spec") or {}).get("containers") or []}
            for status in (pod.get("status") or {}).get("containerStatuses") or []:
                if not (status.get("state") or {}).get("running"):
                    continue
                candidates = [
                    images.get(status.get("name"), ""),
                    str(status.get("imageID", "")).removeprefix("docker-pullable://"),
                ]
                reference = next((c for c in candidates if pattern.match(c)), None)
                image = self.governed_image(reference) if reference else None
                if image:
                    running.append((metadata["namespace"], metadata["name"], status["name"], image))
        return running

    # Vulnerabilities ----------------------------------------------------------------------------------

    def _sbom(self, image: GovernedImage, tag: str) -> tuple[ImageRef, dict | None]:
        ref = ImageRef(image.project, image.repository, tag)
        referrers = self._bridge._attestations(ref, image.digest)
        cyclonedx = [r for t, refs in referrers.items() if is_cyclonedx_predicate_type(t) for r in refs]
        sbom = extract_cyclonedx_sbom(self._bridge._bundle(ref, cyclonedx)) if cyclonedx else None
        return ref, sbom

    def _vex_documents(self, image: GovernedImage, ref: ImageRef, running: bool) -> list[dict]:
        """The DHI OpenVEX of the image's base (when it is a DHI image) and, for a running image, its
        Kubescape runtime OpenVEX documents."""
        documents = []
        provenances = self._bridge._attestations(ref, image.digest).get(SLSA_PREDICATE_TYPE, [])
        base = self._bridge._dhi_base(ref, provenances)
        if base is not None and self._bridge.dhi is not None:
            _, manifest = self._bridge.harbor.manifest(image.path, image.digest)
            document = self._bridge._dhi_openvex(self._bridge.dhi, ref, manifest, *base)
            if document is not None:
                documents.append(document)
        if running:
            for item in self._kubescape_documents():
                annotations = (item.get("metadata") or {}).get("annotations") or {}
                reference = annotations.get(IMAGE_ID_ANNOTATION, "")
                if reference and self.governed_image(reference) == image:
                    documents.append(item["spec"])
        return documents

    def _vulnerability_samples(self, image: GovernedImage, golden: str, running: bool) -> list[tuple]:
        facts = self.facts(image)
        tag = facts.tag if facts else None
        entries = self._harbor.vulnerabilities(image.project, image.repository, image.digest)
        # Report entries a not_affected statement covers, through the SBOM component it names.
        not_affected: set[tuple[str, str, str]] = set()
        if tag:
            ref, sbom = self._sbom(image, tag)
            if sbom is not None:
                for document in self._vex_documents(image, ref, running):
                    vex = openvex_to_cyclonedx(document, sbom)
                    components = {c["bom-ref"]: c for c in vex["components"]}
                    for vulnerability in vex["vulnerabilities"]:
                        for affect in vulnerability["affects"]:
                            component = components.get(affect["ref"], {})
                            not_affected.add(
                                (vulnerability["id"], component.get("name", ""), component.get("version", ""))
                            )
        trivy_before = Counter(severity_of(e.get("severity")) for e in entries)
        trivy_after = Counter(
            severity_of(e.get("severity"))
            for e in entries
            if (e.get("id"), e.get("package"), e.get("version")) not in not_affected
        )

        findings: list[dict] = []
        uuid = self._dt.project_uuid(image.path, tag) if tag else None
        if uuid:
            findings = self._dt.findings(uuid)
        dt_before = Counter(severity_of((f.get("vulnerability") or {}).get("severity")) for f in findings)
        dt_after = Counter(
            severity_of((f.get("vulnerability") or {}).get("severity"))
            for f in findings
            if (f.get("analysis") or {}).get("state") not in ("NOT_AFFECTED", "FALSE_POSITIVE")
            and not (f.get("analysis") or {}).get("isSuppressed")
        )
        base = {"golden": golden, "image": image.path, "digest": image.digest}
        samples = []
        for source, before, after in (
            ("harbor-trivy", trivy_before, trivy_after),
            ("dependency-track", dt_before, dt_after),
        ):
            for vex, counts in (("before", before), ("after", after)):
                for severity in SEVERITIES:
                    labels = {**base, "source": source, "vex": vex, "severity": severity}
                    samples.append((labels, float(counts[severity])))
        return samples

    def _refresh_vulnerabilities(self, running: list[tuple[str, str, str, GovernedImage]]) -> None:
        running_images = {image for *_, image in running}
        images = list(dict.fromkeys([*self.catalog_images(), *running_images]))
        samples = []
        now = time.monotonic()
        for image in images:
            cached = self._vulnerabilities.get(image)
            if cached is None or now - cached[0] > self._ttl:
                facts = self.facts(image)
                golden = (facts.golden if facts else "") or NO_GOLDEN
                try:
                    cached = (now, self._vulnerability_samples(image, golden, image in running_images))
                    self._vulnerabilities[image] = cached
                except POSTURE_ERRORS as error:
                    log.error(
                        "image vulnerabilities not refreshed",
                        extra={
                            "image": image.path,
                            "digest": image.digest,
                            "error": f"{type(error).__name__}: {error}",
                        },
                    )
            if cached is not None:
                samples += cached[1]
        self._sections["vulnerabilities"] = render(
            "harborlab_image_vulnerabilities",
            "Vulnerabilities of a governed image by source and severity, before and after VEX.",
            samples,
        )

    # Running containers -------------------------------------------------------------------------------

    def _refresh_running(self, running: list[tuple[str, str, str, GovernedImage]]) -> None:
        if self._verdicts is None:
            self._verdicts = self._verdicts_factory()
        samples = []
        for namespace, pod, container, image in running:
            facts = self.facts(image)
            if not facts or not facts.golden:
                continue
            if image not in self._signatures:
                self._signatures[image] = self._verdicts.verdict(self._bridge, image)
            signed, attested = self._signatures[image]
            labels = {
                "golden": facts.golden,
                "namespace": namespace,
                "pod": pod,
                "container": container,
                "digest": image.digest,
                "signed": str(signed).lower(),
                "attested": str(attested).lower(),
            }
            samples.append((labels, 1.0))
        self._sections["running"] = render(
            "harborlab_running_containers",
            "Running container of a governed image, with its signature and attestation verdicts.",
            samples,
        )

    # Admission denials and runtime alerts -------------------------------------------------------------

    def _refresh_admission(self) -> None:
        rows = self._logs.query(
            f"_time:{LOGS_WINDOW} kind:=Event objectRef.resource:=pods"
            ' responseStatus.message:"denied the request"'
            " | fields objectRef.namespace, responseStatus.message, requestObject.spec.containers,"
            " requestObject.spec.initContainers, requestObject.spec.ephemeralContainers"
        )
        counts: Counter[tuple[str, str, str]] = Counter()
        for row in rows:
            policies = DENIED_POLICY.findall(row.get("responseStatus.message", ""))
            images = []
            for field in (
                "requestObject.spec.containers",
                "requestObject.spec.initContainers",
                "requestObject.spec.ephemeralContainers",
            ):
                try:
                    containers = json.loads(row.get(field) or "[]")
                except json.JSONDecodeError:
                    containers = []
                images += [c.get("image", "") for c in containers if isinstance(c, dict)]
            goldens = {self.golden_of(image) for image in images} or {NO_GOLDEN}
            for policy in policies:
                for golden in goldens:
                    counts[(golden, policy, row.get("objectRef.namespace", ""))] += 1
        self._sections["admission"] = render(
            "harborlab_admission_violations",
            f"Admission denials of the last {LOGS_WINDOW} per golden image of the denied image and policy.",
            (
                ({"golden": g, "policy": p, "action": "deny", "namespace": n}, float(count))
                for (g, p, n), count in sorted(counts.items())
            ),
        )

    def _refresh_runtime(self) -> None:
        rows = self._logs.query(
            f"_time:{LOGS_WINDOW} RuleID:* | stats by (RuntimeK8sDetails.namespace, "
            "RuntimeK8sDetails.podName, RuntimeK8sDetails.containerName, RuntimeK8sDetails.image, "
            "RuntimeK8sDetails.imageDigest, BaseRuntimeMetadata.alertName) count() alerts"
        )
        counts: Counter[tuple[str, str, str, str, str]] = Counter()
        for row in rows:
            reference = row.get("RuntimeK8sDetails.image", "")
            digest = row.get("RuntimeK8sDetails.imageDigest", "")
            if reference and "@" not in reference and digest.startswith("sha256:"):
                reference = f"{reference}@{digest}"
            golden = self.golden_of(reference) if reference else NO_GOLDEN
            key = (
                golden,
                row.get("RuntimeK8sDetails.namespace", ""),
                row.get("RuntimeK8sDetails.podName", ""),
                row.get("RuntimeK8sDetails.containerName", ""),
                row.get("BaseRuntimeMetadata.alertName", ""),
            )
            counts[key] += int(row.get("alerts", "0") or 0)
        self._sections["runtime"] = render(
            "harborlab_runtime_alerts",
            f"Kubescape runtime alerts of the last {LOGS_WINDOW} per golden image of the alerted container.",
            (
                ({"golden": g, "namespace": n, "pod": p, "container": c, "rule": r}, float(count))
                for (g, n, p, c, r), count in sorted(counts.items())
            ),
        )

    def refresh(self) -> None:
        """Refreshes every section; a failing source keeps its previous section."""
        running: list | None = None
        steps = [
            ("running containers", lambda: self._refresh_running(running)),
            ("vulnerabilities", lambda: self._refresh_vulnerabilities(running)),
            ("admission violations", self._refresh_admission),
            ("runtime alerts", self._refresh_runtime),
        ]
        try:
            running = self.running_containers()
        except POSTURE_ERRORS as error:
            log.error("running containers not listed", extra={"error": f"{type(error).__name__}: {error}"})
            steps = steps[2:]
        for name, step in steps:
            try:
                step()
            except POSTURE_ERRORS as error:
                log.error(f"{name} not refreshed", extra={"error": f"{type(error).__name__}: {error}"})

    def metrics(self) -> str:
        return "".join(
            self._sections[key]
            for key in ("vulnerabilities", "running", "admission", "runtime")
            if key in self._sections
        )
