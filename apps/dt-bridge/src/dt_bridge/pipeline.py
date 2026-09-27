"""From a Harbor image tag to Dependency-Track: the attested CycloneDX SBOM, then the DHI OpenVEX of its base.

Everything is read from the registries; the Harbor event only names the image.
"""

import json
import logging
import time
from dataclasses import dataclass
from urllib.parse import unquote

from dt_bridge.dt_client import DependencyTrackClient
from dt_bridge.registry import IMAGE_CONFIG_MEDIA_TYPES, INDEX_MEDIA_TYPES, Registry, RegistryError
from dt_bridge.sbom import (
    AttestationError,
    extract_cyclonedx_sbom,
    intoto_statement,
    is_cyclonedx_predicate_type,
)
from dt_bridge.vex import openvex_to_cyclonedx

log = logging.getLogger(__name__)

PREDICATE_TYPE_ANNOTATION = "dev.sigstore.bundle.predicateType"
CREATED_ANNOTATION = "org.opencontainers.image.created"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
INTOTO_ARTIFACT_TYPE = "application/vnd.in-toto+json"
INTOTO_PREDICATE_ANNOTATION = "in-toto.io/predicate-type"
OPENVEX_PREDICATE_TYPE = "https://openvex.dev/ns/v0.2.0"
DHI_REGISTRY = "dhi.io"
ANALYSIS_TIMEOUT_SECONDS = 900
FINDINGS_TIMEOUT_SECONDS = 120
POLL_SECONDS = 5
TERMINAL_TOKEN_STATUSES = {"COMPLETED", "FAILED"}


@dataclass(frozen=True)
class ImageRef:
    project: str
    repository: str
    tag: str

    @property
    def path(self) -> str:
        return f"{self.project}/{self.repository}"


def is_image_tag(tag: str) -> bool:
    """Referrers fallback tags (`sha256-<hex>`) and digests are not image versions."""
    return bool(tag) and not tag.startswith("sha256-") and not tag.startswith("sha256:")


def purl_key(purl: str) -> str:
    """Package URL compared across tools: subpath dropped, percent-decoded, qualifiers sorted."""
    body, _, qualifiers = purl.split("#", 1)[0].partition("?")
    return unquote(body) + (
        "?" + "&".join(sorted(unquote(q) for q in qualifiers.split("&") if q)) if qualifiers else ""
    )


@dataclass(frozen=True)
class PendingVex:
    image: ImageRef
    token: str
    vex: dict


class Bridge:
    def __init__(self, harbor: Registry, dt: DependencyTrackClient, dhi: Registry | None) -> None:
        self.harbor = harbor
        self.dt = dt
        self.dhi = dhi

    def _attestations(self, image: ImageRef, digest: str) -> dict[str, list[dict]]:
        by_type: dict[str, list[dict]] = {}
        for referrer in self.harbor.referrers(image.path, digest):
            predicate_type = (referrer.get("annotations") or {}).get(PREDICATE_TYPE_ANNOTATION)
            if predicate_type:
                by_type.setdefault(predicate_type, []).append(referrer)
        return by_type

    def _bundle(self, image: ImageRef, referrers: list[dict]) -> bytes:
        latest = max(referrers, key=lambda r: (r.get("annotations") or {}).get(CREATED_ANNOTATION, ""))
        _, manifest = self.harbor.manifest(image.path, latest["digest"])
        return self.harbor.blob(image.path, manifest["layers"][0]["digest"])

    def process(self, image: ImageRef) -> "PendingVex | None":
        """Uploads the attested SBOM; returns the DHI VEX to apply once Dependency-Track has analysed it."""
        digest, manifest = self.harbor.manifest(image.path, image.tag)
        is_index = manifest.get("mediaType") in INDEX_MEDIA_TYPES or "manifests" in manifest
        config_type = (manifest.get("config") or {}).get("mediaType")
        if not is_index and (manifest.get("artifactType") or config_type not in IMAGE_CONFIG_MEDIA_TYPES):
            log.info("not an image, skipped", extra={"image": image.path, "tag": image.tag, "digest": digest})
            return None

        attestations = self._attestations(image, digest)
        cyclonedx = [r for t, refs in attestations.items() if is_cyclonedx_predicate_type(t) for r in refs]
        if not cyclonedx:
            log.warning("no CycloneDX attestation, skipped", extra={"image": image.path, "tag": image.tag})
            return None
        sbom = extract_cyclonedx_sbom(self._bundle(image, cyclonedx))
        token = self.dt.upload_bom(image.path, image.tag, sbom)
        log.info(
            "SBOM uploaded",
            extra={
                "image": image.path,
                "tag": image.tag,
                "digest": digest,
                "token": token,
                "components": len(sbom.get("components", [])),
            },
        )

        base = self._dhi_base(image, attestations.get(SLSA_PREDICATE_TYPE, []))
        if base is None or self.dhi is None:
            return None
        document = self._dhi_openvex(self.dhi, image, manifest, *base)
        if document is None:
            return None
        return PendingVex(image, token, openvex_to_cyclonedx(document, sbom))

    def apply_vex(self, pending: "PendingVex") -> None:
        image = pending.image
        self._wait_for_analysis(pending.token)
        vex = self._on_dependency_track_findings(image, pending.vex)
        if not vex["vulnerabilities"]:
            log.info(
                "no DHI VEX statement covers an SBOM component", extra={"image": image.path, "tag": image.tag}
            )
            return
        answer = self.dt.upload_vex(image.path, image.tag, vex)
        log.info(
            "DHI VEX uploaded",
            extra={
                "image": image.path,
                "tag": image.tag,
                "token": answer.get("token"),
                "project_uuid": answer.get("projectUuid"),
                "vex": vex,
            },
        )

    def image_of_digest(self, project: str, repository: str, digest: str) -> ImageRef | None:
        """The image tag Harbor holds for a digest: the version of its Dependency-Track project."""
        path = f"{project}/{repository}"
        for tag in self.harbor.tags(path):
            if is_image_tag(tag) and self.harbor.manifest(path, tag)[0] == digest:
                return ImageRef(project, repository, tag)
        return None

    def forward_kubescape(
        self, image: ImageRef, digest: str, name: str, version: object, document: dict
    ) -> None:
        """Uploads the Kubescape runtime VEX of a running image on the components of its attested SBOM."""
        extra = {
            "image": image.path,
            "tag": image.tag,
            "digest": digest,
            "kubescape": name,
            "kubescape_version": version,
        }
        cyclonedx = [
            r
            for t, refs in self._attestations(image, digest).items()
            if is_cyclonedx_predicate_type(t)
            for r in refs
        ]
        if not cyclonedx:
            log.warning("no CycloneDX attestation, Kubescape VEX skipped", extra=extra)
            return
        sbom = extract_cyclonedx_sbom(self._bundle(image, cyclonedx))
        if self.dt.project_uuid(image.path, image.tag) is None:
            token = self.dt.upload_bom(image.path, image.tag, sbom)
            log.info(
                "SBOM uploaded",
                extra={**extra, "token": token, "components": len(sbom.get("components", []))},
            )
            self._wait_for_analysis(token)
        vex = openvex_to_cyclonedx(document, sbom)
        if not vex["vulnerabilities"]:
            log.info("no Kubescape VEX statement covers an SBOM component", extra=extra)
            return
        vex = self._on_dependency_track_findings(image, vex)
        answer = self.dt.upload_vex(image.path, image.tag, vex)
        log.info(
            "Kubescape VEX uploaded",
            extra={
                **extra,
                "token": answer.get("token"),
                "project_uuid": answer.get("projectUuid"),
                "vex": vex,
            },
        )

    def _dhi_base(self, image: ImageRef, provenances: list[dict]) -> tuple[str, str] | None:
        if not provenances:
            return None
        statement = intoto_statement(self._bundle(image, provenances))
        if statement.get("predicateType") != SLSA_PREDICATE_TYPE:
            raise AttestationError(f"provenance predicateType is {statement.get('predicateType')!r}")
        dependencies = (
            (statement.get("predicate") or {}).get("buildDefinition", {}).get("resolvedDependencies", [])
        )
        bases = {
            (dep["uri"], dep.get("digest", {}).get("sha256", ""))
            for dep in dependencies
            if isinstance(dep, dict) and str(dep.get("uri", "")).startswith(f"oci://{DHI_REGISTRY}/")
        }
        if len(bases) != 1:
            return None
        uri, sha256 = bases.pop()
        repository = uri.removeprefix(f"oci://{DHI_REGISTRY}/").split("@", 1)[0]
        last = repository.rsplit("/", 1)[-1]
        if ":" in last:
            repository = repository[: len(repository) - len(last)] + last.split(":", 1)[0]
        return repository, f"sha256:{sha256}"

    def _platform(self, image: ImageRef, manifest: dict) -> tuple[str, str]:
        if "manifests" in manifest:
            platform = manifest["manifests"][0].get("platform", {})
            return platform.get("os", ""), platform.get("architecture", "")
        config = json.loads(self.harbor.blob(image.path, manifest["config"]["digest"]))
        return config.get("os", ""), config.get("architecture", "")

    def _dhi_openvex(
        self, dhi: Registry, image: ImageRef, manifest: dict, repository: str, base_digest: str
    ) -> dict | None:
        platform = self._platform(image, manifest)
        _, base = dhi.manifest(repository, base_digest)
        platform_digest = base_digest
        if "manifests" in base:
            matches = [
                m["digest"]
                for m in base["manifests"]
                if (m.get("platform", {}).get("os"), m.get("platform", {}).get("architecture")) == platform
            ]
            if not matches:
                log.warning("DHI base has no manifest for the image platform", extra={"image": image.path})
                return None
            platform_digest = matches[0]
        best = None
        for referrer in dhi.referrers(repository, platform_digest, INTOTO_ARTIFACT_TYPE):
            if (referrer.get("annotations") or {}).get(INTOTO_PREDICATE_ANNOTATION) != OPENVEX_PREDICATE_TYPE:
                continue
            _, attestation = dhi.manifest(repository, referrer["digest"])
            statement = json.loads(dhi.blob(repository, attestation["layers"][0]["digest"]))
            document = (
                statement.get("predicate")
                if statement.get("predicateType") == OPENVEX_PREDICATE_TYPE
                else None
            )
            if not isinstance(document, dict):
                continue
            updated = document.get("last_updated") or document.get("timestamp") or ""
            if best is None or updated > best[0]:
                best = (updated, document)
        if best is None:
            log.warning(
                "no DHI OpenVEX attestation",
                extra={"image": image.path, "dhi": f"{repository}@{platform_digest}"},
            )
            return None
        log.info("DHI OpenVEX fetched", extra={"image": image.path, "dhi": f"{repository}@{platform_digest}"})
        return best[1]

    def _wait_for_analysis(self, token: str) -> None:
        """Waits for the BOM processing, analysis included, so the VEX meets the findings it produced."""
        deadline = time.monotonic() + ANALYSIS_TIMEOUT_SECONDS
        while (status := self.dt.token_status(token)) not in TERMINAL_TOKEN_STATUSES:
            if time.monotonic() > deadline:
                raise TimeoutError(f"Dependency-Track BOM token {token} still {status} after the timeout")
            time.sleep(POLL_SECONDS)

    def _on_dependency_track_findings(self, image: ImageRef, vex: dict) -> dict:
        """Re-keys the VEX on Dependency-Track's own vulnerability ids (a CVE may be held as an OSV or GHSA
        id with the CVE as alias) where DT reports the pair as a finding; other pairs keep their VEX id."""
        uuid = self.dt.project_uuid(image.path, image.tag)
        findings = self.dt.findings(uuid) if uuid else []
        deadline = time.monotonic() + FINDINGS_TIMEOUT_SECONDS
        while uuid and not findings and time.monotonic() < deadline:
            time.sleep(POLL_SECONDS)
            findings = self.dt.findings(uuid)

        purl_by_ref = {c["bom-ref"]: purl_key(c["purl"]) for c in vex["components"] if c.get("purl")}
        rekeyed: dict[tuple[str, str], dict] = {}
        unmatched: list[dict] = []
        for vulnerability in vex["vulnerabilities"]:
            matched_refs: set[str] = set()
            refs_by_purl: dict[str, list[str]] = {}
            for affect in vulnerability["affects"]:
                refs_by_purl.setdefault(purl_by_ref.get(affect["ref"], ""), []).append(affect["ref"])
            for finding in findings:
                dt_vuln = finding.get("vulnerability") or {}
                ids = {dt_vuln.get("vulnId")} | {
                    value
                    for alias in dt_vuln.get("aliases") or []
                    if isinstance(alias, dict)
                    for value in alias.values()
                    if isinstance(value, str)
                }
                refs = refs_by_purl.get(purl_key((finding.get("component") or {}).get("purl") or ""), [])
                if vulnerability["id"] not in ids or not refs:
                    continue
                key = (dt_vuln["vulnId"], dt_vuln.get("source", ""))
                entry = rekeyed.setdefault(
                    key,
                    {
                        "id": key[0],
                        "source": {"name": key[1]},
                        "analysis": vulnerability["analysis"],
                        "affects": [],
                    },
                )
                entry["affects"] += [{"ref": ref} for ref in refs if {"ref": ref} not in entry["affects"]]
                matched_refs.update(refs)
            remaining = [affect for affect in vulnerability["affects"] if affect["ref"] not in matched_refs]
            if remaining and {**vulnerability, "affects": remaining} not in unmatched:
                unmatched.append({**vulnerability, "affects": remaining})
        return {**vex, "vulnerabilities": list(rekeyed.values()) + unmatched}


def images_of_event(event: dict, governed_projects: set[str]) -> list[ImageRef]:
    """Image tags a Harbor PUSH_ARTIFACT or REPLICATION webhook payload names."""
    data = event.get("event_data") or {}
    images: list[ImageRef] = []
    if event.get("type") == "PUSH_ARTIFACT":
        repository = data.get("repository") or {}
        project, name = repository.get("namespace", ""), repository.get("name", "")
        images += [ImageRef(project, name, r.get("tag") or "") for r in data.get("resources") or []]
    elif event.get("type") == "REPLICATION":
        replication = data.get("replication") or {}
        project = (replication.get("dest_resource") or {}).get("namespace", "")
        for artifact in replication.get("successful_artifact") or []:
            name = (artifact.get("name_tag") or "").split(" [", 1)[0].split(":", 1)[0]
            images += [ImageRef(project, name, reference) for reference in artifact.get("references") or []]
    return [
        image
        for image in dict.fromkeys(images)
        if image.project in governed_projects and image.repository and is_image_tag(image.tag)
    ]


__all__ = ["Bridge", "ImageRef", "PendingVex", "RegistryError", "images_of_event"]
