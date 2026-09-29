"""OpenVEX to CycloneDX VEX conversion: the only module reading OpenVEX vocabulary, deleted once
Dependency-Track imports OpenVEX (DependencyTrack/dependency-track#7094).

Debian products name source packages while the SBOM lists binary packages carrying an `upstream`
qualifier: a product covers an SBOM component of the same type and namespace whose name or upstream
source is the product name, at the product version when it has one. Only `not_affected` statements are
emitted; the other known statuses carry no analysis Dependency-Track should apply, but one that names a
component's own package (same type, namespace, name and version) for the same vulnerability withholds the
`not_affected` of that component: a binary package reported affected is not covered by its source package.
"""

from collections.abc import Iterator
from urllib.parse import unquote

CONTEXT_PREFIX = "https://openvex.dev/ns"
CYCLONEDX_SPEC_VERSION = "1.6"

KNOWN_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}

# OpenVEX justification label -> CycloneDX analysis justification; None where CycloneDX has no
# equivalent (CycloneDX/specification#609): the label then only appears in the analysis detail.
JUSTIFICATIONS: dict[str, str | None] = {
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
    "vulnerable_code_cannot_be_controlled_by_adversary": None,
}


class VexConversionError(ValueError):
    """The OpenVEX document is malformed or uses a status or justification outside the specification."""


class Purl:
    """The parts of a package URL the coverage rule compares, percent-decoded."""

    def __init__(self, value: str) -> None:
        if not value.startswith("pkg:"):
            raise ValueError(f"not a package URL: {value!r}")
        body, _, qualifiers = value.split("#", 1)[0].partition("?")
        path, _, version = body[len("pkg:") :].partition("@")
        segments = [segment for segment in path.strip("/").split("/") if segment]
        if len(segments) < 2:
            raise ValueError(f"package URL without type and name: {value!r}")
        self.type = segments[0].lower()
        self.namespace = "/".join(unquote(segment) for segment in segments[1:-1])
        self.name = unquote(segments[-1])
        self.version = unquote(version) if version else None
        self.qualifiers = {
            key: unquote(qualifier_value)
            for key, _, qualifier_value in (item.partition("=") for item in qualifiers.split("&") if item)
        }

    @property
    def upstream(self) -> str | None:
        upstream = self.qualifiers.get("upstream")
        return upstream.split("@", 1)[0].split(" ", 1)[0] if upstream else None

    def covers(self, component: "Purl") -> bool:
        return (
            self.type == component.type
            and self.namespace == component.namespace
            and self.name in {component.name, component.upstream}
            and (self.version is None or self.version == component.version)
        )

    def names(self, component: "Purl") -> bool:
        return (
            self.type == component.type
            and self.namespace == component.namespace
            and self.name == component.name
            and (self.version is None or self.version == component.version)
        )


def _vulnerability_ids(statement: dict) -> set[str]:
    vulnerability = statement["vulnerability"]
    aliases = vulnerability.get("aliases")
    return {vulnerability["name"]} | {
        alias for alias in (aliases if isinstance(aliases, list) else []) if isinstance(alias, str) and alias
    }


def _sbom_components(components: object) -> Iterator[dict]:
    for component in components if isinstance(components, list) else []:
        if isinstance(component, dict):
            yield component
            yield from _sbom_components(component.get("components"))


def _product_purls(statement: dict) -> list[Purl]:
    products = statement.get("products")
    if not isinstance(products, list) or not products:
        raise VexConversionError(f"statement for {statement['vulnerability']['name']} has no products")
    purls = []
    for product in products:
        if not isinstance(product, dict):
            raise VexConversionError("a statement product is not an object")
        subcomponents = product.get("subcomponents")
        for item in subcomponents if isinstance(subcomponents, list) and subcomponents else [product]:
            identifiers = item.get("identifiers") if isinstance(item.get("identifiers"), dict) else {}
            identifier = item.get("@id") or identifiers.get("purl")
            try:
                purls.append(Purl(identifier if isinstance(identifier, str) else ""))
            except ValueError as error:
                raise VexConversionError(f"product {identifier!r} is not a package URL") from error
    return purls


def _validated_statements(document: object) -> list[dict]:
    if not isinstance(document, dict):
        raise VexConversionError("OpenVEX document is not a JSON object")
    context = document.get("@context")
    if not isinstance(context, str) or not context.startswith(CONTEXT_PREFIX):
        raise VexConversionError(f"@context {context!r} is not an OpenVEX context")
    statements = document.get("statements")
    if not isinstance(statements, list):
        raise VexConversionError("OpenVEX document has no statements list")
    for statement in statements:
        if not isinstance(statement, dict):
            raise VexConversionError("an OpenVEX statement is not an object")
        vulnerability = statement.get("vulnerability")
        if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("name"), str):
            raise VexConversionError("an OpenVEX statement has no vulnerability name")
        name = vulnerability["name"]
        status = statement.get("status")
        if status not in KNOWN_STATUSES:
            raise VexConversionError(f"statement for {name} has unknown status {status!r}")
        justification = statement.get("justification")
        if justification is not None and justification not in JUSTIFICATIONS:
            raise VexConversionError(f"statement for {name} has unknown justification {justification!r}")
        if status == "not_affected" and not justification and not statement.get("impact_statement"):
            raise VexConversionError(
                f"not_affected statement for {name} has no justification nor impact_statement"
            )
    return statements


def _detail(author: object, statement: dict) -> str:
    label = statement.get("justification")
    lines = [
        f"Vendor statement by {author or 'unknown author'}: OpenVEX {statement['status']}"
        + (f", justification {label}" if label else "")
    ]
    lines += [text for text in (statement.get("status_notes"), statement.get("impact_statement")) if text]
    return "\n".join(lines)


def openvex_to_cyclonedx(document: dict, sbom: dict) -> dict:
    """Returns the CycloneDX VEX of the OpenVEX `not_affected` statements on the SBOM components."""
    statements = _validated_statements(document)
    candidates = []
    for component in _sbom_components(sbom.get("components")):
        if isinstance(component.get("purl"), str) and isinstance(component.get("bom-ref"), str):
            try:
                candidates.append((component, Purl(component["purl"])))
            except ValueError:
                continue

    products_by_statement = [_product_purls(statement) for statement in statements]
    contesting = [
        (_vulnerability_ids(statement), products)
        for statement, products in zip(statements, products_by_statement, strict=True)
        if statement["status"] != "not_affected"
    ]

    covered: dict[str, dict] = {}
    vulnerabilities = []
    for statement, products in zip(statements, products_by_statement, strict=True):
        if statement["status"] != "not_affected":
            continue
        ids = _vulnerability_ids(statement)
        refs = []
        for component, purl in candidates:
            if component["bom-ref"] in refs or not any(product.covers(purl) for product in products):
                continue
            if any(
                ids & other_ids and any(p.names(purl) for p in others) for other_ids, others in contesting
            ):
                continue
            refs.append(component["bom-ref"])
            covered.setdefault(
                component["bom-ref"],
                {
                    key: component[key]
                    for key in ("bom-ref", "type", "group", "name", "version", "purl")
                    if key in component
                },
            )
        if not refs:
            continue
        analysis = {"state": "not_affected", "detail": _detail(document.get("author"), statement)}
        justification = JUSTIFICATIONS.get(statement.get("justification") or "")
        if justification:
            analysis["justification"] = justification
        vulnerability = {
            "id": statement["vulnerability"]["name"],
            "analysis": analysis,
            "affects": [{"ref": ref} for ref in refs],
        }
        # CycloneDX requires unique vulnerabilities; DHI documents repeat statements.
        if vulnerability not in vulnerabilities:
            vulnerabilities.append(vulnerability)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "components": list(covered.values()),
        "vulnerabilities": vulnerabilities,
    }
