"""OpenVEX to CycloneDX VEX conversion, the one module removed once Dependency-Track imports OpenVEX.

OpenVEX products name packages (Debian ones by source package); the CycloneDX VEX points at the components
of the project SBOM they cover: same type and namespace, same name or `upstream` qualifier, same version.
"""

import json
from pathlib import Path

import pytest

from dt_bridge.vex import VexConversionError, openvex_to_cyclonedx

FIXTURES = Path(__file__).parent / "fixtures"
SOURCE_DIR = Path(__file__).parent.parent / "src" / "dt_bridge"
VENDOR = "Example Vendor <vex@example.invalid>"
DEBIAN = "?arch=amd64&distro=debian-13.7"
OPENSSL = "pkg:deb/debian/openssl@3.5.7-1~deb13u2%2Bdhi1"

# Not listed: setuptools 70.3.0 is not the SBOM version, CVE-2026-17084 is only under investigation.
NOT_AFFECTED = {
    ("CVE-2010-0928", OPENSSL + DEBIAN),
    ("CVE-2010-0928", "pkg:deb/debian/libssl3t64@3.5.7-1~deb13u2%2Bdhi1" + DEBIAN + "&upstream=openssl"),
    ("CVE-2025-69720", "pkg:deb/debian/libncursesw6@6.5%2B20250216-2%2Bdhi4" + DEBIAN + "&upstream=ncurses"),
    ("GHSA-6v7p-g79w-8964", "pkg:pypi/msgpack@1.1.2"),
    ("CVE-2099-0001", "pkg:deb/debian/libpython-3.13-minimal@3.13.15-2" + DEBIAN + "&upstream=python-3.13"),
    (
        "CVE-2099-0002",
        "pkg:deb/debian/zlib1g@1%3A1.3.dfsg%2Breally1.3.1-1%2Bdhi2" + DEBIAN + "&upstream=zlib",
    ),
    ("CVE-2099-0003", "pkg:deb/debian/libsqlite3-0@3.46.1-7%2Bdeb13u2%2Bdhi1" + DEBIAN + "&upstream=sqlite3"),
}

# CycloneDX justification per statement; None where no CycloneDX value is equivalent (the vendor label
# is then only carried in the analysis detail).
JUSTIFICATIONS = {
    "CVE-2010-0928": None,
    "CVE-2025-69720": "protected_by_mitigating_control",
    "GHSA-6v7p-g79w-8964": "code_not_present",
    "CVE-2099-0001": "code_not_reachable",
    "CVE-2099-0002": "code_not_present",
    "CVE-2099-0003": None,
}

# Vendor text the analysis detail must carry, besides the document author.
DETAILS = {
    "CVE-2010-0928": [
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "Fault injection attacks are outside the OpenSSL threat model.",
    ],
    "CVE-2025-69720": [
        "inline_mitigations_already_exist",
        "Patch applied: standalone fix extracted from the upstream ncurses 6.5 patch 20251213.",
    ],
    "GHSA-6v7p-g79w-8964": [
        "vulnerable_code_not_present",
        "The vulnerable _cmsgpack C extension is not shipped.",
    ],
    "CVE-2099-0001": [
        "vulnerable_code_not_in_execute_path",
        "The affected module is never imported by the interpreter start-up path.",
    ],
    "CVE-2099-0002": ["component_not_present"],
    "CVE-2099-0003": ["The vulnerable FTS5 code path requires a build option the package does not enable."],
}


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text())


def not_affected_pairs(vex):
    purl_by_ref = {component["bom-ref"]: component.get("purl") for component in vex.get("components", [])}
    return {
        (vulnerability["id"], purl_by_ref.get(affect["ref"]))
        for vulnerability in vex["vulnerabilities"]
        if vulnerability["analysis"]["state"] == "not_affected"
        for affect in vulnerability["affects"]
    }


def analyses_by_id(vex):
    return {
        vulnerability["id"]: vulnerability["analysis"]
        for vulnerability in vex["vulnerabilities"]
        if vulnerability["analysis"]["state"] == "not_affected"
    }


def test_not_affected_becomes_cyclonedx_not_affected():
    document = load_fixture("openvex-document.json")
    sbom = load_fixture("cyclonedx-sbom.json")

    vex = openvex_to_cyclonedx(document, sbom)

    assert vex["bomFormat"] == "CycloneDX"
    assert vex["specVersion"] in {"1.4", "1.5", "1.6", "1.7"}
    assert not_affected_pairs(vex) == NOT_AFFECTED
    sbom_refs = {component["bom-ref"] for component in sbom["components"]}
    vex_refs = [component["bom-ref"] for component in vex["components"]]
    assert len(vex_refs) == len(set(vex_refs))
    assert set(vex_refs) <= sbom_refs


def test_vendor_justification_is_mapped():
    document = load_fixture("openvex-document.json")
    sbom = load_fixture("cyclonedx-sbom.json")

    analyses = analyses_by_id(openvex_to_cyclonedx(document, sbom))

    assert {
        vuln_id: analysis.get("justification") for vuln_id, analysis in analyses.items()
    } == JUSTIFICATIONS
    for vuln_id, texts in DETAILS.items():
        for text in [VENDOR, *texts]:
            assert text in analyses[vuln_id]["detail"], (
                f"{vuln_id}: {text!r} missing from the analysis detail"
            )


def test_unknown_status_is_rejected():
    document = load_fixture("openvex-unknown-status.json")
    sbom = load_fixture("cyclonedx-sbom.json")

    with pytest.raises(VexConversionError, match="wont_fix"):
        openvex_to_cyclonedx(document, sbom)


STATEMENT = {
    "vulnerability": {"name": "CVE-2010-0928"},
    "products": [{"@id": OPENSSL + "?os_name=debian&os_version=13"}],
    "status": "not_affected",
    "justification": "vulnerable_code_cannot_be_controlled_by_adversary",
}
CONTEXT = "https://openvex.dev/ns/v0.2.0"


@pytest.mark.parametrize(
    "document",
    [
        pytest.param([STATEMENT], id="not-an-object"),
        pytest.param(
            {"@context": "https://example.invalid/ns", "statements": [STATEMENT]}, id="foreign-context"
        ),
        pytest.param({"@context": CONTEXT}, id="no-statements"),
        pytest.param({"@context": CONTEXT, "statements": STATEMENT}, id="statements-not-a-list"),
        pytest.param(
            {"@context": CONTEXT, "statements": [{**STATEMENT, "vulnerability": {}}]},
            id="no-vulnerability-name",
        ),
        pytest.param({"@context": CONTEXT, "statements": [{**STATEMENT, "products": []}]}, id="no-product"),
        pytest.param(
            {"@context": CONTEXT, "statements": [{**STATEMENT, "products": [{"@id": "openssl 3.5.7"}]}]},
            id="product-not-a-purl",
        ),
        pytest.param(
            {"@context": CONTEXT, "statements": [{**STATEMENT, "justification": "because"}]},
            id="unknown-justification",
        ),
        pytest.param(
            {
                "@context": CONTEXT,
                "statements": [{key: value for key, value in STATEMENT.items() if key != "justification"}],
            },
            id="not-affected-without-justification-or-impact-statement",
        ),
    ],
)
def test_malformed_document_is_rejected(document):
    sbom = load_fixture("cyclonedx-sbom.json")

    with pytest.raises(VexConversionError):
        openvex_to_cyclonedx(document, sbom)


# OpenVEX statement vocabulary: only the conversion module reads it.
OPENVEX_TERMS = [
    "impact_statement",
    "status_notes",
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
]


def test_openvex_conversion_is_isolated_in_vex_module():
    modules = sorted(path for path in SOURCE_DIR.rglob("*.py") if path != SOURCE_DIR / "vex.py")

    readers = [
        f"{path.relative_to(SOURCE_DIR)}: {term}"
        for path in modules
        for term in OPENVEX_TERMS
        if term in path.read_text()
    ]

    assert (SOURCE_DIR / "vex.py").is_file()
    assert readers == []
