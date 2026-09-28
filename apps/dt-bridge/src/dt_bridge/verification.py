"""Sigstore signer policy of the governed images: the build workflow identity, run from this repository."""

import re
from dataclasses import dataclass

from cryptography.x509 import Certificate, SubjectAlternativeName, UniformResourceIdentifier
from sigstore.errors import VerificationError
from sigstore.verify.policy import AllOf, OIDCIssuerV2, OIDCSourceRepositoryURI, VerificationPolicy


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
