"""Closed edge-case profiles for public executable method development.

Profiles describe coverage obligations only.  They contain no fixture paths,
bytes, answers, random seeds, or execution authority.  Their commitments are
the same opaque values already used by the 100-task public registry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal, TypeAlias

from .executable_static_types import domain_sha256


FIXTURE_PROFILE_VERSION: Final[str] = "1.0.0"

FixtureProfileId: TypeAlias = Literal[
    "spaces-unicode",
    "leading-dashes-globs",
    "empty-duplicates",
    "symlinks-ordering",
    "partial-permissions",
]

_PROFILE_CASES: Final[
    tuple[tuple[FixtureProfileId, tuple[str, str]], ...]
] = (
    ("spaces-unicode", ("spaces", "unicode")),
    ("leading-dashes-globs", ("leading-dashes", "glob-characters")),
    ("empty-duplicates", ("empty-input", "duplicate-records")),
    ("symlinks-ordering", ("symlinks", "ordering-variation")),
    ("partial-permissions", ("partial-failure", "permission-errors")),
)


def compute_fixture_profile_sha256(cases: tuple[str, str]) -> str:
    if type(cases) is not tuple or len(cases) != 2 or any(
        type(item) is not str or not item for item in cases
    ):
        raise ValueError("fixture profile cases must be an exact pair of strings")
    return domain_sha256(
        "cbds.executable-static.fixture-profile.v1",
        {
            "profile_version": FIXTURE_PROFILE_VERSION,
            "cases": list(cases),
        },
    )


@dataclass(frozen=True, slots=True)
class ExecutableFixtureProfile:
    profile_id: FixtureProfileId
    cases: tuple[str, str]
    profile_sha256: str
    profile_version: str = FIXTURE_PROFILE_VERSION
    public_method_development: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        expected = dict(_PROFILE_CASES).get(self.profile_id)
        if expected is None or type(self.profile_id) is not str:
            raise ValueError("fixture profile_id is outside the closed profile set")
        if type(self.cases) is not tuple or self.cases != expected:
            raise ValueError("fixture profile cases do not match the closed profile")
        if self.profile_version != FIXTURE_PROFILE_VERSION:
            raise ValueError("fixture profile_version is unsupported")
        if self.profile_sha256 != compute_fixture_profile_sha256(self.cases):
            raise ValueError("fixture profile_sha256 does not match its cases")
        if (
            self.public_method_development is not True
            or self.sealed is not False
            or self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise ValueError("fixture profile authority boundary is invalid")

    def to_public_coverage_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "profile_version": self.profile_version,
            "profile_id": self.profile_id,
            "cases": list(self.cases),
            "profile_sha256": self.profile_sha256,
            "public_method_development": self.public_method_development,
            "sealed": self.sealed,
            "candidate_execution_authorized": self.candidate_execution_authorized,
            "model_selection_eligible": self.model_selection_eligible,
            "claim_authorized": self.claim_authorized,
        }


PUBLIC_DEVELOPMENT_FIXTURE_PROFILES: Final[
    tuple[ExecutableFixtureProfile, ...]
] = tuple(
    ExecutableFixtureProfile(
        profile_id=profile_id,
        cases=cases,
        profile_sha256=compute_fixture_profile_sha256(cases),
    )
    for profile_id, cases in _PROFILE_CASES
)


def fixture_profile_by_sha256(profile_sha256: str) -> ExecutableFixtureProfile:
    matches = tuple(
        profile
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if profile.profile_sha256 == profile_sha256
    )
    if len(matches) != 1:
        raise ValueError("unknown executable fixture profile commitment")
    return matches[0]


__all__ = [
    "FIXTURE_PROFILE_VERSION",
    "PUBLIC_DEVELOPMENT_FIXTURE_PROFILES",
    "ExecutableFixtureProfile",
    "FixtureProfileId",
    "compute_fixture_profile_sha256",
    "fixture_profile_by_sha256",
]
