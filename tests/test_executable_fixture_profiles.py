from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
    compute_fixture_profile_sha256,
    fixture_profile_by_sha256,
)


class ExecutableFixtureProfileTests(unittest.TestCase):
    def test_closed_profiles_preserve_the_five_registry_commitments(self) -> None:
        profiles = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        self.assertEqual(len(profiles), 5)
        self.assertEqual(len({item.profile_id for item in profiles}), 5)
        self.assertEqual(len({item.profile_sha256 for item in profiles}), 5)
        self.assertEqual(
            tuple(item.profile_sha256 for item in profiles),
            (
                "c7f5a2ad4aefa57c50a321aba1c2955ae28b310362c69c6db7a3c3a99507900e",
                "19e8f17e57f5044537600a34794f4890f8efce04e0c7506e3e3911c1e769a752",
                "a04f42bc8aeb09112d0647af3f6cc7225c3b3df23b17bb98c8ea3514bcfd57ef",
                "27b861b9186fc901285fe48c72e6928576fb841639acfff7ef6534dd744b3812",
                "bce4c58b98387103aa15b002ae8eaaba1549724e2d8c50bb12ab1032ba5f88b9",
            ),
        )
        for profile in profiles:
            self.assertEqual(
                fixture_profile_by_sha256(profile.profile_sha256), profile
            )
            self.assertEqual(
                compute_fixture_profile_sha256(profile.cases),
                profile.profile_sha256,
            )
            record = profile.to_public_coverage_record()
            self.assertNotIn("paths", record)
            self.assertNotIn("answers", record)
            for field in (
                "sealed",
                "candidate_execution_authorized",
                "model_selection_eligible",
                "claim_authorized",
            ):
                self.assertIs(record[field], False)

    def test_profiles_are_frozen_and_fail_closed_on_every_semantic_field(self) -> None:
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        with self.assertRaises(FrozenInstanceError):
            profile.profile_id = "empty-duplicates"  # type: ignore[misc]
        mutations = (
            {"profile_id": "not-a-profile"},
            {"cases": [*profile.cases]},
            {"cases": ("spaces", "wrong")},
            {"profile_sha256": "0" * 64},
            {"profile_version": "2.0.0"},
            {"public_method_development": False},
            {"sealed": True},
            {"candidate_execution_authorized": True},
            {"model_selection_eligible": True},
            {"claim_authorized": True},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                replace(profile, **mutation)

    def test_hash_api_rejects_mutable_or_malformed_cases_and_unknown_hashes(self) -> None:
        for value in (
            ["spaces", "unicode"],
            ("spaces",),
            ("spaces", "unicode", "extra"),
            ("spaces", 1),
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                compute_fixture_profile_sha256(value)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            fixture_profile_by_sha256("0" * 64)

    def test_direct_constructor_cannot_relabel_closed_cases(self) -> None:
        template = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        with self.assertRaises(ValueError):
            ExecutableFixtureProfile(
                profile_id="empty-duplicates",
                cases=template.cases,
                profile_sha256=template.profile_sha256,
            )

    def test_public_projection_revalidates_low_level_authority_mutation(self) -> None:
        profile = replace(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0])
        object.__setattr__(profile, "claim_authorized", True)
        with self.assertRaisesRegex(ValueError, "authority boundary"):
            profile.to_public_coverage_record()


if __name__ == "__main__":
    unittest.main()
