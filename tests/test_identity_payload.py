from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts import merge_mappings, validate

GENERATED_AT = "2026-02-03T04:05:06+00:00"
ROOT = Path(__file__).resolve().parent.parent


class IdentityPayloadTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.auto = self.root / "auto.json"
        self.manual = self.root / "manual.json"
        self.contributions = self.root / "contributions"
        self.downloads = self.root / "downloads.json"
        self.contributions.mkdir()
        self._write_json(
            self.auto,
            {
                "schema_version": 1,
                "generated_at": "2026-01-01T00:00:00Z",
                "channel": "conda-forge",
                "packages": {
                    "auto-detailed": {
                        "purl": "pkg:pypi/demo",
                        "type": "pypi",
                        "namespace": None,
                        "pkg_name": "demo",
                        "confidence": 0.99,
                        "sources": ["recipe-source", "artifact"],
                        "auto_verified": True,
                        "alternative_purls": [
                            {
                                "purl": "pkg:github/example/demo",
                                "type": "github",
                                "namespace": "example",
                                "pkg_name": "demo",
                                "confidence": 0.85,
                                "source": "recipe-source",
                            }
                        ],
                        "cpes": ["cpe:2.3:a:example:demo"],
                    },
                    "reviewed": {
                        "purl": "pkg:pypi/project-old",
                        "type": "pypi",
                        "namespace": None,
                        "pkg_name": "project-old",
                        "confidence": 0.7,
                        "sources": ["recipe-deps"],
                    },
                    "reject-me": {
                        "purl": "pkg:pypi/rejected",
                        "type": "pypi",
                        "namespace": None,
                        "pkg_name": "rejected",
                        "confidence": 0.5,
                        "sources": [],
                        "alternative_purls": ["pkg:github/example/rejected"],
                    },
                },
            },
        )
        self._write_json(
            self.manual,
            {
                "schema_version": 1,
                "updated_at": "2026-01-01T00:00:00Z",
                "packages": {
                    "reviewed": {
                        "purl": "pkg:github/reviewer/project",
                        "type": "github",
                        "namespace": "reviewer",
                        "pkg_name": "project",
                        "alternative_purls": ["pkg:pypi/project"],
                        "approved_by": "package-reviewer",
                        "approved_at": "2026-01-02T03:04:05Z",
                    }
                },
            },
        )
        self._write_json(
            self.contributions / "review.json",
            {
                "schema_version": 1,
                "author": "current-reviewer",
                "timestamp": "2026-01-03T04:05:06Z",
                "packages": {
                    "reviewed": {"cpes": ["cpe:2.3:a:reviewer:project"]},
                    "contributed": {
                        "purl": "pkg:github/example/contributed",
                        "type": "github",
                        "namespace": "example",
                        "pkg_name": "contributed",
                    },
                    "reject-me": {"unmapped": True},
                },
            },
        )
        self._write_json(self.downloads, {"packages": []})

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def _generate(self, output_root: Path) -> tuple[Path, Path, Path]:
        bundle = output_root / "mappings.json"
        index = output_root / "mappings-index.json"
        details = output_root / "mapping_packages"
        merge_mappings.main(
            self.auto,
            self.manual,
            self.contributions,
            self.downloads,
            bundle,
            index,
            details,
            generated_at=GENERATED_AT,
        )
        return bundle, index, details

    def test_generator_attests_each_identity_and_preserves_legacy_fields(self) -> None:
        bundle_path, index_path, detail_dir = self._generate(self.root / "out")
        bundle = json.loads(bundle_path.read_text())
        index = json.loads(index_path.read_text())
        reviewed = bundle["packages"]["reviewed"]

        self.assertEqual((bundle["schema_version"], index["schema_version"]), (3, 4))
        self.assertEqual(reviewed["status"], "verified")
        self.assertEqual(reviewed["approved_by"], "current-reviewer")
        # Identity provenance remains with the primary-owning manual layer.
        self.assertEqual(
            reviewed["identities"][0]["provenance"]["review"],
            {
                "status": "verified",
                "reviewer": "package-reviewer",
                "reviewed_at": "2026-01-02T03:04:05Z",
            },
        )
        self.assertEqual(
            reviewed["identities"][1]["provenance"],
            {"availability": "unavailable"},
        )
        self.assertEqual(
            reviewed["identities"][2]["provenance"],
            {
                "availability": "available",
                "source": "manual",
                "review": {
                    "status": "verified",
                    "reviewer": "current-reviewer",
                    "reviewed_at": "2026-01-03T04:05:06Z",
                },
            },
        )
        self.assertEqual(
            bundle["packages"]["auto-detailed"]["identities"][2]["provenance"],
            {
                "availability": "available",
                "source": "auto",
                "review": {"status": "auto-verified", "reviewer": None},
            },
        )
        errors: list[str] = []
        validate.validate_mapping_alternatives(
            self.manual, self.contributions, bundle_path, errors, self.auto
        )
        validate.validate_split_mappings(index_path, detail_dir, errors, bundle_path)
        self.assertEqual(errors, [])

    def test_auto_to_unmapped_clears_rejected_identity(self) -> None:
        bundle_path, _, _ = self._generate(self.root / "unmapped")
        rejected = json.loads(bundle_path.read_text())["packages"]["reject-me"]
        self.assertTrue(rejected["unmapped"])
        self.assertEqual(rejected["status"], "unmapped")
        self.assertEqual(rejected["alternative_purls"], [])
        for key in ("purl", "type", "namespace", "pkg_name"):
            self.assertIsNone(rejected[key])
        self.assertFalse(
            any(identity["kind"] == "purl" for identity in rejected["identities"])
        )

    def test_new_primary_uses_only_current_reviewer(self) -> None:
        self._write_json(
            self.contributions / "later.json",
            {
                "schema_version": 1,
                "author": "new-owner",
                "timestamp": "2026-01-04T04:05:06Z",
                "packages": {
                    "reviewed": {
                        "purl": "pkg:github/new/project",
                        "type": "github",
                        "namespace": "new",
                        "pkg_name": "project",
                    }
                },
            },
        )
        bundle_path, _, _ = self._generate(self.root / "owner")
        reviewed = json.loads(bundle_path.read_text())["packages"]["reviewed"]
        self.assertEqual(reviewed["approved_by"], "new-owner")
        self.assertEqual(
            reviewed["identities"][0]["provenance"]["review"],
            {
                "status": "verified",
                "reviewer": "new-owner",
                "reviewed_at": "2026-01-04T04:05:06Z",
            },
        )

    def test_source_schema_negative_mutations(self) -> None:
        base = json.loads(self.auto.read_text())
        mutations = {
            "unknown schema": lambda value: value.update(schema_version=99),
            "non-object packages": lambda value: value.update(packages=[]),
            "empty identifier": lambda value: value["packages"].update(
                {"": value["packages"].pop("reviewed")}
            ),
            "malformed primary PURL": lambda value: value["packages"][
                "reviewed"
            ].update(purl="not-a-purl"),
            "string alternatives": lambda value: value["packages"]["reviewed"].update(
                alternative_purls="pkg:pypi/nope"
            ),
            "malformed alternative": lambda value: value["packages"]["reviewed"].update(
                alternative_purls=["bad"]
            ),
            "duplicate alternative": lambda value: value["packages"]["reviewed"].update(
                alternative_purls=["pkg:pypi/a", "pkg:pypi/a"]
            ),
            "primary as alternative": lambda value: value["packages"][
                "reviewed"
            ].update(alternative_purls=["pkg:pypi/project-old"]),
            "malformed detailed alternative": lambda value: value["packages"][
                "reviewed"
            ].update(alternative_purls=[{"purl": "pkg:pypi/a"}]),
            "malformed CPE": lambda value: value["packages"]["reviewed"].update(
                cpes=["cpe:bad"]
            ),
            "duplicate CPE": lambda value: value["packages"]["reviewed"].update(
                cpes=["cpe:2.3:a:a:b", "cpe:2.3:a:a:b"]
            ),
            "reserved filename": lambda value: value.update(_filename="wins.json"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                value = copy.deepcopy(base)
                mutate(value)
                with self.assertRaises(ValueError):
                    merge_mappings._validate_source_payload(value, label, kind="auto")

        manual_without_owner = json.loads(self.manual.read_text())
        manual_without_owner["packages"]["reviewed"].pop("approved_by")
        manual_without_owner["packages"]["reviewed"].pop("approved_at")
        with self.assertRaises(ValueError):
            merge_mappings._validate_source_payload(
                manual_without_owner, "manual", kind="manual"
            )

        cpe_without_owner = {
            "schema_version": 1,
            "packages": {
                "cpe-only": {"cpes": ["cpe:2.3:a:example:demo"]},
            },
        }
        with self.assertRaises(ValueError):
            merge_mappings._validate_source_payload(
                cpe_without_owner, "manual CPE", kind="manual"
            )

        contribution = json.loads((self.contributions / "review.json").read_text())
        for key, invalid in (("author", ""), ("timestamp", "not-a-date")):
            with self.subTest(attribution=key):
                value = copy.deepcopy(contribution)
                value[key] = invalid
                with self.assertRaises(ValueError):
                    merge_mappings._validate_source_payload(
                        value, "contribution", kind="contribution"
                    )

        for non_finite in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(non_finite=non_finite):
                value = copy.deepcopy(base)
                value["packages"]["reviewed"]["confidence"] = non_finite
                with self.assertRaisesRegex(ValueError, "finite number"):
                    merge_mappings._validate_source_payload(
                        value, "non-finite", kind="auto"
                    )
                value = copy.deepcopy(base)
                value["packages"]["auto-detailed"]["alternative_purls"][0][
                    "confidence"
                ] = non_finite
                with self.assertRaisesRegex(ValueError, "finite number"):
                    merge_mappings._validate_source_payload(
                        value, "non-finite alternative", kind="auto"
                    )

        duplicate_json = self.root / "duplicate.json"
        duplicate_json.write_text(
            '{"schema_version":1,"schema_version":1,"packages":{}}'
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            merge_mappings._load_json(duplicate_json)
        for token in ("NaN", "Infinity", "-Infinity"):
            nonstandard_json = self.root / f"nonstandard-{token}.json"
            nonstandard_json.write_text(
                f'{{"schema_version":1,"packages":{{}},"confidence":{token}}}'
            )
            with self.assertRaisesRegex(ValueError, "non-standard numeric value"):
                merge_mappings._load_json(nonstandard_json)

    def test_identity_contract_negative_mutations(self) -> None:
        bundle_path, _, _ = self._generate(self.root / "identity-negative")
        packages = json.loads(bundle_path.read_text())["packages"]
        primary = packages["auto-detailed"]
        reviewed = packages["reviewed"]

        def mutate_primary(path: tuple, value: object, base: dict = primary) -> dict:
            result = copy.deepcopy(base)
            target: object = result
            for key in path[:-1]:
                target = target[key]  # type: ignore[index]
            target[path[-1]] = value  # type: ignore[index]
            return result

        cases = [
            (
                "primary availability",
                mutate_primary(
                    ("identities", 0, "provenance", "availability"), "unavailable"
                ),
            ),
            (
                "primary source",
                mutate_primary(("identities", 0, "provenance", "source"), "mystery"),
            ),
            (
                "review status",
                mutate_primary(
                    ("identities", 0, "provenance", "review", "status"), "mystery"
                ),
            ),
            (
                "reviewer type",
                mutate_primary(
                    ("identities", 0, "provenance", "review", "reviewer"), 7
                ),
            ),
            (
                "invented attribution when legacy attribution is absent",
                mutate_primary(
                    ("identities", 0, "provenance", "review", "reviewer"),
                    "borrowed-reviewer",
                ),
            ),
            (
                "confidence type",
                mutate_primary(("identities", 0, "provenance", "confidence"), True),
            ),
            (
                "confidence non-finite",
                mutate_primary(
                    ("identities", 0, "provenance", "confidence"), float("inf")
                ),
            ),
            (
                "sources type",
                mutate_primary(("identities", 0, "provenance", "sources"), "recipe"),
            ),
            (
                "identity forbidden field",
                mutate_primary(("identities", 0, "extra"), True),
            ),
            ("primary invalid PURL", mutate_primary(("identities", 0, "value"), "bad")),
            ("primary empty", mutate_primary(("identities", 0, "value"), "")),
            (
                "duplicate identity",
                mutate_primary(("identities", 1, "value"), "pkg:pypi/demo"),
            ),
            (
                "detailed alternative exact provenance",
                mutate_primary(("identities", 1, "provenance", "confidence"), 0.1),
            ),
            (
                "CPE provenance required",
                mutate_primary(
                    ("identities", 2, "provenance"),
                    {"availability": "unavailable"},
                ),
            ),
        ]
        manual_bad = copy.deepcopy(reviewed)
        manual_bad["identities"][0]["provenance"]["review"]["reviewed_at"] = "yesterday"
        cases.append(("timestamp", manual_bad))
        bare_bad = copy.deepcopy(reviewed)
        bare_bad["identities"][1]["provenance"] = {
            "availability": "unavailable",
            "source": "manual",
        }
        cases.append(("bare alternative exact provenance", bare_bad))
        primary_alt = copy.deepcopy(reviewed)
        primary_alt["alternative_purls"] = [primary_alt["purl"]]
        primary_alt["identities"][1]["value"] = primary_alt["purl"]
        cases.append(("primary as alternative", primary_alt))
        for label, entry in cases:
            with self.subTest(label=label):
                errors: list[str] = []
                validate._validate_identity_contract(entry, label, errors)
                self.assertTrue(errors, label)

        unmapped = packages["reject-me"]
        for label, mutate in (
            ("unmapped status", lambda value: value.update(status="verified")),
            (
                "unmapped coordinates",
                lambda value: value.update(purl="pkg:pypi/rejected"),
            ),
            (
                "unmapped alternatives",
                lambda value: value.update(alternative_purls=["pkg:pypi/rejected"]),
            ),
        ):
            with self.subTest(label=label):
                entry = copy.deepcopy(unmapped)
                mutate(entry)
                errors = []
                validate._validate_identity_contract(entry, label, errors)
                self.assertTrue(errors, label)

    def test_bundle_index_shard_cross_checks_reject_every_mismatch_class(self) -> None:
        bundle_path, index_path, detail_dir = self._generate(self.root / "cross")

        def assert_invalid(mutator) -> None:
            case = self.root / f"case-{len(list(self.root.glob('case-*')))}"
            shutil.copytree(bundle_path.parent, case)
            case_bundle = case / "mappings.json"
            case_index = case / "mappings-index.json"
            mutator(case_bundle, case_index, case / "mapping_packages")
            errors: list[str] = []
            validate.validate_split_mappings(
                case_index, case / "mapping_packages", errors, case_bundle
            )
            self.assertTrue(errors)

        def mutate_json(path: Path, callback) -> None:
            value = json.loads(path.read_text())
            callback(value)
            self._write_json(path, value)

        first_name = next(iter(json.loads(index_path.read_text())["packages"]))
        shard_rel = json.loads(index_path.read_text())["packages"][first_name][
            "detail_path"
        ]
        assert_invalid(
            lambda bundle, index, details: mutate_json(
                index, lambda value: value["packages"].pop(first_name)
            )
        )
        assert_invalid(
            lambda bundle, index, details: mutate_json(
                index, lambda value: value.update(channel="wrong")
            )
        )
        assert_invalid(
            lambda bundle, index, details: mutate_json(
                index,
                lambda value: value["packages"][first_name].update(version="wrong"),
            )
        )
        assert_invalid(
            lambda bundle, index, details: mutate_json(
                index.parent / shard_rel,
                lambda value: value["packages"][first_name].update(summary="wrong"),
            )
        )
        assert_invalid(
            lambda bundle, index, details: mutate_json(
                index, lambda value: value["packages"][first_name].update(identities=[])
            )
        )
        assert_invalid(
            lambda bundle, index, details: mutate_json(
                index.parent / shard_rel,
                lambda value: value.update(schema_version=1),
            )
        )

    def test_validator_rejects_wrong_primary_owner_even_when_legacy_owner_differs(
        self,
    ) -> None:
        bundle_path, _, _ = self._generate(self.root / "wrong-owner")
        bundle = json.loads(bundle_path.read_text())
        # This is structurally valid and deliberately differs from the latest
        # legacy CPE-only attribution; only source-layer ownership catches it.
        bundle["packages"]["reviewed"]["identities"][0]["provenance"]["review"][
            "reviewer"
        ] = "plausible-but-wrong"
        self._write_json(bundle_path, bundle)
        errors: list[str] = []
        validate.validate_mapping_alternatives(
            self.manual, self.contributions, bundle_path, errors, self.auto
        )
        self.assertTrue(any("do not match source layers" in error for error in errors))

    def test_source_replay_rejects_consistent_generated_identity_mutations(
        self,
    ) -> None:
        bundle_path, index_path, detail_dir = self._generate(
            self.root / "source-replay"
        )
        expected_errors: list[str] = []
        expected = validate.replay_source_mappings(
            self.auto, self.manual, self.contributions, expected_errors
        )
        self.assertEqual(expected_errors, [])
        self.assertIsNotNone(expected)

        cases = {
            "primary": ("auto-detailed", 0, "pkg:pypi/tampered-primary"),
            "alternative": ("auto-detailed", 1, "pkg:github/example/tampered-alt"),
            "cpe": ("auto-detailed", 2, "cpe:2.3:a:example:tampered"),
        }
        for label, (name, identity_index, replacement) in cases.items():
            with self.subTest(label=label):
                case = self.root / f"consistent-{label}"
                shutil.copytree(bundle_path.parent, case)
                bundle = json.loads((case / "mappings.json").read_text())
                index = json.loads((case / "mappings-index.json").read_text())
                detail_path = index["packages"][name]["detail_path"]
                shard_path = case / detail_path
                shard = json.loads(shard_path.read_text())
                records = [
                    bundle["packages"][name],
                    index["packages"][name],
                    shard["packages"][name],
                ]
                for record in records:
                    record["identities"][identity_index]["value"] = replacement
                    if label == "primary":
                        record["purl"] = replacement
                    elif label == "alternative":
                        record["alternative_purls"][0]["purl"] = replacement
                    else:
                        record["cpes"][0] = replacement
                self._write_json(case / "mappings.json", bundle)
                self._write_json(case / "mappings-index.json", index)
                self._write_json(shard_path, shard)

                errors: list[str] = []
                validate.validate_mapping_alternatives(
                    self.manual,
                    self.contributions,
                    case / "mappings.json",
                    errors,
                    self.auto,
                    expected,
                )
                validate.validate_split_mappings(
                    case / "mappings-index.json",
                    case / "mapping_packages",
                    errors,
                    case / "mappings.json",
                    expected,
                )
                self.assertTrue(
                    any("do not match source layers" in error for error in errors),
                    errors,
                )

    def test_contribution_sort_uses_utc_instants_and_filename_tiebreaker(self) -> None:
        def contribution(author: str, timestamp: str, purl: str) -> dict:
            return {
                "schema_version": 1,
                "author": author,
                "timestamp": timestamp,
                "packages": {
                    "reviewed": {
                        "purl": purl,
                        "type": "pypi",
                        "namespace": None,
                        "pkg_name": purl.rsplit("/", 1)[-1],
                    }
                },
            }

        reversed_lexical = self.root / "reversed-lexical"
        self._write_json(
            reversed_lexical / "a.json",
            contribution(
                "earlier-instant",
                "2026-01-01T01:00:00+02:00",
                "pkg:pypi/earlier",
            ),
        )
        self._write_json(
            reversed_lexical / "z.json",
            contribution(
                "later-instant",
                "2026-01-01T00:30:00+00:00",
                "pkg:pypi/later",
            ),
        )
        ordered = merge_mappings._load_contributions(reversed_lexical)
        self.assertEqual(
            [item[0]["author"] for item in ordered],
            [
                "earlier-instant",
                "later-instant",
            ],
        )

        equivalent = self.root / "equivalent-offsets"
        self._write_json(
            equivalent / "a.json",
            contribution("first-name", "2026-01-01T01:00:00+01:00", "pkg:pypi/a"),
        )
        self._write_json(
            equivalent / "b.json",
            contribution("second-name", "2026-01-01T00:00:00Z", "pkg:pypi/b"),
        )
        ordered = merge_mappings._load_contributions(equivalent)
        self.assertEqual([item[1] for item in ordered], ["a.json", "b.json"])

        naive = contribution("naive", "2026-01-01T00:00:00", "pkg:pypi/naive")
        with self.assertRaisesRegex(ValueError, "valid ISO-8601 timestamp"):
            merge_mappings._validate_source_payload(naive, "naive", kind="contribution")

    def test_complete_previous_schema_bundle_index_and_detail_are_valid(self) -> None:
        bundle_path, index_path, detail_dir = self._generate(self.root / "legacy")
        bundle = json.loads(bundle_path.read_text())
        index = json.loads(index_path.read_text())
        bundle["schema_version"] = 2
        index["schema_version"] = 3
        for entry in bundle["packages"].values():
            for identity in entry["identities"]:
                if identity["kind"] == "cpe":
                    identity["provenance"] = {"availability": "unavailable"}
        for entry in index["packages"].values():
            for identity in entry["identities"]:
                if identity["kind"] == "cpe":
                    identity["provenance"] = {"availability": "unavailable"}
        self._write_json(bundle_path, bundle)
        self._write_json(index_path, index)
        for shard_path in detail_dir.glob("*.json"):
            shard = json.loads(shard_path.read_text())
            shard["schema_version"] = 2
            for entry in shard["packages"].values():
                for identity in entry["identities"]:
                    if identity["kind"] == "cpe":
                        identity["provenance"] = {"availability": "unavailable"}
            self._write_json(shard_path, shard)

        errors: list[str] = []
        expected = validate.replay_source_mappings(
            self.auto, self.manual, self.contributions, errors
        )
        validate.validate_mapping_alternatives(
            self.manual,
            self.contributions,
            bundle_path,
            errors,
            self.auto,
            expected,
        )
        validate.validate_split_mappings(
            index_path, detail_dir, errors, bundle_path, expected
        )
        self.assertEqual(errors, [])

    def test_unknown_published_schema_is_rejected_but_previous_is_supported(
        self,
    ) -> None:
        errors: list[str] = []
        self.assertEqual(
            validate._validate_schema_version(
                {"schema_version": 2},
                "previous",
                validate.SUPPORTED_BUNDLE_SCHEMAS,
                errors,
            ),
            2,
        )
        self.assertEqual(errors, [])
        validate._validate_schema_version(
            {"schema_version": 99}, "future", validate.SUPPORTED_BUNDLE_SCHEMAS, errors
        )
        self.assertTrue(
            any("unsupported schema_version 99" in error for error in errors)
        )


class RealDataLegacyCompatibilityTest(unittest.TestCase):
    def test_checked_in_legacy_index_and_all_shards_validate_without_row_mismatches(
        self,
    ) -> None:
        index_path = ROOT / "web" / "public" / "mappings-index.json"
        detail_dir = ROOT / "web" / "public" / "mapping_packages"
        index = merge_mappings._load_json(index_path)
        first_shard = merge_mappings._load_json(next(detail_dir.glob("*.json")))
        if index.get("schema_version") != 2 or first_shard.get("schema_version") != 1:
            self.skipTest(
                "checked-in payload is no longer the previous-schema snapshot"
            )
        errors: list[str] = []
        expected = validate.replay_source_mappings(
            ROOT / "mappings" / "auto.json",
            ROOT / "mappings" / "manual.json",
            ROOT / "mappings" / "contributions",
            errors,
        )
        validate.validate_split_mappings(
            index_path, detail_dir, errors, expected_packages=expected
        )
        self.assertEqual(index.get("package_count"), len(expected))
        self.assertEqual(errors, [])

    def test_identity_only_packages_keep_legacy_status_and_attribution_snapshot(
        self,
    ) -> None:
        contributions = merge_mappings._load_contributions(
            ROOT / "mappings" / "contributions"
        )
        last_contribution_is_identity_only: dict[str, bool] = {}
        for contribution, _ in contributions:
            for name, entry in contribution["packages"].items():
                last_contribution_is_identity_only[name] = set(entry) == {"cpes"}
        identity_only_names = {
            name
            for name, is_identity_only in last_contribution_is_identity_only.items()
            if is_identity_only
        }
        self.assertTrue(identity_only_names)

        auto = merge_mappings._load_json(ROOT / "mappings" / "auto.json")["packages"]
        manual_payload = merge_mappings._load_json(ROOT / "mappings" / "manual.json")
        missing = object()
        expected = {
            name: {
                "status": "auto-verified"
                if entry.get("auto_verified")
                else "auto-unverified",
                "source": "auto",
                "approved_by": missing,
                "approved_at": missing,
            }
            for name, entry in auto.items()
        }

        def apply(packages: dict, attribution: dict) -> None:
            for name, override in packages.items():
                state = expected.setdefault(
                    name,
                    {
                        "status": missing,
                        "source": missing,
                        "approved_by": missing,
                        "approved_at": missing,
                    },
                )
                state["status"] = override.get("status", "verified")
                state["source"] = "manual"
                for key, value in attribution.items():
                    if value is not None:
                        state[key] = value

        apply(
            manual_payload["packages"],
            {
                "approved_by": manual_payload.get("updated_by"),
                "approved_at": manual_payload.get("updated_at"),
            },
        )
        for contribution, _ in contributions:
            apply(
                contribution["packages"],
                {
                    "approved_by": contribution["author"],
                    "approved_at": contribution["timestamp"],
                },
            )

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            merge_mappings.main(
                ROOT / "mappings" / "auto.json",
                ROOT / "mappings" / "manual.json",
                ROOT / "mappings" / "contributions",
                ROOT / "mappings" / "top_downloads.json",
                output / "mappings.json",
                output / "mappings-index.json",
                output / "mapping_packages",
                generated_at=GENERATED_AT,
            )
            actual = json.loads((output / "mappings.json").read_text())["packages"]
        for name in identity_only_names:
            with self.subTest(package=name):
                for key in ("status", "source", "approved_by", "approved_at"):
                    wanted = expected[name][key]
                    if wanted is missing:
                        self.assertNotIn(key, actual[name])
                    else:
                        self.assertEqual(actual[name].get(key), wanted)


class OverriddenPrimaryAlternativeTest(unittest.TestCase):
    """Reviewed layers overlay field by field, so an override that promotes a
    PURL the auto layer already listed as an alternative inherits that
    alternative untouched.  The merge has to resolve the collision itself —
    per-file validation only ever sees one layer, and letting it reach
    ``scripts/validate.py`` would fail CI on a routine automap demotion.
    """

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.auto = self.root / "auto.json"
        self.manual = self.root / "manual.json"
        self.contributions = self.root / "contributions"
        self.downloads = self.root / "downloads.json"
        self.contributions.mkdir()
        self._write_json(self.downloads, {"packages": []})

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.write_text(json.dumps(value))

    def _merge(self, auto_entry: dict, override: dict) -> dict:
        self._write_json(
            self.auto,
            {
                "schema_version": 1,
                "generated_at": "2026-01-01T00:00:00Z",
                "channel": "conda-forge",
                "packages": {"widget": auto_entry},
            },
        )
        self._write_json(
            self.manual,
            {
                "schema_version": 1,
                "updated_at": "2026-01-01T00:00:00Z",
                "updated_by": "package-reviewer",
                "packages": {"widget": override},
            },
        )
        self.bundle = self.root / "mappings.json"
        self.index = self.root / "mappings-index.json"
        self.details = self.root / "mapping_packages"
        merge_mappings.main(
            self.auto,
            self.manual,
            self.contributions,
            self.downloads,
            self.bundle,
            self.index,
            self.details,
            generated_at=GENERATED_AT,
        )
        return json.loads(self.bundle.read_text())["packages"]["widget"]

    def _validation_errors(self) -> list[str]:
        errors: list[str] = []
        validate.validate_mapping_alternatives(
            self.manual, self.contributions, self.bundle, errors, self.auto
        )
        validate.validate_split_mappings(self.index, self.details, errors, self.bundle)
        return errors

    @staticmethod
    def _auto_entry(alternatives: list) -> dict:
        return {
            "purl": "pkg:pypi/widget",
            "type": "pypi",
            "namespace": None,
            "pkg_name": "widget",
            "confidence": 0.9,
            "sources": ["recipe-source"],
            "alternative_purls": alternatives,
        }

    def test_inherited_alternative_matching_new_primary_is_dropped(self) -> None:
        widget = self._merge(
            self._auto_entry(["pkg:github/acme/widget"]),
            {"purl": "pkg:github/acme/widget"},
        )
        self.assertEqual(widget["purl"], "pkg:github/acme/widget")
        self.assertEqual(widget["alternative_purls"], [])
        self.assertEqual(
            [(item["role"], item["value"]) for item in widget["identities"]],
            [("primary", "pkg:github/acme/widget")],
        )
        self.assertEqual(self._validation_errors(), [])

    def test_detailed_inherited_alternative_matching_new_primary_is_dropped(
        self,
    ) -> None:
        widget = self._merge(
            self._auto_entry(
                [
                    {
                        "purl": "pkg:github/acme/widget",
                        "type": "github",
                        "namespace": "acme",
                        "pkg_name": "widget",
                        "confidence": 0.6,
                        "source": "recipe-source",
                    }
                ]
            ),
            {"purl": "pkg:github/acme/widget"},
        )
        self.assertEqual(widget["alternative_purls"], [])
        self.assertEqual(self._validation_errors(), [])

    def test_unrelated_inherited_alternatives_survive_the_override(self) -> None:
        widget = self._merge(
            self._auto_entry(["pkg:github/acme/widget", "pkg:npm/widget"]),
            {"purl": "pkg:github/acme/widget"},
        )
        self.assertEqual(widget["alternative_purls"], ["pkg:npm/widget"])
        self.assertEqual(self._validation_errors(), [])

    def test_override_without_a_primary_keeps_inherited_alternatives(self) -> None:
        widget = self._merge(
            self._auto_entry(["pkg:github/acme/widget"]),
            {"cpes": ["cpe:2.3:a:acme:widget"]},
        )
        self.assertEqual(widget["purl"], "pkg:pypi/widget")
        self.assertEqual(widget["alternative_purls"], ["pkg:github/acme/widget"])
        self.assertEqual(self._validation_errors(), [])

    def test_override_supplied_alternatives_replace_the_inherited_list(self) -> None:
        widget = self._merge(
            self._auto_entry(["pkg:github/acme/widget"]),
            {
                "purl": "pkg:github/acme/widget",
                "alternative_purls": ["pkg:pypi/widget"],
            },
        )
        self.assertEqual(widget["alternative_purls"], ["pkg:pypi/widget"])
        self.assertEqual(self._validation_errors(), [])


if __name__ == "__main__":
    unittest.main()
