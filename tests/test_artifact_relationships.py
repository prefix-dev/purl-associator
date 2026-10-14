import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts import artifact_relationships as ar


class ArtifactRelationshipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.records = self.root / "records"
        self.evidence = self.root / "evidence"
        self.records.mkdir()
        self.evidence.mkdir()
        self.subject = {
            "purl": "pkg:conda/conda-forge/example@1.0?build=abc_0&subdir=linux-64",
            "sha256": "a" * 64,
        }
        self.key = ar.subject_key(self.subject)

    def record(
        self,
        upstream="pkg:pypi/example@1.0",
        *,
        subject=None,
        name="proof.json",
        extra_claims=(),
    ):
        subject = copy.deepcopy(subject or self.subject)
        claims = [
            {
                "relationship": "derived_from",
                "upstream": {"purl": upstream, "sha256": "b" * 64},
            },
            *extra_claims,
        ]
        proof = {
            "schema_version": 1,
            "kind": "reviewed-provenance",
            "subject": subject,
            "claims": claims,
            "details": {
                "references": [
                    {
                        "url": "https://example.org/immutable-source",
                        "description": "Synthetic test evidence, not a real identity review.",
                    }
                ],
                "notes": "No byte-comparison or vulnerability evaluation claimed.",
            },
        }
        ref = self.save_proof(proof, name)
        return {
            "schema_version": 1,
            "status": "review-only",
            "operation": "replace",
            "subject": subject,
            "review": {
                "reviewer": "test-reviewer",
                "reviewed_at": "2026-09-24T10:00:00Z",
            },
            "rationale": "Synthetic test review.",
            "relationships": [{**c, "evidence": ref} for c in claims],
        }

    def save_proof(self, proof, name):
        raw = (json.dumps(proof, indent=2) + "\n").encode()
        (self.evidence / name).write_bytes(raw)
        return {"path": name, "sha256": hashlib.sha256(raw).hexdigest()}

    def test_multiple_ecosystems_share_the_same_envelope(self):
        for upstream in (
            "pkg:pypi/example@1.0",
            "pkg:npm/example@1.0",
            "pkg:cargo/example@1.0",
            "pkg:deb/debian/example@1.0-1?arch=amd64&distro=debian-12",
            "pkg:rpm/centos/example@1.0-1.el7?arch=x86_64&distro=centos-7",
            "pkg:nuget/example@1.0",
        ):
            with self.subTest(upstream=upstream):
                record = self.record(upstream)
                result = ar.replay_records([(record, "review.json")], self.evidence)
                self.assertEqual(
                    result[self.key]["relationships"][0]["upstream"]["purl"],
                    upstream,
                )
                self.assertEqual(result[self.key]["status"], "review-only")
                self.assertNotIn("rpm_header", record)

    def test_multiple_components_are_explicit_not_interchangeable(self):
        extra = {
            "relationship": "contains",
            "upstream": {"purl": "pkg:github/example/component", "sha256": None},
        }
        record = self.record(extra_claims=[extra])
        ar.validate_record(record, self.evidence)
        self.assertEqual(len(record["relationships"]), 2)
        self.assertIsNone(record["relationships"][1]["upstream"]["sha256"])

    def test_full_replacement_removal_and_restore_are_deterministic(self):
        initial = self.record(
            name="initial.json",
            extra_claims=[
                {
                    "relationship": "contains",
                    "upstream": {
                        "purl": "pkg:github/example/component",
                        "sha256": None,
                    },
                }
            ],
        )
        replacement = self.record("pkg:pypi/example@1.1", name="replacement.json")
        replacement["review"]["reviewed_at"] = "2026-09-24T12:00:00+01:00"
        remove = copy.deepcopy(replacement)
        remove.update(
            operation="remove",
            relationships=[],
            rationale="Retract the exact reviewed subject.",
        )
        remove["review"]["reviewed_at"] = "2026-09-24T12:00:00Z"
        restore = copy.deepcopy(replacement)
        restore["review"]["reviewed_at"] = "2026-09-24T13:00:00Z"
        rows = [
            (initial, "z.json"),
            (replacement, "b.json"),
            (remove, "a.json"),
            (restore, "c.json"),
        ]
        before = copy.deepcopy(rows)
        replaced = ar.replay_records(rows[:2], self.evidence)[self.key]
        self.assertEqual(len(replaced["relationships"]), 1)
        removed = ar.replay_records(rows[:3], self.evidence)[self.key]
        self.assertEqual(removed["operation"], "remove")
        self.assertEqual(removed["relationships"], [])
        self.assertEqual(removed["source"], "a.json")
        result = ar.replay_records(rows, self.evidence)
        self.assertEqual(result, ar.replay_records(list(reversed(rows)), self.evidence))
        self.assertEqual(result[self.key]["source"], "c.json")
        self.assertEqual(rows, before)

    def test_new_build_does_not_inherit_and_remove_does_not_affect_other_build(self):
        first = self.record(name="first.json")
        second_subject = {
            **self.subject,
            "purl": self.subject["purl"].replace("abc_0", "abc_1"),
            "sha256": "c" * 64,
        }
        second = self.record(subject=second_subject, name="second.json")
        removed = copy.deepcopy(first)
        removed.update(operation="remove", relationships=[])
        removed["review"]["reviewed_at"] = "2026-09-25T00:00:00Z"
        result = ar.replay_records(
            [(first, "first.json"), (second, "second.json"), (removed, "remove.json")],
            self.evidence,
        )
        self.assertEqual(len(result), 2)
        self.assertEqual(result[ar.subject_key(second_subject)]["operation"], "replace")
        self.assertNotIn(
            (self.subject["purl"].replace("abc_0", "abc_2"), self.subject["sha256"]),
            result,
        )

    def test_distinct_archives_at_same_coordinates_are_isolated(self):
        first = self.record(name="first.json")
        different = self.record(
            subject={**self.subject, "sha256": "c" * 64}, name="different.json"
        )
        different["review"]["reviewed_at"] = "2026-09-25T00:00:00Z"
        removed = copy.deepcopy(first)
        removed.update(operation="remove", relationships=[])
        removed["review"]["reviewed_at"] = "2026-09-24T12:00:00Z"
        result = ar.replay_records(
            [
                (first, "first.json"),
                (removed, "removed.json"),
                (different, "different.json"),
            ],
            self.evidence,
        )
        self.assertEqual(len(result), 2)
        self.assertEqual(result[self.key]["operation"], "remove")
        self.assertEqual(
            result[ar.subject_key(different["subject"])]["operation"], "replace"
        )
        self.assertNotIn((self.subject["purl"], "d" * 64), result)

    def test_same_instant_conflicts_fail_but_identical_decisions_tie_break(self):
        first = self.record()
        same = copy.deepcopy(first)
        same["review"]["reviewed_at"] = "2026-09-24T11:00:00+01:00"
        result = ar.replay_records([(same, "b.json"), (first, "a.json")], self.evidence)
        self.assertEqual(result[self.key]["source"], "b.json")
        same.update(operation="remove", relationships=[])
        with self.assertRaisesRegex(ValueError, "conflicting reviews at same instant"):
            ar.replay_records([(same, "b.json"), (first, "a.json")], self.evidence)

    def test_bad_evidence_references_and_bindings_fail_closed(self):
        record = self.record()
        ref = record["relationships"][0]["evidence"]
        for invalid_digest in (None, "", "bad", "a" * 63, 123):
            bad = copy.deepcopy(record)
            bad["relationships"][0]["evidence"]["sha256"] = invalid_digest
            with self.assertRaisesRegex(ValueError, "invalid SHA256"):
                ar.validate_record(bad, self.evidence)
        for path in ("../proof.json", "/tmp/proof.json", "missing.json"):
            bad = copy.deepcopy(record)
            bad["relationships"][0]["evidence"]["path"] = path
            with self.assertRaises(ValueError):
                ar.validate_record(bad, self.evidence)
        outside = self.root / "outside.json"
        outside.write_bytes((self.evidence / ref["path"]).read_bytes())
        (self.evidence / "link.json").symlink_to(outside)
        bad = copy.deepcopy(record)
        bad["relationships"][0]["evidence"]["path"] = "link.json"
        with self.assertRaisesRegex(ValueError, "escaping evidence"):
            ar.validate_record(bad, self.evidence)
        (self.evidence / ref["path"]).write_text("{}")
        with self.assertRaisesRegex(ValueError, "evidence digest mismatch"):
            ar.validate_record(record, self.evidence)
        record = self.record()
        proof = ar.load_document(self.evidence / "proof.json")
        proof["subject"]["sha256"] = "c" * 64
        record["relationships"][0]["evidence"] = self.save_proof(proof, "other.json")
        with self.assertRaisesRegex(ValueError, "different subject"):
            ar.validate_record(record, self.evidence)
        record = self.record()
        record["relationships"][0]["upstream"]["purl"] = "pkg:pypi/another@1.0"
        with self.assertRaisesRegex(ValueError, "not supported by referenced evidence"):
            ar.validate_record(record, self.evidence)

    def test_invalid_operations_duplicates_unknown_schemas_and_weak_derivation(self):
        mutations = [
            lambda d: d.update(schema_version=2),
            lambda d: d.update(status="active"),
            lambda d: d.update(operation="union"),
            lambda d: d.update(operation="remove"),
            lambda d: d.update(relationships=[]),
            lambda d: d.update(rationale=""),
            lambda d: d["review"].update(reviewed_at="2026-09-24T10:00:00"),
            lambda d: d["subject"].update(purl="pkg:conda/conda-forge/example@1.0"),
            lambda d: d["relationships"].append(copy.deepcopy(d["relationships"][0])),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                record = self.record()
                mutate(record)
                with self.assertRaises(ValueError):
                    ar.validate_record(record, self.evidence)
        for upstream in (
            {"purl": "pkg:pypi/example", "sha256": "b" * 64},
            {"purl": "pkg:pypi/example@1.0", "sha256": None},
        ):
            with self.assertRaises(ValueError):
                ar.validate_claim(
                    {"relationship": "derived_from", "upstream": upstream}, self.subject
                )
        with self.assertRaisesRegex(ValueError, "self relationship"):
            ar.validate_claim(
                {"relationship": "contains", "upstream": self.subject}, self.subject
            )

    def test_historical_evidence_remains_required_after_removal(self):
        initial = self.record()
        remove = copy.deepcopy(initial)
        remove.update(operation="remove", relationships=[])
        remove["review"]["reviewed_at"] = "2026-09-25T00:00:00Z"
        (self.evidence / "proof.json").unlink()
        with self.assertRaisesRegex(ValueError, "missing or escaping evidence"):
            ar.replay_records(
                [(initial, "old.json"), (remove, "remove.json")], self.evidence
            )

    def test_disk_loader_rejects_unknown_evidence_and_duplicate_json_keys(self):
        record = self.record()
        (self.records / "review.json").write_text(json.dumps(record))
        self.assertEqual(len(ar.load_relationships(self.records, self.evidence)), 1)
        proof = ar.load_document(self.evidence / "proof.json")
        proof["kind"] = "unknown-adapter"
        self.save_proof(proof, "orphan.json")
        with self.assertRaisesRegex(ValueError, "unsupported evidence kind"):
            ar.load_relationships(self.records, self.evidence)
        (self.root / "duplicate.json").write_text('{"a": 1, "a": 2}')
        with self.assertRaises(ValueError):
            ar.load_document(self.root / "duplicate.json")
        with self.assertRaisesRegex(ValueError, "missing relationship"):
            ar.load_relationships(self.root / "missing", self.evidence)

    def test_distinct_upstream_artifacts_share_purl_but_not_identity(self):
        record = self.record()
        claims = [
            {k: record["relationships"][0][k] for k in ("relationship", "upstream")}
        ]
        claims.append(
            {
                "relationship": "contains",
                "upstream": {"purl": "pkg:pypi/example@1.0", "sha256": "c" * 64},
            }
        )
        claims[1]["relationship"] = "derived_from"
        ar.validate_claims(claims, self.subject)
        multi = self.record(extra_claims=[claims[1]], name="multi.json")
        ar.validate_record(multi, self.evidence)
        self.assertEqual(len(multi["relationships"]), 2)
        with self.assertRaisesRegex(ValueError, "duplicate relationship"):
            ar.validate_claims([*claims, claims[0]], self.subject)
        with self.assertRaisesRegex(ValueError, "duplicate review filename"):
            ar.replay_records([(record, "a.json"), (record, "a.json")], self.evidence)

    def test_rpm_adapter_claim_binding_is_checked(self):
        proof = ar.load_document(
            ar.DEFAULT_EVIDENCE / "libxml2-cos7-x86_64-2.9.1-ha675448_1106.json"
        )
        ar.validate_evidence(proof)
        proof["claims"][1]["upstream"]["purl"] = "pkg:git/example.org/unrelated"
        with self.assertRaisesRegex(ValueError, "RPM evidence claims mismatch"):
            ar.validate_evidence(proof)


if __name__ == "__main__":
    unittest.main()
