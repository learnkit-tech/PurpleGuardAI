#!/usr/bin/env python3
"""Focused tests for PurpleGuard validators (scope + honesty + structure).

Run: cd scripts/engine && python3 -m unittest test_validators -v
"""

from __future__ import annotations

import json
import unittest

from validators import filter_files, path_in_scope, validate

AWS_EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"  # canonical AWS docs example key id


def f(path: str, content: str):
    return {"path": path, "content": content}


class ScopeFilteringTests(unittest.TestCase):
    def test_no_scope_fails_closed(self):
        # An absent scope is not a grant: nothing may be inspected.
        self.assertEqual(validate("proj", [f("src/a.ts", AWS_EXAMPLE_KEY)], None), [])
        self.assertEqual(filter_files([f("a", "x")], None), [])

    def test_empty_authorized_fails_closed(self):
        self.assertEqual(
            validate("proj", [f("src/a.ts", AWS_EXAMPLE_KEY)],
                     {"authorizedPaths": [], "blockedPaths": []}),
            [],
        )

    def test_authorized_glob_includes_file(self):
        self.assertTrue(path_in_scope("src/a.ts", ["src/*"]))
        self.assertTrue(path_in_scope("src/deep/a.ts", ["**/*.ts"]))
        self.assertFalse(path_in_scope("lib/a.ts", ["src/*"]))

    def test_blocked_path_excluded_even_if_authorized(self):
        files = [
            f("src/keys.ts", f'key = "{AWS_EXAMPLE_KEY}"'),
            f("vendor/lib.js", f'key = "{AWS_EXAMPLE_KEY}"'),
        ]
        scope = {"authorizedPaths": ["/**"], "blockedPaths": ["vendor/**"]}
        findings = validate("proj", files, scope)
        self.assertTrue(findings)
        self.assertTrue(all(x["file"] != "vendor/lib.js" for x in findings))

    def test_out_of_scope_file_never_inspected(self):
        files = [f("etc/passwd-ish", AWS_EXAMPLE_KEY)]
        scope = {"authorizedPaths": ["src/**"], "blockedPaths": []}
        self.assertEqual(validate("proj", files, scope), [])


class FindingQualityTests(unittest.TestCase):
    SCOPE = {"authorizedPaths": ["/**"], "blockedPaths": []}

    def test_aws_key_produces_structured_finding(self):
        files = [f("src/config/auth.ts", f'export const K = "{AWS_EXAMPLE_KEY}";\n')]
        findings = validate("proj", files, self.SCOPE)
        self.assertEqual(len(findings), 1)
        x = findings[0]
        for field in ("id", "title", "severity", "repo", "file", "location",
                      "evidence", "attackSteps", "explanation", "remediation"):
            self.assertIn(field, x)
        self.assertTrue(x["id"].startswith("PG-"))
        self.assertEqual(x["repo"], "proj")
        self.assertEqual(x["file"], "src/config/auth.ts")
        self.assertTrue(x["location"].startswith("line "))
        self.assertTrue(x["attackSteps"])  # never empty — backend rejects that

    def test_verdicts_are_honest(self):
        files = [f("src/a.ts", AWS_EXAMPLE_KEY)]
        steps = validate("proj", files, self.SCOPE)[0]["attackSteps"]
        self.assertEqual(steps[0]["verdict"], "exploitable")  # literal proven present
        # The live-use step is honestly blocked, never claimed.
        self.assertEqual(steps[-1]["verdict"], "blocked")
        self.assertIn("does not attempt", " ".join(steps[-1]["log"]))

    def test_secrets_redacted_in_payload(self):
        files = [f("src/a.ts", f'k = "{AWS_EXAMPLE_KEY}"')]
        x = validate("proj", files, self.SCOPE)[0]
        # Evidence, marker, and step logs are redacted — the secret never
        # appears in any UI-facing or log surface.
        redacted_surfaces = json.dumps(
            [x["evidence"], x["vulnerableMarker"],
             [s["log"] for s in x["attackSteps"]]]
        )
        self.assertNotIn(AWS_EXAMPLE_KEY, redacted_surfaces)
        self.assertIn("AKIA", redacted_surfaces)  # redacted prefix is present
        # BUT vulnerableCode stays raw: it seeds the Developer workspace edit
        # buffer, and an approved buffer is what the engine applies to the
        # repo. Redacting it would write corrupted code on approval.
        self.assertIn(AWS_EXAMPLE_KEY, x["vulnerableCode"])

    def test_env_reads_are_not_flagged(self):
        files = [
            f("src/ok.ts", 'k = process.env.AWS_ACCESS_KEY_ID;'),
            f("src/ok2.py", 'k = os.environ["AWS_SECRET_ACCESS_KEY"]'),
        ]
        self.assertEqual(validate("proj", files, self.SCOPE), [])

    def test_tls_disabled_detected(self):
        files = [f("src/client.py", 'import requests\nrequests.get(url, verify=False)\n')]
        findings = validate("proj", files, self.SCOPE)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertIn("TLS", findings[0]["title"])

    def test_private_key_block_detected(self):
        files = [f("keys/id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n")]
        findings = validate("proj", files, self.SCOPE)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "critical")

    def test_clean_repo_is_honestly_empty(self):
        files = [f("src/app.ts", "export const add = (a, b) => a + b;\n")]
        self.assertEqual(validate("proj", files, self.SCOPE), [])

    def test_ids_stable_for_same_input(self):
        files = [f("src/a.ts", AWS_EXAMPLE_KEY)]
        a = validate("proj", files, self.SCOPE)[0]["id"]
        b = validate("proj", files, self.SCOPE)[0]["id"]
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main(verbosity=2)
