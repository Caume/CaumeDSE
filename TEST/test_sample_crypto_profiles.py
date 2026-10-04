#!/usr/bin/env python3
"""Check operational sample profiles against the C storage-profile contract."""

import copy
import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_sample(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PLANNER = load_sample("reprotect_sample", "samples/reprotect-workflow/reprotect_workflow.py")
READINESS = load_sample("readiness_sample", "samples/operational-readiness/readiness_check.py")


def profile_macro(name):
    header = (ROOT / "crypto.h").read_text(encoding="utf-8")
    matches = re.findall(r'^#define\s+' + re.escape(name) + r'\s+"([^"\n]+)"\s*$', header, re.M)
    if len(matches) != 1:
        raise AssertionError(f"expected one string definition for {name}")
    return matches[0]


AES = profile_macro("cmeOpenSSLLegacyStorageProfile")
NLA1 = profile_macro("cmeHerraduraKExProfileHSKENLA1AEAD256")
DUPLEX = profile_macro("cmeHerraduraKExProfileHSKEDuplex256")
NLA2 = profile_macro("cmeHerraduraKExProfileHSKENLA2256")
OBSOLETE = ("hsk-en-la-aead-256", "HERRADURAKEX_HSK_EN_LA_AEAD_256", "CME_OPENSSL_AES256_CBC")


class SampleCryptoProfilesTest(unittest.TestCase):
    def scope(self, target):
        scope = copy.deepcopy(PLANNER.load_json(PLANNER.DEFAULT_SCOPE))
        scope["targetProfile"] = target
        return scope

    def report(self, profile, provider=False):
        with tempfile.TemporaryDirectory() as tmp:
            args = READINESS.parse_args([
                "check", "--storage-path", tmp, "--parser-temp-dir", tmp,
                "--storage-profile", profile, "--tls-auth-state", "required",
                "--build-mode", "release", "--parser-policy-enabled",
            ] + (["--herradura-available"] if provider else []))
            return READINESS.build_report(args)

    def test_profile_sets_match_canonical_c_names(self):
        self.assertEqual(READINESS.HERRADURA_PROFILES, {NLA1})
        self.assertEqual(READINESS.AES_PROFILES, {AES, "aes-256-cbc"})
        self.assertEqual(PLANNER.SUPPORTED_PROFILES, READINESS.HERRADURA_PROFILES | READINESS.AES_PROFILES)

    def test_planner_accepts_real_writable_targets(self):
        for profile in (AES, "aes-256-cbc", NLA1):
            with self.subTest(profile=profile):
                plan = PLANNER.build_plan(self.scope(profile))
                self.assertEqual(plan["targetProfile"], profile)
                commands = PLANNER.build_operator_commands(plan)
                for command in commands["commands"]:
                    self.assertIn("--target-profile " + profile, command["dryRun"])
                    self.assertIn("--target-profile " + profile, command["commit"])

    def test_planner_rejects_read_only_unimplemented_and_fictitious_targets(self):
        for profile in (DUPLEX, NLA2, "unknown-profile", *OBSOLETE):
            with self.subTest(profile=profile):
                with self.assertRaises(PLANNER.ReprotectError):
                    PLANNER.build_plan(self.scope(profile))

    def test_legacy_duplex_can_remain_a_migration_source(self):
        scope = self.scope(AES)
        scope["databases"][0]["sourceProfile"] = DUPLEX
        self.assertEqual(PLANNER.build_plan(scope)["steps"][0]["sourceProfile"], DUPLEX)

    def test_aes_readiness_does_not_require_optional_herradura(self):
        for profile in (AES, "aes-256-cbc"):
            with self.subTest(profile=profile):
                report = self.report(profile)
                self.assertEqual(report["state"], "healthy")
                provider = next(check for check in report["checks"] if check["name"] == "herraduraBuild")
                self.assertFalse(provider["available"])
                self.assertEqual(provider["state"], "healthy")

    def test_nla1_readiness_requires_declared_provider(self):
        self.assertEqual(self.report(NLA1, provider=True)["state"], "healthy")
        missing = self.report(NLA1)
        self.assertEqual(missing["state"], "misconfigured")
        for name in ("storageCryptoProfile", "herraduraBuild"):
            check = next(check for check in missing["checks"] if check["name"] == name)
            self.assertEqual(check["state"], "misconfigured")

    def test_readiness_never_accepts_forbidden_or_fictitious_profiles(self):
        for profile in (DUPLEX, NLA2, "unknown-profile", *OBSOLETE):
            with self.subTest(profile=profile):
                report = self.report(profile, provider=True)
                check = next(check for check in report["checks"] if check["name"] == "storageCryptoProfile")
                self.assertNotEqual(check["state"], "healthy")

    def test_all_readiness_commands_default_to_runtime_aes_profile(self):
        for command in ("check", "context", "metrics", "summary", "nagios", "sarif",
                        "remediation", "threshold", "completion-check"):
            with self.subTest(command=command):
                self.assertEqual(READINESS.parse_args([command]).storage_profile, AES)

    def test_committed_examples_use_canonical_profiles(self):
        scope = PLANNER.load_json(PLANNER.DEFAULT_SCOPE)
        self.assertEqual(scope["targetProfile"], NLA1)
        self.assertEqual({db["sourceProfile"] for db in scope["databases"]}, {AES, NLA1})
        config = json.loads((ROOT / "samples/operational-readiness/config.example.json").read_text())
        self.assertEqual(config["storage_profile"], AES)

    def test_secondary_docs_preserve_storage_policy(self):
        for filename in ("TUTORIAL.md", "API_EXAMPLES.md", "AI_USAGE.md"):
            with self.subTest(filename=filename):
                text = " ".join((ROOT / filename).read_text(encoding="utf-8").split()).lower()
                for marker in (DUPLEX, "legacy migration readback only", NLA2,
                               "unimplemented, demo-only metadata"):
                    self.assertTrue(marker in text, f"{filename}: missing policy statement {marker!r}")
                for obsolete in ("duplex-256` as an evaluation", "duplex-256` is available for evaluation",
                                 "duplex-256` for variable-size fields", "nla2-256` remains experimental",
                                 "nla2-256` as experimental", "nla2-256` experimental"):
                    self.assertFalse(obsolete in text, f"{filename}: stale policy statement {obsolete!r}")


if __name__ == "__main__":
    unittest.main()
