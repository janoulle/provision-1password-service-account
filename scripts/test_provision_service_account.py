#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
SCRIPT = SCRIPT_DIRECTORY / "provision_service_account.py"
SPEC = importlib.util.spec_from_file_location("provision_service_account", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def valid_manifest() -> dict:
    return {
        "schema_version": 1,
        "vault": {"name": "Example Production", "description": "Example runtime credentials"},
        "service_account": {
            "name": "example-provisioner",
            "permissions": ["read_items"],
            "expires_in": None,
        },
        "items": [{"title": "Example API credential", "source_vault": "Private"}],
        "token_storage": {
            "recovery_vault": "Private",
            "recovery_item_title": "Example service-account token",
            "keychain_service": "com.example.service-account",
            "keychain_account": "example-provisioner",
        },
    }


class ManifestTests(unittest.TestCase):
    def write_manifest(self, manifest: dict) -> Path:
        temporary = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        with temporary:
            json.dump(manifest, temporary)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        return Path(temporary.name)

    def test_plan_is_non_secret_and_exact(self) -> None:
        path = self.write_manifest(valid_manifest())
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "plan", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
        plan = json.loads(result.stdout)
        self.assertEqual(plan["destination_vault"], "Example Production")
        self.assertEqual(plan["permissions"], ["read_items"])
        self.assertEqual(plan["item_moves"][0]["from"], "Private")
        self.assertNotIn("ops_", result.stdout)
        self.assertNotIn("secret_value", result.stdout)

    def test_write_permission_requires_read_permission(self) -> None:
        manifest = valid_manifest()
        manifest["service_account"]["permissions"] = ["write_items"]
        with self.assertRaisesRegex(MODULE.ProvisionError, "read_items is required"):
            MODULE.load_manifest(self.write_manifest(manifest))

    def test_recovery_vault_must_be_outside_scope(self) -> None:
        manifest = valid_manifest()
        manifest["token_storage"]["recovery_vault"] = "Example Production"
        with self.assertRaisesRegex(MODULE.ProvisionError, "recovery vault"):
            MODULE.load_manifest(self.write_manifest(manifest))

    def test_destination_must_not_be_builtin(self) -> None:
        manifest = valid_manifest()
        manifest["vault"]["name"] = "Private"
        with self.assertRaisesRegex(MODULE.ProvisionError, "user-managed vault"):
            MODULE.load_manifest(self.write_manifest(manifest))

    def test_confirmation_must_match_service_account_name(self) -> None:
        with self.assertRaisesRegex(MODULE.ProvisionError, "must exactly match"):
            MODULE.apply(valid_manifest(), "wrong-name")

    def test_service_environment_clears_connect_precedence(self) -> None:
        with mock.patch.dict(
            MODULE.os.environ,
            {"OP_CONNECT_HOST": "https://example.invalid", "OP_CONNECT_TOKEN": "not-a-real-token"},
            clear=False,
        ):
            environment = MODULE.service_environment(b"ops_" + b"x" * 600)
        self.assertNotIn("OP_CONNECT_HOST", environment)
        self.assertNotIn("OP_CONNECT_TOKEN", environment)
        self.assertTrue(environment["OP_SERVICE_ACCOUNT_TOKEN"].startswith("ops_"))

    def test_partial_provider_write_reports_recovery_boundary(self) -> None:
        manifest = valid_manifest()
        resolved = [{"id": "item-id", "title": "Example API credential", "source_vault": "Private"}]
        with tempfile.TemporaryDirectory() as directory:
            helper = Path(directory) / "helper"
            helper.touch()
            with (
                mock.patch.object(MODULE, "require_tools"),
                mock.patch.object(MODULE, "personal_environment", return_value={}),
                mock.patch.object(MODULE, "preflight", return_value=(resolved, helper)),
                mock.patch.object(
                    MODULE,
                    "run_command",
                    side_effect=[
                        subprocess.CompletedProcess([], 0, b"", b""),
                        MODULE.ProvisionError("synthetic item move failure"),
                    ],
                ),
            ):
                with self.assertRaisesRegex(MODULE.IncompleteProvisionError, "state may be partial"):
                    MODULE.apply(manifest, "example-provisioner")


class BatchTests(unittest.TestCase):
    def test_invalid_token_never_falls_back(self):
        with self.assertRaises(MODULE.ProvisionError):
            MODULE.service_environment(b"")

    def test_batch_loads_bootstrap_once_and_removes_it_from_child(self):
        with tempfile.TemporaryDirectory() as directory:
            refs = Path(directory) / "refs.env"
            refs.write_text("API_TOKEN=op://Example Production/credential/password\n")
            token = b"ops_" + b"x" * 600
            with (mock.patch.object(MODULE, "keychain_lookup", return_value=subprocess.CompletedProcess([], 0, token)) as lookup,
                  mock.patch.object(MODULE, "run_command", return_value=subprocess.CompletedProcess([], 0, b"never-print-me")) as run,
                  mock.patch.dict(MODULE.os.environ, {"OP_SESSION_example": "old", "OTHER": "op://Private/other/password"})):
                MODULE.run_batch(valid_manifest(), refs, ["--", "approved-program"])
            self.assertEqual(lookup.call_count, 1)
            self.assertEqual(run.call_count, 1)
            args = run.call_args.args[0]
            self.assertEqual(args[-4:], ["/usr/bin/env", "-u", "OP_SERVICE_ACCOUNT_TOKEN", "approved-program"])
            env = run.call_args.kwargs["environment"]
            self.assertEqual(env["OP_BIOMETRIC_UNLOCK_ENABLED"], "false")
            self.assertNotIn("OP_SESSION_example", env)
            self.assertNotIn("OTHER", env)
            self.assertNotIn(token.decode(), str(args))

    def test_batch_rejects_outside_vault_before_keychain(self):
        with tempfile.TemporaryDirectory() as directory:
            refs = Path(directory) / "refs.env"
            refs.write_text("API_TOKEN=op://Private/credential/password\n")
            with mock.patch.object(MODULE, "keychain_lookup") as lookup:
                with self.assertRaises(MODULE.ProvisionError):
                    MODULE.run_batch(valid_manifest(), refs, ["approved-program"])
                lookup.assert_not_called()

    def test_real_os_pipe_preserves_synthetic_bytes(self):
        result = MODULE.run_command([sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"], input_data=b"synthetic-input")
        self.assertEqual(result.stdout, b"synthetic-input")

    def test_source_resolution_does_not_enumerate_private_items(self):
        source = {"id": "exact-id", "title": "Example API credential"}
        with mock.patch.object(MODULE, "run_json", return_value=source) as run:
            resolved = MODULE.resolve_source_items(valid_manifest(), {})
        self.assertEqual(resolved[0]["id"], "exact-id")
        self.assertEqual(run.call_args.args[0][:3], ["op", "item", "get"])
        self.assertEqual(run.call_count, 1)

    def test_unknown_recovery_lookup_failure_stops_before_writes(self):
        with (mock.patch.object(MODULE, "vault_names", return_value=["Private"]),
              mock.patch.object(MODULE, "run_command", return_value=subprocess.CompletedProcess([], 1, b"", b"network failure")),
              mock.patch.object(MODULE, "keychain_lookup") as lookup):
            with self.assertRaisesRegex(MODULE.ProvisionError, "absence is unverified"):
                MODULE.preflight(valid_manifest(), {}, Path("unused"))
            lookup.assert_not_called()

    def test_copy_preserves_source_and_checks_destination(self):
        source = {"id": "source", "title": "Example API credential", "category": "PASSWORD", "fields": [{"id": "password", "value": "synthetic"}]}
        saved = dict(source, id="destination")
        with (mock.patch.object(MODULE, "run_json", side_effect=[source, saved]),
              mock.patch.object(MODULE, "run_command", return_value=subprocess.CompletedProcess([], 0, b'{"id":"destination"}')) as run):
            MODULE.copy_selected_item({"id": "source", "title": source["title"], "source_vault": "Private"}, "Example Production", {})
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][:3], ["op", "item", "create"])
        payload = json.loads(run.call_args.kwargs["input_data"])
        self.assertNotIn("id", payload)
        self.assertEqual(payload["fields"], source["fields"])

    def test_recovery_replacement_is_audited_before_keychain_write(self):
        with (mock.patch.object(MODULE, "require_tools"),
              mock.patch.object(MODULE, "personal_environment", return_value={}),
              mock.patch.object(MODULE, "read_recovery_token", return_value=b"ops_" + b"x" * 600),
              mock.patch.object(MODULE, "verify_scope", side_effect=MODULE.ProvisionError("wrong scope")),
              mock.patch.object(MODULE, "compile_keychain_helper") as compile_helper):
            with self.assertRaises(MODULE.ProvisionError):
                MODULE.sync_keychain(valid_manifest(), "example-provisioner")
            compile_helper.assert_not_called()


if __name__ == "__main__":
    unittest.main()
