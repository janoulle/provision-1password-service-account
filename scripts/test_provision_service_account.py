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


if __name__ == "__main__":
    unittest.main()
