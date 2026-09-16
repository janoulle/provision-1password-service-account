#!/usr/bin/env python3
"""Provision and audit a least-privilege 1Password service account on macOS."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ALLOWED_PERMISSIONS = {"read_items", "write_items", "share_items"}
BUILT_IN_VAULT_NAMES = {"Personal", "Private", "Employee", "Shared"}
SCRIPT_DIRECTORY = Path(__file__).resolve().parent
KEYCHAIN_SOURCE = SCRIPT_DIRECTORY / "store_macos_keychain_secret.swift"


class ProvisionError(RuntimeError):
    """A safe, non-secret error that can be shown to the operator."""


class IncompleteProvisionError(ProvisionError):
    """The provider account exists but storage or verification is incomplete."""


def require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProvisionError(f"{path} must be a non-empty string")
    if "\n" in value or "\r" in value:
        raise ProvisionError(f"{path} must not contain a newline")
    return value


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProvisionError(f"cannot read the manifest: {error}") from error
    if not isinstance(data, dict):
        raise ProvisionError("the manifest root must be an object")
    if data.get("schema_version") != 1:
        raise ProvisionError("schema_version must be 1")

    for key in ("vault", "service_account", "items", "token_storage"):
        if key not in data:
            raise ProvisionError(f"the manifest is missing {key}")

    vault = data["vault"]
    account = data["service_account"]
    items = data["items"]
    storage = data["token_storage"]
    if not isinstance(vault, dict) or not isinstance(account, dict) or not isinstance(storage, dict):
        raise ProvisionError("vault, service_account, and token_storage must be objects")
    if not isinstance(items, list) or not items:
        raise ProvisionError("items must contain at least one selected credential")

    vault_name = require_string(vault.get("name"), "vault.name")
    require_string(vault.get("description"), "vault.description")
    if vault_name in BUILT_IN_VAULT_NAMES:
        raise ProvisionError("vault.name must be a user-managed vault, not a built-in vault")

    require_string(account.get("name"), "service_account.name")
    permissions = account.get("permissions")
    if not isinstance(permissions, list) or not permissions:
        raise ProvisionError("service_account.permissions must be a non-empty list")
    if len(set(permissions)) != len(permissions):
        raise ProvisionError("service_account.permissions contains duplicates")
    invalid_permissions = set(permissions) - ALLOWED_PERMISSIONS
    if invalid_permissions:
        raise ProvisionError("service_account.permissions contains an unsupported permission")
    if "read_items" not in permissions:
        raise ProvisionError("read_items is required for every supported service-account boundary")
    expires_in = account.get("expires_in")
    if expires_in is not None:
        require_string(expires_in, "service_account.expires_in")

    seen_items: set[tuple[str, str]] = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ProvisionError(f"items[{index}] must be an object")
        title = require_string(item.get("title"), f"items[{index}].title")
        source_vault = require_string(item.get("source_vault"), f"items[{index}].source_vault")
        identity = (source_vault, title)
        if identity in seen_items:
            raise ProvisionError("items contains the same source vault and title more than once")
        seen_items.add(identity)
        if item.get("transfer", "move") not in {"move", "copy"}:
            raise ProvisionError("item transfer must be move or copy")
        if source_vault == vault_name:
            raise ProvisionError("an item's source_vault must differ from the destination vault")

    recovery_vault = require_string(storage.get("recovery_vault"), "token_storage.recovery_vault")
    require_string(storage.get("recovery_item_title"), "token_storage.recovery_item_title")
    require_string(storage.get("keychain_service"), "token_storage.keychain_service")
    require_string(storage.get("keychain_account"), "token_storage.keychain_account")
    if recovery_vault == vault_name:
        raise ProvisionError("the recovery vault must be outside the service account's vault scope")

    return data


def safe_plan(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "destination_vault": manifest["vault"]["name"],
        "service_account": manifest["service_account"]["name"],
        "permissions": manifest["service_account"]["permissions"],
        "expires_in": manifest["service_account"].get("expires_in"),
        "item_moves": [
            {
                "title": item["title"],
                "from": item["source_vault"],
                "to": manifest["vault"]["name"],
                "transfer": item.get("transfer", "move"),
            }
            for item in manifest["items"]
        ],
        "recovery_vault": manifest["token_storage"]["recovery_vault"],
        "recovery_item_title": manifest["token_storage"]["recovery_item_title"],
        "keychain_service": manifest["token_storage"]["keychain_service"],
        "keychain_account": manifest["token_storage"]["keychain_account"],
        "provider_changes": [
            "create one vault",
            "transfer selected items using each item's move or copy policy",
            "create one immutable service-account boundary",
            "create one recovery Password item",
            "create one macOS Keychain item",
        ],
    }


def run_command(
    arguments: list[str],
    *,
    input_data: bytes | None = None,
    environment: dict[str, str] | None = None,
    allow_failure: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    # A real OS pipe is required by op's stdin detection. Capture all output.
    # A separate process group permits bounded cleanup of shell descendants.
    try:
        process = subprocess.Popen(
            arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=environment, preexec_fn=os.setpgrp,
        )
        try:
            stdout, stderr = process.communicate(input_data, timeout=120)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise ProvisionError("command interrupted or timed out; reconcile writes before retry") from None
    except OSError:
        raise ProvisionError("command could not start") from None
    result = subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr)
    if result.returncode != 0 and not allow_failure:
        command_name = " ".join(arguments[:3])
        raise ProvisionError(f"{command_name} failed with exit {result.returncode}")
    return result


def run_json(arguments: list[str], *, environment: dict[str, str] | None = None) -> Any:
    result = run_command(arguments, environment=environment)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ProvisionError(f"{' '.join(arguments[:3])} did not return valid JSON") from error


def require_tools() -> None:
    if platform.system() != "Darwin":
        raise ProvisionError("the bundled unattended token store currently requires macOS")
    for executable in ("op", "swiftc", "/usr/bin/security"):
        if not shutil.which(executable):
            raise ProvisionError(f"required executable is not available: {executable}")
    if not KEYCHAIN_SOURCE.is_file():
        raise ProvisionError("the bundled macOS Keychain helper is missing")


def personal_environment() -> dict[str, str]:
    if os.environ.get("OP_SERVICE_ACCOUNT_TOKEN"):
        raise ProvisionError(
            "unset OP_SERVICE_ACCOUNT_TOKEN before provisioning so the personal creator identity is used"
        )
    if os.environ.get("OP_CONNECT_HOST") or os.environ.get("OP_CONNECT_TOKEN"):
        raise ProvisionError(
            "unset OP_CONNECT_HOST and OP_CONNECT_TOKEN before provisioning so the personal creator identity is used"
        )
    environment = os.environ.copy()
    environment.pop("OP_SERVICE_ACCOUNT_TOKEN", None)
    environment.pop("OP_CONNECT_HOST", None)
    environment.pop("OP_CONNECT_TOKEN", None)
    return environment


def vault_names(environment: dict[str, str]) -> list[str]:
    vaults = run_json(["op", "vault", "list", "--format=json"], environment=environment)
    if not isinstance(vaults, list):
        raise ProvisionError("op vault list returned an unexpected value")
    return [vault.get("name") for vault in vaults if isinstance(vault, dict) and isinstance(vault.get("name"), str)]


def resolve_source_items(manifest: dict[str, Any], environment: dict[str, str]) -> list[dict[str, str]]:
    resolved: list[dict[str, str]] = []
    for selected in manifest["items"]:
        source_vault = selected["source_vault"]
        item = run_json(["op", "item", "get", selected["title"], "--vault", source_vault,
                         "--format=json"], environment=environment)
        if not isinstance(item, dict) or item.get("title") != selected["title"] or not isinstance(item.get("id"), str):
            raise ProvisionError("source item did not resolve to one exact identity")
        resolved.append({"id": item["id"], "title": selected["title"],
                         "source_vault": source_vault, "transfer": selected.get("transfer", "move")})

    return resolved


def keychain_lookup(storage: dict[str, Any], *, allow_failure: bool) -> subprocess.CompletedProcess[bytes]:
    return run_command(
        [
            "/usr/bin/security",
            "find-generic-password",
            "-a",
            storage["keychain_account"],
            "-s",
            storage["keychain_service"],
            "-w",
        ],
        allow_failure=allow_failure,
    )


def compile_keychain_helper(directory: Path) -> Path:
    cache = directory / "module-cache"
    cache.mkdir()
    binary = directory / "store-macos-keychain-secret"
    run_command(
        [
            "swiftc",
            "-module-cache-path",
            str(cache),
            str(KEYCHAIN_SOURCE),
            "-o",
            str(binary),
        ]
    )
    return binary


def preflight(
    manifest: dict[str, Any], environment: dict[str, str], helper_directory: Path
) -> tuple[list[dict[str, str]], Path]:
    names = vault_names(environment)
    destination = manifest["vault"]["name"]
    recovery = manifest["token_storage"]["recovery_vault"]
    if destination in names:
        raise ProvisionError("the destination vault already exists; use audit or choose a new boundary")
    if recovery not in names:
        raise ProvisionError("the configured recovery vault is not available to the creator identity")

    storage = manifest["token_storage"]
    existing_recovery = run_command(
        [
            "op",
            "item",
            "get",
            storage["recovery_item_title"],
            "--vault",
            recovery,
            "--format=json",
        ],
        environment=environment,
        allow_failure=True,
    )
    if existing_recovery.returncode == 0:
        raise ProvisionError("the recovery item title already exists")
    # Only the CLI's explicit item-not-found response is absence. Authentication,
    # transport and unknown errors must not lead to a duplicate recovery write.
    if b"isn't an item in" not in existing_recovery.stderr:
        raise ProvisionError("recovery item absence is unverified; reconcile before setup")
    keychain_state = keychain_lookup(storage, allow_failure=True)
    if keychain_state.returncode not in (0, 44):
        raise ProvisionError("Keychain item absence is unverified; reconcile before setup")
    if keychain_state.returncode == 0:
        raise ProvisionError("the configured macOS Keychain item already exists")

    resolved = resolve_source_items(manifest, environment)
    helper = compile_keychain_helper(helper_directory)
    return resolved, helper


def create_recovery_item(
    manifest: dict[str, Any], token: bytes, environment: dict[str, str]
) -> None:
    template = run_json(
        ["op", "item", "template", "get", "Password", "--format=json"],
        environment=environment,
    )
    if not isinstance(template, dict) or not isinstance(template.get("fields"), list):
        raise IncompleteProvisionError("the 1Password Password-item template has an unexpected structure")
    password_fields = [
        field
        for field in template["fields"]
        if isinstance(field, dict) and (field.get("purpose") == "PASSWORD" or field.get("id") == "password")
    ]
    if len(password_fields) != 1:
        raise IncompleteProvisionError("the 1Password Password-item template has no unique password field")
    try:
        password_fields[0]["value"] = token.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IncompleteProvisionError("the service-account token is not valid UTF-8") from error
    template["title"] = manifest["token_storage"]["recovery_item_title"]
    template.pop("id", None)
    payload = json.dumps(template, separators=(",", ":")).encode("utf-8")
    result = run_command(
        [
            "op",
            "item",
            "create",
            "-",
            "--vault",
            manifest["token_storage"]["recovery_vault"],
            "--format=json",
        ],
        input_data=payload,
        environment=environment,
        allow_failure=True,
    )
    if result.returncode != 0:
        raise IncompleteProvisionError("the service account exists, but its recovery item was not created")


def copy_selected_item(item: dict[str, str], destination: str, environment: dict[str, str]) -> None:
    """Preserve an owner recovery item while creating a separate machine copy."""
    source = run_json(["op", "item", "get", item["id"], "--vault", item["source_vault"],
                       "--format=json", "--reveal"], environment=environment)
    if source.get("id") != item["id"] or source.get("title") != item["title"]:
        raise ProvisionError("copy source identity mismatch")
    if source.get("files") or source.get("category") not in {"PASSWORD", "API_CREDENTIAL"}:
        raise ProvisionError("copy supports credential items without attachments only")
    payload = {key: source[key] for key in ("title", "category", "fields", "sections") if key in source}
    result = run_command(["op", "item", "create", "-", "--vault", destination, "--format=json"],
                         input_data=json.dumps(payload).encode(), environment=environment)
    try:
        created = json.loads(result.stdout)
        identifier = created["id"]
    except (ValueError, KeyError, TypeError):
        raise ProvisionError("copy may exist; reconcile before retry") from None
    saved = run_json(["op", "item", "get", identifier, "--vault", destination,
                      "--format=json", "--reveal"], environment=environment)
    def fields(value: dict) -> dict:
        return {(f.get("section", {}).get("id"), f.get("id")): f.get("value", "")
                for f in value.get("fields", [])}
    if saved.get("id") != identifier or saved.get("title") != source["title"] or fields(saved) != fields(source):
        raise ProvisionError("copy readback mismatch; reconcile before retry")


def read_recovery_token(manifest: dict[str, Any], environment: dict[str, str]) -> bytes:
    storage = manifest["token_storage"]
    result = run_command(
        [
            "op",
            "item",
            "get",
            storage["recovery_item_title"],
            "--vault",
            storage["recovery_vault"],
            "--fields",
            "password",
            "--reveal",
        ],
        environment=environment,
    )
    return result.stdout.strip()


def service_environment(token: bytes) -> dict[str, str]:
    try:
        value = token.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProvisionError("the stored service-account token is not valid UTF-8") from error
    environment = os.environ.copy()
    environment.pop("OP_CONNECT_HOST", None)
    environment.pop("OP_CONNECT_TOKEN", None)
    if not value.startswith("ops_") or len(value) <= 512:
        raise ProvisionError("a complete service-account token is required; no personal fallback")
    for name in list(environment):
        if name.startswith("OP_SESSION"):
            environment.pop(name)
    environment["OP_BIOMETRIC_UNLOCK_ENABLED"] = "false"
    environment["OP_SERVICE_ACCOUNT_TOKEN"] = value
    return environment


def verify_scope(manifest: dict[str, Any], token: bytes) -> None:
    environment = service_environment(token)
    expected_vault = manifest["vault"]["name"]
    actual_vaults = vault_names(environment)
    if actual_vaults != [expected_vault]:
        raise ProvisionError("the service account can access an unexpected vault set")

    items = run_json(
        ["op", "item", "list", "--vault", expected_vault, "--format=json"],
        environment=environment,
    )
    actual_titles = sorted(
        item.get("title") for item in items if isinstance(item, dict) and isinstance(item.get("title"), str)
    )
    expected_titles = sorted(item["title"] for item in manifest["items"])
    if actual_titles != expected_titles:
        raise ProvisionError("the service-account vault contains an unexpected item-title set")

    denial = run_command(
        ["op", "vault", "get", manifest["token_storage"]["recovery_vault"], "--format=json"],
        environment=environment,
        allow_failure=True,
    )
    if denial.returncode == 0:
        raise ProvisionError("the service account can access the configured recovery vault")
    # A transport error is not proof of denial. The authoritative accessible
    # vault inventory above establishes exclusion; do not label arbitrary errors.
    if vault_names(environment) != [expected_vault]:
        raise ProvisionError("post-check vault inventory failed")


def apply(manifest: dict[str, Any], confirmation: str) -> None:
    account = manifest["service_account"]
    if confirmation != account["name"]:
        raise ProvisionError("--confirm must exactly match service_account.name")
    require_tools()
    environment = personal_environment()

    with tempfile.TemporaryDirectory(prefix="op-service-account-") as temporary:
        resolved_items, helper = preflight(manifest, environment, Path(temporary))
        writes_started = False
        try:
            run_command(
                [
                    "op",
                    "vault",
                    "create",
                    manifest["vault"]["name"],
                    "--description",
                    manifest["vault"]["description"],
                ],
                environment=environment,
            )
            writes_started = True
            for item in resolved_items:
                if item.get("transfer") == "copy":
                    copy_selected_item(item, manifest["vault"]["name"], environment)
                    continue
                run_command(
                    [
                        "op",
                        "item",
                        "move",
                        item["id"],
                        "--current-vault",
                        item["source_vault"],
                        "--destination-vault",
                        manifest["vault"]["name"],
                    ],
                    environment=environment,
                )

            destination_items = run_json(
                ["op", "item", "list", "--vault", manifest["vault"]["name"], "--format=json"],
                environment=environment,
            )
            moved_titles = sorted(
                item.get("title")
                for item in destination_items
                if isinstance(item, dict) and isinstance(item.get("title"), str)
            )
            expected_titles = sorted(item["title"] for item in manifest["items"])
            if moved_titles != expected_titles:
                raise ProvisionError("the destination vault item set is not exact; service-account creation stopped")

            create_arguments = [
                "op",
                "service-account",
                "create",
                account["name"],
                "--raw",
                "--vault",
                f"{manifest['vault']['name']}:{','.join(account['permissions'])}",
            ]
            if account.get("expires_in"):
                create_arguments.extend(["--expires-in", account["expires_in"]])
            token_result = run_command(create_arguments, environment=environment)
            token = token_result.stdout.strip()
            if not token.startswith(b"ops_") or len(token) <= 512:
                raise IncompleteProvisionError(
                    "the service account may exist, but the returned one-time token failed structural validation"
                )

            try:
                create_recovery_item(manifest, token, environment)
                run_command(
                    [
                        str(helper),
                        manifest["token_storage"]["keychain_service"],
                        manifest["token_storage"]["keychain_account"],
                    ],
                    input_data=token,
                )
                if read_recovery_token(manifest, environment) != token:
                    raise IncompleteProvisionError("the recovery token copy does not match the new token")
                if keychain_lookup(manifest["token_storage"], allow_failure=False).stdout.strip() != token:
                    raise IncompleteProvisionError("the macOS Keychain token copy does not match the new token")
                verify_scope(manifest, token)
            except ProvisionError as error:
                if isinstance(error, IncompleteProvisionError):
                    raise
                raise IncompleteProvisionError(
                    "the service account exists, but token storage or boundary verification did not finish"
                ) from error
            finally:
                token = b""
        except ProvisionError as error:
            if isinstance(error, IncompleteProvisionError):
                raise
            if writes_started:
                raise IncompleteProvisionError(
                    "provider setup stopped after one or more writes; the vault, item, or service-account state may be partial"
                ) from error
            raise IncompleteProvisionError(
                "provider setup stopped before its final boundary verification"
            ) from error

    print("verified: dedicated vault contains the exact selected item set")
    print("verified: recovery and macOS Keychain token copies match")
    print("verified: service account can access only the dedicated vault and exact item-title set")


def audit(manifest: dict[str, Any]) -> None:
    require_tools()
    result = keychain_lookup(manifest["token_storage"], allow_failure=False)
    token = result.stdout.strip()
    if not token.startswith(b"ops_") or len(token) <= 512:
        raise ProvisionError("the macOS Keychain item does not contain a complete service-account token")
    try:
        verify_scope(manifest, token)
    finally:
        token = b""
    print("verified: service account can access only the dedicated vault and exact item-title set")
    print("verified: recovery vault is excluded from the accessible vault inventory")


def sync_keychain(manifest: dict[str, Any], confirmation: str) -> None:
    account_name = manifest["service_account"]["name"]
    if confirmation != account_name:
        raise ProvisionError("--confirm must exactly match service_account.name")
    require_tools()
    environment = personal_environment()
    token = read_recovery_token(manifest, environment)
    if not token.startswith(b"ops_") or len(token) <= 512:
        raise ProvisionError("the recovery item does not contain a complete service-account token")
    try:
        # Verify the replacement before overwriting a working unattended copy.
        verify_scope(manifest, token)
        with tempfile.TemporaryDirectory(prefix="op-service-account-") as temporary:
            helper = compile_keychain_helper(Path(temporary))
            run_command(
                [
                    str(helper),
                    manifest["token_storage"]["keychain_service"],
                    manifest["token_storage"]["keychain_account"],
                ],
                input_data=token,
            )
        if keychain_lookup(manifest["token_storage"], allow_failure=False).stdout.strip() != token:
            raise ProvisionError("the macOS Keychain token copy does not match the recovery item")
        verify_scope(manifest, token)
    finally:
        token = b""
    print("verified: macOS Keychain token copy matches the recovery item")
    print("verified: service account can access only the dedicated vault and exact item-title set")


def run_batch(manifest: dict[str, Any], env_file: Path, command: list[str]) -> None:
    """Use the standard op run implementation, not a persistent secret broker."""
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise ProvisionError("run requires a reviewed child command after --")
    # The env file must contain only explicit secret references, no plaintext.
    import re
    lines = env_file.read_text(encoding="utf-8").splitlines()
    references = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(op://[^\r\n]+)", line)
        if not match or match[1].startswith("OP_"):
            raise ProvisionError("env file must contain NAME=op://vault/item/field references only")
        if not match[2].startswith("op://" + manifest["vault"]["name"] + "/"):
            raise ProvisionError("reference is outside the manifest vault")
        references.append(match)
    if not references:
        raise ProvisionError("at least one secret reference is required")
    token = keychain_lookup(manifest["token_storage"], allow_failure=False).stdout.strip()
    environment = service_environment(token)
    # Discard ambient op references to prevent unrelated resolution by op run.
    environment = {k: v for k, v in environment.items() if not v.startswith("op://")}
    result = run_command([
        "op", "run", "--env-file", str(env_file), "--",
        "/usr/bin/env", "-u", "OP_SERVICE_ACCOUNT_TOKEN", *command,
    ], environment=environment, allow_failure=True)
    # Even masked child output can reveal transformed secrets. Report only status.
    if result.returncode:
        raise ProvisionError("credential batch failed; child output withheld")
    print("completed: one credential batch; child output withheld")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "audit"):
        subparser = subparsers.add_parser(name)
        subparser.add_argument("manifest", type=Path)
    for name in ("apply", "sync-keychain"):
        mutating_parser = subparsers.add_parser(name)
        mutating_parser.add_argument("manifest", type=Path)
        mutating_parser.add_argument("--confirm", required=True)
    runner = subparsers.add_parser("run")
    runner.add_argument("manifest", type=Path)
    runner.add_argument("env_file", type=Path)
    runner.add_argument("child", nargs=argparse.REMAINDER)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        manifest = load_manifest(arguments.manifest)
        if arguments.command == "plan":
            print(json.dumps(safe_plan(manifest), indent=2))
        elif arguments.command == "apply":
            apply(manifest, arguments.confirm)
        elif arguments.command == "audit":
            audit(manifest)
        elif arguments.command == "run":
            run_batch(manifest, arguments.env_file, arguments.child)
        elif arguments.command == "sync-keychain":
            sync_keychain(manifest, arguments.confirm)
    except IncompleteProvisionError as error:
        print(f"incomplete: {error}", file=sys.stderr)
        print(
            "required action: inspect the destination vault, selected source items, Recently Deleted, recovery item, Keychain item, and 1Password Developer service-account list; reconcile them before any retry and revoke a new account if no verified token copy exists",
            file=sys.stderr,
        )
        return 20
    except ProvisionError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
