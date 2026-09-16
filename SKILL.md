---
name: provision-1password-service-account
description: Create, verify, and recover a least-privilege 1Password service account with a dedicated vault and safe one-time-token handling. Use when moving an automation from a personal 1Password CLI session to unattended access, separating project secrets from personal vaults, reducing repeated biometric prompts, or rebuilding a service-account credential boundary on macOS.
---

# Provision a 1Password Service Account

## Check current provider guidance

Read [references/security-model.md](references/security-model.md). Open the linked 1Password documentation before a live setup because permissions, commands, and account-plan requirements can change.

Confirm the workload and boundary:

- one dedicated vault for one application or trust domain;
- the exact existing items that the application needs;
- `read_items` unless the runtime must change 1Password items;
- no vault-creation permission unless the runtime itself must create vaults;
- a recovery vault that the service account cannot access;
- the machine or hosted runtime that needs unattended access;
- the intended token lifetime and rotation owner.

Do not treat a service account as a general replacement for the user's personal 1Password identity.

## Select the operating path

Inspect code and configuration metadata before live reads. Read the operating-path comparison in [security-model.md](references/security-model.md). Use the personal identity only for bounded bootstrap or recovery. Preserve an existing narrow service account; do not add deployment credentials to its vault merely to avoid prompts. Use a separate trust boundary when required. Keep desktop software and bootstrap tokens off production hosts.

For routine work, use one standard `op run` invocation for the full reviewed batch. The bundled wrapper reads the Keychain bootstrap once, disables desktop fallback, resolves explicit references, removes the service-account token from the child, and withholds child output:

```sh
python3 <skill-directory>/scripts/provision_service_account.py run \
  <manifest> <references.env> -- <reviewed-command>
```

The reference file contains only `NAME=op://vault/item/field` lines within the manifest vault. It contains no values. Keep the batch below the 120-second deadline. Commands with external effects still require authorization. Do not start a background shell or persistent secret broker. Memory lifetime is bounded by process exit; Python does not guarantee secure erasure.

Verify process launches with synthetic tests, then record observed owner-prompt counts for bootstrap and routine runs separately. Mocks do not prove zero prompts on the actual Mac. If a synthetic CLI dry run requires authentication, stop: do not use real credentials without the bounded handoff.

## Prepare the manifest

Copy [assets/service-account-plan.example.json](assets/service-account-plan.example.json) to an ignored project-private path. Replace every example value. Use exact item titles. The automation refuses ambiguous title matches.

Do not put secrets, service-account tokens, item contents, account addresses, or private hostnames in the manifest. Treat vault and item titles as private metadata when they reveal sensitive context.

Validate and preview without contacting 1Password:

```sh
python3 <skill-directory>/scripts/provision_service_account.py plan <manifest>
```

Review the exact vault, item moves, immutable permissions, recovery item, and Keychain identifiers. A live run moves items by default. Set an item's `transfer` to `copy` to preserve an owner recovery item; copying supports Password and API Credential items without attachments and verifies destination fields in memory. Review this additional machine-readable copy as an access boundary. For moves, 1Password creates a destination copy and places the original in Recently Deleted with a new destination item ID.

## Perform the setup

Keep the 1Password desktop app open and unlocked. Prefer its CLI integration for the personal creator identity. Do not export a personal account password or Secret Key.

Run the live workflow only after the user authorizes the named account, vault, item moves, and token-storage locations:

```sh
python3 <skill-directory>/scripts/provision_service_account.py apply \
  <manifest> \
  --confirm '<service-account-name>'
```

The script must:

1. Reject an ambient `OP_SERVICE_ACCOUNT_TOKEN` so the creator identity is not confused with an existing service account.
2. Resolve each source item to one exact item ID before any write.
3. Compile the bundled Keychain helper before any provider change.
4. Create the dedicated vault and transfer only the selected items using each item's move or copy policy.
5. Create the service account with the exact immutable permissions from the manifest.
6. Capture the one-time token in process memory only.
7. Create a recovery Password item through JSON on standard input.
8. Store the unattended copy in the macOS login Keychain through the Security framework, with `/usr/bin/security` as the trusted reader.
9. Compare both stored copies with the in-memory token without printing a value.
10. Authenticate as the new service account and verify its exact vault and item boundary.

Do not promise a prompt count. Desktop authorization is scoped to a terminal session, with idle expiry and revocation when the app locks. Run the reviewed bootstrap batch in one terminal session. Announce the exact expected owner action once. If prompts repeat, stop and diagnose session boundaries; do not loop. Never ask the user to relay a token. A service-account run must not fall back to the personal identity.

If any step fails after the first provider write, stop. State that provider state can be partial. Inspect the destination vault, selected source items, Recently Deleted, recovery item, Keychain item, and Developer-console service-account inventory. Do not rerun until every created or moved object is reconciled. Revoke a new service account if no verified token copy exists.

## Verify or recover the boundary

Audit an existing setup from its Keychain copy:

```sh
python3 <skill-directory>/scripts/provision_service_account.py audit <manifest>
```

The audit is read-only. It verifies the exact accessible vault and exact item-title set. It verifies that the configured recovery vault is excluded from the accessible vault inventory. A failed lookup alone does not prove denial. It does not prove that write permission is absent by attempting a write. Use the immutable creation command and the 1Password service-account overview as the permission authority.

1Password CLI 2.34.1 does not provide `op service-account list`. Verify a stored token with `op whoami`, then audit its exact accessible-vault and item inventory. Use the 1Password Developer console for the service-account list, expiration, and revocation state. Do not interpret the command group's help output as an empty list.

The first Keychain read through `/usr/bin/security` can require a macOS access dialog after the helper creates the item. Authorize the exact scoped item with **Always Allow**, then repeat the read in the same workflow. A second authorization dialog on the following lookup means the access rule is not persistent; stop and diagnose it instead of normalizing repeated prompts.

For token rotation, use the 1Password Developer console. Store the replacement recovery copy and Keychain copy before the old token expires. Then run the audit. Do not delete or overwrite the last working copy before the replacement passes.

After the replacement token is saved in the configured recovery Password item, update the unattended copy without placing the token on the clipboard or in a command argument:

```sh
python3 <skill-directory>/scripts/provision_service_account.py sync-keychain \
  <manifest> \
  --confirm '<service-account-name>'
```

This command reads the recovery value into process memory, updates the Keychain item, compares both copies, and audits the service-account boundary.

## Preserve the result

Update the target project's existing operations owner with:

- the non-secret manifest or its ignored path;
- the vault and service-account names;
- the exact permission set and expiry;
- the recovery and runtime token locations;
- the plan, audit, rotation, revocation, and clean-machine recovery commands;
- the provider documentation checked and the date;
- the verification evidence and remaining limits.

Never record token values, item contents, account addresses, one-time codes, or screenshots of secret or authentication dialogs. Commit and push the reusable setup code and non-secret documentation to the confirmed private repository. Treat public publication as a separate boundary and remove personal identifiers, private metadata, and machine-specific paths before review.
