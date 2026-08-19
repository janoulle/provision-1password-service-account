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

## Prepare the manifest

Copy [assets/service-account-plan.example.json](assets/service-account-plan.example.json) to an ignored project-private path. Replace every example value. Use exact item titles. The automation refuses ambiguous title matches.

Do not put secrets, service-account tokens, item contents, account addresses, or private hostnames in the manifest. Treat vault and item titles as private metadata when they reveal sensitive context.

Validate and preview without contacting 1Password:

```sh
python3 <skill-directory>/scripts/provision_service_account.py plan <manifest>
```

Review the exact vault, item moves, immutable permissions, recovery item, and Keychain identifiers. A live run moves items between vaults. 1Password creates a destination copy and places the original in Recently Deleted with a new destination item ID.

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
4. Create the dedicated vault and move only the selected items.
5. Create the service account with the exact immutable permissions from the manifest.
6. Capture the one-time token in process memory only.
7. Create a recovery Password item through JSON on standard input.
8. Store the unattended copy in the macOS login Keychain through the Security framework, with `/usr/bin/security` as the trusted reader.
9. Compare both stored copies with the in-memory token without printing a value.
10. Authenticate as the new service account and verify its exact vault and item boundary.

Expect one user-controlled 1Password approval for the creator session. Keep the prompt active and resume automatically. Do not ask the user to paste or relay the service-account token.

If any step fails after the first provider write, stop. State that provider state can be partial. Inspect the destination vault, selected source items, Recently Deleted, recovery item, Keychain item, and service-account list. Do not rerun until every created or moved object is reconciled. Revoke a new service account if no verified token copy exists.

## Verify or recover the boundary

Audit an existing setup from its Keychain copy:

```sh
python3 <skill-directory>/scripts/provision_service_account.py audit <manifest>
```

The audit is read-only. It verifies the exact accessible vault and exact item-title set. It also verifies that the configured recovery vault is denied. It does not prove that write permission is absent by attempting a write. Use the immutable creation command and the 1Password service-account overview as the permission authority.

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
