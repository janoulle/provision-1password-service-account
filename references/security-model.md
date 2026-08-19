# Security model and provider constraints

## Primary sources

- [Get started with 1Password Service Accounts](https://www.1password.dev/service-accounts/get-started)
- [Manage service accounts](https://www.1password.dev/service-accounts/manage-service-accounts)
- [1Password Service Account security](https://www.1password.dev/service-accounts/security)
- [Use service accounts with 1Password CLI](https://www.1password.dev/service-accounts/use-with-1password-cli)
- [Load secrets into scripts](https://www.1password.dev/cli/secrets-scripts)
- [Apple Keychain access control lists](https://developer.apple.com/documentation/security/access-control-lists)
- [Apple keychain implementations on macOS](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)

Check these sources again before a live setup.

## Constraints that control the workflow

1Password supports service-account creation on 1Password.com and with `op service-account create`. The CLI returns the token once. Treat it as a password and store it immediately.

Vault access, Environment access, vault permissions, and the ability to create vaults are immutable after service-account creation. Create a replacement service account when the boundary must change.

Service accounts cannot access built-in Personal, Private, Employee, or default Shared vaults. Use a user-managed dedicated vault for application credentials. A built-in personal vault is therefore an appropriate recovery-token location when the creator can access it.

The available vault permissions are:

- `read_items`;
- `write_items`, which requires `read_items`;
- `share_items`, which requires `read_items`.

Grant `read_items` alone for a runtime that only retrieves credentials. Do not grant `--can-create-vaults` for normal application secret retrieval.

1Password recommends service accounts for least-privilege script access. `OP_SERVICE_ACCOUNT_TOKEN` is the supported CLI authentication variable. Do not put it in a shell profile, tracked environment file, command argument, log, screenshot, or clipboard.

## macOS unattended-copy tradeoff

The bundled helper stores the token in the file-based macOS login Keychain and assigns an access control list that trusts `/usr/bin/security`. This permits unattended retrieval after the user login Keychain is unlocked. It also means any process running as that unlocked user can invoke `/usr/bin/security` to retrieve that one token.

The service account's immutable vault scope is the primary least-privilege boundary. Keep FileVault, the login password, automatic screen lock, and operating-system updates active. Do not use this design on a shared or untrusted Mac.

Do not install the personal 1Password account or its service-account recovery token on a production host only to avoid local authentication. Provision the runtime with only the provider secrets it needs, or use a supported hosted secret integration when live rotation requirements justify it.
