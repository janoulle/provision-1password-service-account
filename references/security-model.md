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


## Operating-path decision (sources checked 2026-09-16)

Workload: bounded Mac provisioning and deployment diagnostics; unattended hosted
runtime; owner-controlled recovery. Avoid personal-vault reads in routine work.

| Candidate | Fit and boundary |
| --- | --- |
| Desktop CLI session | Bootstrap and recovery. Authorization follows the terminal session, expires after 10 idle minutes or 12 hours, and ends when the app locks. Separate tool executions must not assume shared authorization. |
| Shell plugins | Interactive credential injection. Uses the desktop session model; does not establish unattended access. |
| Dedicated-vault service account with `op run` | Routine Mac batches. One bootstrap lookup per batch; scoped provider secrets go to the child. The bootstrap stays on the Mac. |
| Provider runtime secret store | Hosted runtime secrets after approved provisioning. Do not store deployment authority in the deployed application. |
| Connect server or custom credential broker | Extra service, custody and maintenance burden; not justified for this single-Mac provisioner. |

Use the existing CLI rather than implementing authentication or a secret cache.
The bundled wrapper only controls environment isolation, batch lifetime and safe
output. The provider CLI is proprietary, installed separately, and not vendored.
Current installed CLI and synthetic transport behavior must be checked locally.
The open-source shell-plugin implementation is maintained by 1Password under
MIT, but its authentication boundary does not meet unattended requirements.
Sources: [desktop authorization](https://www.1password.dev/cli/app-integration-security),
[shell-plugin authorization](https://www.1password.dev/cli/shell-plugins/security),
[standard run command](https://www.1password.dev/cli/reference/commands/run),
[shell-plugin source and license](https://github.com/1Password/shell-plugins).

In CLI 2.34.1, `op service-account` exposes `create` and `ratelimit`, but no
`list` command. Use `op whoami` under the stored service-account token and audit
the exact accessible-vault and item inventory. Use the Developer console for
account enumeration, expiration, and revocation. A command that prints the
service-account help page is not inventory evidence.

The macOS Keychain helper can require one access dialog when `/usr/bin/security`
first reads the newly created item. Select **Always Allow** only for the exact
scoped item. Immediately perform a second lookup or a non-mutating batch. If it
prompts again, the ACL is not product-verified and unattended use remains
pending.

Never classify a nonzero lookup as proof that an item is absent or a vault is
forbidden. Preserve ambiguous writes and inspect their exact identity before
retrying. A non-writing CLI dry run can still require authentication. Use only
synthetic input and disable desktop integration for a prompt-free preflight;
report authentication-dependent validation as pending.

Rotation: verify the replacement's scope before overwriting a working Keychain
copy, compare the stored replacement, test a routine batch, then revoke the old
service-account token in the Developer console. Provider credentials have a
separate rotation and revocation lifecycle. Recover from the owner vault or
provider account when the Mac is lost. Never make a runtime or agent the sole
custodian. Revisit this decision when the consumer, host, vault contents, expiry,
or deployment authority changes.
