# Provision a 1Password Service Account

Create and verify a least-privilege 1Password service account for one
application or trust domain. The skill uses a dedicated vault, an explicit item
allowlist, safe one-time-token handling, a recovery copy in 1Password, and an
unattended copy in the macOS login Keychain.

This repository is a curated mirror of one skill whose canonical source is
maintained in a private agent-configuration repository. It does not contain
personal configuration, provider credentials, or unrelated skills. See
[MIRRORING.md](MIRRORING.md).

## What it automates

- Validate and preview a non-secret service-account manifest.
- Resolve exact source items before any provider write.
- Create one user-managed vault and move only the selected items.
- Create an immutable service-account permission boundary.
- Capture the one-time token in process memory instead of shell history or a
  plaintext file.
- Store a recovery Password item through JSON on standard input.
- Store an unattended copy in the macOS login Keychain.
- Audit the exact accessible vault and item-title set.
- Synchronize a rotated recovery token back to Keychain.

## Requirements

- macOS with an unlocked login Keychain
- Python 3.10 or later
- Swift compiler from Xcode or the Xcode Command Line Tools
- [1Password CLI](https://www.1password.dev/cli/) 2.18.0 or later
- A 1Password account with permission to create service accounts
- 1Password desktop-to-CLI integration for the personal creator session

Check current [1Password service-account documentation](https://www.1password.dev/service-accounts/get-started)
before a live setup. Vault access and permissions cannot be changed after
creation, and the service-account token is shown only once.

## Install

Clone the repository into the skills directory supported by your agent
harness. For Codex:

```sh
git clone \
  https://github.com/janoulle/provision-1password-service-account.git \
  ~/.codex/skills/provision-1password-service-account
```

Keep the complete directory structure so the scripts, reference, and manifest
template remain available.

## Use

Ask the agent to use `$provision-1password-service-account` when you want to
move one automation away from a broad personal 1Password CLI session.

Copy `assets/service-account-plan.example.json` to an ignored project-private
path and replace the example metadata. Do not add secrets or tokens.

Preview the exact changes without contacting 1Password:

```sh
python3 scripts/provision_service_account.py plan /path/to/manifest.json
```

After reviewing the vault, item moves, permissions, recovery location, and
Keychain identifiers, run the live setup:

```sh
python3 scripts/provision_service_account.py apply \
  /path/to/manifest.json \
  --confirm '<service-account-name>'
```

Audit an existing boundary from its Keychain copy:

```sh
python3 scripts/provision_service_account.py audit /path/to/manifest.json
```

After saving a rotated token in the configured recovery item, synchronize it
to Keychain without using the clipboard or a command argument:

```sh
python3 scripts/provision_service_account.py sync-keychain \
  /path/to/manifest.json \
  --confirm '<service-account-name>'
```

## Validate

```sh
python3 scripts/sync_from_canonical.py --mirror . --verify-state
python3 -m unittest discover -s tests -v
python3 scripts/test_provision_service_account.py
python3 scripts/provision_service_account.py plan \
  assets/service-account-plan.example.json
swiftc scripts/store_macos_keychain_secret.swift \
  -o /tmp/store-macos-keychain-secret
```

The source-to-mirror check also runs before a release when the private
canonical source is available.

## Security boundary and limitations

- The live setup creates a vault, moves selected items, creates a service
  account, and stores two token copies. Use `plan` before `apply`.
- 1Password does not provide a transaction across those writes. If a later
  step fails, inspect the destination vault, source items, Recently Deleted,
  recovery item, Keychain item, and service-account list before any retry.
- The script rejects an ambient service-account or 1Password Connect identity
  during creation to avoid using the wrong authority.
- The Keychain helper trusts `/usr/bin/security` for unattended retrieval. Any
  process running as the unlocked Mac user can invoke that tool to retrieve
  this one token. The service account's narrow vault scope is the primary
  least-privilege control.
- The workflow currently supports macOS. It does not install a 1Password
  service-account token on a production server.
- The audit verifies accessible vaults and item titles. It does not test write
  denial by modifying an item. Verify immutable permissions in the 1Password
  service-account overview.
- The project has automated tests and has exercised an existing read-only
  boundary. It has not undergone an independent security audit.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License and affiliation

Licensed under Apache License 2.0. This independent project is not affiliated
with or endorsed by 1Password or Apple Inc. 1Password is a trademark of its
respective owner.
