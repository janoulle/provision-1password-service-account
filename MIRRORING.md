# Public mirror policy

This repository is the curated distribution of one reusable skill. The
canonical source remains in a private, version-controlled agent-configuration
repository.

## Publication boundary

The mirror includes:

- `SKILL.md` and `agents/openai.yaml`;
- one generic security-model reference;
- one synthetic manifest template;
- the provisioning, audit, test, and macOS Keychain helper source;
- public documentation, validation, CI, community policy, and licensing.

The mirror must never include private repository history, unrelated skills,
personal configuration, account addresses, real vault or item names, tokens,
credentials, logs, screenshots, private hosts, device identifiers, or private
test evidence.

## Drift controls

`mirror-manifest.json` is the explicit publication allowlist.
`.mirror-state.json` records the SHA-256 value of every mirrored file.

Run:

```sh
python3 scripts/sync_from_canonical.py --mirror . --verify-state
python3 scripts/sync_from_canonical.py \
  --mirror . \
  --source /path/to/provision-1password-service-account \
  --check
```

The first command detects changes inside this repository. The second detects
differences from the private canonical source.

## Refresh workflow

1. Update and validate the canonical skill.
2. Run the source check.
3. Apply expected changes with `--apply`.
4. Review every changed file.
5. Run tests, privacy checks, secret checks, and link validation.
6. Publish only the curated mirror commit.

Reconcile accepted public contributions into the canonical source before
refreshing this mirror. Do not let the two copies become independent
implementations.
