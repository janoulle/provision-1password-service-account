# Contributing

Contributions are welcome when they preserve least privilege, safe token
handling, explicit provider writes, recovery, and the mirror boundary.

## Before opening a pull request

1. Use synthetic vault, item, account, and Keychain identifiers.
2. Never add a token, credential, account address, personal path, private host,
   provider output, screenshot, or private repository reference.
3. Keep service-account creation fail-closed. Do not place a token in a command
   argument, shell profile, tracked environment file, log, or clipboard.
4. Add tests for changed validation, command construction, or storage behavior.
5. Check current primary 1Password and Apple documentation for consequential
   authentication or Keychain changes.
6. Reconcile accepted distributable changes with the canonical source before
   release.
7. Run:

   ```sh
   python3 scripts/sync_from_canonical.py --mirror . --verify-state
   python3 -m unittest discover -s tests -v
   python3 scripts/test_provision_service_account.py
   python3 scripts/provision_service_account.py plan \
     assets/service-account-plan.example.json
   ```

## Pull request descriptions

Use **What**, **Why**, **How**, and **How I validated it**. State provider,
privacy, security, compatibility, recovery, and untested effects directly.

By contributing, you agree that your contribution is licensed under Apache
License 2.0.
