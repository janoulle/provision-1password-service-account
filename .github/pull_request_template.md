## What

Describe the behavior or maintenance outcome that changes.

## Why

Explain the evidence or risk that motivated the change and why it matters.

## How

Describe the approach, provider-write boundary, token flow, Keychain boundary,
recovery behavior, and meaningful tradeoffs.

## How I validated it

Describe automated, synthetic, and live-provider evidence separately. State
untested paths and remaining risk.

## Safety checklist

- [ ] Tests use synthetic identifiers and contain no credentials or tokens.
- [ ] No personal paths, private hosts, provider logs, screenshots, or private
      repository references are included.
- [ ] Tokens do not enter command arguments, shell history, tracked files,
      logs, screenshots, or the clipboard.
- [ ] Immutable service-account permissions are explicit and least privilege.
- [ ] Recovery and partial-failure behavior are documented and tested.
- [ ] Current primary 1Password and Apple documentation supports consequential
      choices.
- [ ] The public mirror state passes validation.
- [ ] Accepted distributable changes have been reconciled with the canonical
      source.
