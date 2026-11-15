# Contributing to Vault Folder

Thank you for helping keep people's files theirs.

## Ground rules

- **Zero dependencies is a feature.** Contributions must use the Node.js
  standard library only. A pull request that adds a runtime dependency will
  not be merged.
- **The format is a contract.** Any change to the on-disk format bumps the
  format version and updates FORMAT.md in the same pull request.
- **Tests are the proof.** Run `npm test` (Node's built-in test runner).
  Behaviour changes need tests; crypto changes need tamper/failure tests.
- **Fail closed.** Wrong secrets, damaged data and unknown format versions
  produce explicit errors — never partial plaintext, never a guess.

## Workflow

1. Fork, branch, make the change.
2. `npm test` green locally.
3. Open a pull request describing the behaviour change and its test evidence.

By contributing you agree your work is licensed under the Apache License 2.0.
