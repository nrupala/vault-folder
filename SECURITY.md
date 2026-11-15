# Security policy

Vault Folder is a security product; we treat reports accordingly.

## Reporting a vulnerability

Email **info@aimlds.org** with the subject `SECURITY: vault-folder`, or open a
GitHub issue for non-sensitive problems. For anything that could expose user
data, email first and do not file details publicly until we have responded.

Please include: affected version, a minimal reproduction, and the impact as
you see it. We aim to acknowledge within 3 business days.

## Never include in any report or issue

- Real vault contents, real file names from a vault you care about, passwords,
  or recovery keys. Reproduce with throwaway vaults only.

## Threat model (summary)

Vault Folder protects file **contents and names** against anyone who obtains
the vault folder without your password or recovery key — a storage provider,
a breached or subpoenaed provider, a stolen synced copy, a curious admin on a
file server. It does not hide that a vault exists, ciphertext sizes, or change
timing, and it cannot protect plaintext on a machine that is itself
compromised while the vault is in use. Losing both the password and the
recovery key makes the vault unrecoverable by design.

## Supported versions

The latest release on the `main` branch is the supported line. The on-disk
format is versioned (see FORMAT.md); readers reject unknown versions rather
than guessing.
