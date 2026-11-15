# Vault Folder

**Your files, encrypted before they ever leave your machine — in any folder, on any storage.**

Vault Folder turns an ordinary folder into a zero-knowledge vault. Put the folder
on your hard drive, a file server, a NAS — or inside the synced folder of
**Google Drive, OneDrive, Dropbox, iCloud or Syncthing** — and everything in it
is ciphertext before the sync client, the server, or the provider ever sees it.
They store it. Only you can read it.

Free forever. Open source under the [Apache License 2.0](LICENSE).
No account. No telemetry. No network calls. **Zero dependencies.**

## Why

Cloud storage is convenient and honest about many things — but your files sit
there readable by the provider, by anyone who breaches or subpoenas the
provider, and by any process with access to the synced copy. Vault Folder keeps
the convenience and removes the readability: encryption happens on your machine,
with keys that never leave your machine.

## Quick start

Requires Node.js 18 or newer. There is nothing to install — no dependencies.

```sh
# create a vault inside your cloud-synced folder
node bin/vaultfolder.mjs init  ~/Google\ Drive/MyVault
# (or: npx vault-folder init … once published — the repo works as-is today)

# add files
node bin/vaultfolder.mjs add   ~/Google\ Drive/MyVault  ~/Documents/taxes-2026.pdf

# see what's inside (names exist only inside the encrypted manifest)
node bin/vaultfolder.mjs list  ~/Google\ Drive/MyVault

# restore a file
node bin/vaultfolder.mjs get   ~/Google\ Drive/MyVault  taxes-2026.pdf  ~/Restored

# remove a file
node bin/vaultfolder.mjs remove ~/Google\ Drive/MyVault taxes-2026.pdf
```

On `init` you get a **recovery key**, shown once and never stored. Write it
down. If you lose both your password and the recovery key, the vault cannot be
opened — by you, by us, or by anyone. That is the point, and it is also the
price. Keep the key somewhere safe.

For scripting, set `VF_PASSWORD` (and `VF_RECOVERY`) in the environment;
otherwise you are prompted without echo.

## How it works

The same envelope-encryption pattern as the Vault Tracker family, applied to files:

- A random **256-bit vault key** encrypts everything in the vault.
- It is wrapped twice, independently: under a key derived from your password
  (**PBKDF2-SHA-256, 600,000 iterations**) and under a key derived from your
  **160-bit recovery key**. Either one opens the vault; neither is stored.
- Every file gets its own random **256-bit file key**, wrapped by the vault key.
- Contents are encrypted in **4 MiB chunks with AES-256-GCM**; each chunk's
  position is bound into its authentication data, so tampering, truncation and
  reordering are detected on read — a damaged or altered copy fails loudly,
  never silently.
- File names live **only** inside the encrypted manifest. The vault folder
  shows an outsider nothing but opaque object ids.

The full byte-level format is specified in [FORMAT.md](FORMAT.md) — anyone can
write an independent reader, and the format is versioned so they always can.

## What the storage provider can still see

Honesty matters more than the pitch: the provider holding your vault can see
**that** a vault exists, roughly **how much** data it holds (ciphertext sizes),
and **when** it changes. It cannot see file names, file contents, or how many
files are inside beyond object count. If your threat model includes hiding
sizes and timing too, this tool alone is not the whole answer.

## Faces & readiness

Readiness is declared per endpoint, plainly:

| Face | Status |
| --- | --- |
| Engine + CLI (Node.js, zero-dependency) | **Shipped — v0.1.0** |
| Product page | **Live** |
| Desktop app | Roadmap |
| Web app (in-browser vaults) | Roadmap |
| Android app | Roadmap |
| Sharing files with other people | Not a goal of this product — it is a *personal* vault |

## Security posture

- No silent telemetry, no trackers, no network code paths at all.
- Wrong passwords and tampered data fail closed, with explicit errors.
- Found a problem? See [SECURITY.md](SECURITY.md). Bug reports and feature
  requests use the issue templates — and never attach real vault contents or
  your recovery key to an issue.

## Licence

Apache License 2.0 — free for anyone, forever, including commercial use.
See [LICENSE](LICENSE).

---

A free gift to the world from **2351485 ALBERTA INC. (AIMLDS)** — the makers of
Vault Tracker. Built on the same zero-trust engine, pointed at your files.
