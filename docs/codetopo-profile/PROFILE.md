# Codetopo Profile — Vault Folder (nrupala/vault-folder)

**What this is.** The agent-facing map of this repository, generated with
Codetopo 0.9.1 (local engine, `~/.cargo/bin/codetopo`) so an arriving agent
can see the machine — topology, trust boundaries, money surface — before it
submits or changes anything. Read this first; the graph snapshot beside it
(`snapshot.json`, `stats.json`) is the measured evidence.

- **Repo:** nrupala/vault-folder
- **Commit profiled:** `a72caa0c5a6a2f0ecd56887a7856820342171098` (main)
- **Engine:** codetopo 0.9.1 · index run 2026-11-18
- **Graph:** 8 files walked · 0 failed · 204 nodes · 478 edges · audit chain valid (3 entries, head `36c5fbbf…6f842`)
- **Nodes by kind:** external 121 · variable 32 · function 27 · file 8 · module 8 · doc 5 · class 1 · method 1 · package 1
- **Edges by kind:** calls 248 · reads 113 · contains 82 · defines 21 · imports 14

## Coverage honesty

Codetopo extracts Rust, TypeScript/JavaScript and Python, plus Markdown as Doc nodes. This repo is tiny and entirely covered in kind: 3 `.mjs` files are the whole codebase (JavaScript extraction), and the 5 Markdown files are indexed as Doc nodes. `docs/index.html` and `package.json` are not parsed into the graph. There is no other code language in this repo — no Swift/Java/Ruby or any native scaffolding — so symbol coverage of the codebase is complete.

## Topology

A zero-dependency Node CLI/library that turns an ordinary (possibly cloud-synced) folder into a zero-knowledge vault (README).

- `src/vault.mjs` — the entire engine: folder encryption/decryption so files are ciphertext before any sync client (Google Drive / OneDrive / Dropbox / iCloud / Syncthing) ever sees them.
- `bin/vaultfolder.mjs` — the CLI entry point over `src/vault.mjs`.
- `test/vault.test.mjs` — the test suite; `FORMAT.md` documents the on-disk vault format; `docs/index.html` is the static docs page.

## Trust boundaries

- **Zero-knowledge, no account, no network:** README states it plainly — "No account. No telemetry. No network calls. Zero dependencies." The sync provider (if the user puts the vault in a synced folder) is trusted with ciphertext only; keys and plaintext never leave the user's machine.
- **No credential store exists to leak:** there is no auth, token or secret handling in the 3-file codebase beyond the user's own vault passphrase/key material handled inside `src/vault.mjs`.
- **Blast radius:** total — `src/vault.mjs` is the product; any change to its format or key handling affects every existing vault (see `FORMAT.md` before touching it).

## Money surface

**No money surface found.** README: "Free forever. Open source under the Apache License 2.0." Greps for `stripe|paddle|checkout|billing` over all source returned no hits; no payment, licence-activation or spend path exists at the profiled commit.

## How an agent should approach

1. Read `README.md`, then this profile, then the snapshot.
2. Use `codetopo` queries against the snapshot (descendants, blast-radius,
   symbol) before editing — especially around the hubs named above.
3. Do not add credentials, account identifiers or key material to any file
   here — names and paths only. Respect the trust boundaries above as
   design constraints, not suggestions.
4. Run the repo's own tests after any change; regenerate this profile
   (below) whenever the code changes.

## Regeneration

`docs/codetopo-profile/refresh.sh` (in this pack) re-downloads the repo
at a named ref, re-runs the index, and rewrites `snapshot.json`,
`stats.json` and the header block inputs of this profile. Regenerate at
every release / material change.

Release gate: NOT RUN — Guardian Mesh: NOT RUN (this profile pack is a
documentation artifact; it is not a release-gate or Guardian Mesh verdict).
