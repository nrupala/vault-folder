# Changelog

All notable changes to Vault Folder are documented here.
Format follows Keep a Changelog; versions follow Semantic Versioning.

## [0.1.0] — 2026-11-15

### Added
- Zero-knowledge file vault engine (format v1, specified in FORMAT.md):
  envelope encryption with a random 256-bit vault key wrapped independently
  by a password-derived key (PBKDF2-SHA-256, 600,000 iterations) and a
  recovery-key-derived key (160-bit base32 recovery key, shown once).
- Per-file random keys; AES-256-GCM chunked encryption (4 MiB chunks) with
  position-bound authentication — tampering, truncation and reordering are
  detected on read.
- Encrypted manifest: file names exist only inside the encryption.
- CLI: `init`, `add`, `list`, `get`, `remove`, `status`. Zero dependencies,
  Node.js ≥ 18 standard library only.
- Test suite covering round-trips, wrong-secret rejection, recovery unlock,
  name/content non-leakage, tamper detection and removal.
- Product page under `docs/`.
