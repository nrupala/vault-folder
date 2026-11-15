# Vault Folder — format specification v1

This document specifies the on-disk format completely, so independent
implementations can read and write Vault Folder vaults. All multi-byte
integers are big-endian. All base64 is standard RFC 4648 with padding.
"ct‖tag" means the GCM ciphertext with the 16-byte authentication tag appended.

## Vault directory layout

```
<vault>/
  vault.json      — header (plaintext JSON, contains no secrets in the clear)
  index.enc       — encrypted manifest
  objects/
    <id>.vf       — one encrypted object per file; <id> is 32 lowercase hex chars
```

## vault.json

```json
{
  "format": "vaultfolder",
  "version": 1,
  "createdAt": "<ISO 8601>",
  "chunkSize": 4194304,
  "kdf":    { "algo": "PBKDF2-SHA256", "iterations": 600000, "salt": "<b64, 16 bytes>" },
  "wrapPassword": { "nonce": "<b64, 12 bytes>", "ct": "<b64, 48 bytes = ct‖tag of the vault key>" },
  "recovery": {
    "salt": "<b64, 16 bytes>",
    "wrap": { "nonce": "<b64, 12 bytes>", "ct": "<b64, ct‖tag of the vault key>" }
  },
  "verifier": { "nonce": "<b64, 12 bytes>", "ct": "<b64, ct‖tag>" }
}
```

Key schedule:

1. **KEK(password)** = PBKDF2-SHA-256(password UTF-8, kdf.salt, 600000, 32 bytes).
2. **Vault key (VK)** = AES-256-GCM-decrypt(KEK, wrapPassword.nonce, wrapPassword.ct,
   AAD = ASCII `"vf-vault-key"`). 32 bytes.
3. **Recovery path**: the recovery key is 20 random bytes encoded as RFC 4648
   base32 (32 chars, displayed grouped by 4 with `-`). KEK(recovery) =
   PBKDF2-SHA-256(normalized base32 string UTF-8, recovery.salt, 600000, 32),
   and VK = AES-256-GCM-decrypt(KEK(recovery), recovery.wrap…, same AAD).
4. **Verifier**: AES-256-GCM-decrypt(VK, verifier.nonce, verifier.ct, AAD =
   `"vf-vault-key"`) must equal ASCII `"vaultfolder-verifier-v1"`. A GCM
   failure at step 2 means the secret was wrong; implementations must fail
   closed with a single undifferentiated error.

## index.enc (manifest)

JSON `{ "nonce": "<b64>", "ct": "<b64>" }` — AES-256-GCM(VK, AAD = ASCII
`"vf-manifest"`) over the UTF-8 JSON manifest:

```json
{ "version": 1,
  "entries": {
    "<id>": { "name": "<original file name>", "size": 12345,
              "mtime": "<ISO 8601>", "addedAt": "<ISO 8601>", "chunks": 4 }
  } }
```

File names appear **only** here, inside the encryption.

## Object files (`objects/<id>.vf`)

```
offset  size  field
0       4     magic "VF01"
4       12    wrap nonce
16      48    wrapped file key = AES-256-GCM(VK, file key, AAD = "vf-wrap:<id>") ct‖tag
64      4     chunk size (uint32)
68      4     chunk count (uint32)
72      …     per chunk i (0-based):
                12    chunk nonce (fresh random per chunk)
                4     chunk ct length (uint32, includes 16-byte tag)
                n     AES-256-GCM(file key, chunk plaintext, AAD = "<id>:<i>") ct‖tag
```

Plaintext chunk i is the file's bytes `[i*chunkSize, (i+1)*chunkSize)`.
An empty file has exactly one chunk of length 0. Decoders must verify every
chunk's tag before releasing its plaintext, and must refuse objects whose
declared lengths run past the end of the file.

## Versioning

`version` in vault.json governs the whole format. Readers must reject
versions they do not implement rather than guessing.
