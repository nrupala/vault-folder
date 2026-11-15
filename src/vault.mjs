// Vault Folder — zero-knowledge file vault engine.
//
// Design (the same envelope pattern as the Vault Tracker family, applied to files):
//   - A random 256-bit vault key (VK) encrypts everything in the vault.
//   - The VK is wrapped twice, independently: once under a key derived from
//     your password (PBKDF2-SHA-256, 600,000 iterations), once under a key
//     derived from a one-time 160-bit recovery key. Either wrap opens the vault.
//   - Every file gets its own random 256-bit file key (FK), wrapped by the VK
//     and stored in the file's object header.
//   - File contents are encrypted in chunks with AES-256-GCM; each chunk's
//     position is bound into its authentication data, so tampering, truncation
//     and chunk reordering are all detected on read.
//   - File names live only inside the encrypted manifest. The vault directory
//     shows an outsider nothing but opaque object ids and ciphertext sizes.
//
// Zero dependencies. Node.js >= 18 standard library only.

import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { randomBytes, pbkdf2, createCipheriv, createDecipheriv } from 'node:crypto';
import { promisify } from 'node:util';

const pbkdf2Async = promisify(pbkdf2);

export const FORMAT_VERSION = 1;
export const KDF_ITERATIONS = 600_000;
const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024; // 4 MiB
const VERIFIER_PLAINTEXT = 'vaultfolder-verifier-v1';
const MAGIC = Buffer.from('VF01', 'utf8');
const WRAP_AAD = Buffer.from('vf-vault-key', 'utf8');

export class VaultError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'VaultError';
    this.code = code;
  }
}

// ---------- small helpers ----------

const b64 = (buf) => Buffer.from(buf).toString('base64');
const unb64 = (s) => Buffer.from(s, 'base64');

async function deriveKek(secret, salt, iterations) {
  return pbkdf2Async(secret, salt, iterations, 32, 'sha256');
}

// AES-256-GCM with the 16-byte auth tag appended to the ciphertext.
function gcmEncrypt(key, plaintext, aad) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  if (aad) cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { nonce, ct: Buffer.concat([body, cipher.getAuthTag()]) };
}

function gcmDecrypt(key, nonce, ctWithTag, aad) {
  if (ctWithTag.length < 16) throw new VaultError('CORRUPT', 'ciphertext too short');
  const tag = ctWithTag.subarray(ctWithTag.length - 16);
  const body = ctWithTag.subarray(0, ctWithTag.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(body), decipher.final()]);
  } catch {
    throw new VaultError('AUTH_FAILED', 'authentication failed (wrong key or tampered data)');
  }
}

// ---------- base32 (RFC 4648) for the recovery key ----------

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    value = (value << 5) | B32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function formatRecoveryKey(rawBase32) {
  return rawBase32.match(/.{1,4}/g).join('-');
}

export function normalizeRecoveryKey(input) {
  return base32Encode(base32Decode(input));
}

// ---------- vault header / manifest ----------

const headerPath = (dir) => path.join(dir, 'vault.json');
const manifestPath = (dir) => path.join(dir, 'index.enc');
const objectsDir = (dir) => path.join(dir, 'objects');
const objectPath = (dir, id) => path.join(objectsDir(dir), `${id}.vf`);

async function readHeader(dir) {
  let raw;
  try {
    raw = await fsp.readFile(headerPath(dir), 'utf8');
  } catch {
    throw new VaultError('NOT_A_VAULT', `no vault found at ${dir} (missing vault.json)`);
  }
  const header = JSON.parse(raw);
  if (header.format !== 'vaultfolder') throw new VaultError('NOT_A_VAULT', 'unrecognized vault header');
  if (header.version !== FORMAT_VERSION) {
    throw new VaultError('UNSUPPORTED_VERSION', `vault format v${header.version} is not supported by this build`);
  }
  return header;
}

async function saveManifest(session) {
  const plain = Buffer.from(JSON.stringify(session.manifest), 'utf8');
  const { nonce, ct } = gcmEncrypt(session.vk, plain, Buffer.from('vf-manifest', 'utf8'));
  const doc = { nonce: b64(nonce), ct: b64(ct) };
  await fsp.writeFile(manifestPath(session.dir), JSON.stringify(doc), { mode: 0o600 });
}

async function loadManifest(dir, vk) {
  let doc;
  try {
    doc = JSON.parse(await fsp.readFile(manifestPath(dir), 'utf8'));
  } catch {
    throw new VaultError('CORRUPT', 'vault manifest is missing or unreadable');
  }
  const plain = gcmDecrypt(vk, unb64(doc.nonce), unb64(doc.ct), Buffer.from('vf-manifest', 'utf8'));
  return JSON.parse(plain.toString('utf8'));
}

// ---------- public API ----------

/**
 * Create a new vault in `dir`. Returns { recoveryKey } — shown once, never stored.
 * Options: { chunkSize } (bytes; stored in the header, mainly for tests).
 */
export async function createVault(dir, password, opts = {}) {
  if (!password) throw new VaultError('NO_SECRET', 'a password is required');
  try {
    await fsp.access(headerPath(dir));
    throw new VaultError('EXISTS', `a vault already exists at ${dir}`);
  } catch (e) {
    if (e.code === 'EXISTS') throw e;
  }
  await fsp.mkdir(objectsDir(dir), { recursive: true });

  const chunkSize = opts.chunkSize ?? DEFAULT_CHUNK_SIZE;
  const salt = randomBytes(16);
  const kek = await deriveKek(password, salt, KDF_ITERATIONS);
  const vk = randomBytes(32);

  const wrapPassword = gcmEncrypt(kek, vk, WRAP_AAD);

  const recoveryRaw = base32Encode(randomBytes(20)); // 160-bit recovery key
  const recoverySalt = randomBytes(16);
  const recoveryKek = await deriveKek(recoveryRaw, recoverySalt, KDF_ITERATIONS);
  const wrapRecovery = gcmEncrypt(recoveryKek, vk, WRAP_AAD);

  const verifier = gcmEncrypt(vk, Buffer.from(VERIFIER_PLAINTEXT, 'utf8'), WRAP_AAD);

  const header = {
    format: 'vaultfolder',
    version: FORMAT_VERSION,
    createdAt: new Date().toISOString(),
    chunkSize,
    kdf: { algo: 'PBKDF2-SHA256', iterations: KDF_ITERATIONS, salt: b64(salt) },
    wrapPassword: { nonce: b64(wrapPassword.nonce), ct: b64(wrapPassword.ct) },
    recovery: {
      salt: b64(recoverySalt),
      wrap: { nonce: b64(wrapRecovery.nonce), ct: b64(wrapRecovery.ct) },
    },
    verifier: { nonce: b64(verifier.nonce), ct: b64(verifier.ct) },
  };
  await fsp.writeFile(headerPath(dir), JSON.stringify(header, null, 2), { mode: 0o600 });

  const session = { dir, vk, header, manifest: { version: 1, entries: {} } };
  await saveManifest(session);
  return { recoveryKey: formatRecoveryKey(recoveryRaw) };
}

async function unlockWithKek(dir, header, kek) {
  let vk;
  try {
    vk = gcmDecrypt(kek, unb64(header.wrapPassword.nonce), unb64(header.wrapPassword.ct), WRAP_AAD);
  } catch {
    throw new VaultError('BAD_SECRET', 'that password or recovery key does not open this vault');
  }
  const check = gcmDecrypt(vk, unb64(header.verifier.nonce), unb64(header.verifier.ct), WRAP_AAD);
  if (check.toString('utf8') !== VERIFIER_PLAINTEXT) {
    throw new VaultError('CORRUPT', 'vault verifier mismatch — the vault header is damaged');
  }
  const manifest = await loadManifest(dir, vk);
  return { dir, vk, header, manifest };
}

export async function unlockWithPassword(dir, password) {
  const header = await readHeader(dir);
  const kek = await deriveKek(password, unb64(header.kdf.salt), header.kdf.iterations);
  return unlockWithKek(dir, header, kek);
}

export async function unlockWithRecovery(dir, recoveryKey) {
  const header = await readHeader(dir);
  const normalized = normalizeRecoveryKey(recoveryKey);
  // Recovery unwraps through its own wrap slot; try it via a header shim.
  const recKek = await deriveKek(normalized, unb64(header.recovery.salt), header.kdf.iterations);
  const shim = { ...header, wrapPassword: header.recovery.wrap };
  return unlockWithKek(dir, shim, recKek);
}

/** Header-only status (no unlock): safe to show anyone. */
export async function vaultStatus(dir) {
  const header = await readHeader(dir);
  let objects = 0;
  try {
    objects = (await fsp.readdir(objectsDir(dir))).filter((f) => f.endsWith('.vf')).length;
  } catch { /* objects dir absent */ }
  return { version: header.version, createdAt: header.createdAt, chunkSize: header.chunkSize, objects };
}

export function listEntries(session) {
  return Object.entries(session.manifest.entries)
    .map(([id, e]) => ({ id, ...e }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export function resolveEntry(session, ref) {
  if (session.manifest.entries[ref]) return { id: ref, ...session.manifest.entries[ref] };
  const matches = listEntries(session).filter((e) => e.name === ref);
  if (matches.length === 0) throw new VaultError('NOT_FOUND', `no file named "${ref}" in this vault`);
  if (matches.length > 1) {
    throw new VaultError('AMBIGUOUS', `"${ref}" matches ${matches.length} files — use the id from \`list\``);
  }
  return matches[0];
}

/** Encrypt a file into the vault. Returns the new entry { id, name, size, chunks }. */
export async function addFile(session, filePath, name = path.basename(filePath)) {
  const stat = await fsp.stat(filePath);
  if (!stat.isFile()) throw new VaultError('NOT_A_FILE', `${filePath} is not a file`);
  const { dir, vk, header } = session;
  const chunkSize = header.chunkSize;
  const id = randomBytes(16).toString('hex');
  const fk = randomBytes(32);
  const wrapped = gcmEncrypt(vk, fk, Buffer.from(`vf-wrap:${id}`, 'utf8'));
  const chunks = Math.max(1, Math.ceil(stat.size / chunkSize));

  const src = await fsp.open(filePath, 'r');
  const dst = await fsp.open(objectPath(dir, id), 'w', 0o600);
  try {
    const head = Buffer.alloc(4 + 12 + wrapped.ct.length + 4 + 4);
    let off = 0;
    MAGIC.copy(head, off); off += 4;
    wrapped.nonce.copy(head, off); off += 12;
    wrapped.ct.copy(head, off); off += wrapped.ct.length;
    head.writeUInt32BE(chunkSize, off); off += 4;
    head.writeUInt32BE(chunks, off);
    await dst.write(head);

    const buf = Buffer.alloc(chunkSize);
    for (let i = 0; i < chunks; i++) {
      const want = Math.min(chunkSize, stat.size - i * chunkSize);
      const { bytesRead } = await src.read(buf, 0, want, i * chunkSize);
      const { nonce, ct } = gcmEncrypt(fk, buf.subarray(0, bytesRead), Buffer.from(`${id}:${i}`, 'utf8'));
      const lenBuf = Buffer.alloc(4);
      lenBuf.writeUInt32BE(ct.length, 0);
      await dst.write(nonce);
      await dst.write(lenBuf);
      await dst.write(ct);
    }
  } finally {
    await src.close();
    await dst.close();
  }

  session.manifest.entries[id] = {
    name,
    size: stat.size,
    mtime: stat.mtime.toISOString(),
    addedAt: new Date().toISOString(),
    chunks,
  };
  await saveManifest(session);
  return { id, name, size: stat.size, chunks };
}

/** Decrypt a vault entry to `outPath`, verifying every chunk's auth tag. */
export async function extractFile(session, ref, outPath) {
  const entry = resolveEntry(session, ref);
  const { dir, vk } = session;
  const src = await fsp.open(objectPath(dir, entry.id), 'r');
  try {
    const stat = await src.stat();
    const headLen = 4 + 12 + 48 + 4 + 4;
    const head = Buffer.alloc(headLen);
    await src.read(head, 0, headLen, 0);
    if (!head.subarray(0, 4).equals(MAGIC)) throw new VaultError('CORRUPT', 'object header magic mismatch');
    const wrapNonce = head.subarray(4, 16);
    const wrapCt = head.subarray(16, 64);
    const chunkSize = head.readUInt32BE(64);
    const chunks = head.readUInt32BE(68);
    const fk = gcmDecrypt(vk, wrapNonce, wrapCt, Buffer.from(`vf-wrap:${entry.id}`, 'utf8'));

    const dst = await fsp.open(outPath, 'w', 0o600);
    try {
      let pos = headLen;
      for (let i = 0; i < chunks; i++) {
        const meta = Buffer.alloc(16);
        await src.read(meta, 0, 16, pos);
        const nonce = meta.subarray(0, 12);
        const len = meta.readUInt32BE(12);
        pos += 16;
        if (pos + len > stat.size) throw new VaultError('CORRUPT', 'object is truncated');
        const ct = Buffer.alloc(len);
        await src.read(ct, 0, len, pos);
        pos += len;
        let plain;
        try {
          plain = gcmDecrypt(fk, nonce, ct, Buffer.from(`${entry.id}:${i}`, 'utf8'));
        } catch {
          throw new VaultError('TAMPERED', `chunk ${i} of "${entry.name}" failed authentication — the stored copy is damaged or was altered`);
        }
        await dst.write(plain);
      }
    } finally {
      await dst.close();
    }
    return entry;
  } finally {
    await src.close();
  }
}

/** Remove an entry and its encrypted object. */
export async function removeFile(session, ref) {
  const entry = resolveEntry(session, ref);
  await fsp.unlink(objectPath(session.dir, entry.id)).catch(() => {});
  delete session.manifest.entries[entry.id];
  await saveManifest(session);
  return entry;
}
