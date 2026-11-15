import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { randomBytes } from 'node:crypto';
import {
  createVault, unlockWithPassword, unlockWithRecovery,
  addFile, extractFile, removeFile, listEntries, vaultStatus, VaultError,
} from '../src/vault.mjs';

const PW = 'correct horse battery staple';
const CHUNK = 64 * 1024;

async function tmpVault(t) {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'vf-test-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const dir = path.join(root, 'vault');
  const { recoveryKey } = await createVault(dir, PW, { chunkSize: CHUNK });
  return { root, dir, recoveryKey };
}

async function writeSource(root, name, bytes) {
  const p = path.join(root, name);
  await fsp.writeFile(p, bytes);
  return p;
}

test('create + unlock with password round-trips', async (t) => {
  const { dir } = await tmpVault(t);
  const session = await unlockWithPassword(dir, PW);
  assert.equal(listEntries(session).length, 0);
  const status = await vaultStatus(dir);
  assert.equal(status.version, 1);
  assert.equal(status.objects, 0);
});

test('wrong password is rejected', async (t) => {
  const { dir } = await tmpVault(t);
  await assert.rejects(() => unlockWithPassword(dir, 'wrong password'), (e) => e.code === 'BAD_SECRET');
});

test('recovery key opens the vault (with or without dashes)', async (t) => {
  const { dir, recoveryKey } = await tmpVault(t);
  const a = await unlockWithRecovery(dir, recoveryKey);
  assert.equal(listEntries(a).length, 0);
  const b = await unlockWithRecovery(dir, recoveryKey.replaceAll('-', ' ').toLowerCase());
  assert.equal(listEntries(b).length, 0);
  await assert.rejects(() => unlockWithRecovery(dir, 'AAAA-AAAA-AAAA'), (e) => e.code === 'BAD_SECRET');
});

test('add / list / get round-trips bytes exactly, across chunks', async (t) => {
  const { root, dir } = await tmpVault(t);
  const session = await unlockWithPassword(dir, PW);
  const payload = randomBytes(200_000); // > 3 chunks at 64 KiB
  const src = await writeSource(root, 'payload.bin', payload);
  const entry = await addFile(session, src);
  assert.equal(entry.chunks, 4);

  const relocked = await unlockWithPassword(dir, PW);
  const entries = listEntries(relocked);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].name, 'payload.bin');
  assert.equal(entries[0].size, payload.length);

  const out = path.join(root, 'restored.bin');
  await extractFile(relocked, 'payload.bin', out);
  assert.deepEqual(await fsp.readFile(out), payload);
});

test('empty file round-trips', async (t) => {
  const { root, dir } = await tmpVault(t);
  const session = await unlockWithPassword(dir, PW);
  const src = await writeSource(root, 'empty.txt', Buffer.alloc(0));
  await addFile(session, src);
  const out = path.join(root, 'empty-out.txt');
  await extractFile(session, 'empty.txt', out);
  assert.equal((await fsp.readFile(out)).length, 0);
});

test('the vault directory leaks neither names nor content', async (t) => {
  const { root, dir } = await tmpVault(t);
  const session = await unlockWithPassword(dir, PW);
  const secretName = 'tax-return-2026-secret.pdf';
  const marker = Buffer.from('PLAINTEXT-MARKER-9f27c1');
  const src = await writeSource(root, secretName, Buffer.concat([marker, randomBytes(1024)]));
  await addFile(session, src);

  const names = [];
  const walk = async (d) => {
    for (const e of await fsp.readdir(d, { withFileTypes: true })) {
      names.push(e.name);
      const p = path.join(d, e.name);
      if (e.isDirectory()) await walk(p);
      else {
        const bytes = await fsp.readFile(p);
        assert.ok(!bytes.includes(marker), `plaintext marker found in ${e.name}`);
        assert.ok(!bytes.includes(Buffer.from(secretName)), `file name found in ${e.name}`);
      }
    }
  };
  await walk(dir);
  assert.ok(!names.some((n) => n.includes('tax-return')), 'file name visible in vault directory listing');
});

test('a tampered chunk fails authentication on read', async (t) => {
  const { root, dir } = await tmpVault(t);
  const session = await unlockWithPassword(dir, PW);
  const src = await writeSource(root, 'data.bin', randomBytes(150_000));
  const entry = await addFile(session, src);
  const objPath = path.join(dir, 'objects', `${entry.id}.vf`);
  const bytes = await fsp.readFile(objPath);
  bytes[bytes.length - 40] ^= 0xff; // flip a bit inside the last chunk's ciphertext
  await fsp.writeFile(objPath, bytes);
  await assert.rejects(
    () => extractFile(session, entry.id, path.join(root, 'out.bin')),
    (e) => e.code === 'TAMPERED' || e.code === 'AUTH_FAILED',
  );
});

test('remove deletes the entry and its object', async (t) => {
  const { root, dir } = await tmpVault(t);
  const session = await unlockWithPassword(dir, PW);
  const src = await writeSource(root, 'gone.txt', Buffer.from('bye'));
  const entry = await addFile(session, src);
  await removeFile(session, entry.id);
  assert.equal(listEntries(session).length, 0);
  await assert.rejects(() => fsp.access(path.join(dir, 'objects', `${entry.id}.vf`)));
  const status = await vaultStatus(dir);
  assert.equal(status.objects, 0);
});

test('creating a second vault over an existing one is refused', async (t) => {
  const { dir } = await tmpVault(t);
  await assert.rejects(() => createVault(dir, PW), (e) => e instanceof VaultError && e.code === 'EXISTS');
});
