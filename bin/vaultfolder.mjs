#!/usr/bin/env node
// Vault Folder CLI — create and use zero-knowledge file vaults in any folder:
// a local directory, a file-server mount, or the synced folder of Google
// Drive, OneDrive, Dropbox, iCloud, Syncthing… The storage only ever holds
// ciphertext. Keys never leave your machine.
//
// Usage:
//   vaultfolder init  <vaultDir>
//   vaultfolder add   <vaultDir> <file...> [--name <storedName>]   (single file only for --name)
//   vaultfolder list  <vaultDir>
//   vaultfolder get   <vaultDir> <name|id> [outDir]
//   vaultfolder remove <vaultDir> <name|id>
//   vaultfolder status <vaultDir>
//
// Secrets: set VF_PASSWORD / VF_RECOVERY in the environment for scripting,
// otherwise you are prompted (input is not echoed).

import path from 'node:path';
import { promises as fsp } from 'node:fs';
import {
  createVault, unlockWithPassword, unlockWithRecovery,
  addFile, extractFile, removeFile, listEntries, vaultStatus, VaultError,
} from '../src/vault.mjs';

function promptSecret(label) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      let data = '';
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', (d) => { data += d; });
      process.stdin.on('end', () => resolve(data.split('\n')[0].trim()));
      process.stdin.on('error', reject);
      process.stderr.write(label);
      return;
    }
    process.stderr.write(label);
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let value = '';
    const onData = (ch) => {
      if (ch === '\n' || ch === '\r' || ch === '') {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stderr.write('\n');
        resolve(value);
      } else if (ch === '') {
        process.exit(130);
      } else if (ch === '') {
        value = value.slice(0, -1);
      } else {
        value += ch;
      }
    };
    stdin.on('data', onData);
  });
}

async function getPassword(confirm = false) {
  if (process.env.VF_PASSWORD) return process.env.VF_PASSWORD;
  const pw = await promptSecret('Vault password: ');
  if (!pw) throw new VaultError('NO_SECRET', 'a password is required');
  if (confirm) {
    const again = await promptSecret('Repeat password: ');
    if (pw !== again) throw new VaultError('MISMATCH', 'the two passwords do not match');
  }
  return pw;
}

async function unlock(dir, useRecovery) {
  if (useRecovery) {
    const rec = process.env.VF_RECOVERY || (await promptSecret('Recovery key: '));
    if (!rec) throw new VaultError('NO_SECRET', 'a recovery key is required');
    return unlockWithRecovery(dir, rec);
  }
  return unlockWithPassword(dir, await getPassword(false));
}

function humanSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MiB`;
  return `${(n / 1024 ** 3).toFixed(2)} GiB`;
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const useRecovery = rest.includes('--recovery');
  const args = rest.filter((a) => a !== '--recovery');

  switch (cmd) {
    case 'init': {
      const dir = args[0];
      if (!dir) throw new VaultError('USAGE', 'usage: vaultfolder init <vaultDir>');
      const pw = await getPassword(true);
      const { recoveryKey } = await createVault(dir, pw);
      console.log(`Vault created at ${path.resolve(dir)}`);
      console.log('');
      console.log('Your recovery key (shown once — it is NOT stored anywhere):');
      console.log(`  ${recoveryKey}`);
      console.log('');
      console.log('Write it down and keep it somewhere safe. If you lose both your');
      console.log('password and this key, the vault cannot be opened — by anyone.');
      break;
    }
    case 'add': {
      const [dir, ...files] = args;
      let name;
      const nameIdx = files.indexOf('--name');
      if (nameIdx >= 0) { name = files[nameIdx + 1]; files.splice(nameIdx, 2); }
      if (!dir || files.length === 0) throw new VaultError('USAGE', 'usage: vaultfolder add <vaultDir> <file...>');
      if (name && files.length !== 1) throw new VaultError('USAGE', '--name applies to a single file');
      const session = await unlock(dir, useRecovery);
      for (const f of files) {
        const entry = await addFile(session, f, name);
        console.log(`added  ${entry.name}  (${humanSize(entry.size)}, ${entry.chunks} chunk${entry.chunks === 1 ? '' : 's'})  id=${entry.id}`);
      }
      break;
    }
    case 'list': {
      const dir = args[0];
      if (!dir) throw new VaultError('USAGE', 'usage: vaultfolder list <vaultDir>');
      const session = await unlock(dir, useRecovery);
      const entries = listEntries(session);
      if (entries.length === 0) { console.log('(vault is empty)'); break; }
      for (const e of entries) console.log(`${e.id}  ${humanSize(e.size).padStart(10)}  ${e.name}`);
      console.log(`${entries.length} file${entries.length === 1 ? '' : 's'}`);
      break;
    }
    case 'get': {
      const [dir, ref, outDir = '.'] = args;
      if (!dir || !ref) throw new VaultError('USAGE', 'usage: vaultfolder get <vaultDir> <name|id> [outDir]');
      const session = await unlock(dir, useRecovery);
      const entry = listEntries(session).find((e) => e.id === ref || e.name === ref);
      const outName = entry ? entry.name : 'restored-file';
      await fsp.mkdir(outDir, { recursive: true });
      const outPath = path.join(outDir, outName);
      const done = await extractFile(session, ref, outPath);
      console.log(`restored  ${done.name}  ->  ${path.resolve(outPath)}  (${humanSize(done.size)})`);
      break;
    }
    case 'remove': {
      const [dir, ref] = args;
      if (!dir || !ref) throw new VaultError('USAGE', 'usage: vaultfolder remove <vaultDir> <name|id>');
      const session = await unlock(dir, useRecovery);
      const entry = await removeFile(session, ref);
      console.log(`removed  ${entry.name}`);
      break;
    }
    case 'status': {
      const dir = args[0];
      if (!dir) throw new VaultError('USAGE', 'usage: vaultfolder status <vaultDir>');
      const s = await vaultStatus(dir);
      console.log(`vault format v${s.version} · created ${s.createdAt} · ${s.objects} stored object${s.objects === 1 ? '' : 's'} · chunk size ${humanSize(s.chunkSize)}`);
      break;
    }
    default:
      console.error('Vault Folder — zero-knowledge file vaults for any folder.');
      console.error('Commands: init | add | list | get | remove | status   (see the header of this file or README.md)');
      process.exit(cmd ? 2 : 0);
  }
}

main().catch((e) => {
  if (e instanceof VaultError) console.error(`error: ${e.message}`);
  else console.error(`error: ${e.message ?? e}`);
  process.exit(1);
});
