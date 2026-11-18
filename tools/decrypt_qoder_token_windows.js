#!/usr/bin/env node
// Windows 版 Qoder CN token 读取：Electron safeStorage (Chromium OSCrypt v10)。
// Local State 中 os_crypt.encrypted_key 为 DPAPI blob，解密得到 AES-256 主密钥；
// auth.v1.dat 格式: "v10" + 12 字节 IV + AES-GCM 密文(含 tag)。
// 用法: node tools/decrypt_qoder_token_windows.js [--stdout]
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const userData = path.join(os.homedir(), 'AppData', 'Roaming', 'com.qodercn.app.stable');
const localState = path.join(userData, 'Local State');
const authFile = path.join(userData, 'auth.v1.dat');

function unprotectDpapi(base64) {
  const ps = `
Add-Type -AssemblyName System.Security
$b = [Convert]::FromBase64String('${base64}')
$p = [System.Security.Cryptography.ProtectedData]::Unprotect($b, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[Convert]::ToBase64String($p)
`;
  const out = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], { encoding: 'utf8' });
  return Buffer.from(out.trim(), 'base64');
}

function main() {
  const state = JSON.parse(fs.readFileSync(localState, 'utf8'));
  const blob = Buffer.from(state.os_crypt.encrypted_key, 'base64');
  if (blob.subarray(0, 5).toString() !== 'DPAPI') throw new Error('encrypted_key 不是 DPAPI blob');
  const key = unprotectDpapi(blob.subarray(5).toString('base64'));
  if (key.length !== 32) throw new Error(`DPAPI 解出的主密钥长度异常: ${key.length}`);

  const data = fs.readFileSync(authFile);
  if (data.subarray(0, 3).toString() !== 'v10') throw new Error('auth.v1.dat 不是 v10 格式');
  const iv = data.subarray(3, 15);
  const tag = data.subarray(data.length - 16);
  const ciphertext = data.subarray(15, data.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  const auth = JSON.parse(plain.toString('utf8'));

  if (process.argv.includes('--stdout')) {
    process.stdout.write(auth.token);
    return;
  }
  if (process.argv.includes('--info-json')) {
    process.stdout.write(JSON.stringify({ expiresAt: auth.expiresAt, length: auth.token.length }));
    return;
  }
  console.log('token 长度:', auth.token.length);
  console.log('过期时间:', auth.expiresAt);
  console.log('用户 ID:', auth.user && auth.user.id);
}

Promise.resolve()
  .then(main)
  .catch((e) => {
    console.error('ERROR ' + e.message);
    process.exit(1);
  });
