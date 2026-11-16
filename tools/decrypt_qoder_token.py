#!/usr/bin/env python3
"""解密 Qoder CN 客户端 auth.v1.dat 里的登录 token（Electron safeStorage 算法）。

算法: AES-128-CBC
  密钥派生: PBKDF2-SHA1(password=keychain密码, salt="saltysalt", iterations=1003, dklen=16)
  IV: 16 字节 0x20
  密文布局: [3字节"v10"前缀][AES密文]
  明文为 JSON: { token, refreshToken, expiresAt, refreshTokenExpiresAt, user }

用法:
  python3 decrypt_qoder_token.py                    # 打印 token 信息
  python3 decrypt_qoder_token.py --stdout           # 仅输出 token（供 sync 脚本读取）
  python3 decrypt_qoder_token.py --ensure-fresh     # 临近过期时唤起客户端刷新后再输出
  python3 decrypt_qoder_token.py --pbcopy           # 复制 token 到剪贴板
"""
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

KEYCHAIN_SERVICE = 'Qoder CN App Safe Storage'
AUTH_FILE = os.path.expanduser('~/Library/Application Support/com.qodercn.app.stable/auth.v1.dat')
PBKDF2_SALT = b'saltysalt'
PBKDF2_ITER = 1003
PBKDF2_DKLEN = 16
AES_IV = bytes([0x20] * 16)

APP_NAME = 'Qoder CN'
NEAR_EXPIRY = timedelta(days=2)
REFRESH_TIMEOUT = int(os.environ.get('QODER_REFRESH_TIMEOUT', '45'))


def parse_iso(ts):
    """解析客户端写入的 ISO8601 时间，无法解析时返回 None。"""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except ValueError:
        return None


def ensure_fresh(auth_path, auth):
    """token 临近或已经过期时唤起客户端，等待其自动刷新，返回最新的 auth。"""
    exp = parse_iso(auth.get('expiresAt'))
    now = datetime.now(timezone.utc)
    if exp is None or exp > now + NEAR_EXPIRY:
        return auth

    print(f'[INFO] token 将于 {auth.get("expiresAt")} 过期，唤起 {APP_NAME} 刷新', file=sys.stderr)
    subprocess.run(['open', '-gj', '-a', APP_NAME], check=False)

    latest = auth
    deadline = time.time() + REFRESH_TIMEOUT
    while time.time() < deadline:
        time.sleep(3)
        try:
            candidate = decrypt(auth_path)
        except SystemExit:
            continue
        new_exp = parse_iso(candidate.get('expiresAt'))
        if new_exp and (exp is None or new_exp > exp):
            print('[INFO] 客户端已刷新 token', file=sys.stderr)
            return candidate
        latest = candidate
    return latest



def get_keychain_password():
    """从 macOS 钥匙串获取 Electron safeStorage 加密密码。"""
    try:
        return subprocess.check_output(
            ['security', 'find-generic-password', '-s', KEYCHAIN_SERVICE, '-w'],
            stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError:
        print(f'ERROR 未找到钥匙串条目 "{KEYCHAIN_SERVICE}"，请先启动并登录 Qoder CN 客户端')
        sys.exit(1)


def decrypt(auth_path):
    """解密 auth.v1.dat，返回包含 token 等字段的 dict。"""
    if not os.path.exists(auth_path):
        print(f'ERROR 凭据文件不存在: {auth_path}')
        print('请先启动并登录 Qoder CN 客户端')
        sys.exit(1)

    pw = get_keychain_password()
    data = open(auth_path, 'rb').read()
    if data[:3] != b'v10':
        print(f'ERROR 未知的加密前缀: {data[:3]}')
        sys.exit(1)

    ciphertext = data[3:]
    key = hashlib.pbkdf2_hmac('sha1', pw, PBKDF2_SALT, PBKDF2_ITER, dklen=PBKDF2_DKLEN)

    proc = subprocess.Popen(
        ['openssl', 'enc', '-d', '-aes-128-cbc', '-K', key.hex(), '-iv', AES_IV.hex()],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    plain, err = proc.communicate(ciphertext)
    if proc.returncode != 0:
        print(f'ERROR AES 解密失败: {err.decode()}')
        sys.exit(1)

    # PKCS7 去填充
    pad_len = plain[-1]
    if 1 <= pad_len <= 16:
        plain = plain[:-pad_len]

    return json.loads(plain)


def main():
    auth_path = AUTH_FILE
    for i, arg in enumerate(sys.argv):
        if arg == '--auth-file' and i + 1 < len(sys.argv):
            auth_path = sys.argv[i + 1]

    auth = decrypt(auth_path)

    if '--ensure-fresh' in sys.argv:
        auth = ensure_fresh(auth_path, auth)
        exp = parse_iso(auth.get('expiresAt'))
        if exp and exp <= datetime.now(timezone.utc):
            print(
                f'ERROR Qoder token 已过期（{auth.get("expiresAt")}）且客户端未自动刷新，'
                f'请手动打开 {APP_NAME} 重新登录',
                file=sys.stderr,
            )
            sys.exit(1)

    token = auth.get('token', '')
    if not token:
        print('ERROR 解密成功但未找到 token 字段')
        sys.exit(1)

    if '--stdout' in sys.argv:
        print(token)
        return

    print('token 长度:', len(token))
    print('token 前缀:', token[:8] + '...')
    print('过期时间:', auth.get('expiresAt'))
    print('refresh 过期:', auth.get('refreshTokenExpiresAt'))

    if '--pbcopy' in sys.argv:
        subprocess.run(['pbcopy'], input=token.encode())
        print('已复制到剪贴板')


if __name__ == '__main__':
    main()
