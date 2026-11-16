#!/usr/bin/env python3
"""读取 WorkBuddy 桌面端登录态里的 access token。

WorkBuddy 5.9.2 起 workbuddy-desktop.info 中的 token 被写成 $wbEncrypted 加密信封，
无法直接读取；但 Tencent-Cloud.coding-copilot.info 仍保存明文 accessToken，优先读它。

用法:
  python3 decrypt_workbuddy_token.py                     # 打印 token 信息
  python3 decrypt_workbuddy_token.py --stdout            # 仅输出 token（供 sync 脚本读取）
  python3 decrypt_workbuddy_token.py --ensure-fresh      # 临近过期时唤起客户端刷新后再输出
  python3 decrypt_workbuddy_token.py --pbcopy            # 复制 token 到剪贴板

环境变量:
  TOKEN_NEAR_EXPIRY_DAYS  剩余多少天视为“临近过期”，默认 2
  TOKEN_REFRESH_TIMEOUT   等待客户端刷新秒数，默认 45
"""
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

AUTH_DIR = os.path.expanduser(
    os.environ.get('WB_AUTH_DIR') or '~/Library/Application Support/CodeBuddyExtension/Data/Public/auth'
)
CANDIDATES = [
    os.path.join(AUTH_DIR, 'Tencent-Cloud.coding-copilot.info'),
    os.path.join(AUTH_DIR, 'workbuddy-desktop.info'),
]

APP_NAME = 'WorkBuddy'
NEAR_EXPIRY = timedelta(days=float(os.environ.get('TOKEN_NEAR_EXPIRY_DAYS', '2')))
REFRESH_TIMEOUT = int(os.environ.get('TOKEN_REFRESH_TIMEOUT', '45'))


def parse_expiry(value):
    """兼容 ISO8601 字符串与秒/毫秒时间戳，无法解析时返回 None。"""
    if value is None:
        return None
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return None
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 1e11 else value
        try:
            return datetime.fromtimestamp(seconds, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    return None


def load(path):
    """返回 (token, auth)，读不到可用明文 token 时抛 ValueError。"""
    auth = json.load(open(path)).get('auth', {})
    token = auth.get('accessToken', '')
    if not isinstance(token, str) or not token.startswith('eyJ') or token.count('.') != 2:
        raise ValueError('未找到明文 accessToken（可能是 $wbEncrypted 加密信封）')
    return token, auth


def pick():
    errors = []
    for path in CANDIDATES:
        try:
            token, auth = load(path)
            return path, token, auth
        except Exception as exc:
            errors.append(f'{os.path.basename(path)}: {exc}')
    raise SystemExit('ERROR 读取 WorkBuddy token 失败 → ' + '; '.join(errors))


def ensure_fresh(path, auth):
    """token 临近或已经过期时唤起客户端，等待其自动刷新，返回最新的 auth。"""
    exp = parse_expiry(auth.get('expiresAt'))
    now = datetime.now(timezone.utc)
    if exp is None or exp > now + NEAR_EXPIRY:
        return auth

    print(f'[INFO] token 将于 {exp.isoformat()} 过期，唤起 {APP_NAME} 刷新', file=sys.stderr)
    subprocess.run(['open', '-gj', '-a', APP_NAME], check=False)

    latest = auth
    deadline = time.time() + REFRESH_TIMEOUT
    while time.time() < deadline:
        time.sleep(3)
        try:
            _, candidate = load(path)
        except Exception:
            continue
        new_exp = parse_expiry(candidate.get('expiresAt'))
        if new_exp and (exp is None or new_exp > exp):
            print('[INFO] 客户端已刷新 token', file=sys.stderr)
            return candidate
        latest = candidate
    return latest


def main():
    path, token, auth = pick()

    if '--ensure-fresh' in sys.argv:
        auth = ensure_fresh(path, auth)
        token = auth.get('accessToken', '')
        exp = parse_expiry(auth.get('expiresAt'))
        if not token:
            print('ERROR 刷新后仍未找到 token，请手动打开 WorkBuddy 重新登录', file=sys.stderr)
            sys.exit(1)
        if exp and exp <= datetime.now(timezone.utc):
            print(
                f'ERROR WorkBuddy token 已过期（{exp.isoformat()}）且客户端未自动刷新，'
                f'请手动打开 {APP_NAME} 重新登录',
                file=sys.stderr,
            )
            sys.exit(1)

    if '--stdout' in sys.argv:
        print(token)
        return

    exp = parse_expiry(auth.get('expiresAt'))
    print('来源:', path)
    print('token 长度:', len(token))
    print('过期时间:', exp.isoformat() if exp else auth.get('expiresAt'))
    if '--pbcopy' in sys.argv:
        subprocess.run(['pbcopy'], input=token.encode())
        print('已复制到剪贴板')


if __name__ == '__main__':
    main()
