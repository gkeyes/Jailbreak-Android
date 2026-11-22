#!/usr/bin/env python3
"""核对 app/src/main/assets/ 与 tools/assets-ledger.json 是否一致。

作用（对应审计 P1「资产台账」）：
- 每个打进 APK 的文件都必须在台账里登记，且 size / git blob SHA-1 对得上；
- 台账里填了 sha256 就一并校验；
- 有未登记的新文件 → 报警（--strict 下失败）；
- tools/ksud.lock.properties 的字段必须齐全、链接与 tag/repo 一致。

用法：
  tools/check_assets.py            # 打印核对表，只有硬错误才返回 1
  tools/check_assets.py --strict   # 未登记文件也算错误
  tools/check_assets.py --update   # 把算出来的 sha256 写回台账
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEDGER = ROOT / "tools" / "assets-ledger.json"
LOCK = ROOT / "tools" / "ksud.lock.properties"
ASSETS_DIR = ROOT / "app" / "src" / "main" / "assets"

# 不参与安装的说明文件，允许不出现在台账里
ALLOWLIST = {"README.payloads.md", "README.md"}

LOCK_REQUIRED = ("repo", "tag", "url", "apkSha256", "entry", "size", "sha256", "license")


def blob_sha1(data: bytes) -> str:
    """git 对象内容的 SHA-1，等价于 `git hash-object <file>`。"""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def load_lock() -> dict:
    values = {}
    for line in LOCK.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def is_sha256(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower())


def check_lock(errors: list, notes: list) -> None:
    if not LOCK.exists():
        errors.append("缺少 tools/ksud.lock.properties")
        return

    lock = load_lock()
    for key in LOCK_REQUIRED:
        if not lock.get(key):
            errors.append(f"ksud.lock 缺少字段 {key}")

    for key in ("sha256", "apkSha256"):
        value = lock.get(key, "")
        if value and not is_sha256(value):
            errors.append(f"ksud.lock 的 {key} 不是 64 位十六进制")

    if not lock.get("size", "").isdigit():
        errors.append(f"ksud.lock 的 size 不是十进制字节数：{lock.get('size')}")

    url = lock.get("url", "")
    tag = lock.get("tag", "")
    repo = lock.get("repo", "")
    if url:
        path = urllib.parse.urlparse(url).path
        if tag and f"/{tag}/" not in path:
            errors.append(f"ksud.lock 的 url 里没有 /{tag}/：{url}")
        if repo and repo not in url:
            errors.append(f"ksud.lock 的 url 与 repo={repo} 不一致：{url}")
    entry = lock.get("entry", "")
    if entry and not entry.startswith("lib/"):
        notes.append(f"ksud.lock 的 entry 不在 APK 的 lib/ 下：{entry}")

    notes.append(
        "ksud 锁定："
        + " ".join(f"{k}={lock.get(k, '?')}" for k in ("repo", "tag", "entry"))
        + f" sha256={lock.get('sha256', '?')[:16]}…"
    )


def main() -> int:
    strict = "--strict" in sys.argv
    update = "--update" in sys.argv
    if not LEDGER.exists():
        print(f"缺少 {LEDGER.relative_to(ROOT)}")
        return 1
    ledger = json.loads(LEDGER.read_text(encoding="utf-8"))

    errors: list = []
    warnings: list = []
    notes: list = []
    listed = set()
    changed = False

    for entry in ledger.get("assets", []):
        name = entry.get("name", "")
        path = ROOT / entry.get("path", f"app/src/main/assets/{name}")
        listed.add(name)
        label = f"assets/{name}"
        if not path.exists():
            errors.append(f"{label} 台账有登记但文件不存在")
            continue

        data = path.read_bytes()
        size, digest = len(data), blob_sha1(data)
        sha256 = hashlib.sha256(data).hexdigest()
        flags = []

        if entry.get("size") != size:
            errors.append(f"{label} size 不符：台账 {entry.get('size')} 实际 {size}")
            flags.append("size")
        if entry.get("gitBlobSha1") != digest:
            errors.append(f"{label} blobSha1 不符：台账 {entry.get('gitBlobSha1')} 实际 {digest}")
            flags.append("blob")

        recorded = entry.get("sha256")
        if recorded is None:
            warnings.append(f"{label} 台账未记录 sha256（本次算出 {sha256}）")
            if update:
                entry["sha256"] = sha256
                changed = True
        elif recorded != sha256:
            errors.append(f"{label} sha256 不符：台账 {recorded} 实际 {sha256}")
            flags.append("sha256")

        status = entry.get("status", "?")
        if status in ("black-box", "unverified", "draft-source-unlinked"):
            notes.append(f"{label} 状态 {status} → {entry.get('action', '待处置')}")
        print(f"{'OK ' if not flags else 'BAD'} {label:<18} {size:>9}  {status:<24} {sha256[:16]}")

    if ASSETS_DIR.is_dir():
        actual = {p.name for p in ASSETS_DIR.iterdir() if p.is_file()}
        for extra in sorted(actual - listed - ALLOWLIST):
            message = f"assets/{extra} 未登记进台账"
            (errors if strict else warnings).append(message)
        for missing in sorted(listed - actual):
            errors.append(f"台账登记了 assets/{missing}，但目录里没有")

    check_lock(errors, notes)

    if update and changed:
        LEDGER.write_text(
            json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print("\n已把 sha256 写回 tools/assets-ledger.json")

    print()
    for note in notes:
        print(f"NOTE {note}")
    for warning in warnings:
        print(f"WARN {warning}")
    for error in errors:
        print(f"FAIL {error}")

    if errors:
        print(f"\n{len(errors)} 处硬错误")
        return 1
    print(f"\n台账一致（{len(listed)} 项，{len(warnings)} 条提示）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
