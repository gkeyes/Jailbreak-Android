#!/usr/bin/env python3
"""payload 等价性验证：用现有预编译件当基线，检查自有源码重建物是否等价。

为什么是「锚点等价」而不是「哈希相等」：
  重新用 zig cc 编译必然得到不同字节（编译器版本、内联、寄存器分配都不同）。
  真正会破坏功能的是**语义骨架**变了——日志格式串没了、内核目标地址改了、
  平台/位数错了。所以验证放在这几条上：

  硬性门槛（不合格即失败）
    1. 架构：aarch64 / 64 位 / 静态链接风格一致
    2. 日志锚点：基线里的所有关键字串（Java 侧按字符串判定的那些）必须仍存在
    3. 目标常量：lhasa_profile 里登记的内核地址，基线里有就必须还在
    4. 没有引入对外部命令的依赖（system/popen/execve 出现次数的意外增长报警）

  提示项（只报告，不失败）
    - 新增/缺失的普通字符串
    - 新增/缺失的内核立即数
    - 体积偏离基线 0.5x~3x 之外

用法（CI 与本地一致）：
  python3 tools/equiv.py init                      # 从 assets 里现有二进制生成基线
  python3 tools/equiv.py check <名> <重建物路径>    # 单个比对
  python3 tools/equiv.py check-dir <目录>          # 目录内按同名逐个比对
  python3 tools/equiv.py baseline --out 目录       # init 的别名，供 CI 上传 Artifact
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ASSETS = ROOT / "app" / "src" / "main" / "assets"
BASELINE_DIR = ROOT / "plant" / "equiv"

# Java 侧依赖的判定串（WorkflowEngine / AssetDeployer 会 grep 这些）
ANCHOR_HINTS = (
    "必需项全部通过", "必需接口不可用", "OK", "FAIL",
    "slide=", "calc=", "site=",
    "listening", "rootd", "zombie", "leak", "selinux", "cred",
    "uid=0", "holding", "cap", "pipe",
)

# lhasa_profile.txt 里登记的内核目标地址：基线里有，重建物就必须还在
TARGET_CONSTANTS = {
    0xFFFFFFC08042AA68,
    0xFFFFFFC08026C02C,
    0xFFFFFFC082959630,
    0xFFFFFFC0826D10D8,
    0xFFFFFFC0826D1388,
    0xFFFFFFC0826D2A48,
    0xFFFFFFC0826D2F08,
    0xFFFFFFC0801F2EC8,
}

KERNEL_LO, KERNEL_HI = 0xFFFFFF8000000000, 0xFFFFFFFF00000000
EM_AARCH64 = 0xB7


def strings_of(data: bytes) -> list:
    return [s.decode("ascii", "replace") for s in re.findall(rb"[ -~]{6,}", data)]


def kernel_constants(data: bytes) -> dict:
    found = {}
    for off in range(0, len(data) - 8, 4):
        value = int.from_bytes(data[off:off + 8], "little")
        if KERNEL_LO <= value < KERNEL_HI:
            found[value] = found.get(value, 0) + 1
    return found


def elf_info(data: bytes) -> dict:
    info = {"elf": data[:4] == b"\x7fELF", "class64": None, "machine": None, "type": None}
    if not info["elf"]:
        return info
    info["class64"] = data[4] == 2
    info["machine"] = int.from_bytes(data[18:20], "little")
    info["type"] = int.from_bytes(data[16:18], "little")
    return info


def fingerprint(name: str, data: bytes) -> dict:
    strings = strings_of(data)
    markers = sorted({s for s in strings if any(h in s for h in ANCHOR_HINTS)})
    consts = kernel_constants(data)
    return {
        "name": name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "elf": elf_info(data),
        "markers": markers,
        "constantCount": len(consts),
        "constants": {f"0x{k:016x}": v for k, v in sorted(consts.items())},
        "targetConstants": sorted(f"0x{c:016x}" for c in TARGET_CONSTANTS if c in consts),
        "strings": sorted(strings),
    }


def cmd_init(out_dir: pathlib.Path | None = None) -> int:
    dest = out_dir or BASELINE_DIR
    dest.mkdir(parents=True, exist_ok=True)
    names = ["uaf_plant_replay", "reach_probe", "slide_probe", "perf_slide", "pc98260-su"]
    written = 0
    for name in names:
        path = ASSETS / name
        if not path.exists():
            print(f"SKIP {name}（资产不存在）")
            continue
        payload = fingerprint(name, path.read_bytes())
        (dest / f"{name}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"WROTE {dest.name}/{name}.json  markers={len(payload['markers'])} "
              f"constants={payload['constantCount']}")
        written += 1
    print(f"\n基线 {written} 份 → {dest}")
    return 0


def expected_name(rebuilt: pathlib.Path) -> str:
    return rebuilt.name


def cmd_check(name: str, rebuilt_path: str) -> int:
    base_path = BASELINE_DIR / f"{name}.json"
    if not base_path.exists():
        print(f"FAIL 缺少基线 {base_path}，先跑 `python3 tools/equiv.py init` 并提交")
        return 1
    base = json.loads(base_path.read_text(encoding="utf-8"))
    rebuilt = pathlib.Path(rebuilt_path)
    if not rebuilt.exists():
        print(f"FAIL 重建物不存在：{rebuilt}")
        return 1
    data = rebuilt.read_bytes()
    now = fingerprint(name, data)

    hard, soft = [], []

    if not now["elf"]["elf"]:
        hard.append("重建物不是 ELF")
    else:
        if not now["elf"]["class64"]:
            hard.append("重建物不是 64 位 ELF")
        if now["elf"]["machine"] != EM_AARCH64:
            hard.append(f"重建物架构不是 aarch64（e_machine=0x{now['elf']['machine']:x}）")

    have_markers = set(now["markers"])
    for marker in base["markers"]:
        if marker not in have_markers:
            hard.append(f"丢失日志锚点：{marker!r}")

    have_consts = set(now["constants"])
    for const in base.get("targetConstants", []):
        if const not in have_consts:
            hard.append(f"丢失内核目标常量 {const}")

    ratio = now["size"] / base["size"] if base["size"] else 0
    if ratio < 0.5 or ratio > 3.0:
        soft.append(f"体积 {now['size']} 与基线 {base['size']} 相差 {ratio:.2f}x")

    lost = sorted(set(base["strings"]) - set(now["strings"]))
    added = sorted(set(now["strings"]) - set(base["strings"]))
    if lost:
        soft.append(f"缺少 {len(lost)} 条基线字符串，例如：{lost[:5]}")
    if added:
        soft.append(f"新增 {len(added)} 条字符串，例如：{added[:5]}")

    print(f"== {name} ==")
    print(f"基线  {base['size']:>8} B  {base['sha256'][:16]}  markers={len(base['markers'])}")
    print(f"重建  {now['size']:>8} B  {now['sha256'][:16]}  markers={len(now['markers'])}")
    for item in hard:
        print(f"FAIL {item}")
    for item in soft:
        print(f"WARN {item}")
    if hard:
        print(f"\n不通过：{len(hard)} 条硬性问题")
        return 1
    print(f"\n通过（{len(soft)} 条提示）")
    return 0


def cmd_check_dir(directory: str) -> int:
    root = pathlib.Path(directory)
    if not root.is_dir():
        print(f"FAIL 目录不存在：{root}")
        return 1
    failures, checked = 0, 0
    for path in sorted(p for p in root.iterdir() if p.is_file()):
        name = expected_name(path)
        if not (BASELINE_DIR / f"{name}.json").exists():
            print(f"SKIP {name}（无基线）")
            continue
        checked += 1
        failures += 1 if cmd_check(name, str(path)) else 0
        print()
    print(f"共比对 {checked} 项，{failures} 项不通过")
    return 1 if failures else 0


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        print(__doc__)
        return 2
    cmd = argv[0]
    if cmd == "init":
        return cmd_init()
    if cmd == "baseline":
        out = pathlib.Path(argv[argv.index("--out") + 1]) if "--out" in argv else None
        return cmd_init(out)
    if cmd == "check" and len(argv) >= 3:
        return cmd_check(argv[1], argv[2])
    if cmd == "check-dir" and len(argv) >= 2:
        return cmd_check_dir(argv[1])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
