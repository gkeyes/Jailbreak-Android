#!/usr/bin/env python3
"""CVE-2026-99491 补丁状态静态判定（离线，只读）。

判据来自上游修复提交 ef32877368a7（"HID: wacom: Fix Use-After-Free in
wacom_intuos_pad"）：

- 修复版在 `wacom_remove_shared_data()` 中新增 `synchronize_rcu()`（新调用）。
  这是最稳的二进制特征：未修复版该函数里没有对 `synchronize_rcu` 的调用。
- 修复版新增 `wacom_report_touch_mute()` 辅助函数，`wacom_intuos_pad()` 改调它；
  但静态函数可能被内联，所以只作为辅助证据。

输入：# vmlinux-to-elf 还原后的 ELF（或任何带函数符号的 aarch64 ELF）。

用法：
  tools/devtests/99491/patch_check.py <kernel.elf>            # 判定并打印
  tools/devtests/99491/patch_check.py <kernel.elf> --json     # 机器可读
  tools/devtests/99491/patch_check.py <kernel.elf> --dump-calls wacom_intuos_pad

退出码：0 未修补（漏洞可用）/ 1 已修补 / 2 未知（符号缺失或无法判定）。
"""

from __future__ import annotations

import argparse
import json
import sys

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:  # pragma: no cover
    print("缺少 pyelftools：python3 -m pip install pyelftools", file=sys.stderr)
    raise SystemExit(2)


def load_symbols(path: str):
    """返回 {name: (addr, size, shndx)}，只取 STT_FUNC。"""
    funcs = {}
    with open(path, "rb") as handle:
        elf = ELFFile(handle)
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if symbol["st_info"]["type"] != "STT_FUNC":
                    continue
                name = symbol.name
                if not name:
                    continue
                addr = int(symbol["st_value"])
                size = int(symbol["st_size"])
                if addr == 0:
                    continue
                # 同名符号保留首个（kallsyms 里偶有重复别名）
                funcs.setdefault(name, (addr, size, int(symbol["st_shndx"] or 0)))
    return funcs


def section_for(elf_path: str, symbol_addr: int, size: int):
    """返回 (file_offset, data, base_addr)；仅支持 PROGBITS 且可文件映射的段。"""
    with open(elf_path, "rb") as handle:
        elf = ELFFile(handle)
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            start = int(segment["p_vaddr"])
            filesz = int(segment["p_filesz"])
            if start <= symbol_addr < start + filesz:
                offset = int(segment["p_offset"]) + (symbol_addr - start)
                length = max(size, 4)
                if symbol_addr + length > start + filesz:
                    length = start + filesz - symbol_addr
                return offset, length
        return None


def disassemble(elf_path: str, func_name: str):
    """返回 [(addr, mnemonic, op_str)]，失败返回 None。"""
    try:
        import capstone
        from capstone import Cs, CS_ARCH_ARM64
    except ImportError:  # pragma: no cover
        return None

    symbols = load_symbols(elf_path)
    if func_name not in symbols:
        return None
    addr, size, _ = symbols[func_name]
    if size <= 0:
        size = 0x400
    region = section_for(elf_path, addr, size)
    if region is None:
        return None
    file_offset, length = region
    with open(elf_path, "rb") as handle:
        handle.seek(file_offset)
        code = handle.read(length)
    md = Cs(CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return [(ins.address, ins.mnemonic, ins.op_str) for ins in md.disasm(code, addr)]


def branch_targets(instructions):
    """收集所有 b/bl 的目标地址。"""
    targets = set()
    for _, mnemonic, op_str in instructions:
        if mnemonic not in ("b", "bl", "br", "blr"):
            continue
        op = op_str.split(",")[0].strip()
        if op.startswith("#"):
            op = op[1:]
        try:
            if op.startswith("0x") or op.isdigit():
                targets.add(int(op, 0))
        except ValueError:
            continue
    return targets


def calls_to(instructions, target_addr: int) -> list:
    hits = []
    for addr, mnemonic, op_str in instructions:
        if mnemonic not in ("b", "bl", "br", "blr"):
            continue
        op = op_str.split(",")[0].strip().lstrip("#")
        try:
            if int(op, 0) == target_addr:
                hits.append((addr, mnemonic, op_str))
        except ValueError:
            continue
    return hits


def resolve_call_hits(instructions, target_names, targets):
    """对函数内所有直接调用，按目标地址匹配一批候选符号名。"""
    resolved = {}
    for target_name in target_names:
        if target_name not in targets:
            continue
        hits = calls_to(instructions, targets[target_name][0])
        if hits:
            resolved[target_name] = hits
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", help="vmlinux-to-elf 产出的 ELF")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--dump-calls", metavar="FUNC", help="打印指定函数的直接调用")
    parser.add_argument(
        "--require-symbols",
        default="wacom_remove_shared_data,wacom_intuos_pad",
        help="必须存在的函数符号（逗号分隔）",
    )
    args = parser.parse_args()

    try:
        symbols = load_symbols(args.elf)
    except Exception as error:  # noqa: BLE001
        print(f"读取 ELF 失败：{error}", file=sys.stderr)
        return 2

    required = [name for name in args.require_symbols.split(",") if name]
    missing = [name for name in required if name not in symbols]

    targets = {}
    for name in (
        "synchronize_rcu",
        "input_report_switch",
        "input_sync",
        "wacom_report_touch_mute",
    ):
        if name in symbols:
            targets[name] = symbols[name]

    if args.dump_calls:
        instructions = disassemble(args.elf, args.dump_calls)
        if instructions is None:
            print(f"无法反汇编 {args.dump_calls}", file=sys.stderr)
            return 2
        for addr, mnemonic, op_str in instructions:
            if mnemonic in ("b", "bl"):
                print(f"0x{addr:x}: {mnemonic} {op_str}")
        return 0

    evidence = {
        "elf": args.elf,
        "missing_symbols": missing,
        "wacom_remove_shared_data_calls_synchronize_rcu": None,
        "wacom_intuos_pad_calls_wacom_report_touch_mute": None,
        "wacom_intuos_pad_calls_input_report_switch_and_sync": None,
    }

    if "wacom_remove_shared_data" not in symbols:
        print("PATCH_STATE=unknown reason=missing_symbol:wacom_remove_shared_data")
        if args.json:
            print(json.dumps(evidence, ensure_ascii=False, indent=2))
        return 2

    instructions = disassemble(args.elf, "wacom_remove_shared_data")
    if instructions is None:
        print("PATCH_STATE=unknown reason=cannot_disassemble")
        if args.json:
            print(json.dumps(evidence, ensure_ascii=False, indent=2))
        return 2

    calls = resolve_call_hits(
        instructions,
        ["synchronize_rcu"],
        {k: v for k, v in symbols.items() if k == "synchronize_rcu"},
    )
    has_synchronize = bool(calls.get("synchronize_rcu"))
    evidence["wacom_remove_shared_data_calls_synchronize_rcu"] = has_synchronize

    supporting = []
    pad = disassemble(args.elf, "wacom_intuos_pad")
    if pad is not None:
        if "wacom_report_touch_mute" in symbols:
            muted = calls_to(pad, symbols["wacom_report_touch_mute"][0])
            evidence["wacom_intuos_pad_calls_wacom_report_touch_mute"] = bool(muted)
            if muted:
                supporting.append("calls:wacom_report_touch_mute")
        if "input_report_switch" in symbols and "input_sync" in symbols:
            has_switch = bool(calls_to(pad, symbols["input_report_switch"][0]))
            has_sync = bool(calls_to(pad, symbols["input_sync"][0]))
            evidence["wacom_intuos_pad_calls_input_report_switch_and_sync"] = (
                has_switch and has_sync
            )

    verdict = "patched" if has_synchronize else "unpatched"
    if missing:
        # 必需符号缺失时不能断言未修补
        verdict = "unknown"
        supporting.append("missing:" + ",".join(missing))

    evidence["verdict"] = verdict
    evidence["supporting"] = supporting
    if args.json:
        print(json.dumps(evidence, ensure_ascii=False, indent=2))
    else:
        print(f"kernel            : {args.elf}")
        print(f"wacom_remove_shared_data -> synchronize_rcu : {has_synchronize}")
        print(
            "wacom_intuos_pad -> wacom_report_touch_mute : "
            f"{evidence['wacom_intuos_pad_calls_wacom_report_touch_mute']}"
        )
        print(
            "wacom_intuos_pad -> input_report_switch+sync: "
            f"{evidence['wacom_intuos_pad_calls_input_report_switch_and_sync']}"
        )
        print(f"PATCH_STATE={verdict}")
    return 0 if verdict == "unpatched" else 1 if verdict == "patched" else 2


if __name__ == "__main__":
    sys.exit(main())
