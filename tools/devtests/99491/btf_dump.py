#!/usr/bin/env python3
"""解析原始 BTF（/sys/kernel/btf/vmlinux）并输出结构体成员偏移。

只读离线工具，用于给 99491 profile 标定结构体偏移：
  tools/devtests/99491/btf_dump.py <vmlinux.btf> --struct input_dev
  tools/devtests/99491/btf_dump.py <vmlinux.btf> --struct task_struct --json
  tools/devtests/99491/btf_dump.py <vmlinux.btf> --selftest

BTF 格式参考 include/uapi/linux/btf.h：
  header: magic(0xeb9f) u16, version u8, flags u8, hdr_len u32,
          type_off u32, type_len u32, str_off u32, str_len u32
  type:   name_off u32, info u32, size/type u32
          info: vlen=低16位, kind=(info>>24)&0x1f, kflag=(info>>31)
  STRUCT/UNION: vlen × { name_off u32, type u32, offset u32 }
          kflag=1 时 offset 低24位是 bit 偏移、高8位是 bitfield 大小
  INT:    +u32 encoding ; ARRAY: +3×u32 ; ENUM: vlen×2×u32 ; FUNC_PROTO: vlen×2×u32
"""

from __future__ import annotations

import argparse
import json
import struct
import sys

BTF_MAGIC = 0xEB9F
KIND_NAMES = {
    0: "UNKN",
    1: "INT",
    2: "PTR",
    3: "ARRAY",
    4: "STRUCT",
    5: "UNION",
    6: "ENUM",
    7: "FWD",
    8: "TYPEDEF",
    9: "VOLATILE",
    10: "CONST",
    11: "RESTRICT",
    12: "FUNC",
    13: "FUNC_PROTO",
    14: "VAR",
    15: "DATASEC",
    16: "FLOAT",
    17: "DECL_TAG",
    18: "TYPE_TAG",
    19: "ENUM64",
}

# 每种 kind 的额外固定长度（不含成员/参数等 vlen 项）
EXTRA_LEN = {
    1: 4,  # INT encoding
    3: 12,  # ARRAY
    4: 0, 5: 0,  # STRUCT / UNION 由 vlen 决定
    6: 0,  # ENUM: vlen*8
    13: 0,  # FUNC_PROTO: vlen*8
    14: 4,  # VAR linkage
    15: 12,  # DATASEC: vlen*12
    16: 0,  # FLOAT
    17: 8,  # DECL_TAG
    19: 0,  # ENUM64: vlen*12
}
VLEN_ITEM_LEN = {4: 12, 5: 12, 6: 8, 13: 8, 15: 12, 19: 12}


class BTF:
    def __init__(self, blob: bytes):
        if len(blob) < 24:
            raise ValueError("BTF 太短")
        magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from(
            "<HBBIIIII", blob, 0
        )
        if magic != BTF_MAGIC:
            raise ValueError(f"BTF magic 不对：0x{magic:04x}")
        self.version = version
        self.hdr_len = hdr_len
        type_start = hdr_len + type_off
        str_start = hdr_len + str_off
        self.type_blob = blob[type_start : type_start + type_len]
        self.str_blob = blob[str_start : str_start + str_len]
        self.types = [None]  # 1-based，0 = void
        self._parse_types()

    def string(self, off: int) -> str:
        if off < 0 or off >= len(self.str_blob):
            return ""
        end = self.str_blob.find(b"\0", off)
        if end < 0:
            end = len(self.str_blob)
        return self.str_blob[off:end].decode("utf-8", "replace")

    def _parse_types(self):
        data = self.type_blob
        pos = 0
        while pos + 12 <= len(data):
            name_off, info, size_type = struct.unpack_from("<III", data, pos)
            pos += 12
            kind = (info >> 24) & 0x1F
            vlen = info & 0xFFFF
            kflag = (info >> 31) & 1
            entry = {
                "name": self.string(name_off),
                "kind": kind,
                "kind_name": KIND_NAMES.get(kind, f"KIND{kind}"),
                "vlen": vlen,
                "kflag": kflag,
                "size_type": size_type,
                "members": None,
                "extra": None,
            }
            if kind == 3:  # ARRAY
                elem_type, index_type, nelems = struct.unpack_from("<III", data, pos)
                pos += 12
                entry["elem_type"] = elem_type
                entry["index_type"] = index_type
                entry["array_count"] = nelems
            elif kind in (4, 5):  # STRUCT / UNION
                members = []
                for _ in range(vlen):
                    m_name, m_type, m_off = struct.unpack_from("<III", data, pos)
                    pos += 12
                    if kflag:
                        bit_off = m_off & 0xFFFFFF
                        bit_size = (m_off >> 24) & 0xFF
                    else:
                        bit_off = m_off
                        bit_size = 0
                    members.append(
                        {
                            "name": self.string(m_name),
                            "type": m_type,
                            "bit_offset": bit_off,
                            "bitfield_size": bit_size,
                        }
                    )
                entry["members"] = members
            elif kind in VLEN_ITEM_LEN:
                item = VLEN_ITEM_LEN[kind]
                pos += item * vlen
            else:
                pos += EXTRA_LEN.get(kind, 0)
            self.types.append(entry)

    def type_of(self, type_id: int):
        if type_id <= 0 or type_id >= len(self.types):
            return None
        return self.types[type_id]

    def size_of(self, type_id: int, depth: int = 0) -> int:
        entry = self.type_of(type_id)
        if entry is None or depth > 8:
            return 0
        kind = entry["kind"]
        if kind in (1, 4, 5, 6, 16, 19):  # INT/STRUCT/UNION/ENUM/FLOAT/ENUM64
            return entry["size_type"]
        if kind == 3:  # ARRAY
            return entry["array_count"] * self.size_of(entry["elem_type"], depth + 1)
        if kind in (2, 8, 9, 10, 11, 18):  # PTR/TYPEDEF/CV/TYPE_TAG
            return 8 if kind == 2 else self.size_of(entry["size_type"], depth + 1)
        return 0

    def resolve_name(self, type_id: int) -> str:
        entry = self.type_of(type_id)
        if entry is None:
            return "void"
        if entry["kind"] == 2:
            return self.resolve_name(entry["size_type"]) + " *"
        if entry["kind"] in (8, 9, 10, 11, 18):
            return self.resolve_name(entry["size_type"])
        if entry["kind"] == 3:
            return self.resolve_name(entry["elem_type"]) + "[]"
        if entry["kind"] in (4, 5):
            prefix = "struct " if entry["kind"] == 4 else "union "
            return prefix + (entry["name"] or "<anon>")
        return entry["name"] or entry["kind_name"]


def find_struct(btf: BTF, name: str):
    want = name.replace("struct ", "").replace("union ", "")
    matches = [
        (index, entry)
        for index, entry in enumerate(btf.types)
        if entry and entry["kind"] in (4, 5) and entry["name"] == want
    ]
    if not matches:
        return None
    # 优先取 size 最大的（内核里可能有同名 fwd/重复定义）
    return max(matches, key=lambda item: item[1]["size_type"])


def describe_member(
    btf: BTF, member, base_bits: int, path: str, out: list, depth: int
):
    entry = btf.type_of(member["type"])
    name = member["name"] or "<anon>"
    full = f"{path}.{name}" if path else name
    bits = base_bits + member["bit_offset"]
    out.append(
        {
            "path": full,
            "bit_offset": bits,
            "byte_offset": bits // 8,
            "bitfield_size": member["bitfield_size"],
            "type": btf.resolve_name(member["type"]),
            "declared_type": member["type"],
        }
    )
    if entry is None or depth >= 1:
        return
    # 展开一层的嵌套结构体（例如 work_struct.func / input_handle.dev）
    kind = entry["kind"]
    if kind in (4, 5) and entry["vlen"] <= 64:
        for child in entry["members"]:
            describe_member(btf, child, bits, full, out, depth + 1)


def dump_struct(btf: BTF, name: str, expand: bool = True):
    found = find_struct(btf, name)
    if not found:
        return None
    index, entry = found
    out = []
    for member in entry["members"]:
        describe_member(btf, member, 0, "", out, 0)
    # 重新按一层/两层输出（describe_member 内部已展开一层）
    return {
        "struct": entry["name"],
        "size": entry["size_type"],
        "type_id": index,
        "members": out,
    }


def self_test() -> int:
    """手工构造一个最小 BTF，验证解析器/偏移展开。"""
    strings = b"\0int\0inner\0a\0b\0outer\0x\0in\0name\0"
    str_off = {}
    cursor = 0
    for part in strings.split(b"\0"):
        str_off[part.decode()] = cursor
        cursor += len(part) + 1

    def s(name: str) -> int:
        return str_off[name]

    types = b""
    # type 1: int (size 4)
    types += struct.pack("<III", s("int"), (1 << 24) | 0, 4) + struct.pack("<I", 0)
    # type 2: struct inner { int a; int b; } size 8
    inner_members = struct.pack("<III", s("a"), 1, 0) + struct.pack("<III", s("b"), 1, 32)
    types += struct.pack("<III", s("inner"), (4 << 24) | 2, 8) + inner_members
    # type 3: struct outer { int x; struct inner in; char name[4]; } size 4+8+4 = 16
    # name[] 用 int 数组近似（char 未定义），只验证偏移
    outer_members = (
        struct.pack("<III", s("x"), 1, 0)
        + struct.pack("<III", s("in"), 2, 32)
        + struct.pack("<III", s("name"), 1, 96)
    )
    types += struct.pack("<III", s("outer"), (4 << 24) | 3, 16) + outer_members

    header_len = 24
    type_len = len(types)
    type_off = 0
    str_off_val = type_off + type_len
    blob = struct.pack(
        "<HBBIIIII", BTF_MAGIC, 1, 0, header_len, type_off, type_len, str_off_val, len(strings)
    ) + types + strings

    btf = BTF(blob)
    dumped = dump_struct(btf, "outer")
    assert dumped and dumped["size"] == 16, dumped
    by_path = {m["path"]: m for m in dumped["members"]}
    checks = [
        ("x", 0),
        ("in", 4),
        ("in.a", 4),
        ("in.b", 8),
        ("name", 12),
    ]
    ok = True
    for path, want in checks:
        got = by_path.get(path)
        if got is None or got["byte_offset"] != want:
            print(f"[selftest] FAIL {path}: got={got} want_off={want}")
            ok = False
    print(f"[selftest] struct outer size={dumped['size']} members={len(dumped['members'])}")
    print("[selftest] " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("btf", nargs="?", help="原始 BTF 文件（/sys/kernel/btf/vmlinux）")
    parser.add_argument("--struct", action="append", default=[], help="要导出的结构体名")
    parser.add_argument("--no-expand", action="store_true", help="只输出一层成员")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    parser.add_argument("--selftest", action="store_true", help="用内置假 BTF 自检")
    args = parser.parse_args()

    if args.selftest:
        return self_test()
    if not args.btf:
        parser.print_help()
        return 2
    try:
        with open(args.btf, "rb") as handle:
            btf = BTF(handle.read())
    except Exception as error:  # noqa: BLE001
        print(f"解析 BTF 失败：{error}", file=sys.stderr)
        return 2
    print(f"BTF version={btf.version} types={len(btf.types) - 1}", file=sys.stderr if args.json else sys.stdout)
    results = {}
    for name in args.struct:
        dumped = dump_struct(btf, name, expand=not args.no_expand)
        if dumped is None:
            print(f"MISS struct {name}", file=sys.stderr)
            continue
        results[name] = dumped
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0 if len(results) == len(args.struct) else 1
    for name, dumped in results.items():
        print(f"\n== struct {dumped['struct']} (size=0x{dumped['size']:x}) ==")
        for member in dumped["members"]:
            bits = ""
            if member["bitfield_size"]:
                bits = f" bitfield={member['bitfield_size']}"
            print(
                f"  +0x{member['byte_offset']:<4x} {member['path']:<40s} "
                f"{member['type']}{bits}"
            )
    return 0 if len(results) == len(args.struct) else 1


if __name__ == "__main__":
    sys.exit(main())
