#!/usr/bin/env python3
"""从唯一事实源 lhasa_99491_profile.json 校验并生成 plant/99491/profile.h。

CVE-2026-99491 real_cred 链把**全部** build-specific 常量（内核符号、结构偏移、
KCFI 类型 id、spray 几何、KSU 路径）放在一个扁平 JSON profile 里；本工具负责：

  1. --check：按 schema 做 fail-closed 校验——
       * 字段完备 / 类型正确 / 无未知键（calibration 等元数据白名单除外）；
       * release 精确匹配 lhasa_profile.txt 里的已标定 release（或 --release 指定）；
       * 8 个 sym 落在 [stext,etext)（text）或内核数据窗口（data），VA 规范、对齐；
       * 所有偏移在 [0, 对应 size) 内，几何关系自洽；
       * 2 MiB KASLR 对齐（JSON 可选 kaslr_align，缺省 2 MiB）。
  2. --gen：把校验后的值生成 plant/99491/profile.h（C 常量 + struct +
     cve99491_profile_builtin()）。生成文件禁止手改，改 JSON 后重跑本工具。

用法：
  tools/99491/gen_profile.py --check                 # 校验 app/src/main/assets/lhasa_99491_profile.json
  tools/99491/gen_profile.py --gen                   # 校验后生成 plant/99491/profile.h
  tools/99491/gen_profile.py --check --gen --json PATH --out PATH
  tools/99491/gen_profile.py --check --json plant/99491/example-profile.json \\
      --allow-unknown-release --allow-unverified     # 自检占位 profile

退出码：0 通过；1 校验失败；2 用法/IO 错误。

schema 出处：Yunnijian/CVE-2026-99491 tools/realcred/profile.h（GPL-2.0-only，
repo commit 1923ac893d582e4b87b748ea033be4a004d894b1）；本移植新增 stext/etext/
kaslr_align/ksu_backend/hal_patch_*/selinux_policycap 等可选项，见
tools/99491/README.md。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_JSON = ROOT / "app" / "src" / "main" / "assets" / "lhasa_99491_profile.json"
DEFAULT_REF = ROOT / "app" / "src" / "main" / "assets" / "lhasa_profile.txt"
DEFAULT_OUT = ROOT / "plant" / "99491" / "profile.h"

KASLR_DEFAULT = 0x200000  # 2 MiB：本机 KASLR 粒度（docs/99491-test-plan.md §7）
TEXT_SYMS = ("sym_uhid_worker", "sym_ihe_default", "sym_inject_event")
DATA_SYMS = (
    "sym_selinux_state",
    "sym_init_cred",
    "sym_per_cpu_offset",
    "sym_runqueues",
    "sym_input_dev_list",
)
# 内核数据窗口上界（相对 stext）：本机 selinux_state 在 stext+43 MiB，留足余量。
DATA_WINDOW = 0x20000000
KERNEL_VA_MIN = 0xFFFF000000000000

U32 = ("num", 4)
U64 = ("num", 8)


def STR(cap: int):
    return ("str", cap)


# (JSON key, C kind, 分组注释)。顺序即生成 struct 的字段顺序。
FIELDS = [
    # identity
    ("format", U32, "identity"),
    ("cve", STR(32), "identity"),
    ("release", STR(128), "identity"),
    ("arch", STR(32), "identity"),
    ("label", STR(96), "identity"),
    ("verified", U32, "identity"),
    ("page_size", U32, "identity"),
    # link-time kernel symbols (VAs; boot slide added at runtime)
    ("sym_uhid_worker", U64, "link-time kernel symbols"),
    ("sym_ihe_default", U64, "link-time kernel symbols"),
    ("sym_inject_event", U64, "link-time kernel symbols"),
    ("sym_selinux_state", U64, "link-time kernel symbols"),
    ("sym_init_cred", U64, "link-time kernel symbols"),
    ("sym_per_cpu_offset", U64, "link-time kernel symbols"),
    ("sym_runqueues", U64, "link-time kernel symbols"),
    ("sym_input_dev_list", U64, "link-time kernel symbols"),
    # leak selectors / KCFI ids
    ("cred_site_low21", U64, "leak selectors and KCFI type ids"),
    ("kcfi_handle_events", U64, "leak selectors and KCFI type ids"),
    ("kcfi_handler_event", U64, "leak selectors and KCFI type ids"),
    # layout selectors inside the anchor input_buf
    ("c_off_h", U32, "layout selectors (fake objects in the anchor input_buf)"),
    ("c_off_p", U32, "layout selectors (fake objects in the anchor input_buf)"),
    ("c_off_d", U32, "layout selectors (fake objects in the anchor input_buf)"),
    ("c_off_e", U32, "layout selectors (fake objects in the anchor input_buf)"),
    ("c_off_scratch", U32, "layout selectors (fake objects in the anchor input_buf)"),
    ("c_off_fake", U32, "layout selectors (fake objects in the anchor input_buf)"),
    # task/rq layout
    ("ts_off_cred", U32, "task_struct / runqueue layout"),
    ("ts_off_real_cred", U32, "task_struct / runqueue layout"),
    ("ts_off_comm", U32, "task_struct / runqueue layout"),
    ("rq_off_curr", U32, "task_struct / runqueue layout"),
    ("rq_off_idle", U32, "task_struct / runqueue layout"),
    # uhid_device layout
    ("uhid_input_buf_data_off", U32, "uhid_device layout"),
    ("uhid_waitq_head_off", U32, "uhid_device layout"),
    ("uhid_outq_off", U32, "uhid_device layout"),
    ("uhid_worker_off", U32, "uhid_device layout"),
    ("uhid_worker_func_off", U32, "uhid_device layout"),
    ("uhid_serial_read_base_off", U32, "uhid_device layout"),
    ("uhid_waitq_self", U32, "uhid_device layout"),
    # input_dev / input_handle / input_handler layout
    ("input_dev_size", U32, "input_dev / input_handle / input_handler layout"),
    ("input_dev_evbit_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_dev_swbit_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_dev_grab_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_dev_event_lock_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_dev_num_vals_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_dev_max_vals_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_dev_vals_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_dev_absbit_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_dev_absinfo_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_dev_event_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_dev_hlist_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_dev_inhibited_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_dev_id_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_dev_node_off", U32, "input_dev / input_handle / input_handler layout"),
    ("absinfo_size", U32, "input_dev / input_handle / input_handler layout"),
    ("input_handle_size", U32, "input_dev / input_handle / input_handler layout"),
    ("input_handle_dev_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_handle_handler_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_handle_events_off", U32, "input_dev / input_handle / input_handler layout"),
    ("input_handler_event_off", U32, "input_dev / input_handle / input_handler layout"),
    # cred layout
    ("cred_req", U32, "cred layout"),
    ("cred_bytes", U32, "cred layout"),
    ("cred_uid_off", U32, "cred layout"),
    ("cred_euid_off", U32, "cred layout"),
    ("cred_securebits_off", U32, "cred layout"),
    ("cred_cap_permitted_off", U32, "cred layout"),
    ("cred_cap_effective_off", U32, "cred layout"),
    ("cred_cap_bset_off", U32, "cred layout"),
    ("cred_security_off", U32, "cred layout"),
    ("cred_user_off", U32, "cred layout"),
    ("cred_user_ns_off", U32, "cred layout"),
    ("cred_rcu_off", U32, "cred layout"),
    ("cred_rcu_size", U32, "cred layout"),
    # selinux_state
    ("selinux_enforcing_off", U32, "selinux_state layout and target domain"),
    ("selinux_initialized_off", U32, "selinux_state layout and target domain"),
    ("selinux_restore_value", U32, "selinux_state layout and target domain"),
    ("selinux_shell_domain", STR(64), "selinux_state layout and target domain"),
    # capability ABI
    ("cap_last_cap", U32, "capability ABI"),
    ("cap_full_mask", U64, "capability ABI"),
    # spray geometry
    ("spray_pairs", U32, "spray geometry and reclaim defaults"),
    ("spray_len", U32, "spray geometry and reclaim defaults"),
    ("spray_count", U32, "spray geometry and reclaim defaults"),
    ("spray_spread_ms", U32, "spray geometry and reclaim defaults"),
    ("spray_burst_min", U32, "spray geometry and reclaim defaults"),
    ("spray_burst_step", U32, "spray geometry and reclaim defaults"),
    ("spray_wait_ms", U32, "spray geometry and reclaim defaults"),
    ("spray_hold_wait_ms", U32, "spray geometry and reclaim defaults"),
    ("spray_fill", U32, "spray geometry and reclaim defaults"),
    ("spray_trigger_rounds", U32, "spray geometry and reclaim defaults"),
    ("spray_respray_rounds", U32, "spray geometry and reclaim defaults"),
    ("spray_cpu", U32, "spray geometry and reclaim defaults"),
    ("spray_skb_req", U32, "spray geometry and reclaim defaults"),
    # PackageManager binder ABI
    ("pm_binder_lib", STR(64), "PackageManager binder ABI"),
    ("pm_service", STR(64), "PackageManager binder ABI"),
    ("pm_interface", STR(128), "PackageManager binder ABI"),
    ("pm_txn_get_application_info", U32, "PackageManager binder ABI"),
    ("pm_txn_get_package_info", U32, "PackageManager binder ABI"),
    ("pm_user_id", U32, "PackageManager binder ABI"),
    # KernelSU manager / paths
    ("ksu_manager", STR(96), "KernelSU manager, paths and loader strings"),
    ("ksu_manager_apk_root", STR(96), "KernelSU manager, paths and loader strings"),
    ("ksu_workdir", STR(192), "KernelSU manager, paths and loader strings"),
    ("ksu_module_name", STR(64), "KernelSU manager, paths and loader strings"),
    ("ksu_ksud_name", STR(64), "KernelSU manager, paths and loader strings"),
    ("ksu_ksud_path", STR(192), "KernelSU manager, paths and loader strings"),
    ("ksu_ksu_bin_dir", STR(192), "KernelSU manager, paths and loader strings"),
    ("ksu_modules_dir", STR(192), "KernelSU manager, paths and loader strings"),
    ("ksu_lib_subpath", STR(96), "KernelSU manager, paths and loader strings"),
    ("ksu_lib_subpath_v8a", STR(96), "KernelSU manager, paths and loader strings"),
    # ---- 本移植新增：生成时可由 JSON 覆盖，缺省值见 DEFAULTS ----
    ("stext", U64, "port additions (calibration cross-checks)"),
    ("etext", U64, "port additions (calibration cross-checks)"),
    ("kaslr_align", U32, "port additions (calibration cross-checks)"),
    ("selinux_policycap", U64, "port additions (calibration cross-checks)"),
    ("ksu_backend", STR(32), "port additions (KSU loader selection)"),
    ("hal_patch_enable", U32, "port additions (vendor HAL repair switch)"),
    ("hal_patch_domains", STR(192), "port additions (vendor HAL repair switch)"),
]

OPTIONAL = {
    "stext",
    "etext",
    "kaslr_align",
    "selinux_policycap",
    "ksu_backend",
    "hal_patch_enable",
    "hal_patch_domains",
}
IGNORED = {"calibration"}
DEFAULTS = {
    "kaslr_align": KASLR_DEFAULT,
    "selinux_policycap": 0,
    "ksu_backend": "auto",
    "hal_patch_enable": 1,
    "hal_patch_domains": "hal_audio_default hal_camera_default",
}
BACKENDS = ("auto", "asset", "manager")

FIELD_NAMES = [f[0] for f in FIELDS]
FIELD_SPEC = {f[0]: f[1] for f in FIELDS}
FIELD_GROUP = {f[0]: f[2] for f in FIELDS}

ABS_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
WORKDIR_RE = re.compile(r"^/data/local/tmp/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
KSUSD_PATH_RE = re.compile(r"^/data/(?:local/tmp|adb)/[A-Za-z0-9._-]+$")
RELEASE_RE = re.compile(r"^6\.18\.\d+-android\d+-[0-9a-z]+-g[0-9a-f]{6,}-ab[a-z]*\d+-4k$")
PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.]*$")
DOMAIN_RE = re.compile(r"^u:r:[A-Za-z0-9_.]+:s0$")
HAL_DOMAIN_RE = re.compile(r"^[a-z][a-z0-9_]*$")
HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]{1,16}$")


class CheckError(Exception):
    pass


def fail(msg: str) -> None:
    raise CheckError(msg)


def warn(msg: str) -> None:
    print(f"WARN {msg}")


def info(msg: str) -> None:
    print(f"     {msg}")


def relpath(path: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def read_reference(path: pathlib.Path) -> dict:
    """解析 lhasa_profile.txt：release= 行 -> 字段 dict。"""
    if not path.exists():
        fail(f"缺少参考常量表 {relpath(path)}（release→stext/etext 来源）")
    lines = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line.startswith("release="):
            continue
        fields = {}
        release = ""
        for token in line.split():
            if token.startswith("release="):
                release = token[len("release="):]
            elif "=" in token:
                key, _, value = token.partition("=")
                fields[key] = value
        if release:
            lines[release] = fields
    if not lines:
        fail(f"{relpath(path)} 里没有 release= 行")
    return lines


def parse_num(key: str, value) -> int:
    if isinstance(value, bool):
        fail(f"{key}: 布尔值不是数字")
    if isinstance(value, int):
        n = value
    elif isinstance(value, str):
        try:
            n = int(value, 0)
        except ValueError:
            fail(f"{key}: 不是数字或 0x 十六进制字符串：{value!r}")
    else:
        fail(f"{key}: 需要数字或 0x 十六进制字符串，得到 {type(value).__name__}")
    if n < 0:
        fail(f"{key}: 不允许负数 ({n})")
    return n


def parse_value(key: str, value, kind):
    if kind[0] == "str":
        if not isinstance(value, str):
            fail(f"{key}: 需要字符串，得到 {type(value).__name__}")
        cap = kind[1]
        try:
            raw = value.encode("utf-8")
        except UnicodeEncodeError:
            fail(f"{key}: 不是合法 UTF-8")
        if not raw:
            fail(f"{key}: 空字符串")
        if b"\x00" in raw or b"\n" in raw or b"\r" in raw:
            fail(f"{key}: 不允许 NUL/换行")
        if len(raw) >= cap:
            fail(f"{key}: 太长（{len(raw)} 字节，C 数组容量 {cap}）")
        return value
    n = parse_num(key, value)
    width = kind[1]
    if n > (1 << (8 * width)) - 1:
        fail(f"{key}: 超出 {width * 8} 位范围 ({n:#x})")
    return n


def load_json(path: pathlib.Path) -> tuple[dict, bytes]:
    if not path.exists():
        fail(f"缺少 profile JSON：{relpath(path)}")
    raw = path.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"{relpath(path)} 不是合法 JSON：{exc}")
    if not isinstance(data, dict):
        fail(f"{relpath(path)} 顶层必须是 JSON object")
    return data, raw


def check_values(data: dict, opts) -> dict:
    """类型/范围/schema 校验，返回规范化后的 {key: value}。"""
    values = {}
    missing = [k for k in FIELD_NAMES if k not in OPTIONAL and k not in data]
    if missing:
        fail("缺字段：" + ", ".join(missing))
    for key, kind, _group in FIELDS:
        if key not in data:
            continue
        values[key] = parse_value(key, data[key], kind)

    unknown = [k for k in data if k not in FIELD_SPEC and k not in IGNORED]
    if unknown and not opts.allow_extra:
        fail("未知字段（防止拼写错误）：" + ", ".join(sorted(unknown)))
    if unknown:
        warn("忽略未知字段：" + ", ".join(sorted(unknown)))

    # ---- identity ----
    if values["format"] != 1:
        fail(f"format 必须是 1，得到 {values['format']}")
    if values["cve"] != "CVE-2026-99491":
        fail(f"cve 必须是 CVE-2026-99491，得到 {values['cve']!r}")
    if values["arch"] not in ("arm64", "aarch64"):
        fail(f"arch 不支持：{values['arch']!r}（只认 arm64/aarch64）")
    if values["page_size"] not in (4096, 16384, 65536):
        fail(f"page_size 不合理：{values['page_size']}")
    if values["verified"] not in (0, 1):
        fail(f"verified 必须是 0/1，得到 {values['verified']}")
    if values["verified"] == 0:
        msg = "verified=0（标定未完成全链验收，禁止进入发布通道）"
        if opts.require_verified:
            fail(msg)
        warn(msg)

    release = values["release"]
    if not RELEASE_RE.match(release):
        warn(f"release 形态不像本机 6.18.21 build：{release!r}")
    if opts.release and release != opts.release:
        fail(f"release 不匹配：profile={release} 期望={opts.release}")

    # ---- reference: release -> stext/etext ----
    ref = read_reference(opts.reference)
    if release not in ref:
        msg = f"release {release} 不在 {relpath(opts.reference)} 的已标定列表里"
        if not opts.allow_unknown_release:
            fail(msg + "（确实要跳过请加 --allow-unknown-release）")
        warn(msg)
        ref_text = None
    else:
        ref_text = ref[release]

    stext = values.get("stext")
    etext = values.get("etext")
    if ref_text:
        try:
            ref_stext = int(ref_text["stext"], 0)
            ref_etext = int(ref_text["etext"], 0)
        except (KeyError, ValueError):
            fail(f"参考表 {release} 行缺少 stext/etext")
        if stext is not None and stext != ref_stext:
            fail(f"stext={stext:#x} 与参考表 {ref_stext:#x} 不一致")
        if etext is not None and etext != ref_etext:
            fail(f"etext={etext:#x} 与参考表 {ref_etext:#x} 不一致")
        stext, etext = ref_stext, ref_etext
        values["stext"] = stext
        values["etext"] = etext
    elif stext is None or etext is None:
        warn("无法从参考表取得 stext/etext，跳过 text 区间校验")
        stext = etext = 0
        values["stext"] = 0
        values["etext"] = 0

    # ---- KASLR ----
    kaslr = values.get("kaslr_align", KASLR_DEFAULT)
    if kaslr & (kaslr - 1) or kaslr < 0x1000 or kaslr > 0x40000000:
        fail(f"kaslr_align 必须是 4096..1GiB 的 2 的幂，得到 {kaslr:#x}")
    values["kaslr_align"] = kaslr

    # ---- 符号地址 ----
    def check_va(key: str) -> int:
        va = values[key]
        if va < KERNEL_VA_MIN:
            fail(f"{key}={va:#x} 不是内核态虚拟地址")
        if va & 3:
            fail(f"{key}={va:#x} 未按 4 字节对齐")
        if va == 0xFFFFFFFFFFFFFFFF:
            fail(f"{key} 是无效地址")
        return va

    if stext:
        if stext < KERNEL_VA_MIN:
            fail(f"stext={stext:#x} 不是内核态虚拟地址")
        # stext/etext 是链接期地址，本身不要求 2 MiB 对齐；2 MiB 对齐的是
        # KASLR slide（运行时 - 链接期），见下面的 calibration.slide 校验。
        if not (stext < etext <= stext + 64 * 1024 * 1024):
            fail(f"stext/etext 区间不合理：{stext:#x}..{etext:#x}")
        for key in TEXT_SYMS:
            va = check_va(key)
            if not (stext <= va < etext):
                fail(f"{key}={va:#x} 不在 .text [{stext:#x},{etext:#x}) 内")
        for key in DATA_SYMS:
            va = check_va(key)
            if not (etext <= va < stext + DATA_WINDOW):
                fail(f"{key}={va:#x} 不在内核数据窗口 [{etext:#x},{stext + DATA_WINDOW:#x}) 内")
    else:
        for key in TEXT_SYMS + DATA_SYMS:
            check_va(key)

    # slide 一致性（calibration.slide 只校验，不生成）
    cal = data.get("calibration")
    if cal is not None:
        if not isinstance(cal, dict):
            fail("calibration 必须是 object")
        slide_raw = cal.get("slide")
        if slide_raw is not None:
            try:
                slide = parse_num("calibration.slide", slide_raw)
            except CheckError:
                if isinstance(slide_raw, str) and not slide_raw.startswith("0x"):
                    fail("calibration.slide 需要 0x 十六进制字符串")
                raise
            if slide % kaslr:
                fail(f"calibration.slide={slide:#x} 未按 kaslr_align={kaslr:#x} 对齐")
            if slide >= 0x80000000:
                fail(f"calibration.slide={slide:#x} 超出 KASLR 合理范围")

    # ---- 非符号 u64 ----
    if not (0 < values["cred_site_low21"] < 0x200000):
        fail(f"cred_site_low21={values['cred_site_low21']} 必须落在 low-21 位窗口 [1,2MiB)")
    for key in ("kcfi_handle_events", "kcfi_handler_event"):
        if not (0 < values[key] <= 0xFFFFFFFF):
            fail(f"{key} 必须是 32 位 KCFI 类型 id，得到 {values[key]:#x}")
    values.setdefault("selinux_policycap", 0)
    if values["selinux_policycap"] > 0xFFFFFFFFFFFFFFFF:
        fail("selinux_policycap 超出 64 位")

    # ---- 布局 ----
    c_offs = [values[f"c_off_{n}"] for n in ("h", "p", "d", "e", "scratch", "fake")]
    if any(off >= 4096 for off in c_offs):
        fail("c_off_* 必须 < 4096（anchor input_buf 大小）")
    if any(a >= b for a, b in zip(c_offs, c_offs[1:])):
        warn("c_off_* 不是严格递增（h<p<d<e<scratch<fake），请人工复核")

    idev_size = values["input_dev_size"]
    if not (0x200 <= idev_size <= 0x2000) or idev_size % 8:
        fail(f"input_dev_size 不合理：{idev_size}")
    if values["c_off_d"] + idev_size > 4096:
        fail("c_off_d + input_dev_size 超出 anchor input_buf（4096）")
    if values["c_off_fake"] + values["cred_bytes"] > 4096:
        fail("c_off_fake + cred_bytes 超出 anchor input_buf（4096）")
    for key in FIELD_NAMES:
        if key.startswith("input_dev_") and key.endswith("_off"):
            if values[key] >= idev_size:
                fail(f"{key}={values[key]} 超出 input_dev_size={idev_size}")
    if values["input_dev_vals_off"] + 8 > idev_size:
        fail("input_dev_vals_off + 8 超出 input_dev_size")

    ih_size = values["input_handle_size"]
    if not (32 <= ih_size <= 512):
        fail(f"input_handle_size 不合理：{ih_size}")
    for key in ("input_handle_dev_off", "input_handle_handler_off",
                "input_handle_events_off"):
        if values[key] + 8 > ih_size:
            fail(f"{key}+8 超出 input_handle_size={ih_size}")
    if values["input_handle_handler_off"] != values["input_handle_dev_off"] + 8:
        warn("input_handle_handler_off != dev_off+8，请人工复核")
    if values["input_handle_events_off"] != values["input_handle_dev_off"] + 16:
        warn("input_handle_events_off != dev_off+16，请人工复核")
    if not (0 <= values["input_handler_event_off"] < 64) or \
            values["input_handler_event_off"] % 8:
        fail("input_handler_event_off 必须是 <64 的 8 字节对齐偏移")
    if not (16 <= values["absinfo_size"] <= 64) or values["absinfo_size"] % 4:
        fail(f"absinfo_size 不合理：{values['absinfo_size']}")

    # uhid 布局
    for key in ("uhid_input_buf_data_off", "uhid_waitq_head_off", "uhid_outq_off",
                "uhid_worker_off", "uhid_worker_func_off",
                "uhid_serial_read_base_off", "uhid_waitq_self"):
        if not (0 < values[key] < 0x8000):
            fail(f"{key}={values[key]} 超出 uhid_device 合理范围")
    if not (values["uhid_serial_read_base_off"] <= values["uhid_waitq_self"]):
        fail("uhid_serial_read_base_off 必须 <= uhid_waitq_self")
    if (values["uhid_waitq_self"] - values["uhid_serial_read_base_off"]) % 4:
        fail("(uhid_waitq_self - uhid_serial_read_base_off) 必须是 4 的倍数")
    if (values["uhid_worker_func_off"] - values["uhid_serial_read_base_off"]) % 4:
        fail("(uhid_worker_func_off - uhid_serial_read_base_off) 必须是 4 的倍数")
    if values["uhid_worker_func_off"] < values["uhid_worker_off"]:
        fail("uhid_worker_func_off 必须 >= uhid_worker_off")
    if values["uhid_outq_off"] != values["uhid_waitq_head_off"] + 4:
        warn("uhid_outq_off != uhid_waitq_head_off+4，请人工复核")

    # task / rq 布局
    for key in ("ts_off_cred", "ts_off_real_cred", "ts_off_comm",
                "rq_off_curr", "rq_off_idle"):
        if not (0 < values[key] < 0x8000) or values[key] % 4:
            fail(f"{key}={values[key]} 不合法（需要 <0x8000 且 4 字节对齐）")
    if values["ts_off_real_cred"] >= values["ts_off_cred"]:
        fail("ts_off_real_cred 必须 < ts_off_cred")
    if values["ts_off_comm"] <= values["ts_off_cred"]:
        fail("ts_off_comm 必须在 cred 之后")
    if values["rq_off_idle"] <= values["rq_off_curr"]:
        fail("rq_off_idle 必须 > rq_off_curr")

    # cred 布局
    cred_bytes = values["cred_bytes"]
    if not (64 <= cred_bytes <= 256) or cred_bytes % 8:
        fail(f"cred_bytes 不合理：{cred_bytes}")
    if values["cred_req"] < cred_bytes or values["cred_req"] - cred_bytes >= 64:
        warn(f"cred_req={values['cred_req']} 与 cred_bytes={cred_bytes} 相差过大")
    for key in ("cred_uid_off", "cred_euid_off", "cred_securebits_off",
                "cred_cap_permitted_off", "cred_cap_effective_off",
                "cred_cap_bset_off", "cred_security_off", "cred_user_off",
                "cred_user_ns_off", "cred_rcu_off"):
        if values[key] >= cred_bytes:
            fail(f"{key}={values[key]} 超出 cred_bytes={cred_bytes}")
    for key in ("cred_uid_off", "cred_euid_off", "cred_securebits_off"):
        if values[key] + 4 > cred_bytes:
            fail(f"{key}+4 超出 cred_bytes")
    for key in ("cred_cap_permitted_off", "cred_cap_effective_off",
                "cred_cap_bset_off", "cred_security_off", "cred_user_off",
                "cred_user_ns_off"):
        if values[key] + 8 > cred_bytes:
            fail(f"{key}+8 超出 cred_bytes")
        if values[key] % 8:
            fail(f"{key}={values[key]} 未按 8 字节对齐")
    if values["cred_rcu_off"] + values["cred_rcu_size"] > cred_bytes:
        fail("cred_rcu_off + cred_rcu_size 超出 cred_bytes")
    for key in ("cred_cap_effective_off", "cred_cap_permitted_off"):
        if values[key] < values["cred_securebits_off"]:
            fail(f"{key} 必须在 securebits 之后")

    # selinux_state
    if values["selinux_enforcing_off"] != 0:
        fail("selinux_enforcing_off 必须是 0（selinux_state 首个字节）")
    if values["selinux_initialized_off"] != 1:
        fail("selinux_initialized_off 必须是 1（enforcing 之后一个字节）")
    if values["selinux_restore_value"] < 1:
        fail("selinux_restore_value 必须 > 0")
    dom = values["selinux_shell_domain"]
    if not DOMAIN_RE.match(dom):
        fail(f"selinux_shell_domain 形态不合法：{dom!r}")
    if "permissive" in dom or "unconfined" in dom:
        warn("目标域看起来过于宽松，请确认这是期望的 shell 域")

    # capability ABI
    last = values["cap_last_cap"]
    if not (1 <= last <= 62):
        fail(f"cap_last_cap 不合理：{last}")
    if values["cap_full_mask"] != (1 << (last + 1)) - 1:
        fail(f"cap_full_mask={values['cap_full_mask']:#x} 与 cap_last_cap={last} 不一致")

    # spray 几何
    if not (1 <= values["spray_pairs"] <= 64):
        fail("spray_pairs 必须是 1..64")
    if values["spray_len"] < idev_size or values["spray_len"] > 4096:
        fail(f"spray_len={values['spray_len']} 不合法（需 >= input_dev_size 且 <=4096）")
    if not (1 <= values["spray_count"] <= 65536):
        fail("spray_count 必须是 1..65536")
    if values["spray_spread_ms"] > 5000:
        fail("spray_spread_ms 过大")
    if not (32 <= values["spray_burst_min"] <= 65536):
        fail("spray_burst_min 必须是 32..65536")
    if not (8 <= values["spray_burst_step"] <= 4096):
        fail("spray_burst_step 必须是 8..4096")
    if values["spray_wait_ms"] > 5000 or values["spray_hold_wait_ms"] > 10000:
        fail("spray_wait_ms/spray_hold_wait_ms 过大")
    if values["spray_fill"] > 4096:
        fail("spray_fill 过大")
    if not (1 <= values["spray_trigger_rounds"] <= 16):
        fail("spray_trigger_rounds 必须是 1..16")
    if not (1 <= values["spray_respray_rounds"] <= 64):
        fail("spray_respray_rounds 必须是 1..64")
    if values["spray_cpu"] > 63:
        fail("spray_cpu 必须是 0..63")
    if values["spray_skb_req"] and (
            values["spray_skb_req"] < values["spray_len"] or
            values["spray_skb_req"] > 8192):
        fail("spray_skb_req 必须为 0 或 [spray_len, 8192]")
    if values["spray_skb_req"]:
        aligned_len = ((values["spray_len"] + 63) // 64) * 64
        if (values["spray_skb_req"] - aligned_len) % 64 or \
                not (0 < values["spray_skb_req"] - aligned_len <= 1024):
            warn(f"spray_skb_req={values['spray_skb_req']} 与 ALIGN(spray_len,64)"
                 f"={aligned_len} 的差值不像 ALIGN(sizeof(skb_shared_info),64)，"
                 "请人工复核")

    # PackageManager
    if not (values["pm_binder_lib"] and values["pm_service"] and values["pm_interface"]):
        fail("pm_binder_lib/pm_service/pm_interface 均不能为空")
    if not values["pm_interface"].startswith("android."):
        fail("pm_interface 必须是以 android. 开头的 binder 接口名")
    for key, hi in (("pm_txn_get_application_info", 0xFFFF),
                    ("pm_txn_get_package_info", 0xFFFF)):
        if not (1 <= values[key] <= hi):
            fail(f"{key} 必须是 1..{hi}")
    if values["pm_user_id"] > 999:
        fail("pm_user_id 必须是 0..999")

    # KernelSU
    if not PKG_RE.match(values["ksu_manager"]):
        fail(f"ksu_manager 不是合法包名：{values['ksu_manager']!r}")
    if values["ksu_manager_apk_root"] != "/data/app":
        fail("ksu_manager_apk_root 必须是 /data/app")
    if not WORKDIR_RE.match(values["ksu_workdir"]):
        fail(f"ksu_workdir 必须是 /data/local/tmp/<name> 形式：{values['ksu_workdir']!r}")
    if ".." in values["ksu_workdir"]:
        fail("ksu_workdir 不允许 '..'")
    if not values["ksu_module_name"].endswith(".ko"):
        fail("ksu_module_name 必须以 .ko 结尾")
    if not values["ksu_ksud_name"]:
        fail("ksu_ksud_name 不能为空")
    if not KSUSD_PATH_RE.match(values["ksu_ksud_path"]):
        fail(f"ksu_ksud_path 必须是 /data/local/tmp/<name> 形式：{values['ksu_ksud_path']!r}")
    for key in ("ksu_ksu_bin_dir", "ksu_modules_dir"):
        if not ABS_PATH_RE.match(values[key]) or ".." in values[key]:
            fail(f"{key} 不是合法绝对路径：{values[key]!r}")
        if not values[key].startswith("/data/adb/"):
            fail(f"{key} 必须在 /data/adb/ 下：{values[key]!r}")
    for key in ("ksu_lib_subpath", "ksu_lib_subpath_v8a"):
        if not ABS_PATH_RE.match("/" + values[key]) or ".." in values[key]:
            fail(f"{key} 不是合法相对库路径：{values[key]!r}")
        if not values[key].startswith("lib/"):
            fail(f"{key} 必须位于 lib/ 下")
    if not values["ksu_lib_subpath_v8a"].endswith("libksud.so") and \
            "lib64" not in values["ksu_lib_subpath_v8a"]:
        warn("ksu_lib_subpath_v8a 不以 libksud.so 结尾，确认压缩库名")

    # port additions
    backend = values.get("ksu_backend", "auto")
    if backend not in BACKENDS:
        fail(f"ksu_backend 必须是 {'/'.join(BACKENDS)}，得到 {backend!r}")
    hal_enable = values.get("hal_patch_enable", 1)
    if hal_enable not in (0, 1):
        fail("hal_patch_enable 必须是 0/1")
    hal_domains = values.get("hal_patch_domains", "")
    if hal_enable:
        names = hal_domains.split()
        if not names or len(names) > 8:
            fail("hal_patch_enable=1 时 hal_patch_domains 需要 1..8 个域")
        for name in names:
            if not HAL_DOMAIN_RE.match(name):
                fail(f"hal_patch_domains 含非法域：{name!r}")
        if len(hal_domains) >= 192:
            fail("hal_patch_domains 过长")
    values["hal_patch_domains"] = hal_domains
    values["hal_patch_enable"] = hal_enable

    for key in OPTIONAL:
        if key not in values:
            values[key] = DEFAULTS.get(key, 0)
    return values


def c_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def c_array_cap(kind) -> int:
    return kind[1]


def emit_header(values: dict, meta: dict) -> str:
    lines = []
    src = meta["json_rel"]
    sha = meta["sha256"]
    ref = meta["ref_rel"]
    lines.append("/*")
    lines.append(" * CVE-2026-99491 lhasa kernel profile -- GENERATED FILE, DO NOT EDIT.")
    lines.append(" *")
    lines.append(" * Generated by tools/99491/gen_profile.py from")
    lines.append(f" *   {src}")
    lines.append(f" *   sha256 {sha}")
    lines.append(f" * release  : {values['release']}")
    lines.append(f" * arch     : {values['arch']}")
    lines.append(f" * label    : {values['label']}")
    lines.append(f" * verified : {values['verified']}")
    lines.append(f" * stext    : 0x{values['stext']:x}")
    lines.append(f" * etext    : 0x{values['etext']:x}"
                 f"   (derived from {ref})")
    lines.append(" *")
    lines.append(" * Schema follows Yunnijian/CVE-2026-99491 tools/realcred/profile.h")
    lines.append(" * (GPL-2.0-only, commit 1923ac893d582e4b87b748ea033be4a004d894b1);")
    lines.append(" * see ../NOTICE.  Regenerate with: python3 tools/99491/gen_profile.py --gen")
    lines.append(" */")
    lines.append("#ifndef CVE99491_PROFILE_H")
    lines.append("#define CVE99491_PROFILE_H")
    lines.append("")
    lines.append("#include <stdio.h>")
    lines.append("#include <string.h>")
    lines.append("")
    lines.append("/* Default locations (device-level bootstrap constants). */")
    lines.append('#define CVE99491_WORKDIR         "/data/local/tmp/cve99491"')
    lines.append("#define CVE99491_PROFILE_DEFAULT CVE99491_WORKDIR \"/profile.json\"")
    lines.append('#define CVE99491_PROFILE_ENV     "CVE99491_PROFILE"')
    lines.append("")
    lines.append("/* Runtime buffer ceilings. */")
    lines.append("#define CVE99491_CRED_MAX        256")
    lines.append("#define CVE99491_SPRAY_PAIRS_MAX 64")
    lines.append("")
    lines.append("/* Profile provenance (for --self-test and the [p] markers). */")
    lines.append(f'#define CVE99491_PROFILE_SHA256   "{sha}"')
    lines.append(f'#define CVE99491_PROFILE_RELEASE  "{c_escape(values["release"])}"')
    lines.append(f'#define CVE99491_PROFILE_SOURCE   "{c_escape(src)}"')
    lines.append(f"#define CVE99491_PROFILE_VERIFIED {values['verified']}u")
    lines.append(f"#define CVE99491_PROFILE_FIELD_COUNT {len(FIELDS)}u")
    lines.append("")
    lines.append("/* Flat constants (one per generated field). */")
    for key, kind, _group in FIELDS:
        value = values[key]
        if kind[0] == "str":
            lines.append(f'#define CVE99491S_{key.upper()} "{c_escape(value)}"')
        elif kind[1] == 4:
            lines.append(f"#define CVE99491P_{key.upper()} {value}u")
        else:
            lines.append(f"#define CVE99491P_{key.upper()} 0x{value:x}ULL")
    lines.append("")
    lines.append("struct cve99491_profile {")
    last_group = None
    for key, kind, group in FIELDS:
        if group != last_group:
            lines.append(f"    /* {group}. */")
            last_group = group
        if kind[0] == "str":
            lines.append(f"    char {key}[{kind[1]}];")
        elif kind[1] == 4:
            lines.append(f"    unsigned int {key};")
        else:
            lines.append(f"    unsigned long long {key};")
    lines.append("};")
    lines.append("")
    lines.append("/* Built-in profile: the values the binary was compiled against.  The")
    lines.append(" * runtime --profile JSON overrides it when supplied; the runtime release")
    lines.append(" * and page-size checks stay fail-closed either way. */")
    lines.append("static inline void cve99491_profile_builtin(struct cve99491_profile *p)")
    lines.append("{")
    lines.append("    memset(p, 0, sizeof(*p));")
    for key, kind, _group in FIELDS:
        if kind[0] == "str":
            lines.append(
                f"    snprintf(p->{key}, sizeof(p->{key}), \"%s\", "
                f"CVE99491S_{key.upper()});")
        else:
            lines.append(f"    p->{key} = CVE99491P_{key.upper()};")
    lines.append("}")
    lines.append("")
    lines.append("/*")
    lines.append(" * Known-good PackageManager ABI values.  They are a last-resort fallback")
    lines.append(" * for profiles that omit pm_*: the caller must announce the fallback.")
    lines.append(" * Returns 1 when it filled at least one missing field.")
    lines.append(" */")
    lines.append("static inline int cve99491_profile_pm_assumed(struct cve99491_profile *p)")
    lines.append("{")
    lines.append("    int filled = 0;")
    lines.append("")
    lines.append("    if (!p->pm_binder_lib[0]) {")
    lines.append("        snprintf(p->pm_binder_lib, sizeof(p->pm_binder_lib), \"%s\",")
    lines.append('                 "libbinder_ndk.so");')
    lines.append("        filled = 1;")
    lines.append("    }")
    lines.append("    if (!p->pm_service[0]) {")
    lines.append("        snprintf(p->pm_service, sizeof(p->pm_service), \"%s\", \"package\");")
    lines.append("        filled = 1;")
    lines.append("    }")
    lines.append("    if (!p->pm_interface[0]) {")
    lines.append("        snprintf(p->pm_interface, sizeof(p->pm_interface), \"%s\",")
    lines.append('                 "android.content.pm.IPackageManager");')
    lines.append("        filled = 1;")
    lines.append("    }")
    lines.append("    if (!p->pm_txn_get_application_info) {")
    lines.append("        p->pm_txn_get_application_info = 9;")
    lines.append("        filled = 1;")
    lines.append("    }")
    lines.append("    if (!p->pm_txn_get_package_info) {")
    lines.append("        p->pm_txn_get_package_info = 3;")
    lines.append("        filled = 1;")
    lines.append("    }")
    lines.append("    if (!p->ksu_manager[0]) {")
    lines.append("        snprintf(p->ksu_manager, sizeof(p->ksu_manager), \"%s\",")
    lines.append('                 "me.weishu.kernelsu");')
    lines.append("        filled = 1;")
    lines.append("    }")
    lines.append("    return filled;")
    lines.append("}")
    lines.append("")
    lines.append("#endif /* CVE99491_PROFILE_H */")
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="gen_profile.py",
        description="校验 lhasa_99491_profile.json 并生成 plant/99491/profile.h")
    parser.add_argument("--check", action="store_true",
                        help="只校验（默认动作）")
    parser.add_argument("--gen", action="store_true", help="校验后生成 profile.h")
    parser.add_argument("--json", type=pathlib.Path, default=DEFAULT_JSON,
                        help=f"profile JSON（默认 {relpath(DEFAULT_JSON)}）")
    parser.add_argument("--out", type=pathlib.Path, default=DEFAULT_OUT,
                        help=f"输出 header（默认 {relpath(DEFAULT_OUT)}）")
    parser.add_argument("--reference", type=pathlib.Path, default=DEFAULT_REF,
                        help=f"release→stext/etext 参考表（默认 {relpath(DEFAULT_REF)}）")
    parser.add_argument("--release", default="",
                        help="要求 release 与此值完全相等（CI/发布门禁用）")
    parser.add_argument("--allow-unknown-release", action="store_true",
                        help="release 不在参考表时只警告（占位 profile 自检用）")
    parser.add_argument("--allow-unverified", action="store_true",
                        help="允许 verified=0（占位/预标定 profile 自检用）")
    parser.add_argument("--allow-extra", action="store_true",
                        help="忽略未知顶层字段（默认报错）")
    parser.add_argument("--require-verified", action="store_true",
                        help="verified=0 视为失败（发布通道）")
    args = parser.parse_args(argv)
    if args.allow_unverified:
        args.require_verified = False

    if not args.check and not args.gen:
        args.check = True

    try:
        data, raw = load_json(args.json)
        values = check_values(data, args)
        if args.check:
            info(f"release={values['release']} verified={values['verified']} "
                 f"fields={len(FIELDS)}")
            info(f"stext=0x{values['stext']:x} etext=0x{values['etext']:x} "
                 f"kaslr_align=0x{values['kaslr_align']:x}")
            info(f"text syms 3/3, data syms 5/5, layout ok")
            print(f"OK {relpath(args.json)}（schema + 区间 + 对齐校验通过）")
        if args.gen:
            meta = {
                "json_rel": relpath(args.json),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "ref_rel": relpath(args.reference),
            }
            text = emit_header(values, meta)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(text, encoding="utf-8")
            print(f"[gen] 写了 {relpath(args.out)}（sha256 "
                  f"{hashlib.sha256(text.encode()).hexdigest()[:16]}…）")
        return 0
    except CheckError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
