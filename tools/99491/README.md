# tools/99491 — profile 校验与 `profile.h` 生成器

CVE-2026-99491 `real_cred` 链把**全部 build-specific 常量**放在唯一事实源
`app/src/main/assets/lhasa_99491_profile.json` 里；本目录的 `gen_profile.py`
负责 fail-closed 校验，并把 JSON 生成 C 形态的
[`plant/99491/profile.h`](../../plant/99491/profile.h)（宏 + `struct cve99491_profile` +
`cve99491_profile_builtin()`）。**`profile.h` 是生成物，禁止手改；改 JSON 后重跑。**

```sh
python3 tools/99491/gen_profile.py --check \
    --json app/src/main/assets/lhasa_99491_profile.json   # 只校验（默认动作）
python3 tools/99491/gen_profile.py --gen                  # 校验 + 生成 profile.h
python3 tools/99491/gen_profile.py --check --gen --json PATH --out PATH
python3 tools/99491/gen_profile.py --check --json plant/99491/example-profile.json \
    --allow-unknown-release                              # 占位 schema 自检
```

退出码：`0` 通过，`1` 校验失败（stderr 有 `FAIL …`），`2` 用法/IO 错误。
无第三方依赖（Python >= 3.8，只用标准库）。

---

## 1. 数据来源与 `release` 匹配

| 输入 | 用途 |
|---|---|
| `app/src/main/assets/lhasa_99491_profile.json` | 唯一事实源（符号地址、结构偏移、几何、KSU/PM 字符串、`verified`） |
| `app/src/main/assets/lhasa_profile.txt` | `release=` 行的 `stext/etext` 参考表：校验 profile 的 `release` **精确命中**其中一条，并用该行 `stext/etext` 做地址区间校验 |
| `--release VALUE` | 可选：要求 JSON `release` 与之逐字相等（CI/发布门禁用） |
| `--reference PATH` | 可选：换参考常量表 |

`release` 必须出现在参考表里（占位 profile 用 `--allow-unknown-release` 才只警告）。
JSON 可选带 `stext/etext`；若带，必须与参考表该行一致，否则 FAIL——两边不一致说明标定输入有漂移。

---

## 2. JSON schema

扁平 JSON 对象，`format=1`、`cve="CVE-2026-99491"`。**必需键 105 个**（与 `plant/99491/exp.c`
的 `cve99491_profile` 一一对应，按语义分组）：

| 组 | 键 |
|---|---|
| identity (7) | `format` `cve` `release` `arch` `label` `verified` `page_size` |
| 链接期符号 (8) | `sym_uhid_worker` `sym_ihe_default` `sym_inject_event` `sym_selinux_state` `sym_init_cred` `sym_per_cpu_offset` `sym_runqueues` `sym_input_dev_list`（64 位地址；字符串 `"0x…"` 或 JSON 整数都接受） |
| 泄漏/KCFI (3) | `cred_site_low21`（< 2 MiB）`kcfi_handle_events` `kcfi_handler_event`（32 位 id） |
| 布局选择器 (6) | `c_off_h` `c_off_p` `c_off_d` `c_off_e` `c_off_scratch` `c_off_fake`（< 4096） |
| task/rq (5) | `ts_off_cred` `ts_off_real_cred` `ts_off_comm` `rq_off_curr` `rq_off_idle` |
| uhid_device (7) | `uhid_input_buf_data_off` `uhid_waitq_head_off` `uhid_outq_off` `uhid_worker_off` `uhid_worker_func_off` `uhid_serial_read_base_off` `uhid_waitq_self` |
| input_dev/handle/handler (21) | `input_dev_size` `input_dev_evbit_off` `input_dev_swbit_off` `input_dev_grab_off` `input_dev_event_lock_off` `input_dev_num_vals_off` `input_dev_max_vals_off` `input_dev_vals_off` `input_dev_absbit_off` `input_dev_absinfo_off` `input_dev_event_off` `input_dev_hlist_off` `input_dev_inhibited_off` `input_dev_id_off` `input_dev_node_off` `absinfo_size` `input_handle_size` `input_handle_dev_off` `input_handle_handler_off` `input_handle_events_off` `input_handler_event_off` |
| cred (13) | `cred_req` `cred_bytes` `cred_uid_off` `cred_euid_off` `cred_securebits_off` `cred_cap_permitted_off` `cred_cap_effective_off` `cred_cap_bset_off` `cred_security_off` `cred_user_off` `cred_user_ns_off` `cred_rcu_off` `cred_rcu_size` |
| selinux_state (4) | `selinux_enforcing_off`(必须 0) `selinux_initialized_off`(必须 1) `selinux_restore_value` `selinux_shell_domain`(`u:r:<dom>:s0`) |
| capability (2) | `cap_last_cap` `cap_full_mask`（必须 `(1<<(last+1))-1`） |
| spray 几何 (13) | `spray_pairs` `spray_len` `spray_count` `spray_spread_ms` `spray_burst_min` `spray_burst_step` `spray_wait_ms` `spray_hold_wait_ms` `spray_fill` `spray_trigger_rounds` `spray_respray_rounds` `spray_cpu` `spray_skb_req` |
| PackageManager (6) | `pm_binder_lib` `pm_service` `pm_interface` `pm_txn_get_application_info` `pm_txn_get_package_info` `pm_user_id` |
| KernelSU (10) | `ksu_manager` `ksu_manager_apk_root` `ksu_workdir` `ksu_module_name` `ksu_ksud_name` `ksu_ksud_path` `ksu_ksu_bin_dir` `ksu_modules_dir` `ksu_lib_subpath` `ksu_lib_subpath_v8a` |

**可选键 7 个**（缺省值见下表；移植新增，用于标定交叉校验与厂商/KSU 开关）：

| 键 | 缺省 | 说明 |
|---|---|---|
| `stext` / `etext` | 取参考表对应 release 行 | 链接期 `.text` 区间；文本符号须落在其中、数据符号落在 `[etext, stext+512MiB)`；不要求 stext 本身 2 MiB 对齐 |
| `kaslr_align` | `2097152`（2 MiB） | KASLR 粒度；运行时 `slide % kaslr_align == 0` 是 fail-closed 校验；必须是 4096..1 GiB 的 2 的幂 |
| `selinux_policycap` | `0`（=未知） | BTF 标定记录；用于日志/未来校验，不参与链 |
| `ksu_backend` | `"auto"` | `auto`（先 assets ksud 再 manager libksud）/`asset`（只用 assets，缺失即失败）/`manager` |
| `hal_patch_enable` | `1` | 厂商 HAL 修复开关：`0`=永不补（严格按计划 §6「仅异常时补」）；`1`=模块 Live 且 `sys.boot_completed != 1` 时补 |
| `hal_patch_domains` | `"hal_audio_default hal_camera_default"` | 空格分隔的域列表（1..8 个，`[a-z][a-z0-9_]*`，< 192 B） |

其他顶层键：`calibration`（对象元数据：`method/slide/boot_id/kernel_build/spl/pending`）允许存在，
**校验但不生成**（其中 `slide` 若给出则要求按 `kaslr_align` 对齐）；其他未知键直接 FAIL（防止拼写错误，
可用 `--allow-extra` 放过）。

`verified` 语义：`0`=已标定但未通过全链验收（当前），`1`=通过 S6/S7。校验只警告 `0`；
发布门禁加 `--require-verified` 变成 FAIL。

---

## 3. 校验规则（fail-closed）

1. **schema**：必需键齐全、类型正确、无未知键；字符串长度 < C 数组容量（C 侧 `snprintf` 前先卡死）。
2. **release**：精确命中 `lhasa_profile.txt` 的 `release=` 集合（或 `--release` 指定值）；`arch ∈ {arm64,aarch64}`；
   `page_size ∈ {4096,16384,65536}`；`format=1`；`cve` 固定。
3. **地址**：全部符号必须是规范内核 VA（`>>48 == 0xffff`）且 4 字节对齐；3 个文本符号落在
   `[stext,etext)`，5 个数据符号落在 `[etext, stext+0x20000000)`（本机 `selinux_state` 在 stext+43 MiB）。
4. **KASLR**：`kaslr_align` 为 2 的幂；`calibration.slide`（如有）按 `kaslr_align` 对齐且 < 2 GiB。
5. **布局**：`*_off < 对应 size`（input_dev/input_handle/cred 各自的 size）；`cred` 指针/8 字节字段 8 字节对齐；
   `input_dev_size`、`spray_len`、`c_off_* + size <= 4096` 等几何关系与 `exp.c` 运行期校验互为双保险。
6. **不变式**：`selinux_state` enforcing@0/initialized@1；`cap_full_mask == (1<<(last+1))-1`；
   `cred_req >= cred_bytes`；uhid 泄漏索引整除关系；路径/包名/域名的字符集与长度（防 shell 拼接与截断）。
7. 以上任一失败 → `FAIL …`、退出 1、**不会生成 profile.h**。

---

## 4. 生成物结构（不手改）

`plant/99491/profile.h` 由固定模板渲染（同一 JSON 生成字节相同）：

- 头注释：来源 JSON 路径 + **JSON sha256** + release/arch/label/verified + `stext/etext` 来源；
- `CVE99491_WORKDIR` 等设备级缺省、`CVE99491_CRED_MAX`/`SPRAY_PAIRS_MAX` 上限；
- `CVE99491_PROFILE_SHA256/RELEASE/SOURCE/VERIFIED/FIELD_COUNT`；
- 每字段一个 `CVE99491P_<KEY>`（数字）或 `CVE99491S_<KEY>`（字符串）；
- `struct cve99491_profile`（字段顺序 = schema 顺序；末尾是本移植新增字段）；
- `cve99491_profile_builtin()`：编译内置 profile（运行时缺失 `<workdir>/profile.json` 时的回落）；
- `cve99491_profile_pm_assumed()`：PackageManager 缺省值的显式兜底（上游同款）。

`plant/99491/exp.c` 只 include 这个头，不内嵌任何地址/偏移/几何 ⇒ OTA 换内核时只改 JSON + 重跑
`build.sh`，源码零改动。

---

## 5. 标定工作流（S3）

1. root 只读导出 boot Image/BTF，按 `docs/99491-test-plan.md` §7 双来源交叉校验每个字段；
2. 把值写进 `app/src/main/assets/lhasa_99491_profile.json`（只改这个文件）；
3. `python3 tools/99491/gen_profile.py --check --json app/src/main/assets/lhasa_99491_profile.json` → 0 FAIL；
4. `bash plant/99491/build.sh` → 重新生成 `profile.h` 并编译（CI 用 zig，本机回退 gcc）；
5. 真机 `--stage=leak` → `oracle` → `write` → `selinux` → `full`（每阶段预期输出见
   `plant/99491/README.md` §4/§5；一次一脚本、不调参重试）；
6. S6/S7 全绿后把 `verified` 改 `1`，重新 `build.sh`；发布门禁加 `--require-verified`。

> 只要改了 JSON（哪怕只是 `verified` 或 `label`），都必须重新 `build.sh`：运行期会用
> `profile_compare_builtin()` 逐字段比对显式 `--profile` JSON 与编译内置 profile，
> 不一致直接 `PROFILE_MISMATCH` 退出 3（防止旧二进制配新标定值）。

---

## 6. 已知边界 / 待办

- `stext/etext` 目前从 `app/src/main/assets/lhasa_profile.txt` 的 release 行派生；若将来 99491 profile
  支持多条 release，建议把 `stext/etext` 直接写进 JSON（生成器已支持且会与参考表交叉校验）。
- `selinux_policycap` 只记录不进链；等写原语需要精确判断 EV_ABS defuzz 时可接进 `exp.c`。
- `calibration` 块只做最小校验（对象 + slide 对齐），不生成、不参与 `PROFILE_MISMATCH` 比对。
- 生成器目前是“单 profile 单 header”；若未来要一 ELF 多 release，改成生成 profile 表（参考
  `tools/gen_xr_profiles.py` 的形态），`exp.c` 的 CLI/阶段逻辑不需要动。
- 本工具不负责资产台账/CI publish（T3）：`plant.yml` 需要把 `exp` 及其等价基线接入
  `tools/equiv.py` 与 `tools/assets-ledger.json`。
