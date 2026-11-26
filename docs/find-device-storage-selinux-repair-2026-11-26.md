# 小米 18 Fold「查找设备存储损坏」单文件标签修复记录

日期：2026-11-26（Asia/Singapore）  
归档分支：`next-99491-realcred`

本次在一台 `lhasa` 设备上确认：`/mnt/vendor/persist/fdsd/st` 的 SELinux 标签为 `unlabeled`，内核明确拒绝 `hal_mtdservice_default` 读取该文件。本机文件上下文规则及访问策略共同指向应使用的标签 `vendor_persist_drm_file`。

完成本机文件备份后，仅对 `st` 执行一次 `restorecon`，恢复系统规定的标签。命令成功，文件内容的 SHA-256 在修复前后一致。用户随后反馈：“应该是修复好了，我没看到报错了。”

**当前结论：单文件标签修复已验证，用户观察到原告警不再出现，初步修复成功。** 这不是整分区损坏的诊断，也不是对其他设备通用的删文件教程。

## 1. 设备与操作边界

| 项目 | 本次实际记录 |
|---|---|
| 用户提供的机型名称 | 小米 18 Fold |
| 设备代号 / 型号 | `lhasa` / `2608BPX34C` |
| 系统增量版本 | `OS4.0.31.0.XPNCNXM` |
| Android / 安全补丁 | Android 17 / 2026-10-01 |
| Bootconfig | `vbmeta.device_state=locked`、`verifiedbootstate=green`、槽位 `_b` |
| SELinux 检查时状态 | `Enforcing` |
| 已授权 Root 会话 | `uid=0(root)`，`context=u:r:ksu:s0` |
| 持久分区挂载 | `/dev/block/sdd2` → `/mnt/vendor/persist`，ext4、`rw,seclabel` |

本次使用用户已经提供的临时 Root，未实施或修改提权链。本文归档到该分支不代表已经证明故障由该分支、某个 payload 或某次提权产生。

用户要求最小改动，并要求遇到修复权限不足时立即告知。本次修复命令未遇到权限不足；没有为完成操作关闭 SELinux、扩大文件权限或替换分区镜像。

## 2. 从告警定位到具体拒绝

用户现象为持续出现“查找设备存储损坏，您的设备处于不安全的状态”一类提示。该提示只能作为排查入口，不能单独证明整块闪存、整个 `persist` 或设备安全密钥已损坏。

### 文件状态

通过已授权 Root 读取的目录信息如下。这里只保留必要元数据，未公开文件内容。

| 文件 | 大小 | 属主 / 权限 | 修复前 SELinux 标签 |
|---|---:|---|---|
| `fdsd/st` | 628 字节 | `system:system` / `0600` | `u:object_r:unlabeled:s0` |
| `fdsd/st_tmp` | 11168 字节 | `system:system` / `0600` | `u:object_r:vendor_persist_drm_file:s0` |
| `fdsd/tp` | 20 字节 | `system:system` / `0600` | `u:object_r:vendor_persist_drm_file:s0` |

目录 `fdsd` 自身的标签也是 `vendor_persist_drm_file`。这里的显著异常是 `st` 的安全标签，并非已经确认其文件内容损坏。

### 内核拒绝记录

内核日志中的关键 AVC 字段如下，已省略时间、进程号和 inode：

```text
avc: denied { read }
name="st" dev="sdd2"
scontext=u:r:hal_mtdservice_default:s0
tcontext=u:object_r:unlabeled:s0
tclass=file permissive=0
```

这条记录确认了实际发生的访问失败：安全服务尝试读取 `st`，被 SELinux 强制访问控制拒绝。它比“看到安全提示，所以推测整个分区坏了”更具体。

### 本机规则交叉核对

本机 `/vendor/etc/selinux/vendor_file_contexts` 包含：

```text
/persist/fdsd(/.*)?              u:object_r:vendor_persist_drm_file:s0
/mnt/vendor/persist/fdsd(/.*)?   u:object_r:vendor_persist_drm_file:s0
```

本机 `vendor_sepolicy.cil` 还包含 `hal_mtdservice_default` 对 `vendor_persist_drm_file` 文件类型的 `read`、`open`、`getattr` 等允许规则。

因此，本次同时具备三类证据：文件当前标签异常、对应的实际读取拒绝、系统对正确标签及访问权限的明确规定。

## 3. 分区健康与检查范围

只读检查结果：

- `persist` 已挂载为读写，容量约 108 MiB，已用约 18 MiB，剩余约 90 MiB。
- inode 使用 203 / 32768，未见空间或 inode 耗尽。
- `/sys/fs/ext4/sdd2/errors_count`、`first_error_time`、`last_error_time` 均为 `0`。
- 在本次可读取的内核日志中，未发现匹配的存储 I/O、ext4 损坏或中止错误。

这些结果没有提供“整分区损坏”的证据，但也不等于完成了全面硬件健康检测。

对现有文件逐项进行 `restorecon -n -v` 干运行时，还发现一个电池策略 CSV 的标签与当前规则不同。该文件没有与本次 `st` 读取失败对应的直接证据，因此没有一并修改。

采集注意：`restorecon` 的详细说明会出现在标准错误输出中。本次自动采集在合并 stdout/stderr 后正确记录了两项差异；不能因只采集 stdout 得到空结果，就认定所有标签正常。所有诊断性调用均带 `-n`，没有执行批量重标记。

## 4. 备份与最小修复

### 修复前保存

在操作者本地保存了 `st`、`st_tmp`、`tp` 三个文件的备份，并对每个文件进行了：

1. 读取手机端 SHA-256。
2. 保存文件字节到本地。
3. 比较本地摘要和再次读取的手机端摘要，确认复制期间内容一致。

同时记录了原始标签、属主、权限、大小及诊断结果。备份目录权限为 `0700`，备份文件权限为 `0600`。

这些是**本机当前状态的文件备份**，不是完整 `persist` 镜像或历史健康备份，也不能补回此前已经丢失的资料。原始备份、完整设备摘要、账号数据及本机绝对路径均未上传到仓库。

### 先干运行，再修改一个文件

在已授权的 Root shell 中，先核对单文件干运行结果：

```sh
restorecon -n -v /mnt/vendor/persist/fdsd/st
```

干运行明确指出应从 `unlabeled` 恢复为 `vendor_persist_drm_file`。完成备份并确认文件内容未变化后，实际执行的修复只有：

```sh
restorecon -v /mnt/vendor/persist/fdsd/st
```

输出中的关键变化：

```text
from u:object_r:unlabeled:s0
to   u:object_r:vendor_persist_drm_file:s0
```

没有删除 `st`、`st_tmp` 或 `tp`，没有修改文件内容、属主或普通权限，也没有刷写 `persist`、清除用户数据、修改 Bootloader 状态或使用全局宽松的 SELinux 设置。已请用户手动重启进行验证，代理未发送重启命令；本记录没有单独取得重启完成时间或重启后标签读回。

## 5. 验证结果与尚未证明的内容

| 验证项 | 结果 |
|---|---|
| 修复命令执行 | 成功，未遇到权限不足 |
| `st` 标签读回 | 已为 `vendor_persist_drm_file` |
| `st` 内容 | 修复前后 SHA-256 一致 |
| 其他文件或分区改动 | 未执行 |
| 用户后续测试 | 用户反馈未再看到原报错，初步通过 |
| 重启后的标签再次读回 | 本次未完成独立读回 |
| 小米账号及“查找设备”完整功能 | 未进行完整功能验收 |
| 长时间复发情况 | 尚未观察 |

用户在测试过程中曾表示仍在观察，之后反馈“应该是修复好了，我没看到报错了”。因此，本记录采用“初步修复成功”，不把一次观察写成长期稳定或全部功能通过。

## 6. 对原因的判断

**已经确认的是直接故障：`st` 的异常标签导致系统安全服务读取被拒绝。** 标签恢复后，用户反馈原告警未再出现，这支持该标签异常与本次症状有关。

尚未确认的是标签最初为何异常。文件复制、恢复、工具写入时未正确处理安全属性，或者系统迁移、策略变化，都只能列为可能机制。本次没有足够的历史证据确认具体操作、工具或责任来源；文件修改时间也不能证明是谁修改了安全标签。

临时 Root 为本次诊断及单文件修复提供了权限，但不构成“临时 Root 必然造成该问题”的证据，也不能证明故障由本仓库的某条提权链产生。

## 7. 复用条件与参考资料

复用本次处理前，应在目标设备上重新确认：路径、异常标签、对应的实际拒绝日志、本机期望标签、备份以及真实可用的权限。某个文件在其他机型上可能有不同用途或策略；本文不是无条件执行的通用修复脚本。

若权限不足，应停止对应修改并向操作者说明具体失败点，不以关闭安全控制或整分区覆盖作为替代。如果后续仍报错，应读取新的错误证据，再判断是否存在标签之外的问题。

- [Android：SELinux 安全模型](https://source.android.com/docs/security/features/selinux)：说明 SELinux 对包括 Root 在内的进程实行强制访问控制。
- [Herry：小米“查找手机存储损坏”案例](https://blog.herry001.com/2023/03/07/fix-find-my-phone-storage-error-for-xiaomi-devices/)：提供了旧机型 `persist/fdsd` 排查线索，同时提醒整刷 `persist` 的风险。本次未照搬其删除文件操作。
- [用户补充的 CSDN 文章](https://blog.csdn.net/java5/article/details/154763194)：只读取了公开部分，未获取付费内容。公开部分将 `fastboot flash persist` 当作诊断查询，不应照此操作。
- [Fastboot 官方命令定义](https://android.googlesource.com/platform/system/core/+/master/fastboot/fastboot.cpp)：`flash` 是刷写操作；省略文件名也不使它变成只读查询。本次没有用刷写命令检测分区。

发布范围仅包含上述诊断与修复记录；不包含 ADB 配对码、网络地址、设备序列号、账号标识、完整日志或原始状态文件。
