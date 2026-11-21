# 这里必须放三个原生程序

三个必需的、一个诊断用的，构建前用 `tools\copy_assets.ps1` 从 `..\..\lhasa_port\plant\build\` 复制过来：

- `reach_probe`        —— 接口可达性诊断（应用里的「先做接口诊断」按钮）
- `slide_probe`        —— 测本次开机的 KASLR 位移
- `uaf_plant_replay`   —— 主利用（已改成 lhasa 常量）
- `pc98260-su`         —— 提权后连 root 服务的客户端

复制命令：

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\copy_assets.ps1
```

缺任何一个，应用启动后会在「写入程序」这一步报错。
