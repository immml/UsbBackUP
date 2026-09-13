# usbguard

**Windows 专用 USB 自动备份与加密工具** —— 无 UI、无 HID 依赖、纯 Go 标准库实现。

> ⚠️ **使用前必读**：本工具会对接入本机的可移动存储介质执行**自动**读写操作。
> 请先完整阅读 [DISCLAIMER.md](DISCLAIMER.md) 与本文档的「安全提示」一节。
> 本工具仅限用于你本人自有、或已获得明确书面授权的设备与存储介质。

---

## 1. 它做什么

插入 U 盘后，`usbguard` 自动判断该介质属于哪一类，并执行对应动作：

```
                    ┌──────────────────────────┐
   USB 插入事件 ───► │  winvol：卷类型 / 就绪检查 │
                    └────────────┬─────────────┘
                                 ▼
                    ┌──────────────────────────┐
                    │ keyfile：私钥存在性检测    │  ← 只判定"有没有"，不读取内容
                    └───────┬──────────┬───────┘
                     检测到私钥 │          │ 未检测到
                     （已授权） │          │
                                ▼          ▼
        ┌───────────────────────────┐  ┌──────────────────────────────┐
        │ 分支 A：本地备份回写        │  │ winvol：容量门控              │
        │ 本地「备份文件夹」          │  │ 已占用容量 > 阈值(默认10GiB)? │
        │   → <U盘>:\backup\         │  └────┬───────────────────┬─────┘
        │ 不删源盘任何文件            │   超过 │                   │ 未超过
        └───────────────────────────┘        ▼                   ▼
                                     ┌──────────────┐  ┌────────────────────────┐
                                     │   直接跳过    │  │ 分支 B：整盘打包 + 加密  │
                                     └──────────────┘  │ zip → AES-256-GCM      │
                                                       │ → RSA-4096-OAEP 包装会话│
                                                       │ → %TEMP%\backup\*.usbk │
                                                       │ 源盘全程只读            │
                                                       └────────────────────────┘
```

**两个分支都不会删除、移动、改名或改写源介质上的任何文件。**

### 关键行为约定

| 项 | 行为 |
|---|---|
| 私钥检测 | **只做存在性判定**：比对文件名模式 + 文件开头 4 KiB 的内容特征。不读取、不解析、不复制、不缓存、不写日志、不外传任何私钥内容 |
| 授权分支写入位置 | 仅 `<U盘>:\backup\`。不覆盖该目录外的任何对象；同名文件默认跳过 |
| 非授权分支 | 只读源盘；产物为单一加密容器 `{卷标}.zip.usbk` |
| 明文 zip | **默认不落盘**（流式直送加密器）。如需保留，显式加 `--keep-plain-zip` |
| 网络 | **零网络访问**。全部二进制不含任何 socket / HTTP / DNS 调用 |
| 隐蔽性 | 无加壳、无免杀、无隐藏进程/窗口/端口、不写自启动、不修改注册表 |

---

## 2. 加密方案

采用标准**混合加密**：非对称算法只用于包装对称密钥，数据本身由对称算法加密。

```
                    随机会话密钥（32 字节，仅存在于内存）
                              │
        RSA-4096-OAEP(SHA-256)│  ← 非对称算法只用在这里
                              ▼
                     512 字节"包装密钥" ──► 写入容器头
                              
   明文流 ──► AES-256-GCM 分块(默认 1 MiB) ──► 密文帧 ──► .usbk 容器
```

| 组成 | 算法 / 参数 |
|---|---|
| 密钥包装 | RSA-4096 + OAEP(SHA-256)，label `usbbackup/v1`（协议常量，与仓库路径无关）（下限 2048 位） |
| 数据加密 | AES-256-GCM，默认分块 1 MiB |
| 分块 Nonce | 8 字节随机前缀 ‖ 4 字节块序号（大端），保证同密钥下绝不重复 |
| 分块 AAD | 容器头哈希 ‖ 块序号 ‖ 帧标志 → 防块重排、跨文件拼接、头部篡改 |
| 完整性 | 每块独立认证；末块元数据帧携带明文 SHA-256 与明文长度，缺块即判定截断 |
| 内存占用 | O(块大小)，约数 MiB 峰值，不整份载入 |
| 私钥口令保护 | PBKDF2-HMAC-SHA256（60 万次）+ AES-256-GCM（可选） |

容器格式（`.usbk`，头部为明文，不含任何密钥材料）：

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 4 | 魔数 `USBK` |
| 4 | 2 | 版本 |
| 6 | 2 | 密钥包装算法编号 |
| 8 | 2 | 数据加密算法编号 |
| 10 | 4 | 分块大小 |
| 14 | 8 | 明文长度（0 = 见末块元数据） |
| 22 | 8 | Nonce 随机前缀 |
| 30 | 32 | 明文 SHA-256 |
| 62 | 32 | 公钥指纹（SHA-256） |
| 94 | 2 | 包装密钥长度 |
| 96 | n | 包装密钥 |

之后是密文帧序列：`[1B 标志][4B 密文长度][密文 + 16B Tag]`，最后一帧为元数据帧。

---

## 3. 安装

### 3.1 直接使用预编译产物

把 `dist\` 下的 4 个 exe 放到任意目录（建议 `C:\Program Files\usbguard\`），然后：

```powershell
# 生成密钥对（首次使用）
.\usbkeygen.exe generate --out C:\ProgramData\usbguard\keys

# 登记公钥（配置只保存公钥，不保存私钥）
.\usbkeygen.exe use C:\ProgramData\usbguard\keys\usbguard.pub.pem

# 校验配置与环境
.\usbguard.exe config-check

# 只读诊断：看看某个盘符会被怎么处理（不写任何数据）
.\usbguard.exe probe --drive E:
```

### 3.2 从源码构建

需要 **Go 1.24 或更高版本**（开发环境实测 Go 1.27.1）。零第三方依赖，可离线构建。

```powershell
cd D:\path\to\usbguard
.\build.ps1 -Version 0.1.0 -Test
```

或在任何 shell 中手工构建：

```bash
# Linux (含 WSL / Git Bash) 交叉编译 Windows 产物
cd /d/Users/flowe/WorkBuddy/渗透/usbguard
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -o dist/ github.com/immml/UsbBackup/cmd/usbguard github.com/immml/UsbBackup/cmd/usbkeygen github.com/immml/UsbBackup/cmd/usbcomp github.com/immml/UsbBackup/cmd/usbunseal
```

目标平台：Windows 10 1809+ / Windows 11 / Windows Server 2019+，**amd64**。

---

## 4. 使用

### 4.1 生成器 `usbkeygen`

启动时会**强制展示安全警告与免责声明**，并要求输入 `I AGREE` 才能继续。

| 子命令 | 说明 |
|---|---|
| `generate` | 生成 RSA 密钥对。`--bits`（默认 4096，下限 2048）、`--out`、`--private`、`--public`、`--force`、`--pass`（交互式口令）、`--pass-file` |
| `use <公钥>` | 选择已有公钥并登记到配置。传入私钥会被明确拒绝 |
| `inspect <公钥>` | 查看公钥位数与 SHA-256 指纹（分组十六进制） |
| `selftest` | 就地验证混合加密往返、篡改检测、截断检测、错误密钥拒绝。全程内存操作，不落盘 |
| `version` | 版本信息 |

自动化场景可加 `--yes` 跳过 `I AGREE` 交互。

### 4.2 主程序 `usbguard`

| 子命令 | 说明 | 状态 |
|---|---|---|
| `run` | 前台常驻运行（事件驱动 + 轮询兜底） | 计划 M4 |
| `once --drive E:` | 单盘执行一次作业 | 计划 M4 |
| `list` | 列出可移动卷及其容量 | ✅ 可用 |
| `probe --drive E:` | 只读诊断：卷信息 + 私钥检测结论 + 将走哪个分支 | ✅ 可用 |
| `config-check` | 校验配置与环境（源目录、输出目录可写、公钥、审计目录） | ✅ 可用 |
| `version` | 版本信息 | ✅ 可用 |

> 建议：第一次在任何机器上运行前，先 `usbguard probe --drive <盘符>` 确认判定结果符合预期。
> 该命令**只读**，不会写入任何数据。

### 4.3 压缩器 `usbcomp`

```powershell
.\usbcomp.exe pack D:\重要资料 -o D:\out\mybackup.usbk
```

`--store` 全部不压缩、`--exclude` 追加排除项、`--threads` 并发度、`--keep-plain-zip` 额外保留明文 zip。
源目录 → 流式 zip → 混合加密 → 单一 `.usbk`。源目录全程只读。

### 4.4 解压器 `usbunseal`

```powershell
# 查看容器头（无需私钥）
.\usbunseal.exe list D:\out\mybackup.usbk

# 校验完整性（不解出明文）
.\usbunseal.exe verify D:\out\mybackup.usbk --key .\usbguard.key.pem --pass

# 解密并解压到指定目录
.\usbunseal.exe unseal D:\out\mybackup.usbk -d D:\restore --key .\usbguard.key.pem
```

安全设计：目标目录必须显式指定；默认不覆盖已存在文件；拒绝一切可能逃逸目标目录的条目名（Zip Slip 防护）；
解密失败时统一报错，不区分「密钥错误」与「数据被篡改」。

---

## 5. 配置

配置文件默认位于 `%LOCALAPPDATA%\usbguard\config.json`，也可用 `--config` 指定。

优先级：**命令行 flag > 环境变量 `USBGUARD_*` > `config.json` > 内置默认值**。

```json
{
  "backup_source_dir": "%USERPROFILE%\\usbguard-backup",
  "output_dir": "%TEMP%\\backup",
  "public_key_path": "C:\\ProgramData\\usbguard\\keys\\usbguard.pub.pem",
  "authorized_backup_subdir": "backup",
  "audit_file": "%LOCALAPPDATA%\\usbguard\\audit.jsonl",
  "monitor": {
    "poll_interval_sec": 5,
    "debounce_sec": 5,
    "ready_timeout_sec": 10,
    "job_timeout_min": 30,
    "process_mounted_on_start": true,
    "poll_only": false
  },
  "detect": {
    "mode": "both",
    "max_depth": 4,
    "max_files": 5000,
    "max_headers_bytes": 4096,
    "timeout_sec": 20,
    "marker_file": ".usbguard-allow",
    "scan_contents": true,
    "extra_name_patterns": [],
    "extra_content_markers": []
  },
  "gate": {
    "used_threshold_bytes": 10737418240,
    "max_total_bytes": 0,
    "free_space_margin_percent": 5
  },
  "archive": {
    "store_already_compressed": true,
    "keep_plain_zip": false,
    "excludes": [],
    "threads": 0
  },
  "retention": { "keep_per_volume": 5, "dedup_enabled": true },
  "log": { "level": "info", "file": "...", "max_size_mb": 10, "max_backups": 5, "console": true }
}
```

支持的 `USBGUARD_*` 环境变量：
`USBGUARD_BACKUP_SOURCE_DIR`、`USBGUARD_OUTPUT_DIR`、`USBGUARD_PUBLIC_KEY`、`USBGUARD_LOG_LEVEL`、
`USBGUARD_AUDIT_FILE`、`USBGUARD_USED_THRESHOLD_BYTES`、`USBGUARD_POLL_INTERVAL_SEC`。

路径支持 `%VAR%` 与 `${VAR}` 展开。配置优先级冲突时高优先级生效，并以 DEBUG 级记录来源。

### 授权标记（可选，比启发式更确定）

在 U 盘根目录放一个 `.usbguard-allow`，内容为已登记公钥的指纹：

```
fingerprint=1a2b 3c4d 5e6f ...
```

只要该指纹与配置中的公钥一致，就判定为「已授权」，无需依赖文件名/内容启发式。
**该标记只使用公钥指纹，全程不涉及任何私钥材料。**

### 审计日志

`audit.jsonl`（JSON Lines）每行一条记录，包含：时间、盘符、卷标、文件系统、卷序列号、容量、走的分支、
`has_keyfile` 布尔值与命中计数、扫描文件数、产物名、结果、耗时。

**审计记录不含私钥内容、不含私钥文件名、不含文件清单、不含任何文件内容。**

---

## 6. 安全提示

1. **私钥与口令丢了就找不回来。** 本工具不提供后门、密钥托管或找回机制。请把私钥与口令离线备份（离线介质 + 纸质记录）。
2. **先验证，再生产。** 在把本工具用于重要数据之前，请先在非生产环境中跑一遍 `probe` / `once`。
3. **备份源目录要干净。** 授权分支会把本地「备份文件夹」内容写入 U 盘，请确认该目录不含你不希望扩散的数据。
4. **明文 zip 是敏感的。** 默认不落盘；若使用 `--keep-plain-zip`，请在使用后立即安全删除明文产物。
5. **启用 BitLocker / 设备加密**能进一步防止介质丢失后的离线读取——本工具保护的是备份产物，不是整个磁盘。
6. **明文私钥落盘的风险**：`generate` 默认输出未加密的 PKCS#8 私钥。如需口令保护，请加 `--pass`。
   注意：本工具的口令保护采用自有格式（`USBGUARD ENCRYPTED PRIVATE KEY`，PBKDF2-SHA256 60 万次 + AES-256-GCM），
   与 `openssl` 的 PBES2 格式**不互通**；这样做是为了避免使用弱 KDF。
7. **Go 的 `rsa.PrivateKey` 无法彻底内存清零**（标准库不提供该 API），本工具只做了尽力而为的字段清除。
   真正的防护依赖操作系统内存隔离与进程生命周期管理。
8. **配置文件只保存公钥。** `usbkeygen use` 会拒绝任何私钥输入。

### 信任边界

| 在信任边界内 | 在信任边界外 |
|---|---|
| 本机操作系统与当前用户账户 | 目标介质上的既有数据（被当作不可信输入解析） |
| 本工具自身二进制 | 归档条目名（解包时全部校验后才落盘） |
| 已登记的**公钥** | 私钥（只在解密/生成时显式提供，不持久化） |

---

## 7. 项目结构

```
usbguard/
├── cmd/
│   ├── usbguard/        常驻主程序（监控 / 编排 / 诊断）
│   ├── usbkeygen/       生成器（密钥对生成 + 公钥选择）
│   ├── usbcomp/         压缩器（带混合加密）
│   └── usbunseal/       解压器（解密 + 解压）
├── internal/
│   ├── winmon/          设备插入事件监控（Windows 消息 + 轮询兜底）
│   ├── winvol/          卷类型 / 容量 / 门控 / 盘符枚举
│   ├── keyfile/         私钥存在性检测（文件名 + 内容特征 + 授权标记）
│   ├── copier/          授权分支：本地备份回写
│   ├── archive/         流式 zip 打包与安全解包（含 Zip Slip 防护）
│   ├── crypto/          混合加密容器（读 / 写 / 解析）
│   ├── keystore/        密钥生成、加载、指纹、口令保护
│   ├── backup/          流水线编排、产物命名、审计
│   ├── config/          配置加载 / 校验 / 合并
│   ├── logx/            分级日志 + 大小轮转
│   ├── cli/             安全警告横幅、无回显口令输入、退出码
│   ├── fsutil/          Windows 路径工具（长路径 / 净化 / 包含关系）
│   └── version/         构建期注入的版本信息
├── REQUIREMENTS.md      完整需求表（功能点 / 优先级 / 异常处理 / 安全注意事项）
├── DISCLAIMER.md        免责声明
├── LICENSE              CC BY-NC-SA 4.0
└── build.ps1            构建脚本
```

---

## 8. 开发状态

| 阶段 | 内容 | 状态 |
|---|---|---|
| M0 | 需求表 + 开发环境 + 骨架 + 文档三件套 + Git | ✅ 完成 |
| M1 | `crypto` 混合加密容器 + `keystore` 密钥管理 | ✅ 完成（含单测） |
| M2 | `archive` 流式打包 / 安全解包执行器 + `copier` 复制执行器 | 待开发 |
| M3 | `winvol` 卷信息与门控 ✅；`keyfile` 检测 ✅ | ✅ 完成（含单测） |
| M4 | `winmon` 设备监控 + `backup` 流水线 + 服务化 | 待开发 |
| M5 | 4 个 CLI 集成测试 + Windows 实机验证 | 部分完成（框架就绪） |

当前已实现的模块都有单元测试覆盖，`go vet ./...` 与 `go test ./...` 全绿。

---

## 9. 许可

本项目采用 **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International（CC BY-NC-SA 4.0）** 协议。

- **署名（BY）** —— 再分发或改编时必须保留原作者署名与本声明
- **非商业性使用（NC）** —— 不得将本项目或其改编作品用于任何商业用途
- **相同方式共享（SA）** —— 改编作品必须以相同协议分发

协议全文见 [LICENSE](LICENSE) 或 <https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode>。

---

## 10. 免责声明

**本软件按「现状」（AS IS）提供，不附带任何形式的明示或默示担保。**
作者与贡献者不对因使用本软件产生的任何直接、间接、附带、特殊、惩罚性或后果性损害承担责任，
包括但不限于数据丢失、数据损坏、数据泄露、业务中断、设备损坏或利润损失。

使用者须自行确保其使用行为符合所在国家/地区的法律法规，并自行承担全部法律后果。
本工具的合法使用范围仅限于**你本人自有的设备与介质**，或**你已获得明确书面授权**的设备和存储介质。

完整条款见 [DISCLAIMER.md](DISCLAIMER.md)。
