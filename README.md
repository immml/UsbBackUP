# usbbackup

**Windows 专用 USB 自动备份与加密工具** —— 无 UI、无 HID 依赖、纯 Go 标准库实现。

> ⚠️ **使用前必读**：本工具会对接入本机的可移动存储介质执行**自动**读写操作。
> 请先完整阅读 [DISCLAIMER.md](DISCLAIMER.md) 与本文档的「安全提示」一节。
> 本工具仅限用于你本人自有、或已获得明确书面授权的设备与存储介质。
>
> 🚀 **第一次用？先看 [TUTORIAL.md](TUTORIAL.md)**（从生成密钥到还原文件的完整实操）。

---

## 1. 它做什么

### 三个角色（典型部署形态）

| 角色 | 程序 | 运行位置 | 持有内容 |
|---|---|---|---|
| **生成器** | `usbkeygen` | 你的机器 | 生成密钥对；**私钥始终留在你这里** |
| **生成向导** | `usbsetup` | 你的机器 | 交互式一步步问，产出同一个客户端（不用记参数） |
| **客户端** | 生成器产出的 `client.exe` | 目标机器 | 只有**公钥与配置**，硬编码进 exe |
| **解压器** | `usbunseal` | 你的机器 | 用**私钥**解密并还原 |

```
生成器 ──产出──► 客户端（内嵌配置+公钥）──在目标机器上──► 打包加密 .usbk
   │                                                          │
   └──私钥留在本地──────► 解压器 ◄──────取回 .usbk──────────────┘
```

客户端**没有私钥**：即使整个 exe 被人拷走，也解不开它自己产出的文件。
这不是靠隐藏，而是混合加密里"公钥可公开、私钥不离开你"的直接结果。

### 插入后做什么

插入 U 盘后，`usbbackup`（或客户端）自动判断该介质属于哪一类，并执行对应动作：

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
                                                       │ → RSA-OAEP 包装会话密钥  │
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
        RSA-OAEP(SHA-256)      │  ← 非对称算法只用在这里
                              ▼
                     512 字节"包装密钥" ──► 写入容器头
                              
   明文流 ──► AES-256-GCM 分块(默认 1 MiB) ──► 密文帧 ──► .usbk 容器
```

| 组成 | 算法 / 参数 |
|---|---|
| 密钥包装 | RSA + OAEP(SHA-256)，label `usbbackup/v1`（协议常量，与仓库路径无关）；默认 4096 位、下限 2048 位 |
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

把 `dist\` 下的 4 个 exe 放到任意目录（建议 `C:\Program Files\usbbackup\`），然后：

```powershell
# 生成密钥对（首次使用）
.\usbkeygen.exe generate --out C:\ProgramData\usbbackup\keys

# 登记公钥（配置只保存公钥，不保存私钥）
.\usbkeygen.exe use C:\ProgramData\usbbackup\keys\usbbackup.pub.pem

# 校验配置与环境
.\usbbackup.exe config-check

# 只读诊断：看看某个盘符会被怎么处理（不写任何数据）
.\usbbackup.exe probe --drive E:
```

### 3.2 从源码构建

需要 **Go 1.24 或更高版本**（开发环境实测 Go 1.27.1）。零第三方依赖，可离线构建。

```powershell
cd D:\path\to\usbbackup
.\build.ps1 -Version 0.1.0 -Test
```

或在任何 shell 中手工构建：

```bash
# Linux (含 WSL / Git Bash) 交叉编译 Windows 产物
cd /d/Users/flowe/WorkBuddy/渗透/usbbackup
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -o dist/ github.com/immml/UsbBackUP/cmd/usbbackup github.com/immml/UsbBackUP/cmd/usbkeygen github.com/immml/UsbBackUP/cmd/usbcomp github.com/immml/UsbBackUP/cmd/usbunseal
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
| **`build-client`** | **产出内嵌配置与公钥的客户端 exe**（见下节） |
| **`install-usb`** | **组装一个便携工具 U 盘**：全套工具 + 客户端 + 密钥 + 授权标记 |
| `version` | 版本信息 |

自动化场景可加 `--yes` 跳过 `I AGREE` 交互。

### 4.1.1b 交互式生成向导 `usbsetup`

```powershell
.\usbsetup.exe
```

双击进黑窗口，一问一答五步走完（密钥 → 产物目录 → 阈值 → 打包上限 → 输出），
每步直接回车用默认值。与 `usbkeygen build-client` 共用同一份生成逻辑
（`internal/clientgen`），产物行为完全一致。

### 4.1.2 首次确认与静默运行

被部署端（客户端，或 `usbbackup` 本体）**首次用一条命令确认，之后无人值守静默运行**：

| 命令 | 作用 |
|---|---|
| `accept` | 展示完整安全警告与免责声明，要求输入 `I AGREE` |
| `accept --yes` | 部署脚本用：非交互记录确认 |
| `accept --check` | 查看当前是否已确认（未确认退出码 2） |
| `accept --revoke` | 撤销确认，恢复首次确认流程 |
| `accept --force` | 已确认时重新确认 |

确认后写入明文记录 `%LOCALAPPDATA%\usbbackup\agreement.json`
（含确认时间、程序版本、许可协议、客户端标识），此后 `run` / `once`
**不再展示横幅、不再要求输入**，直接执行。

```
未确认 ──► run/once 展示免责声明并要求 I AGREE ──► 拒绝则退出码 2
                    │ 输入 I AGREE
                    ▼
              写入 agreement.json ──► 之后 run/once 静默运行
```

要点：

- 记录**只能**由 `accept` 显式写入。命令行 `--yes` 只跳过**当次**确认，不留下记录——
  避免"跑一次脚本就永久静默"。
- 记录明文、可查看、可撤销；伪造或缺少确认短语的文件一律按"未确认"处理。
- 静默只是不再打扰：**不自启动、不加壳、不隐藏进程**，日志与审计照常写入。
- 服务由 SCM 启动、没有控制台，不做交互；`install-service` 会提示本机是否已确认。

典型部署序列：`accept --yes` → `install-service`（可选，需管理员）→ `start`。

### 4.1.1 产出客户端（推荐部署方式）

```powershell
# 1) 生成密钥对（私钥留在本地，绝不随客户端分发）
.\usbkeygen.exe generate --out .\keys

# 2) 产出客户端：配置与公钥硬编码进 exe
.\usbkeygen.exe build-client `
  --public .\keys\usbbackup.pub.pem `
  --template .\usbbackup.exe `
  --output-dir '%TEMP%\backup' `
  --threshold 10GiB `
  --name 'Client-A' `
  -o .\client.exe
```

产出的 `client.exe` 拿到目标机器上**直接运行即可**，不需要 config.json、不需要公钥文件：

```powershell
.\client.exe run          # 常驻监控（事件驱动）
.\client.exe once         # 处理当前已插入的盘后退出
.\client.exe probe        # 只读诊断，不写任何数据
```

常用选项：`--output-dir`（产物目录，支持 `%TEMP%`）、`--source-dir`（分支 A 的本地备份源）、
`--threshold`（容量阈值，支持 `10GiB`/`10GB`）、`--max-total`（打包上限，`0` 表示不限制）、
`--name`（客户端标识，写入内嵌配置便于溯源）、`--config`（以某份配置文件为基础）、`--force`。

**实现机制**：把 `usbbackup.exe` 复制一份，在文件末尾追加一个带 SHA-256 校验和的配置块
（PE 文件尾部追加数据不影响运行，自解压安装包用的是同一招）。客户端启动时从自身读取该块。
生成器不要求目标机器有 Go 工具链。

**为什么这么设计**：生成器在**你的机器**上跑一次，产出的客户端自带一切；
目标机器上没有可改的配置文件，也就无法通过改配置来改变客户端行为。
客户端模式下 `--config` 会被明确忽略并在输出中提示。

**内嵌内容只有配置与公钥**：任何把私钥塞进客户端的尝试都会被拒绝
（`embedcfg.EnsureNoSecret`），因为客户端会落在他人可控的机器上，内嵌即等于公开。

### 4.2 主程序 `usbbackup`

| 子命令 | 说明 |
|---|---|
| `run` | 前台常驻运行（事件驱动 + 轮询兜底），Ctrl+C 退出 |
| `once --drive E:` | 对单个盘符执行一次作业（验证与排障用） |
| `list [--all]` | 列出可移动卷及其容量 |
| `probe --drive E:` | 只读诊断：卷信息 + 私钥检测结论 + 将走哪个分支（**不写任何数据**） |
| `config-check` | 校验配置与运行环境（源目录、输出目录可写、公钥、审计目录、源守卫） |
| `install-service` / `uninstall-service` | 注册 / 删除 Windows 服务（需管理员） |
| `start` / `stop` / `status` | 控制已注册的服务 |
| `version` | 版本信息 |

`run` / `once` 选项：

| 选项 | 说明 |
|---|---|
| `--dry-run` | 只做检测与门控判定，不写入任何数据 |
| `--poll-only` | 强制仅用轮询通道（排障用；默认事件驱动） |
| `--allow-fixed` | 允许对固定磁盘执行作业。**仅供验证与排障**，生产不要开启 |
| `--overwrite` | 回写时覆盖目标同名文件（默认跳过） |
| `--verify-hash` | 回写后按 SHA-256 逐文件校验 |
| `--service` | 以 Windows 服务方式运行（由 SCM 调用，勿手工执行） |
| `--simulate-arrival E:` | 注入一次模拟的"卷到达"事件，用于在没有物理介质时验证完整链路 |

> 建议：第一次在任何机器上运行前，先 `usbbackup probe --drive <盘符>` 确认判定结果符合预期。
> 该命令**只读**，不写任何数据。本机没有可移动介质时，可用
> `usbbackup once --drive C: --allow-fixed --dry-run` 验证判定与门控逻辑。

### 4.2.1 注册为 Windows 服务（需管理员）

```powershell
cd D:\path\to\usbbackup
.\usbbackup.exe install-service
.\usbbackup.exe start
.\usbbackup.exe status
```

服务启动类型为**手动**（不会自动开机启动）。要开机自启请显式执行
`sc.exe config usbbackup start= auto` —— 本工具刻意不代劳（见 `REQUIREMENTS.md` G-07）。

> **部署注意（实测发现）**：服务以 `LocalSystem` 运行，此时 `%LOCALAPPDATA%` 解析为
> `C:\Windows\System32\config\systemprofile\AppData\Local`，而不是当前用户的目录。
> 因此服务部署**必须**在 `config.json` 里写**绝对路径**（配置、密钥、输出目录、日志），
> 或把 `--config` 指向绝对路径的配置文件。否则会出现"日志不知道去哪了"。

### 4.3 压缩器 `usbcomp`

```powershell
.\usbcomp.exe pack D:\重要资料 -o D:\out\mybackup.usbk
```

`--store` 全部不压缩、`--exclude <模式>` 追加排除项（可重复）、`--threads` 并发度提示、
`--keep-plain-zip` 额外保留明文 zip、`--quiet` 不输出进度。
源目录 → 流式 zip → 混合加密 → 单一 `.usbk`。源目录全程只读。

### 4.4 解压器 `usbunseal`

```powershell
# 查看容器头（无需私钥）
.\usbunseal.exe list D:\out\mybackup.usbk

# 校验完整性（不解出明文）
.\usbunseal.exe verify D:\out\mybackup.usbk --key .\usbbackup.key.pem --pass

# 解密并解压到指定目录
.\usbunseal.exe unseal D:\out\mybackup.usbk -d D:\restore --key .\usbbackup.key.pem
```

`--dry-run` 只校验条目不写入、`--force` 覆盖已存在文件、`--keep-zip` 只解出明文 zip。

安全设计：目标目录必须显式指定；默认不覆盖已存在文件；拒绝一切可能逃逸目标目录的条目名（Zip Slip 防护）；
对"解压炸弹"设有单条目与总量双上限；解密失败时统一报错，不区分「密钥错误」与「数据被篡改」。

---

## 5. 配置

配置文件默认位于 `%LOCALAPPDATA%\usbbackup\config.json`，也可用 `--config` 指定。

优先级：**命令行 flag > 环境变量 `USBBACKUP_*` > `config.json` > 内置默认值**。

```json
{
  "backup_source_dir": "%USERPROFILE%\\usbbackup-source",
  "output_dir": "%TEMP%\\backup",
  "public_key_path": "C:\\ProgramData\\usbbackup\\keys\\usbbackup.pub.pem",
  "authorized_backup_subdir": "backup",
  "audit_file": "%LOCALAPPDATA%\\usbbackup\\audit.jsonl",
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
    "marker_file": ".usbbackup-allow",
    "scan_contents": true,
    "extra_name_patterns": [],
    "extra_content_markers": []
  },
  "gate": {
    "used_threshold": "10GiB",
    "used_threshold_bytes": 10737418240,
    "max_total_bytes": 10737418240,
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

支持的 `USBBACKUP_*` 环境变量：
`USBBACKUP_BACKUP_SOURCE_DIR`、`USBBACKUP_OUTPUT_DIR`、`USBBACKUP_PUBLIC_KEY`、`USBBACKUP_LOG_LEVEL`、
`USBBACKUP_AUDIT_FILE`、`USBBACKUP_USED_THRESHOLD`（人类可读，如 `10GiB`）、
`USBBACKUP_USED_THRESHOLD_BYTES`、`USBBACKUP_MAX_TOTAL_BYTES`、`USBBACKUP_POLL_INTERVAL_SEC`。

路径支持 `%VAR%` 与 `${VAR}` 展开。配置优先级冲突时高优先级生效，并以 DEBUG 级记录来源。

### 容量阈值与打包上限

`gate` 段有两个值，含义不同：

| 字段 | 含义 | 默认 | 比较对象 |
|---|---|---|---|
| `used_threshold` / `used_threshold_bytes` | 超过就**不备份** | `10GiB` | 卷的已占用容量 |
| `max_total_bytes` | 超过就**不打包** | `10GiB`（`0` 表示不限制） | 待打包的数据量（同样是已占用容量） |

**单位可以写清楚**，避免裸字节数写错位数：

- `"10GiB"` / `"10G"` → 10 × 1024³（二进制，Windows 资源管理器口径）
- `"10GB"` → 10 × 1000³（十进制，硬盘厂商标称口径）
- 还支持 `KiB` / `MiB` / `TiB` / `KB` / `MB` / `TB` 与小数（如 `1.5TiB`）

两种写法表达同一件事，**只写其中一种**。同时写且含义不一致时配置校验会直接报错。

> 注意：`max_total_bytes` 比的是**待打包的数据量**，不是介质容量。
> 一块 64 GiB 的 U 盘只用了 500 MiB 会正常备份；反之若拿容量来比，
> 大容量小占用的盘会被全部跳过，与意图相反。

### 授权标记（可选，比启发式更确定）

在 U 盘根目录放一个 `.usbbackup-allow`，内容为已登记公钥的指纹：

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
usbbackup/
├── cmd/
│   ├── usbbackup/        常驻主程序（监控 / 编排 / 诊断）
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
| M2 | `archive` 流式打包 / 安全解包执行器 + `copier` 复制执行器 | ✅ 完成（含单测） |
| M3 | `winvol` 卷信息与门控 + `keyfile` 私钥存在性检测 | ✅ 完成（含单测） |
| M4 | `winmon` 设备监控 + `backup` 流水线 + `winsvc` 服务化 | ✅ 完成（含单测） |
| M5 | 4 个 CLI + 构建脚本 + Windows 实机验证 | ✅ 完成 |

全部模块均有单元测试覆盖，`go vet ./...` 与 `go test ./...` 全绿。

### 8.1 实机验证记录

以下场景均以**真实二进制**跑通（不只是单测）：

| 场景 | 结果 |
|---|---|
| 容量门控：已占用 193 GiB > 阈值 10 GiB | 正确跳过，审计记录 `branch=skipped` / `skip_reason=used-over-threshold` |
| 分支 B：整盘打包 + 混合加密 | 生成 `VOL_X.zip.usbk`；`unseal` 解出后与原始目录**逐字节一致** |
| 分支 A：介质含 `id_rsa` | 识别为已授权，回写 3 个文件到 `\backup\`，源目录零改动，清单已生成 |
| 常驻 `run`（事件通道 + 模拟到达） | 两个分支均正确执行，作业队列串行化生效 |
| 单实例互斥 | 第二个实例被拒，退出码 4 |
| Zip Slip | 真实构造含 `../` 与绝对路径条目的容器 → 2 个条目被阻断，无文件逃出目标目录，退出码 5 |
| 错误私钥 / 篡改 / 截断 | 全部被拒绝 |
| Windows 服务 | install → start（STATE 4 RUNNING）→ stop → uninstall 全链路通过，卸载后无残留 |

### 8.2 由"跑一遍"发现并修复的缺陷

这些缺陷**单测无法发现**，全部是实际运行才暴露的：

| # | 缺陷 | 后果 |
|---|---|---|
| 1 | `fsutil.IsSubPath` 对卷根重复追加分隔符（`E:\` → `E:\\`） | 子路径判定恒为假，源守卫与自复制守卫**双双失效** |
| 2 | `winvol.Query` 对非可移动卷提前返回 | 容量/就绪全为 0，诊断输出无用 |
| 3 | Go `flag` 包遇位置参数即停止解析 | `usbkeygen use <路径> --config x`、`usbcomp pack <目录> -o out` 全部失效 |
| 4 | 容器头把算法方案标为固定 `RSA-4096` | 与实际 2048 位密钥不符，误导运维 |
| 5 | `DEV_BROADCAST_VOLUME.dbcv_size` 用 `unsafe.Sizeof` 填充 | Go 结构体对齐补到 20 字节（C 结构为 18），`RegisterDeviceNotificationW` 返回 `ERROR_INVALID_DATA`，事件通道完全不可用 |
| 6 | 服务模式仍要求 `I AGREE` 交互确认 | SCM 拉起进程立即退出，报 1053「服务没有及时响应启动或控制请求」 |
| 7 | 直接转述 `sc.exe` 输出 | 中文系统下 sc.exe 输出 GBK，按 UTF-8 解码成乱码；改为翻译退出码 + 只取 ASCII 行 |

另外修正了一处**设计假设错误**：卷到达事件不能通过消息专用窗口 +
`RegisterDeviceNotificationW` 获取（消息专用窗口不在广播范围，且 `DBT_DEVTYP_VOLUME`
不是合法过滤器类型），已改为隐藏的顶层窗口接收默认广播。详见 `REQUIREMENTS.md` D-01。

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
