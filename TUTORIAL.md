# usbbackup 使用教程

从零开始走一遍：**生成密钥 → 产出客户端 → 部署 → 取回 → 还原**。

> ⚠️ 开工前请先读 [DISCLAIMER.md](DISCLAIMER.md)。本工具仅限用于你本人自有、
> 或已获得明确书面授权的设备与存储介质。

---

## 0. 先搞清楚三件事

### 三个角色

| 角色 | 程序 | 在哪跑 | 手里有什么 |
|---|---|---|---|
| **生成器** | `usbkeygen.exe` | 你的机器 | 生成密钥对；**私钥留在你这里** |
| **客户端** | 生成器产出的 `client.exe` | 目标机器 | 只有**公钥 + 配置**，内嵌在 exe 里 |
| **解压器** | `usbunseal.exe` | 你的机器 | 用**私钥**解密还原 |

客户端**没有私钥**——即使整个 exe 被拷走，也解不开它自己产出的文件。

### 插入 U 盘后会发生什么

```
插入 U 盘
   │
   ├─► 检测到"疑似私钥文件" ──► 分支 A：把本地备份文件夹复制到 <U盘>:\backup\
   │                              （只写这个目录，不删不改写源盘任何文件）
   │
   └─► 未检测到 ──► 已占用容量 > 阈值？
                      ├─ 是 ──► 跳过，什么都不做
                      └─ 否 ──► 分支 B：整盘打包 + 混合加密
                                 → <输出目录>\{卷标}.zip.usbk
                                 （源盘全程只读，不删任何文件）
```

两个分支都**不会删除、移动、改写源介质上的任何文件**。

### 阈值与上限（容易混淆）

| 字段 | 含义 | 默认 | 比的是 |
|---|---|---|---|
| `used_threshold` | 超过就**不备份** | 10 GiB | 卷的已占用容量 |
| `max_total_bytes` | 超过就**不打包** | 10 GiB（`0`=不限制） | 待打包的数据量（同样是已占用） |

单位可以写清楚：`10GiB`（二进制，Windows 口径）/ `10GB`（十进制，厂标口径）/ `1.5TiB`。

---

## 1. 准备

把四个 exe 放在**同一个目录**（`build-client` 默认在这里找 `usbbackup.exe` 模板）：

```
D:\usbbackup\
├── usbkeygen.exe    生成器
├── usbbackup.exe    主程序（同时是客户端模板）
├── usbunseal.exe    解压器
└── usbcomp.exe      独立压缩器（可选，手工打包用）
```

---

## 2. 第一步：生成密钥对（你的机器）

```powershell
# PowerShell
cd D:\usbbackup
.\usbkeygen.exe generate --out .\keys
```

完成后 `.\keys\` 下有两个文件：

| 文件 | 说明 |
|---|---|
| `usbbackup.pub.pem` | 公钥 —— 会被内嵌进客户端，可以公开 |
| `usbbackup.key.pem` | 私钥 —— **只留在你这里**，解密全靠它 |

**建议加口令**（私钥落盘时加密）：

```powershell
.\usbkeygen.exe generate --out .\keys --pass
```

常用选项：`--bits 4096`（默认）、`--force`（覆盖已有）、`--pass-file <文件>`（脚本用）。

> 🔒 **私钥与口令一旦丢失，密文无法恢复。** 没有后门、没有找回机制。
> 立刻把 `keys\` 整个目录备份到离线介质。

确认公钥没问题：

```powershell
.\usbkeygen.exe inspect .\keys\usbbackup.pub.pem --yes
```

---

## 3. 第二步：产出客户端

```powershell
.\usbkeygen.exe build-client `
  --public .\keys\usbbackup.pub.pem `
  -o .\client.exe `
  --output-dir 'C:\ProgramData\usbbackup\out' `
  --threshold 10GiB `
  --name 'Office-PC-01' `
  --yes
```

产出 `client.exe`。它的配置与公钥已经**硬编码在里面**。

| 选项 | 说明 |
|---|---|
| `--public` | 公钥 PEM（**必填**，传私钥会被拒绝） |
| `-o` | 输出客户端路径（**必填**） |
| `--output-dir` | 产物输出目录，支持 `%TEMP%` 等变量；默认 `%TEMP%\backup` |
| `--source-dir` | 分支 A 的本地备份源目录（想用回写功能就设它） |
| `--threshold` | 容量阈值，如 `10GiB` / `500MiB` |
| `--max-total` | 打包上限，`0` 表示不限制 |
| `--name` | 客户端标识，写进内嵌配置便于溯源 |
| `--template` | 客户端模板，默认同目录的 `usbbackup.exe` |
| `--config` | 以某份 config.json 为基础再覆盖 |
| `--force` | 覆盖已存在的输出文件 |

**检查产出的客户端**（可选但推荐）：

```powershell
.\client.exe config-check
```

应看到 `内嵌公钥可用 2048 位，指纹 …` 与 `产物输出目录可写 …`。

---

## 4. 第三步：部署到目标机器

把 **`client.exe` 一个文件**拷到目标机器即可——不需要 config.json，不需要公钥文件。

### 4.1 首次确认（一次即可）

```powershell
.\client.exe accept
```

会展示完整安全警告与免责声明，输入 `I AGREE` 回车。批量部署用脚本：

```powershell
.\client.exe accept --yes
```

确认后写明文记录 `%LOCALAPPDATA%\usbbackup\agreement.json`，此后不再提示。

| 命令 | 作用 |
|---|---|
| `accept --check` | 查看是否已确认（未确认退出码 2） |
| `accept --revoke` | 撤销，恢复首次确认流程 |
| `accept --force` | 已确认时重新确认 |

> `--yes`（全局开关）只跳过**当次**确认，不写记录。永久静默只能靠 `accept`。

### 4.2 运行

```powershell
.\client.exe run      # 常驻监控，U 盘插入即自动处理
.\client.exe once     # 处理当前已插入的盘，然后退出
.\client.exe list     # 列出可移动卷
.\client.exe probe --drive E:   # 只读诊断：会走哪个分支（不写任何数据）
```

想开机就在后台跑，注册成服务（需管理员）：

```powershell
.\client.exe install-service
.\client.exe start
.\client.exe status
```

服务是**手动启动**类型，本工具不写任何自启动项。

---

## 5. 第四步：取回产物

产物在客户端的 `output_dir`（默认 `%TEMP%\backup`），文件名形如：

```
MyUSB.zip.usbk
VOL_E.zip.usbk          # 卷标为空时用 VOL_<盘符>
```

同卷默认保留最近 **5 份**。把 `.usbk` 文件拷回你的机器。

---

## 6. 第五步：解密还原（你的机器）

### 先看容器头（不需要私钥）

```powershell
.\usbunseal.exe list .\MyUSB.zip.usbk
```

可以看到容器版本、密钥包装算法、**公钥指纹**、分块大小等。

### 校验完整性（需要私钥，不落盘）

```powershell
.\usbunseal.exe verify .\MyUSB.zip.usbk --key .\keys\usbbackup.key.pem --yes
```

### 解密并解压

```powershell
.\usbunseal.exe unseal .\MyUSB.zip.usbk -d .\restore --key .\keys\usbbackup.key.pem --yes
```

私钥带口令时会提示输入（无回显）。

> 用错私钥会直接失败——这是设计：**没有后门**。
> 解密失败时统一报错，不区分"密钥错"与"数据被篡改"。

---

## 7. 进阶：用回写分支（分支 A）

想在"检测到疑似私钥的 U 盘"上**写入**本地备份，生成客户端时指定源目录：

```powershell
.\usbkeygen.exe build-client `
  --public .\keys\usbbackup.pub.pem `
  -o .\client.exe `
  --source-dir 'D:\我的备份资料' `
  --yes
```

此后插入的盘若被判定"持有私钥"，就会把 `D:\我的备份资料` 复制到 `<U盘>:\backup\`。

**更确定的做法**（不依赖文件名/内容启发式）：在 U 盘根目录放 `.usbbackup-allow`，
内容是**公钥指纹**：

```
fingerprint=6aea c417 ed1d e038 ...
```

指纹从 `usbkeygen inspect` 或 `client.exe config-check` 里取。

> 关于"私钥检测"：只做**存在性判定**——比对文件名模式与文件开头 4 KiB 的内容特征，
> 不读取、不解析、不复制、不外传任何私钥内容，缓冲区用完即清零。
> 日志与审计只记布尔值和命中计数。

---

## 8. 进阶：不生成客户端，本机直接用

```powershell
# 1) 登记公钥到配置
.\usbkeygen.exe use .\keys\usbbackup.pub.pem

# 2) 改配置（可选）
notepad "$env:LOCALAPPDATA\usbbackup\config.json"

# 3) 首次确认后运行
.\usbbackup.exe accept
.\usbbackup.exe run
```

配置文件默认在 `%LOCALAPPDATA%\usbbackup\config.json`，可用 `--config` 指定。
优先级：**内嵌配置（客户端）> 命令行 > 环境变量 `USBBACKUP_*` > config.json > 内置默认**。

只想手工打包某个目录（不走监控）：

```powershell
.\usbcomp.exe pack D:\资料 -o D:\out\my.usbk --public .\keys\usbbackup.pub.pem --yes
```

---

## 9. 排障

### 退出码

| 码 | 含义 | 怎么处理 |
|---|---|---|
| 0 | 成功 | — |
| 1 | 命令行用法错误 | 看该子命令的用法输出 |
| 2 | 未确认免责声明 | 执行 `accept` |
| 4 | 运行期错误 | 看日志与错误信息 |
| 5 | 部分成功 | `config-check` 里有未通过项 |

### 日志

- 默认：`%LOCALAPPDATA%\usbbackup\logs\usbbackup.log`
- 审计：`%LOCALAPPDATA%\usbbackup\audit.jsonl`（JSON Lines，**不含文件名与内容**）
- 级别在配置里调：`"log": {"level": "debug"}`

### 常见问题

**`client.exe run` 没反应？**
它是 `windowsgui` 程序，双击不会弹窗口。看日志或任务管理器里的进程。

**提示"未检测到私钥，容量门控跳过"？**
U 盘已占用容量超过阈值。调大 `--threshold` 重新生成客户端。

**`probe` 报"不是可移动卷"？**
`probe` 只接受真实可移动介质。对固定盘验证请用 `once --drive X: --allow-fixed`
（`--allow-fixed` 仅供排障，生产不要开）。

**服务启动报 1053？**
确认服务映像路径存在且是**绝对路径**。服务以 LocalSystem 运行时
`%LOCALAPPDATA%` 解析到 `C:\Windows\System32\config\systemprofile\AppData\Local`，
与交互式运行**不是同一路径**——服务部署务必在配置里写绝对路径。

**`sc.exe` 相关输出乱码？**
已知问题已处理：程序只取 `sc` 输出的 ASCII 行并翻译退出码。

**插入 U 盘没触发？**
先 `.\client.exe list` 看盘符是否被识别；再用 `--poll-only` 验证轮询通道是否可用。

---

## 10. 安全检查清单

部署前逐条确认：

- [ ] 私钥已离线备份（U 盘 / 纸质），口令单独保存
- [ ] 客户端里**只有公钥**——`build-client` 传私钥会被拒绝
- [ ] 目标设备是你自有或已获**明确书面授权**的
- [ ] 只把 `client.exe` 拷到目标机器，**不要拷 `keys\` 目录**
- [ ] 未使用 `--allow-fixed`（生产环境）
- [ ] 产物输出目录不在被扫描的盘上（防递归套娃，程序已有守卫）

---

## 11. 一图流

```
你的机器                          目标机器                    你的机器
─────────                        ─────────                  ─────────
usbkeygen generate  ──┐
  私钥 usbbackup.key.pem（留在本地）
  公钥 usbbackup.pub.pem
                      │
usbkeygen build-client ┘
      │
      └─► client.exe ──────────►  client.exe accept    ← 首次确认一次
          （内嵌配置+公钥）        client.exe run       ← 之后静默运行
                                      │
                                   插入 U 盘
                                      │
                              打包 + 混合加密
                                      │
                                  MyUSB.zip.usbk ─────►  usbunseal unseal
                                                          --key 私钥
                                                              │
                                                           还原文件
```

---

相关文档：[README.md](README.md)（完整说明）· [REQUIREMENTS.md](REQUIREMENTS.md)（需求表）·
[DISCLAIMER.md](DISCLAIMER.md)（免责声明）· [LICENSE](LICENSE)（CC BY-NC-SA 4.0）
