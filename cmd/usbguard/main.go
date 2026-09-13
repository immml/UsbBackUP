// Command usbguard 是常驻主程序（需求 F-101 ~ F-107 / F-801 ~ F-809 / F-1xx）。
//
// 用法：
//
//	usbguard run                   前台常驻运行（事件驱动 + 轮询兜底）
//	usbguard once [--drive E:]     对单个盘符执行一次作业（用于验证与排障）
//	usbguard list                  列出当前可移动卷及其容量
//	usbguard probe --drive E:      只读诊断：卷信息 + 私钥检测结论（不写任何数据）
//	usbguard config-check          校验配置文件与运行环境
//	usbguard version               显示版本信息
//
// 说明：`run` / `once` 的流水线执行器计划于 M4 完成；`list` / `probe` /
// `config-check` 已可用，且全部为只读操作，可安全地在生产机上先做验证。
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/immml/UsbBackup/internal/backup"
	"github.com/immml/UsbBackup/internal/cli"
	"github.com/immml/UsbBackup/internal/config"
	"github.com/immml/UsbBackup/internal/fsutil"
	"github.com/immml/UsbBackup/internal/keyfile"
	"github.com/immml/UsbBackup/internal/version"
	"github.com/immml/UsbBackup/internal/winvol"
)

const toolName = "usbguard"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return cli.ExitUsage
	}
	sub, rest := args[0], args[1:]

	switch sub {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version.MultiLine())
		return cli.ExitOK
	case "help", "--help", "-h":
		printUsage(stdout)
		return cli.ExitOK
	}

	cfgPath, skipConfirm := cli.ExtractGlobalFlags(args)

	// 常驻运行会写数据，因此需要确认；只读诊断子命令不打扰用户。
	switch sub {
	case "run", "once":
		if skipConfirm {
			cli.RenderNotice(stdout, toolName)
		} else {
			cli.RenderBanner(stdout, toolName)
			if err := cli.ConfirmAgreement(stdin, stdout); err != nil {
				return cli.ExitNotAgreed
			}
		}
	}

	switch sub {
	case "config-check":
		return cmdConfigCheck(cfgPath, stdout, stderr)
	case "list":
		return cmdList(rest, stdout, stderr)
	case "probe":
		return cmdProbe(rest, cfgPath, stdout, stderr)
	case "once":
		return cmdOnce(rest, stdout, stderr)
	case "run":
		return cmdRun(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知子命令 %q\n\n", sub)
		printUsage(stderr)
		return cli.ExitUsage
	}
}

func printUsage(w io.Writer) {
	cli.PrintHelp(w, "usbguard —— Windows 专用 USB 自动备份与加密工具", []string{
		"用法：",
		"  usbguard run [--config 路径] [--yes]            前台常驻运行",
		"  usbguard once [--drive E:] [--yes]              单次执行一个盘符的作业",
		"  usbguard list                                   列出当前可移动卷",
		"  usbguard probe --drive E:                       只读诊断（不写任何数据）",
		"  usbguard config-check                           校验配置与运行环境",
		"  usbguard version                                显示版本信息",
		"",
		"行为概述：",
		"  检测到介质持有私钥 → 把本地备份文件夹内容复制到该介质 \\backup\\ 目录；",
		"  未检测到私钥       → 若已占用容量 ≤ 阈值则整盘打包并混合加密到 %TEMP%\\backup\\，",
		"                       超过阈值则直接跳过。",
		"  两个分支都不会删除或改写源介质上的任何文件。",
		"",
		"提示：首次使用建议先跑 `usbguard probe --drive <盘符>` 确认判定结果符合预期。",
	})
}

// loadConfig 统一加载配置：命令行 --config > 默认路径 > 内置默认，并叠加环境变量。
//
// cfgPath 由 cli.ExtractGlobalFlags 在入口统一取出，此处不再自行解析参数。
func loadConfig(cfgPath string, stderr io.Writer) (*config.Config, string, int) {
	cfg, loaded, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return nil, "", cli.ExitRuntime
	}
	cfg.ApplyEnv()
	resolved := cfgPath
	if resolved == "" {
		resolved = config.DefaultConfigPath()
	}
	if !loaded {
		fmt.Fprintf(stderr, "提示：未找到配置文件 %s，本次使用内置默认值。\n", resolved)
	}
	return cfg, resolved, cli.ExitOK
}

func cmdConfigCheck(cfgPath string, stdout, stderr io.Writer) int {
	cfg, path, code := loadConfig(cfgPath, stderr)
	if cfg == nil {
		return code
	}
	fmt.Fprintf(stdout, "配置文件：%s\n\n", path)
	fmt.Fprintln(stdout, "生效配置：")
	for _, line := range cfg.Summary() {
		fmt.Fprintf(stdout, "  %s\n", line)
	}

	problems := 0
	fmt.Fprintln(stdout, "\n检查项：")
	report := func(name string, ok bool, detail string) {
		mark := "OK  "
		if !ok {
			mark = "FAIL"
			problems++
		}
		fmt.Fprintf(stdout, "  [%s] %s %s\n", mark, name, detail)
	}

	src := config.ExpandPath(cfg.BackupSourceDir)
	if st, err := os.Stat(fsutil.LongPath(src)); err == nil && st.IsDir() {
		report("备份源目录存在", true, src)
	} else {
		report("备份源目录存在", false, fmt.Sprintf("%s（授权分支将无数据可回写）", src))
	}

	out := config.ExpandPath(cfg.OutputDir)
	if err := os.MkdirAll(out, 0o755); err != nil {
		report("产物输出目录可写", false, fmt.Sprintf("%s（%v）", out, err))
	} else {
		f, err := os.CreateTemp(out, ".usbguard-writecheck-*")
		if err != nil {
			report("产物输出目录可写", false, fmt.Sprintf("%s（%v）", out, err))
		} else {
			name := f.Name()
			_ = f.Close()
			_ = os.Remove(name)
			report("产物输出目录可写", true, out)
		}
	}

	pubPath := config.ExpandPath(cfg.PublicKeyPath)
	if _, err := os.Stat(pubPath); err == nil {
		report("公钥文件存在", true, fmt.Sprintf("%s（执行 probe 可校验其可用性）", pubPath))
	} else {
		report("公钥文件存在", false, fmt.Sprintf("%s（未登记公钥则无法执行加密）", pubPath))
	}

	audit := config.ExpandPath(cfg.AuditFile)
	if err := os.MkdirAll(dirOf(audit), 0o755); err == nil {
		report("审计目录可写", true, audit)
	} else {
		report("审计目录可写", false, fmt.Sprintf("%s（%v）", audit, err))
	}

	if problems > 0 {
		fmt.Fprintf(stderr, "\n共 %d 项检查未通过。\n", problems)
		return cli.ExitPartial
	}
	fmt.Fprintln(stdout, "\n全部检查通过。")
	return cli.ExitOK
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			if i == 0 {
				return p[:1]
			}
			return p[:i]
		}
	}
	return "."
}

func cmdList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showAll := fs.Bool("all", false, "显示全部盘符（含固定磁盘、光驱等）")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}

	roots, err := winvol.Roots()
	if err != nil {
		fmt.Fprintf(stderr, "枚举盘符失败：%v\n", err)
		return cli.ExitRuntime
	}
	if len(roots) == 0 {
		fmt.Fprintln(stdout, "未检测到任何盘符。")
		return cli.ExitOK
	}

	// 列宽按显示宽度计算（CJK 字符占两列），否则中文列名会导致表格错位。
	const (
		wDrive, wType, wReady, wFS = 7, 12, 6, 10
		wTotal, wUsed, wFree       = 12, 12, 12
	)
	line := func(drive, typ, ready, fsname, total, used, free, label string) {
		fmt.Fprintf(stdout, "%s %s %s %s %s %s %s  %s\n",
			padRight(drive, wDrive), padRight(typ, wType), padRight(ready, wReady),
			padRight(fsname, wFS), padLeft(total, wTotal), padLeft(used, wUsed),
			padLeft(free, wFree), label)
	}
	line("盘符", "类型", "就绪", "文件系统", "总容量", "已占用", "剩余", "卷标")

	shownRemovable := 0
	for _, r := range roots {
		v, qerr := winvol.Query(r)
		if !v.Removable {
			if !*showAll {
				continue
			}
			line(v.Root, winvol.DriveTypeName(v.DriveType), yesNo(v.Ready),
				emptyDash(v.FileSystem), fsutil.HumanBytes(v.TotalBytes),
				fsutil.HumanBytes(v.UsedBytes), fsutil.HumanBytes(v.FreeBytes), emptyDash(v.Label))
			continue
		}
		shownRemovable++
		line(v.Root, winvol.DriveTypeName(v.DriveType), yesNo(v.Ready),
			emptyDash(v.FileSystem), fsutil.HumanBytes(v.TotalBytes),
			fsutil.HumanBytes(v.UsedBytes), fsutil.HumanBytes(v.FreeBytes), emptyDash(v.Label))
		// 可移动卷但读取异常时给出原因，便于排障。
		if qerr != nil && v.Ready {
			fmt.Fprintf(stdout, "  注：%v\n", qerr)
		}
	}

	if shownRemovable == 0 && !*showAll {
		fmt.Fprintln(stdout, "\n当前没有可移动卷。插好 U 盘后重试，或用 `list --all` 查看全部盘符。")
	}
	return cli.ExitOK
}

func cmdProbe(args []string, cfgPath string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	drive := fs.String("drive", "", "盘符，如 E:（必填）")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	cfg, _, code := loadConfig(cfgPath, stderr)
	if cfg == nil {
		return code
	}
	if *drive == "" {
		fmt.Fprintln(stderr, "错误：必须指定 --drive，例如 --drive E:")
		return cli.ExitUsage
	}

	root, err := winvol.NormalizeRoot(*drive)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitUsage
	}

	fmt.Fprintln(stdout, "只读诊断（本命令不写任何数据、不修改任何文件）：")
	fmt.Fprintf(stdout, "  目标卷根        : %s\n", root)

	v, qerr := winvol.Query(root)
	fmt.Fprintf(stdout, "  卷类型          : %s\n", winvol.DriveTypeName(v.DriveType))
	if !v.Removable {
		fmt.Fprintln(stdout, "  判定            : 非可移动卷 → 生产运行时会直接跳过（F-301）")
		if qerr != nil {
			fmt.Fprintf(stdout, "  查询补充        : %v\n", qerr)
		}
		return cli.ExitPartial
	}
	if !v.Ready {
		fmt.Fprintf(stdout, "  就绪            : 否（%v）\n", qerr)
		fmt.Fprintln(stdout, "  判定            : 卷未就绪 → 生产运行时会跳过（F-305）")
		return cli.ExitPartial
	}
	fmt.Fprintf(stdout, "  卷标 / 文件系统 : %s / %s\n",
		winvol.LabelOrFallback(v), emptyDash(v.FileSystem))
	fmt.Fprintf(stdout, "  卷序列号        : %08X\n", v.SerialNumber)
	fmt.Fprintf(stdout, "  总容量/已占用/剩余: %s / %s / %s\n",
		fsutil.HumanBytes(v.TotalBytes), fsutil.HumanBytes(v.UsedBytes), fsutil.HumanBytes(v.FreeBytes))
	fmt.Fprintf(stdout, "  产物命名(分支B) : %s\n", backup.ProductName(v))

	// 私钥存在性检测（只读）。
	m, err := keyfile.NewMatcher(cfg.Detect.ExtraNamePatterns, cfg.Detect.ExtraContentMarkers, cfg.Detect.MaxHeadersBytes)
	if err != nil {
		fmt.Fprintf(stderr, "错误：构造检测器失败：%v\n", err)
		return cli.ExitRuntime
	}
	fp := ""
	if cfg.PublicKeyPath != "" {
		if pub, err := loadPubFingerprint(cfg.PublicKeyPath); err == nil {
			fp = pub
		}
	}
	res, err := keyfile.Scan(osCtx(), keyfile.Options{
		Root: root, Matcher: m, Detect: cfg.Detect, AllowedFingerprint: fp,
	})
	if err != nil {
		fmt.Fprintf(stderr, "检测失败：%v\n", err)
		return cli.ExitRuntime
	}
	// 注意：这里只输出布尔值与计数，不输出命中文件名（G-02）。
	fmt.Fprintf(stdout, "  私钥存在性      : %v（命中 %d 次，类型 %v）\n",
		res.Authorized, res.HitCount, res.Kinds)
	fmt.Fprintf(stdout, "  检测开销        : 检查 %d 个文件 / %d 个目录，读取 %s，耗时 %s%s\n",
		res.FilesScanned, res.DirsScanned, fsutil.HumanBytes(res.BytesRead), res.Duration,
		truncatedNote(res.Truncated))

	if res.Authorized {
		target, cerr := copierTarget(cfg, root)
		if cerr != nil {
			fmt.Fprintf(stdout, "  将执行          : 分支 A（回写本地备份）— 前置校验未通过：%v\n", cerr)
			return cli.ExitPartial
		}
		fmt.Fprintf(stdout, "  将执行          : 分支 A — 把 %s 复制到 %s\n",
			config.ExpandPath(cfg.BackupSourceDir), target)
		fmt.Fprintln(stdout, "                    只在该目录内写入，不删除源盘任何文件。")
	} else {
		policy := winvol.EvaluateGate(v, cfg.Gate.UsedThresholdBytes, cfg.Gate.MaxTotalBytes)
		if policy.Proceed {
			fmt.Fprintf(stdout, "  将执行          : 分支 B — 整盘打包并混合加密到 %s\\%s\n",
				config.ExpandPath(cfg.OutputDir), backup.ProductName(v))
			fmt.Fprintln(stdout, "                    源盘只读，不删除源文件。")
		} else {
			fmt.Fprintf(stdout, "  将执行          : 跳过（%s）\n", policy.Reason)
		}
	}
	return cli.ExitOK
}

func cmdOnce(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "once：单盘作业执行器尚未实现（计划于 M4）。")
	fmt.Fprintln(stderr, "现在可先用 `usbguard probe --drive <盘符>` 做只读验证。")
	return cli.ExitNotImplemented
}

func cmdRun(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "run：常驻监控与流水线尚未实现（计划于 M4）。")
	fmt.Fprintln(stderr, "现在可先用 `usbguard list` 与 `usbguard probe` 验证卷信息与判定逻辑。")
	return cli.ExitNotImplemented
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

// padRight / padLeft 按**显示宽度**补齐（CJK 字符占两列）。
// 只用了 fmt 的 %-Ns 会按字节/字符数计算，中文列必然错位。
func padRight(s string, width int) string {
	w := dispWidth(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

func padLeft(s string, width int) string {
	w := dispWidth(s)
	if w >= width {
		return s
	}
	return strings.Repeat(" ", width-w) + s
}

func dispWidth(s string) int {
	n := 0
	for _, r := range s {
		if isWideRune(r) {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// isWideRune 判断是否为双宽字符（East Asian Wide / Fullwidth）。
func isWideRune(r rune) bool {
	switch {
	case r < 0x1100:
		return false
	case r >= 0x1100 && r <= 0x115F, // Hangul Jamo
		r >= 0x2E80 && r <= 0x303E,   // CJK 部首 / 标点
		r >= 0x3041 && r <= 0x33FF,   // 假名 / CJK 兼容
		r >= 0x3400 && r <= 0x4DBF,   // CJK 扩展 A
		r >= 0x4E00 && r <= 0x9FFF,   // CJK 统一表意文字
		r >= 0xA000 && r <= 0xA4CF,   // 彝文
		r >= 0xAC00 && r <= 0xD7A3,   // Hangul 音节
		r >= 0xF900 && r <= 0xFAFF,   // CJK 兼容表意文字
		r >= 0xFE30 && r <= 0xFE6F,   // CJK 兼容形式
		r >= 0xFF00 && r <= 0xFF60,   // 全角形式
		r >= 0xFFE0 && r <= 0xFFE6,   // 全角符号
		r >= 0x20000 && r <= 0x3FFFD: // CJK 扩展 B 及以后
		return true
	}
	return false
}

func truncatedNote(t bool) string {
	if t {
		return "（已达扫描上限，结果可能不完整）"
	}
	return ""
}
