// Command usbcomp 是压缩器（带混合加密），需求 F-A01 ~ F-A05。
//
// 状态：命令行框架与参数校验已就绪；打包执行器计划于 M2 完成
// （依赖 archive.ZipStream + crypto.EncryptStream 的管道串联）。
//
// 用法：
//
//	usbcomp pack <源目录> -o <输出.usbk> [--store] [--keep-plain-zip]
//	usbcomp version
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/immml/UsbBackUP/internal/archive"
	"github.com/immml/UsbBackUP/internal/cli"
	"github.com/immml/UsbBackUP/internal/config"
	"github.com/immml/UsbBackUP/internal/version"
)

const toolName = "usbcomp"

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
		cli.RenderBanner(stdout, toolName)
		printUsage(stdout)
		return cli.ExitOK
	}

	cfgPath, skipConfirm := cli.ExtractGlobalFlags(args)
	if skipConfirm {
		cli.RenderNotice(stdout, toolName)
	} else {
		cli.RenderBanner(stdout, toolName)
		if err := cli.ConfirmAgreement(stdin, stdout); err != nil {
			return cli.ExitNotAgreed
		}
	}

	switch sub {
	case "pack":
		return cmdPack(rest, cfgPath, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知子命令 %q\n\n", sub)
		printUsage(stderr)
		return cli.ExitUsage
	}
}

func printUsage(w io.Writer) {
	cli.PrintHelp(w, "usbcomp —— 压缩器（带混合加密）", []string{
		"用法：",
		"  usbcomp pack <源目录> -o <输出.usbk> [选项]",
		"  usbcomp version",
		"",
		"选项：",
		"  -o string          输出容器路径（必填，建议以 .usbk 结尾）",
		"  --config string    配置文件路径（读取公钥与打包策略）",
		"  --public string    直接指定公钥文件（覆盖配置）",
		"  --store            对所有文件都不压缩（CPU 换取速度）",
		"  --exclude string   追加排除项，可重复，支持 * 通配",
		"  --keep-plain-zip   额外保留明文 zip（默认不落盘，见 D-03）",
		"  --threads int      压缩并发度（0 = 自动）",
		"  --yes              跳过免责声明确认（自动化用）",
		"",
		"行为：源目录 → 流式 zip → AES-256-GCM 加密（会话密钥由 RSA-4096-OAEP 包装）",
		"      → 单一 .usbk 容器。源目录全程只读。",
	})
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func cmdPack(args []string, cfgPath string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pack", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("o", "", "输出容器路径（必填）")
	pubPath := fs.String("public", "", "公钥文件路径（覆盖配置）")
	store := fs.Bool("store", false, "所有文件都不压缩")
	keepZip := fs.Bool("keep-plain-zip", false, "额外保留明文 zip")
	threads := fs.Int("threads", 0, "压缩并发度")
	var excludes stringList
	fs.Var(&excludes, "exclude", "追加排除项（可重复）")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "用法：usbcomp pack <源目录> -o <输出.usbk>")
		return cli.ExitUsage
	}
	src := fs.Arg(0)
	if *out == "" {
		fmt.Fprintln(stderr, "错误：必须通过 -o 指定输出容器路径。")
		return cli.ExitUsage
	}

	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitRuntime
	}
	cfg.ApplyEnv()

	pub := *pubPath
	if pub == "" {
		pub = cfg.PublicKeyPath
	}
	if pub == "" {
		fmt.Fprintln(stderr, "错误：未指定公钥。请先用 `usbkeygen use <公钥.pem>` 登记，或使用 --public 指定。")
		return cli.ExitUsage
	}
	if _, err := os.Stat(config.ExpandPath(pub)); err != nil {
		fmt.Fprintf(stderr, "错误：公钥文件不可读：%s（%v）\n", pub, err)
		return cli.ExitRuntime
	}

	srcAbs, err := filepath.Abs(src)
	if err != nil {
		fmt.Fprintf(stderr, "错误：解析源目录失败：%v\n", err)
		return cli.ExitRuntime
	}
	if st, err := os.Stat(srcAbs); err != nil || !st.IsDir() {
		fmt.Fprintf(stderr, "错误：源目录不可用：%s\n", srcAbs)
		return cli.ExitRuntime
	}
	outAbs, err := filepath.Abs(*out)
	if err != nil {
		fmt.Fprintf(stderr, "错误：解析输出路径失败：%v\n", err)
		return cli.ExitRuntime
	}
	// 源守卫（F-507）：输出不得位于源目录之内，否则会递归膨胀。
	if err := archive.CheckSourceGuard(srcAbs, filepath.Dir(outAbs)); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitRuntime
	}
	if *keepZip {
		fmt.Fprintln(stdout, "[警告] 已开启 --keep-plain-zip：会在磁盘上留下明文 zip，")
		fmt.Fprintln(stdout, "       明文等于绕过加密，请在使用后立即安全删除。")
	}

	opt := archive.ZipOptions{
		SourceRoot:             srcAbs,
		Excludes:               excludes,
		StoreAlreadyCompressed: !*store,
		Threads:                *threads,
	}
	fmt.Fprintf(stdout, "源目录        : %s\n", srcAbs)
	fmt.Fprintf(stdout, "输出容器      : %s\n", outAbs)
	fmt.Fprintf(stdout, "公钥          : %s\n", config.ExpandPath(pub))
	fmt.Fprintf(stdout, "压缩策略      : Store=%v（已压缩格式自动跳过压缩）\n", *store)

	stats, err := archive.ZipStream(osCtx(), io.Discard, opt)
	if err != nil {
		fmt.Fprintf(stderr, "\n错误：%v\n", err)
		fmt.Fprintln(stderr, "（打包执行器计划于 M2 完成；当前可先用 `usbkeygen selftest` 验证加密内核。）")
		return cli.ExitNotImplemented
	}
	_ = stats
	return cli.ExitOK
}
