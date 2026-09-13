// Command usbcomp 是压缩器（带混合加密），需求 F-A01 ~ F-A05。
//
// 用法：
//
//	usbcomp pack <源目录> -o <输出.usbk> [选项]
//	usbcomp version
//
// 行为：源目录 → 流式 zip → AES-256-GCM 加密（会话密钥由 RSA 公钥包装）
// → 单一 `.usbk` 容器。源目录全程只读，明文 zip 默认不落盘（决策 D-03）。
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
	"github.com/immml/UsbBackUP/internal/crypto"
	"github.com/immml/UsbBackUP/internal/fsutil"
	"github.com/immml/UsbBackUP/internal/keystore"
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
		fmt.Fprintln(stdout, version.MultiLineFor(toolName))
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
		"  --public string    直接指定公钥文件（覆盖配置）",
		"  --store            对所有文件都不压缩（CPU 换取速度）",
		"  --exclude string   追加排除项，可重复，支持 * 通配",
		"  --threads int      压缩并发度提示（0 = 自动）",
		"  --keep-plain-zip   额外保留明文 zip（默认不落盘，见决策 D-03）",
		"  --quiet            不输出进度",
		"",
		"全局开关（可放在任意位置）：",
		"  --config string    配置文件路径",
		"  --yes              跳过免责声明确认（自动化用）",
		"",
		"行为：源目录 → 流式 zip → 混合加密 → 单一 .usbk 容器。源目录全程只读。",
	})
}

// stringList 支持重复出现的 --exclude。
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
	quiet := fs.Bool("quiet", false, "静默模式：不输出进度")
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
	// 源守卫（F-507）：输出不得位于源目录之内，否则下一轮会把产物再包一层。
	if err := archive.CheckSourceGuard(srcAbs, filepath.Dir(outAbs)); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitRuntime
	}
	if *keepZip {
		fmt.Fprintln(stdout, "[警告] 已开启 --keep-plain-zip：会在磁盘上留下明文 zip，")
		fmt.Fprintln(stdout, "       明文等于绕过加密，请在使用后立即安全删除。")
	}

	pubKey, err := keystore.LoadPublicKey(config.ExpandPath(pub))
	if err != nil {
		fmt.Fprintf(stderr, "错误：公钥无法加载：%v\n", err)
		return cli.ExitRuntime
	}
	fpBytes, fpText, err := keystore.PublicKeyFingerprint(pubKey)
	if err != nil {
		fmt.Fprintf(stderr, "错误：计算公钥指纹失败：%v\n", err)
		return cli.ExitRuntime
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
	fmt.Fprintf(stdout, "公钥指纹      : %s\n", fpText)
	fmt.Fprintf(stdout, "压缩策略      : Store=%v（已压缩格式自动跳过压缩）\n", *store)

	// 容器先写临时文件，全部成功后再改名，避免留下"看起来完整"的半成品。
	tmpPath := outAbs + ".part"
	outFile, err := os.OpenFile(fsutil.LongPath(tmpPath), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "错误：无法创建输出文件：%v\n", err)
		return cli.ExitRuntime
	}

	// 打包 → 加密以管道串联：明文 zip 不落盘（决策 D-03）。
	pr, pw := io.Pipe()
	type zipOutcome struct {
		stats archive.ZipStats
		err   error
	}
	zipDone := make(chan zipOutcome, 1)

	if !*quiet {
		opt.Progress = func(st archive.ZipStats) {
			fmt.Fprintf(stdout, "\r  已打包 %d 个文件，原始 %s ...", st.Files, fsutil.HumanBytes(st.RawBytes))
		}
	}

	go func() {
		cw := archive.NewCountingWriter(pw)
		st, zerr := archive.ZipStream(osCtx(), cw, opt)
		// 必须把打包错误带给加密侧，否则加密侧会一直阻塞在 Read 上。
		_ = pw.CloseWithError(zerr)
		zipDone <- zipOutcome{stats: st, err: zerr}
	}()

	sum, encErr := crypto.EncryptStream(outFile, pr, crypto.EncryptOptions{
		PublicKey:            pubKey,
		PublicKeyFingerprint: fpBytes,
	})
	zs := <-zipDone
	closeErr := outFile.Close()
	_ = pr.Close()

	if encErr != nil || zs.err != nil {
		_ = os.Remove(fsutil.LongPath(tmpPath))
		if encErr != nil {
			fmt.Fprintf(stderr, "\n错误：加密失败：%v\n", encErr)
		} else {
			fmt.Fprintf(stderr, "\n错误：打包失败：%v\n", zs.err)
		}
		return cli.ExitRuntime
	}
	if closeErr != nil {
		_ = os.Remove(fsutil.LongPath(tmpPath))
		fmt.Fprintf(stderr, "\n错误：写入输出文件失败：%v\n", closeErr)
		return cli.ExitRuntime
	}

	if err := os.Rename(fsutil.LongPath(tmpPath), fsutil.LongPath(outAbs)); err != nil {
		_ = os.Remove(fsutil.LongPath(tmpPath))
		fmt.Fprintf(stderr, "\n错误：重命名产物失败：%v\n", err)
		return cli.ExitRuntime
	}

	// --keep-plain-zip：额外重跑一次打包写到磁盘（默认关闭，见 D-03 / Q-02）。
	if *keepZip {
		plainPath := strings.TrimSuffix(outAbs, ".usbk") + ".zip"
		pf, perr := os.OpenFile(fsutil.LongPath(plainPath), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if perr != nil {
			fmt.Fprintf(stderr, "\n警告：无法写出明文 zip：%v\n", perr)
		} else {
			if _, perr := archive.ZipStream(osCtx(), archive.NewCountingWriter(pf), opt); perr != nil {
				fmt.Fprintf(stderr, "\n警告：明文 zip 打包失败：%v\n", perr)
			}
			_ = pf.Close()
			fmt.Fprintf(stdout, "\n明文 zip      : %s（请在使用后立即安全删除）\n", plainPath)
		}
	}

	fmt.Fprintln(stdout, "\n\n完成。")
	fmt.Fprintf(stdout, "  打包文件数  : %d（跳过 %d）\n", zs.stats.Files, zs.stats.Skipped)
	fmt.Fprintf(stdout, "  原始 / 归档 : %s / %s\n",
		fsutil.HumanBytes(zs.stats.RawBytes), fsutil.HumanBytes(sum.PlainBytes))
	fmt.Fprintf(stdout, "  容器体积    : %s（%d 块，%s）\n",
		fsutil.HumanBytes(sum.CipherBytes), sum.Chunks, sum.Header.DataAlg)
	fmt.Fprintf(stdout, "  输出        : %s\n", outAbs)
	fmt.Fprintln(stdout, "  提示：解密需要配套私钥；私钥或口令丢失则数据不可恢复。")
	return cli.ExitOK
}
