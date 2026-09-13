// Command usbunseal 是解压器：用私钥解密容器并解压，需求 F-B01 ~ F-B07。
//
// 状态：`list`（只读查看容器头）已可用；`verify` / `unseal` 计划于 M2 完成
// （依赖 archive.UnzipStream 的 Zip Slip 防护实现）。
//
// 用法：
//
//	usbunseal list <容器.usbk>
//	usbunseal verify <容器.usbk> --key <私钥.pem> [--pass] [--pass-file 文件]
//	usbunseal unseal <容器.usbk> -d <目标目录> --key <私钥.pem> [--force]
//	usbunseal version
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/immml/UsbBackup/internal/archive"
	"github.com/immml/UsbBackup/internal/cli"
	"github.com/immml/UsbBackup/internal/crypto"
	"github.com/immml/UsbBackup/internal/fsutil"
	"github.com/immml/UsbBackup/internal/keystore"
	"github.com/immml/UsbBackup/internal/version"
)

const toolName = "usbunseal"

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
	case "list":
		// 只读查看容器头，不接触任何密钥，不需要免责声明确认。
		return cmdList(rest, stdout, stderr)
	case "help", "--help", "-h":
		cli.RenderBanner(stdout, toolName)
		printUsage(stdout)
		return cli.ExitOK
	}

	_, skipConfirm := cli.ExtractGlobalFlags(args)
	if skipConfirm {
		cli.RenderNotice(stdout, toolName)
	} else {
		cli.RenderBanner(stdout, toolName)
		if err := cli.ConfirmAgreement(stdin, stdout); err != nil {
			return cli.ExitNotAgreed
		}
	}

	switch sub {
	case "verify":
		return cmdVerify(rest, stdout, stderr)
	case "unseal":
		return cmdUnseal(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知子命令 %q\n\n", sub)
		printUsage(stderr)
		return cli.ExitUsage
	}
}

func printUsage(w io.Writer) {
	cli.PrintHelp(w, "usbunseal —— 解压器（解密 + 解压）", []string{
		"用法：",
		"  usbunseal list <容器.usbk>                        查看容器头（无需私钥）",
		"  usbunseal verify <容器.usbk> --key <私钥>          仅校验完整性，不解出明文",
		"  usbunseal unseal <容器.usbk> -d <目录> --key <私钥> 解密并解压到指定目录",
		"  usbunseal version",
		"",
		"选项：",
		"  --key string        私钥文件（PKCS#8 / PKCS#1 PEM）",
		"  --pass              交互式输入私钥口令（无回显）",
		"  --pass-file string  从文件读取口令（首行）",
		"  --force             覆盖已存在的文件（默认跳过）",
		"  --dry-run           只列出将写出的条目，不实际写入",
		"  --yes               跳过免责声明确认（自动化用）",
		"",
		"安全说明：",
		"  · 解包会拒绝一切可能逃逸目标目录的条目名（Zip Slip 防护）；",
		"  · 目标目录必须显式指定，默认不覆盖已存在文件；",
		"  · 解密失败时不会区分「密钥错误」与「数据被篡改」，避免信息泄露。",
	})
}

// cmdList 读取并展示容器头（F-B01）。不涉及任何密钥材料。
func cmdList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "用法：usbunseal list <容器.usbk>")
		return cli.ExitUsage
	}
	path := fs.Arg(0)

	f, err := os.Open(fsutil.LongPath(path))
	if err != nil {
		fmt.Fprintf(stderr, "打开容器失败：%v\n", err)
		return cli.ExitRuntime
	}
	defer f.Close()

	hdr, headerBytes, err := crypto.ReadHeader(f)
	if err != nil {
		fmt.Fprintf(stderr, "解析容器头失败：%v\n", err)
		return cli.ExitRuntime
	}
	st, err := f.Stat()
	if err != nil {
		fmt.Fprintf(stderr, "读取文件信息失败：%v\n", err)
		return cli.ExitRuntime
	}

	fmt.Fprintf(stdout, "容器文件        : %s\n", path)
	fmt.Fprintf(stdout, "文件大小        : %s（%d 字节）\n", fsutil.HumanBytes(st.Size()), st.Size())
	fmt.Fprintln(stdout, hdr.Describe())
	fmt.Fprintf(stdout, "容器头长度      : %d 字节\n", headerBytes)
	fmt.Fprintf(stdout, "密文负载长度    : %s\n", fsutil.HumanBytes(st.Size()-headerBytes))
	fmt.Fprintln(stdout, "\n提示：该文件为混合加密容器，需要使用配套私钥才能解密。")
	return cli.ExitOK
}

// cmdVerify 仅校验完整性（F-B02），不写出明文。
func cmdVerify(args []string, stdout, stderr io.Writer) int {
	keyPath, passphrase, code := prepareDecrypt(args, stdout, stderr)
	if code != cli.ExitOK {
		return code
	}
	if keyPath == "" {
		return cli.ExitUsage
	}
	fmt.Fprintf(stdout, "私钥            : %s\n", keyPath)
	_ = passphrase
	fmt.Fprintln(stderr, "\nverify：解密校验执行器尚未实现（计划于 M2）。")
	fmt.Fprintln(stderr, "现在可先用 `usbkeygen selftest` 验证加密内核的往返与篡改检测。")
	return cli.ExitNotImplemented
}

// cmdUnseal 解密并解压（F-B03 ~ F-B07）。
func cmdUnseal(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("unseal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dest := fs.String("d", "", "解压目标目录（必填）")
	keyPath := fs.String("key", "", "私钥文件（必填）")
	usePass := fs.Bool("pass", false, "交互式输入私钥口令")
	passFile := fs.String("pass-file", "", "从文件读取口令")
	force := fs.Bool("force", false, "覆盖已存在文件")
	dryRun := fs.Bool("dry-run", false, "只列出条目，不写入")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "用法：usbunseal unseal <容器.usbk> -d <目录> --key <私钥>")
		return cli.ExitUsage
	}
	if *dest == "" {
		fmt.Fprintln(stderr, "错误：必须通过 -d 显式指定解压目标目录（防止误写到当前目录）。")
		return cli.ExitUsage
	}
	if *keyPath == "" {
		fmt.Fprintln(stderr, "错误：必须通过 --key 指定私钥文件。")
		return cli.ExitUsage
	}
	_, _ = *usePass, *passFile

	fmt.Fprintf(stdout, "容器            : %s\n", fs.Arg(0))
	fmt.Fprintf(stdout, "目标目录        : %s\n", *dest)
	fmt.Fprintf(stdout, "私钥            : %s\n", *keyPath)
	fmt.Fprintf(stdout, "覆盖已存在文件  : %v\n", *force)

	stats, err := archive.UnzipStream(osCtx(), nil, 0, archive.UnzipOptions{
		DestDir: *dest, Force: *force, DryRun: *dryRun,
	})
	if err != nil {
		fmt.Fprintf(stderr, "\n错误：%v\n", err)
		fmt.Fprintln(stderr, "（解包执行器计划于 M2 完成；Zip Slip 防护逻辑已实现，可参考 internal/archive/guards.go。）")
		return cli.ExitNotImplemented
	}
	_ = stats
	return cli.ExitOK
}

// prepareDecrypt 解析私钥与口令相关参数，并校验私钥可加载。
func prepareDecrypt(args []string, stdout, stderr io.Writer) (keyPath string, passphrase []byte, code int) {
	fs := flag.NewFlagSet("decrypt-common", flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String("key", "", "私钥文件")
	usePass := fs.Bool("pass", false, "交互式输入口令")
	passFile := fs.String("pass-file", "", "从文件读取口令")
	if err := cli.ParseArgs(fs, args); err != nil {
		return "", nil, cli.ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "用法：usbunseal <子命令> <容器.usbk> --key <私钥>")
		return "", nil, cli.ExitUsage
	}
	if *key == "" {
		fmt.Fprintln(stderr, "错误：必须通过 --key 指定私钥文件。")
		return "", nil, cli.ExitUsage
	}

	switch {
	case *passFile != "":
		p, err := cli.ReadPassphraseFromFile(*passFile)
		if err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return "", nil, cli.ExitRuntime
		}
		passphrase = p
	case *usePass:
		p, err := cli.ReadPassphrase("请输入私钥口令：")
		if err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return "", nil, cli.ExitRuntime
		}
		passphrase = p
	}

	if _, err := keystore.LoadPrivateKey(*key, passphrase); err != nil {
		switch {
		case strings.Contains(err.Error(), "口令"):
			fmt.Fprintf(stderr, "私钥加载失败：%v（可加 --pass 或 --pass-file）\n", err)
		default:
			fmt.Fprintf(stderr, "私钥加载失败：%v\n", err)
		}
		return "", nil, cli.ExitRuntime
	}
	return *key, passphrase, cli.ExitOK
}
