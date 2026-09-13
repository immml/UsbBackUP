// Command usbkeygen 是密钥生成器（需求 F-901 ~ F-906 / F-701 ~ F-705）。
//
// 启动时强制展示安全警告与免责声明，并要求输入 I AGREE 确认。
//
// 用法：
//
//	usbkeygen generate [--bits 4096] [--out 目录] [--force] [--pass] [--pass-file 文件]
//	usbkeygen use <公钥.pem|公钥.cer> [--config 配置路径]
//	usbkeygen inspect <公钥.pem>
//	usbkeygen selftest
//	usbkeygen version
//
// 全局开关：
//
//	--yes  跳过 I AGREE 交互确认（仅用于自动化，请自行确认已阅读条款）
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/immml/UsbBackUP/internal/cli"
	"github.com/immml/UsbBackUP/internal/config"
	"github.com/immml/UsbBackUP/internal/crypto"
	"github.com/immml/UsbBackUP/internal/keystore"
	"github.com/immml/UsbBackUP/internal/version"
)

const toolName = "usbkeygen"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return cli.ExitUsage
	}

	sub := args[0]
	rest := args[1:]

	// `version` 不展示横幅（它是诊断命令，需要干净的输出）。
	if sub == "version" || sub == "--version" || sub == "-v" {
		fmt.Fprintln(stdout, version.MultiLineFor(toolName))
		return cli.ExitOK
	}
	if sub == "help" || sub == "--help" || sub == "-h" {
		cli.RenderBanner(stdout, toolName)
		printUsage(stdout)
		return cli.ExitOK
	}

	// 全局开关可出现在任意位置，统一在此处读取。
	cfgPath, skipConfirm := cli.ExtractGlobalFlags(args)

	// F-901 / F-902：显著展示警告 + 强制确认。
	// --yes 面向自动化：改印简短安全提示，避免整屏警告污染脚本日志。
	if skipConfirm {
		cli.RenderNotice(stdout, toolName)
	} else {
		cli.RenderBanner(stdout, toolName)
		if err := cli.ConfirmAgreement(stdin, stdout); err != nil {
			return cli.ExitNotAgreed
		}
	}

	switch sub {
	case "generate":
		return cmdGenerate(rest, stdin, stdout, stderr)
	case "use":
		return cmdUse(rest, cfgPath, stdout, stderr)
	case "inspect":
		return cmdInspect(rest, stdout, stderr)
	case "selftest":
		return cmdSelfTest(rest, stdout, stderr)
	case "build-client":
		return cmdBuildClient(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知子命令 %q\n\n", sub)
		printUsage(stderr)
		return cli.ExitUsage
	}
}

func printUsage(w io.Writer) {
	cli.PrintHelp(w, "usbkeygen —— usbbackup 密钥生成器", []string{
		"用法：",
		"  usbkeygen generate [选项]          生成新的 RSA 密钥对",
		"  usbkeygen use <公钥文件>            选择已有公钥并登记到配置",
		"  usbkeygen inspect <公钥文件>        查看公钥位数与指纹",
		"  usbkeygen selftest                 就地校验混合加密往返（不落盘）",
		"  usbkeygen build-client             产出内嵌配置与公钥的客户端 exe",
		"  usbkeygen version                  显示版本信息",
		"",
		"用于自动化时可在子命令后追加 --yes 跳过 I AGREE 交互确认。",
		"",
		"generate 选项：",
		"  --bits int         RSA 位数（默认 4096，下限 2048，上限 8192）",
		"  --out string       输出目录（默认当前目录）",
		"  --private string   私钥输出路径（默认 <out>/usbbackup.key.pem）",
		"  --public string    公钥输出路径（默认 <out>/usbbackup.pub.pem）",
		"  --force            允许覆盖已存在的密钥文件",
		"  --pass             交互式设置私钥口令（无回显）",
		"  --pass-file string 从文件读取口令（首行）",
		"",
		"build-client 选项：",
		"  --public string    公钥 PEM 路径（必填，只能是公钥）",
		"  -o string          输出客户端路径（必填）",
		"  --template string  客户端模板 exe（默认同目录 usbbackup.exe）",
		"  --config string    基础配置文件（可选）",
		"  --output-dir DIR   覆盖产物输出目录（支持 %TEMP%）",
		"  --source-dir DIR   覆盖分支 A 的本地备份源目录",
		"  --threshold SIZE   覆盖容量门控阈值（如 10GiB / 10GB）",
		"  --max-total SIZE   覆盖打包体积上限（0 或 unlimited 表示不限制）",
		"  --name string      客户端标识",
		"  --force            覆盖已存在的输出文件",
		"",
		"use 选项：",
		"  --config string    配置文件路径（默认 %LOCALAPPDATA%\\usbbackup\\config.json）",
		"",
		"安全提示：generate 成功后请立即离线备份私钥与口令。私钥丢失则密文不可恢复。",
	})
}

func cmdGenerate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bits := fs.Int("bits", keystore.DefaultRSAKeyBits, "RSA 位数")
	outDir := fs.String("out", ".", "输出目录")
	privPath := fs.String("private", "", "私钥输出路径")
	pubPath := fs.String("public", "", "公钥输出路径")
	force := fs.Bool("force", false, "允许覆盖已存在的文件")
	usePass := fs.Bool("pass", false, "交互式设置私钥口令")
	passFile := fs.String("pass-file", "", "从文件读取口令（首行）")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}

	var passphrase []byte
	switch {
	case *passFile != "":
		p, err := cli.ReadPassphraseFromFile(*passFile)
		if err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return cli.ExitUsage
		}
		passphrase = p
	case *usePass:
		p, err := cli.ReadPassphrase("请输入私钥保护口令（至少 8 位）：")
		if err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return cli.ExitRuntime
		}
		confirm, err := cli.ReadPassphrase("请再次输入口令以确认：")
		if err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return cli.ExitRuntime
		}
		if !bytes.Equal(p, confirm) {
			fmt.Fprintln(stderr, "错误：两次输入的口令不一致。")
			return cli.ExitUsage
		}
		passphrase = p
	}
	defer func() {
		for i := range passphrase {
			passphrase[i] = 0
		}
	}()

	fmt.Fprintf(stdout, "正在生成 RSA-%d 密钥对，可能需要数秒……\n", *bits)
	kp, err := keystore.Generate(keystore.GenerateOptions{
		Bits:        *bits,
		OutDir:      *outDir,
		PrivatePath: *privPath,
		PublicPath:  *pubPath,
		Force:       *force,
		Passphrase:  passphrase,
	})
	if err != nil {
		fmt.Fprintf(stderr, "生成失败：%v\n", err)
		return cli.ExitRuntime
	}

	fmt.Fprintln(stdout, "\n生成完成。")
	fmt.Fprintf(stdout, "  私钥（请离线保管，切勿外发）：%s\n", absOr(kp.PrivatePath))
	fmt.Fprintf(stdout, "  公钥（可安全分发）          ：%s\n", absOr(kp.PublicPath))
	fmt.Fprintf(stdout, "  密钥位数                    ：%d\n", kp.Bits)
	fmt.Fprintf(stdout, "  私钥口令保护                ：%s\n", yesNo(kp.Encrypted))
	fmt.Fprintf(stdout, "  公钥指纹(SHA-256)           ：%s\n", kp.Fingerprint)
	fmt.Fprintln(stdout, "\n下一步：")
	fmt.Fprintf(stdout, "  1) 登记公钥：usbkeygen use %q\n", kp.PublicPath)
	fmt.Fprintln(stdout, "  2) 立即把私钥与口令备份到离线介质（U 盘/纸质记录），并妥善保管。")
	if !kp.Encrypted {
		fmt.Fprintln(stdout, "\n  [警告] 本次私钥未设置口令保护。若担心明文私钥落盘风险，")
		fmt.Fprintln(stdout, "         建议改用 --pass 重新生成，或自行用强口令工具加密后离线保存。")
	}
	return cli.ExitOK
}

func cmdUse(args []string, cfgPath string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("use", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "用法：usbkeygen use <公钥文件> [--config 配置路径]")
		return cli.ExitUsage
	}
	pubPath := fs.Arg(0)

	fp, cfg, err := keystore.SelectPublicKey(cfgPath, pubPath)
	if err != nil {
		fmt.Fprintf(stderr, "登记失败：%v\n", err)
		if strings.Contains(err.Error(), "私钥") {
			fmt.Fprintln(stderr, "提示：配置文件只允许保存公钥；请提供 usbbackup.pub.pem 这类公钥文件。")
		}
		return cli.ExitRuntime
	}
	cfgFile := cfgPath
	if cfgFile == "" {
		cfgFile = config.DefaultConfigPath()
	}
	fmt.Fprintln(stdout, "公钥已登记到配置。")
	fmt.Fprintf(stdout, "  配置文件    ：%s\n", cfgFile)
	fmt.Fprintf(stdout, "  公钥路径    ：%s\n", cfg.PublicKeyPath)
	fmt.Fprintf(stdout, "  公钥指纹    ：%s\n", fp)
	return cli.ExitOK
}

func cmdInspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "用法：usbkeygen inspect <公钥文件>")
		return cli.ExitUsage
	}
	pub, err := keystore.LoadPublicKey(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "读取公钥失败：%v\n", err)
		return cli.ExitRuntime
	}
	_, fp, err := keystore.PublicKeyFingerprint(pub)
	if err != nil {
		fmt.Fprintf(stderr, "计算指纹失败：%v\n", err)
		return cli.ExitRuntime
	}
	fmt.Fprintf(stdout, "公钥文件    ：%s\n", absOr(fs.Arg(0)))
	fmt.Fprintf(stdout, "算法        ：RSA\n")
	fmt.Fprintf(stdout, "模数位数    ：%d\n", pub.N.BitLen())
	fmt.Fprintf(stdout, "公钥指纹    ：%s\n", fp)
	if pub.N.BitLen() < crypto.MinRSAKeyBits {
		fmt.Fprintf(stdout, "\n[警告] 该公钥位数低于容器要求下限 %d 位，无法用于加密。\n", crypto.MinRSAKeyBits)
		return cli.ExitPartial
	}
	return cli.ExitOK
}

// cmdSelfTest 就地验证混合加密往返、篡改检测与截断检测（F-705 / F-504）。
// 全程使用内存中的临时密钥与临时数据，**不写任何文件**。
func cmdSelfTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	size := fs.Int("size", 2<<20, "自检数据大小（字节）")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if *size < 1024 || *size > 64<<20 {
		fmt.Fprintln(stderr, "自检数据大小需在 1 KiB 到 64 MiB 之间。")
		return cli.ExitUsage
	}

	failures := 0
	check := func(name string, ok bool, detail string) {
		mark := "通过"
		if !ok {
			mark = "失败"
			failures++
		}
		fmt.Fprintf(stdout, "  [%s] %s%s\n", mark, name, detail)
	}

	fmt.Fprintln(stdout, "混合加密自检（全部在内存中进行，不落盘）：")

	// 1) 临时密钥对（2048 位即可满足自检，密钥强度下限仍由 generate 保证）。
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(stderr, "自检失败：生成临时密钥出错：%v\n", err)
		return cli.ExitRuntime
	}
	fp, fpText, err := keystore.PublicKeyFingerprint(&key.PublicKey)
	if err != nil {
		fmt.Fprintf(stderr, "自检失败：计算指纹出错：%v\n", err)
		return cli.ExitRuntime
	}
	check("临时密钥与指纹计算", true, fmt.Sprintf("（指纹 %s）", fpText))

	// 2) 构造明文（伪随机内容，避免全零数据掩盖问题）。
	plaintext := make([]byte, *size)
	if _, err := rand.Read(plaintext); err != nil {
		fmt.Fprintf(stderr, "自检失败：生成测试数据出错：%v\n", err)
		return cli.ExitRuntime
	}

	// 3) 加密。
	const chunk = 64 << 10
	var cipherBuf bytes.Buffer
	esum, err := crypto.EncryptStream(&cipherBuf, bytes.NewReader(plaintext), crypto.EncryptOptions{
		PublicKey:            &key.PublicKey,
		PublicKeyFingerprint: fp,
		ChunkSize:            chunk,
	})
	if err != nil {
		check("流式混合加密", false, fmt.Sprintf("（%v）", err))
		fmt.Fprintln(stderr, "\n自检未通过。")
		return cli.ExitRuntime
	}
	check("流式混合加密", true,
		fmt.Sprintf("（明文 %d 字节 → 密文 %d 字节，%d 块）", esum.PlainBytes, esum.CipherBytes, esum.Chunks))
	// 密文必须大于明文（含容器头、Tag、元数据块），且不能包含明文片段。
	check("密文尺寸合理", esum.CipherBytes > esum.PlainBytes, "")
	check("密文不含明文片段", !bytes.Contains(cipherBuf.Bytes(), plaintext[:64]), "")

	// 4) 解密往返。
	var outBuf bytes.Buffer
	dsum, err := crypto.DecryptStream(&outBuf, bytes.NewReader(cipherBuf.Bytes()), crypto.DecryptOptions{
		PrivateKey:           key,
		PublicKeyFingerprint: fp,
	})
	if err != nil {
		check("流式解密", false, fmt.Sprintf("（%v）", err))
		fmt.Fprintln(stderr, "\n自检未通过。")
		return cli.ExitRuntime
	}
	check("流式解密", true, fmt.Sprintf("（%d 块）", dsum.Chunks))
	check("明文逐字节一致", bytes.Equal(plaintext, outBuf.Bytes()), "")
	check("明文哈希一致", dsum.PlainSHA256 == esum.PlainSHA256, "")

	// 5) 篡改检测：翻转密文中部一个字节，必须解密失败。
	tampered := make([]byte, len(cipherBuf.Bytes()))
	copy(tampered, cipherBuf.Bytes())
	mid := len(tampered) / 2
	tampered[mid] ^= 0x01
	var junk bytes.Buffer
	_, errTamper := crypto.DecryptStream(&junk, bytes.NewReader(tampered), crypto.DecryptOptions{PrivateKey: key})
	check("篡改检测（翻转 1 字节）", errTamper != nil, detailOr(errTamper, "（未检出，严重问题）"))

	// 6) 截断检测：砍掉尾部 32 字节。
	truncated := cipherBuf.Bytes()[:len(cipherBuf.Bytes())-32]
	var junk2 bytes.Buffer
	_, errTrunc := crypto.DecryptStream(&junk2, bytes.NewReader(truncated), crypto.DecryptOptions{PrivateKey: key})
	check("截断检测（去掉末块）", errTrunc != nil, detailOr(errTrunc, "（未检出，严重问题）"))

	// 7) 错误密钥必须失败。
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(stderr, "自检失败：生成第二把临时密钥出错：%v\n", err)
		return cli.ExitRuntime
	}
	var junk3 bytes.Buffer
	_, errWrongKey := crypto.DecryptStream(&junk3, bytes.NewReader(cipherBuf.Bytes()), crypto.DecryptOptions{PrivateKey: other})
	check("错误私钥被拒绝", errWrongKey != nil, detailOr(errWrongKey, "（未拒绝，严重问题）"))

	// 8) 容器头可解析且不含密钥材料（只应包含被公钥加密的包装密钥）。
	if hdr, _, err := crypto.ReadHeader(bytes.NewReader(cipherBuf.Bytes())); err != nil {
		check("容器头可解析", false, fmt.Sprintf("（%v）", err))
	} else {
		check("容器头可解析", true, fmt.Sprintf("（%s / %s）", hdr.KeyAlg, hdr.DataAlg))
	}

	if failures > 0 {
		fmt.Fprintf(stderr, "\n自检未通过：%d 项失败。\n", failures)
		return cli.ExitRuntime
	}
	fmt.Fprintln(stdout, "\n自检全部通过。")
	return cli.ExitOK
}

func detailOr(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	return fmt.Sprintf("（已正确拒绝：%v）", err)
}

func absOr(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func yesNo(b bool) string {
	if b {
		return "是"
	}
	return "否"
}
