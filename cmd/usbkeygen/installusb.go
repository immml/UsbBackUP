package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackUP/internal/cli"
	"github.com/immml/UsbBackUP/internal/clientgen"
	"github.com/immml/UsbBackUP/internal/keystore"
	"github.com/immml/UsbBackUP/internal/version"
	"github.com/immml/UsbBackUP/internal/winvol"
)

// toolFiles 是要装进工具 U 盘的可执行文件（相对本程序所在目录）。
var toolFiles = []string{
	"usbsetup.exe", "usbkeygen.exe", "usbunseal.exe", "usbbackup.exe", "usbcomp.exe",
}

// toolkitOptions 是组装工具盘的输入。
type toolkitOptions struct {
	// Dest 是目标根目录（U 盘根目录）。
	Dest string
	// ToolDir 是工具 exe 的来源目录（一般是本程序所在目录）。
	ToolDir string
	// PublicKeyPath / PrivateKeyPath 是密钥来源。
	PublicKeyPath  string
	PrivateKeyPath string
	// WithPrivate 决定是否把私钥写进 U 盘。
	WithPrivate bool
	// WithClient 决定是否生成/复制 client.exe。
	WithClient bool
	// Force 允许覆盖已存在的同名文件。
	Force bool
}

// cmdInstallUSB 把一个「便携工具 U 盘」组装到指定盘符。
//
// 盘内布局：
//
//	<U盘>\
//	├── usbsetup.exe / usbkeygen.exe / usbunseal.exe / usbbackup.exe / usbcomp.exe
//	├── client.exe            生成器产出的客户端（内嵌配置与公钥）
//	├── keys\usbbackup.pub.pem
//	├── keys\usbbackup.key.pem（默认带；--without-private 可排除）
//	├── .usbbackup-allow      授权标记，内容是公钥指纹
//	└── README.txt            用法与私钥风险说明
//
// .usbbackup-allow 不只是"钥匙"：客户端做私钥存在性检测时会命中它，
// 于是这个盘走**回写分支**而不是被整盘打包——工具盘因此不会被自己人备份走。
func cmdInstallUSB(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("install-usb", flag.ContinueOnError)
	fs.SetOutput(stderr)
	drive := fs.String("drive", "", "目标 U 盘盘符，如 E:（必填）")
	pub := fs.String("public", "", "公钥路径（默认与本程序同目录的 keys/usbbackup.pub.pem）")
	priv := fs.String("private", "", "私钥路径（默认与本程序同目录的 keys/usbbackup.key.pem）")
	keyDir := fs.String("keys", "", "密钥目录（同时给出公钥与私钥时可只写这一项）")
	withoutPriv := fs.Bool("without-private", false, "不把私钥写进 U 盘")
	noClient := fs.Bool("no-client", false, "不生成/复制 client.exe")
	force := fs.Bool("force", false, "目标已有同名文件时覆盖")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if strings.TrimSpace(*drive) == "" {
		fmt.Fprintln(stderr, "用法：usbkeygen install-usb --drive E: [--keys DIR] [--without-private] [--no-client] [--force]")
		return cli.ExitUsage
	}

	root, err := winvol.NormalizeRoot(*drive)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitUsage
	}
	vol, err := winvol.Query(root)
	if err != nil {
		// 区分"盘符不存在/没插介质"与"插了但不是 U 盘"：
		// 两者的处理办法完全不同，报成同一句会让人白找半天。
		if vol.DriveType == winvol.DriveNoRootDir || vol.DriveType == winvol.DriveUnknown {
			fmt.Fprintf(stderr, "错误：%s 不存在或没有插入介质。\n", root)
			return cli.ExitRuntime
		}
		fmt.Fprintf(stderr, "错误：无法访问 %s：%v\n", root, err)
		return cli.ExitRuntime
	}
	if !vol.Ready {
		fmt.Fprintf(stderr, "错误：%s 未就绪（介质未插入？）\n", root)
		return cli.ExitRuntime
	}
	if !vol.Removable {
		fmt.Fprintf(stderr, "错误：%s 不是可移动磁盘（类型 %s），拒绝写入。\n", root, winvol.DriveTypeName(vol.DriveType))
		fmt.Fprintln(stderr, "      这个命令只往 U 盘装东西；若是固定盘请确认盘符。")
		return cli.ExitUsage
	}

	exeDir := exeDirOf()
	pubPath := firstNonEmpty(*pub, filepath.Join(*keyDir, "usbbackup.pub.pem"), filepath.Join(exeDir, "keys", "usbbackup.pub.pem"))
	privPath := firstNonEmpty(*priv, filepath.Join(*keyDir, "usbbackup.key.pem"), filepath.Join(exeDir, "keys", "usbbackup.key.pem"))

	pubRaw, err := os.ReadFile(pubPath)
	if err != nil {
		fmt.Fprintf(stderr, "错误：读取公钥失败：%v\n", err)
		fmt.Fprintln(stderr, "      请用 --public 指定，或先执行 usbkeygen generate。")
		return cli.ExitRuntime
	}
	pubKey, err := keystore.ParsePublicKeyPEM(pubRaw)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitRuntime
	}
	_, fpText, err := keystore.PublicKeyFingerprint(pubKey)
	if err != nil {
		fmt.Fprintf(stderr, "错误：计算公钥指纹失败：%v\n", err)
		return cli.ExitRuntime
	}

	withPriv := !*withoutPriv
	if withPriv {
		if _, err := os.Stat(privPath); err != nil {
			fmt.Fprintf(stderr, "提示：未找到私钥 %s，本次不写入私钥。\n", privPath)
			withPriv = false
		}
	}

	fmt.Fprintf(stdout, "目标 U 盘  : %s（%s，剩余 %s）\n", root, emptyOr(vol.Label, "无卷标"), humanBytes(vol.FreeBytes))
	fmt.Fprintf(stdout, "公钥指纹  : %s\n", fpText)
	fmt.Fprintf(stdout, "写入私钥  : %v\n\n", withPriv)

	n, err := assembleToolkit(toolkitOptions{
		Dest:           root,
		ToolDir:        exeDir,
		PublicKeyPath:  pubPath,
		PrivateKeyPath: privPath,
		WithPrivate:    withPriv,
		WithClient:     !*noClient,
		Force:          *force,
	}, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitRuntime
	}

	fmt.Fprintf(stdout, "\n完成：共写入 %d 项到 %s\n", n, root)
	if withPriv {
		fmt.Fprintln(stdout)
		if privateIsEncrypted(toolkitOptions{WithPrivate: true, PrivateKeyPath: privPath}) {
			fmt.Fprintln(stdout, "  [!] 盘上有**带口令的私钥**。盘与口令同时丢失 = 所有备份可被解开，")
			fmt.Fprintln(stdout, "      且口令不要写在这个盘上。请随身保管，或改用 --without-private 只带公钥。")
		} else {
			fmt.Fprintln(stdout, "  [!] 盘上有**明文私钥**。U 盘一旦丢失或被复制，")
			fmt.Fprintln(stdout, "      所有用它加密的备份都能被解开。请随身保管，")
			fmt.Fprintln(stdout, "      或改用 --without-private 只带公钥。")
		}
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  用法：把本盘插到目标机器，运行 client.exe（先 accept 一次，之后静默）；")
	fmt.Fprintln(stdout, "        取回 .usbk 后，用本盘上的 usbunseal.exe 解密还原。")
	return cli.ExitOK
}

// assembleToolkit 把工具、客户端、密钥、授权标记与说明写入目标根目录。
//
// 与盘符校验分离，这样即使机器上没有可移动介质，
// 这段组装逻辑也能在临时目录里被单元测试覆盖。
func assembleToolkit(opt toolkitOptions, out io.Writer) (int, error) {
	written := 0

	// 1) 工具本体：缺失的跳过（允许只带部分工具）。
	for _, name := range toolFiles {
		src := filepath.Join(opt.ToolDir, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := copyFile(src, filepath.Join(opt.Dest, name), opt.Force); err != nil {
			return written, fmt.Errorf("复制 %s 失败: %w", name, err)
		}
		written++
		fmt.Fprintf(out, "  [OK] %s\n", name)
	}

	// 2) 客户端：优先复用同目录已有的，否则现场生成一个。
	if opt.WithClient {
		dst := filepath.Join(opt.Dest, "client.exe")
		clientSrc := filepath.Join(opt.ToolDir, "client.exe")
		if _, err := os.Stat(clientSrc); err == nil {
			if err := copyFile(clientSrc, dst, opt.Force); err != nil {
				return written, fmt.Errorf("复制 client.exe 失败: %w", err)
			}
			fmt.Fprintln(out, "  [OK] client.exe（复用已有）")
		} else {
			pubRaw, err := os.ReadFile(opt.PublicKeyPath)
			if err != nil {
				return written, fmt.Errorf("读取公钥失败: %w", err)
			}
			res, err := clientgen.Build(clientgen.Options{
				PublicKeyPEM: pubRaw,
				Template:     filepath.Join(opt.ToolDir, "usbbackup.exe"),
				Output:       dst,
				ClientName:   "usb-toolkit",
				Force:        opt.Force,
			})
			if err != nil {
				return written, fmt.Errorf("生成 client.exe 失败: %w", err)
			}
			fmt.Fprintf(out, "  [OK] client.exe（现场生成，%d 位公钥）\n", res.KeyBits)
		}
		written++
	}

	// 3) 密钥目录。
	keyDst := filepath.Join(opt.Dest, "keys")
	if err := os.MkdirAll(keyDst, 0o755); err != nil {
		return written, fmt.Errorf("创建 keys 目录失败: %w", err)
	}
	if err := copyFile(opt.PublicKeyPath, filepath.Join(keyDst, "usbbackup.pub.pem"), opt.Force); err != nil {
		return written, fmt.Errorf("写入公钥失败: %w", err)
	}
	fmt.Fprintln(out, "  [OK] keys/usbbackup.pub.pem")
	written++
	if opt.WithPrivate {
		if err := copyFile(opt.PrivateKeyPath, filepath.Join(keyDst, "usbbackup.key.pem"), opt.Force); err != nil {
			return written, fmt.Errorf("写入私钥失败: %w", err)
		}
		kind := "明文"
		if raw, err := os.ReadFile(opt.PrivateKeyPath); err == nil && keystore.IsEncryptedPrivateKeyPEM(raw) {
			kind = "口令保护"
		}
		fmt.Fprintf(out, "  [OK] keys/usbbackup.key.pem（%s）\n", kind)
		written++
	}

	// 4) 授权标记：让这个盘走回写分支，而不是被整盘打包。
	pubRaw, err := os.ReadFile(opt.PublicKeyPath)
	if err != nil {
		return written, err
	}
	pubKey, err := keystore.ParsePublicKeyPEM(pubRaw)
	if err != nil {
		return written, err
	}
	_, fpText, err := keystore.PublicKeyFingerprint(pubKey)
	if err != nil {
		return written, err
	}
	marker := fmt.Sprintf("# usbbackup 授权标记：持有该公钥指纹的介质走回写分支\n"+
		"# 生成时间 %s（生成器 %s）\nfingerprint=%s\n",
		time.Now().Format(time.RFC3339), version.Version, fpText)
	if err := writeFile(filepath.Join(opt.Dest, ".usbbackup-allow"), []byte(marker), opt.Force); err != nil {
		return written, fmt.Errorf("写入授权标记失败: %w", err)
	}
	fmt.Fprintln(out, "  [OK] .usbbackup-allow（授权标记）")
	written++

	// 5) 说明文件（每次都重写，保证与盘内实际内容一致）。
	//    README 必须如实反映私钥是否带口令，否则现场的人会按错误的风险等级处理。
	readme := toolkitReadme(fpText, opt.WithPrivate, privateIsEncrypted(opt))
	if err := writeFile(filepath.Join(opt.Dest, "README.txt"), []byte(readme), true); err != nil {
		return written, fmt.Errorf("写入 README.txt 失败: %w", err)
	}
	fmt.Fprintln(out, "  [OK] README.txt")
	written++

	return written, nil
}

// privateIsEncrypted 判断本次上盘的私钥是否带口令保护。
// 读取失败时按"明文"处理——宁可把风险说重，也不说轻。
func privateIsEncrypted(opt toolkitOptions) bool {
	if !opt.WithPrivate {
		return false
	}
	raw, err := os.ReadFile(opt.PrivateKeyPath)
	if err != nil {
		return false
	}
	return keystore.IsEncryptedPrivateKeyPEM(raw)
}

// toolkitReadme 生成盘内说明文件。
func toolkitReadme(fingerprint string, hasPriv, privEncrypted bool) string {
	var b strings.Builder
	b.WriteString("usbbackup 便携工具盘\n")
	b.WriteString("====================\n\n")
	b.WriteString("盘里有什么\n")
	b.WriteString("  usbsetup.exe      交互式生成向导（推荐，双击即问即答）\n")
	b.WriteString("  usbkeygen.exe     生成器（命令行）\n")
	b.WriteString("  usbunseal.exe     解压器（用私钥解密还原）\n")
	b.WriteString("  usbbackup.exe     主程序 / 客户端模板\n")
	b.WriteString("  usbcomp.exe       独立压缩器（手工打包某个目录）\n")
	b.WriteString("  client.exe        已内嵌配置与公钥的客户端\n")
	b.WriteString("  keys/             密钥材料（见下方风险）\n")
	b.WriteString("  .usbbackup-allow  授权标记（公钥指纹）\n\n")
	b.WriteString("怎么用（目标机器上）\n")
	b.WriteString("  1) 插上本盘，运行 client.exe accept   ← 首次确认一次\n")
	b.WriteString("  2) 运行 client.exe run                ← 之后静默常驻\n")
	b.WriteString("  3) 取回产物 .usbk，用 usbunseal.exe 解密：\n")
	b.WriteString("     usbunseal.exe unseal <文件>.usbk -d <目录> --key keys/usbbackup.key.pem\n")
	b.WriteString("     私钥带口令时追加 --pass（交互式）或 --pass-file <口令文件>\n\n")
	b.WriteString("为什么这个盘不会被备份走\n")
	b.WriteString("  盘根目录有 .usbbackup-allow（内容是指纹）。客户端检测到它\n")
	b.WriteString("  会走「回写分支」，把本机备份源目录的内容复制进本盘 backup/，\n")
	b.WriteString("  而不是把整盘打包带走。\n\n")
	b.WriteString("公钥指纹\n")
	fmt.Fprintf(&b, "  %s\n\n", fingerprint)
	if hasPriv && privEncrypted {
		b.WriteString("[!] 私钥风险（口令保护）\n")
		b.WriteString("  本盘 keys/usbbackup.key.pem 带口令保护：不知道口令则无法解开。\n")
		b.WriteString("  但口令保护不等于安全——盘和口令同时丢失就等于明文丢失：\n")
		b.WriteString("  - 不要把口令写在这个盘上的任何文件里（包括本文件）；\n")
		b.WriteString("  - 不要把这个盘插到不受你控制的机器上；\n")
		b.WriteString("  - 解密时会提示输入口令（usbunseal --pass）。\n")
	} else if hasPriv {
		b.WriteString("[!] 私钥风险（明文，高风险）\n")
		b.WriteString("  本盘 keys/usbbackup.key.pem 是**明文私钥**，拿到盘就能解密：\n")
		b.WriteString("  - 盘丢了 = 所有用对应公钥加密的备份都能被解开；\n")
		b.WriteString("  - 不要把这个盘插到不受你控制的机器上；\n")
		b.WriteString("  - 更稳妥的做法：换成带口令的私钥，或只带公钥（--without-private 重装）。\n")
	} else {
		b.WriteString("本盘只带公钥，私钥未上盘：解密时需要从你的电脑取私钥。\n")
	}
	fmt.Fprintf(&b, "\n生成于 usbbackup %s\n", version.Version)
	return b.String()
}

// ---- 小工具 ----

func exeDirOf() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func emptyOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func copyFile(src, dst string, force bool) error {
	if !force {
		if _, err := os.Stat(dst); err == nil {
			return fmt.Errorf("%s 已存在（加 --force 覆盖）", dst)
		}
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func writeFile(path string, body []byte, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s 已存在（加 --force 覆盖）", path)
		}
	}
	return os.WriteFile(path, body, 0o644)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
