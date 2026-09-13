package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackUP/internal/cli"
	"github.com/immml/UsbBackUP/internal/config"
	"github.com/immml/UsbBackUP/internal/embedcfg"
	"github.com/immml/UsbBackUP/internal/keystore"
	"github.com/immml/UsbBackUP/internal/version"
)

// cmdBuildClient 产出一个「配置与公钥已内嵌」的客户端可执行文件。
//
// 用途：把客户端部署到目标机器上时，不需要再分发 config.json 与公钥文件，
// 客户端启动即按预设行为运行。内嵌的只有**公钥**，私钥始终留在你自己手里。
func cmdBuildClient(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("build-client", flag.ContinueOnError)
	fs.SetOutput(stderr)
	template := fs.String("template", "", "客户端模板 exe（默认与本工具同目录的 usbbackup.exe）")
	pub := fs.String("public", "", "公钥 PEM 文件路径（必填，只能是公钥）")
	cfgFile := fs.String("config", "", "基础配置文件（可选，未给则用内置默认配置）")
	out := fs.String("o", "", "输出客户端路径（必填，如 .\\client.exe）")
	name := fs.String("name", "", "客户端标识，写入内嵌配置便于溯源")
	outDir := fs.String("output-dir", "", "覆盖产物输出目录（支持 %TEMP% 等变量）")
	srcDir := fs.String("source-dir", "", "覆盖分支 A 的本地备份源目录")
	threshold := fs.String("threshold", "", "覆盖容量门控阈值（如 10GiB / 10GB）")
	maxTotal := fs.String("max-total", "", "覆盖打包体积上限（如 10GiB；0 或 unlimited 表示不限制）")
	force := fs.Bool("force", false, "允许覆盖已存在的输出文件")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}

	if strings.TrimSpace(*pub) == "" || strings.TrimSpace(*out) == "" {
		fmt.Fprintln(stderr, "用法：usbkeygen build-client --public <公钥.pem> -o <client.exe> [--template usbbackup.exe]")
		fmt.Fprintln(stderr, "      [--config 配置.json] [--output-dir DIR] [--source-dir DIR] [--threshold 10GiB]")
		return cli.ExitUsage
	}

	// 1) 公钥：只接受公钥，误传私钥直接拒绝（客户端会落在他人机器上）。
	pubRaw, err := os.ReadFile(*pub)
	if err != nil {
		fmt.Fprintf(stderr, "错误：读取公钥失败：%v\n", err)
		return cli.ExitRuntime
	}
	pubKey, err := keystore.ParsePublicKeyPEM(pubRaw)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		fmt.Fprintln(stderr, "提示：客户端只能内嵌公钥。私钥请自行离线保管，用于 usbunseal 解密。")
		return cli.ExitRuntime
	}
	fpBytes, fpText, err := keystore.PublicKeyFingerprint(pubKey)
	if err != nil {
		fmt.Fprintf(stderr, "错误：计算公钥指纹失败：%v\n", err)
		return cli.ExitRuntime
	}

	// 2) 配置：以内置默认打底，再叠加文件与命令行覆盖。
	cfg := config.Default()
	if strings.TrimSpace(*cfgFile) != "" {
		loaded, _, err := config.Load(*cfgFile)
		if err != nil {
			fmt.Fprintf(stderr, "错误：读取基础配置失败：%v\n", err)
			return cli.ExitRuntime
		}
		cfg = loaded
	}
	if strings.TrimSpace(*outDir) != "" {
		cfg.OutputDir = *outDir
	}
	if strings.TrimSpace(*srcDir) != "" {
		cfg.BackupSourceDir = *srcDir
	}
	if strings.TrimSpace(*threshold) != "" {
		n, err := config.ParseSize(*threshold)
		if err != nil {
			fmt.Fprintf(stderr, "错误：--threshold 无法解析：%v\n", err)
			return cli.ExitUsage
		}
		cfg.Gate.UsedThresholdBytes = n
		cfg.Gate.UsedThreshold = *threshold
	}
	if strings.TrimSpace(*maxTotal) != "" {
		n, err := config.ParseSize(*maxTotal)
		if err != nil {
			fmt.Fprintf(stderr, "错误：--max-total 无法解析：%v\n", err)
			return cli.ExitUsage
		}
		cfg.Gate.MaxTotalBytes = n
	}
	// 客户端不读取外部配置文件，公钥路径仅作展示用途。
	cfg.PublicKeyPath = "<内嵌于客户端>"
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "错误：配置校验失败：%v\n", err)
		return cli.ExitRuntime
	}

	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "错误：序列化配置失败：%v\n", err)
		return cli.ExitRuntime
	}

	// 3) 模板：默认取与本工具同目录的 usbbackup.exe。
	tpl := strings.TrimSpace(*template)
	if tpl == "" {
		tpl = defaultClientTemplate()
	}
	if fi, err := os.Stat(tpl); err != nil {
		fmt.Fprintf(stderr, "错误：找不到客户端模板 %s：%v\n", tpl, err)
		fmt.Fprintln(stderr, "提示：把 usbbackup.exe 放在本工具同目录，或用 --template 指定路径。")
		return cli.ExitRuntime
	} else if fi.IsDir() {
		fmt.Fprintf(stderr, "错误：模板 %s 是目录\n", tpl)
		return cli.ExitUsage
	}

	outPath, err := filepath.Abs(*out)
	if err != nil {
		fmt.Fprintf(stderr, "错误：解析输出路径失败：%v\n", err)
		return cli.ExitRuntime
	}
	if _, err := os.Stat(outPath); err == nil && !*force {
		fmt.Fprintf(stderr, "错误：%s 已存在（加 --force 覆盖）\n", outPath)
		return cli.ExitRuntime
	}

	// 4) 追加内嵌块（含私钥守卫，含校验和）。
	payload := embedcfg.Payload{
		ConfigJSON:     cfgJSON,
		PublicKeyPEM:   string(pubRaw),
		ClientName:     strings.TrimSpace(*name),
		BuiltAt:        time.Now().Format(time.RFC3339),
		BuilderVersion: version.Version,
	}
	if err := embedcfg.Append(tpl, outPath, payload); err != nil {
		fmt.Fprintf(stderr, "错误：生成客户端失败：%v\n", err)
		return cli.ExitRuntime
	}

	// 5) 回读自检：确认产物能正确读出同样的公钥指纹。
	got, err := embedcfg.Read(outPath)
	if err != nil {
		fmt.Fprintf(stderr, "错误：客户端自检失败（读回内嵌配置时出错）：%v\n", err)
		return cli.ExitRuntime
	}
	gotPub, err := keystore.ParsePublicKeyPEM([]byte(got.PublicKeyPEM))
	if err != nil {
		fmt.Fprintf(stderr, "错误：客户端自检失败（内嵌公钥不可用）：%v\n", err)
		return cli.ExitRuntime
	}
	gotFP, _, err := keystore.PublicKeyFingerprint(gotPub)
	if err != nil || gotFP != fpBytes {
		fmt.Fprintln(stderr, "错误：客户端自检失败（回读的公钥指纹与源不一致）")
		return cli.ExitRuntime
	}

	// 6) 输出摘要。
	fmt.Fprintln(stdout, "客户端已生成。")
	fmt.Fprintf(stdout, "  输出        : %s\n", outPath)
	if got.ClientName != "" {
		fmt.Fprintf(stdout, "  客户端标识  : %s\n", got.ClientName)
	}
	fmt.Fprintf(stdout, "  模板        : %s\n", tpl)
	fmt.Fprintf(stdout, "  内嵌公钥    : %d 位，指纹 %s\n", pubKey.N.BitLen(), fpText)
	fmt.Fprintf(stdout, "  产物输出目录: %s\n", cfg.OutputDir)
	fmt.Fprintf(stdout, "  容量门控阈值: %s\n", humanThreshold(cfg))
	fmt.Fprintf(stdout, "  生成时间    : %s（生成器 %s）\n", got.BuiltAt, got.BuilderVersion)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  内嵌内容只有配置与公钥；私钥不在其中，也不应随客户端分发。")
	fmt.Fprintln(stdout, "  客户端运行后产出的 .usbk 只能用对应私钥解密（usbunseal）。")

	// 清掉内存里的公钥副本无实际意义（公钥本就公开），这里只做变量归零的示意。
	_ = pubRaw
	return cli.ExitOK
}

// defaultClientTemplate 返回默认的客户端模板路径：与本工具同目录的 usbbackup.exe。
func defaultClientTemplate() string {
	exe, err := os.Executable()
	if err != nil {
		return "usbbackup.exe"
	}
	return filepath.Join(filepath.Dir(exe), "usbbackup.exe")
}

// humanThreshold 把阈值显示成人类可读形式。
func humanThreshold(c *config.Config) string {
	if s := strings.TrimSpace(c.Gate.UsedThreshold); s != "" {
		return fmt.Sprintf("%s（%d 字节）", s, c.Gate.UsedThresholdBytes)
	}
	return fmt.Sprintf("%d 字节", c.Gate.UsedThresholdBytes)
}
