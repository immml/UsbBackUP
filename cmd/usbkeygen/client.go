package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/immml/UsbBackUP/internal/cli"
	"github.com/immml/UsbBackUP/internal/clientgen"
	"github.com/immml/UsbBackUP/internal/config"
	"github.com/immml/UsbBackUP/internal/keystore"
)

// cmdBuildClient 产出一个「配置与公钥已内嵌」的客户端可执行文件。
//
// 用途：把客户端部署到目标机器上时，不需要再分发 config.json 与公钥文件，
// 客户端启动即按预设行为运行。内嵌的只有**公钥**，私钥始终留在你自己手里。
//
// 若不想记这些参数，可用交互式向导：usbsetup.exe
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
		fmt.Fprintln(stderr, "提示：不想记参数可用交互式向导 usbsetup.exe")
		return cli.ExitUsage
	}

	// 1) 公钥：只接受公钥，误传私钥直接拒绝（客户端会落在他人机器上）。
	pubRaw, err := os.ReadFile(*pub)
	if err != nil {
		fmt.Fprintf(stderr, "错误：读取公钥失败：%v\n", err)
		return cli.ExitRuntime
	}
	if _, err := keystore.ParsePublicKeyPEM(pubRaw); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		fmt.Fprintln(stderr, "提示：客户端只能内嵌公钥。私钥请自行离线保管，用于 usbunseal 解密。")
		return cli.ExitRuntime
	}

	// 2) 基础配置。
	var base *config.Config
	if strings.TrimSpace(*cfgFile) != "" {
		loaded, _, err := config.Load(*cfgFile)
		if err != nil {
			fmt.Fprintf(stderr, "错误：读取基础配置失败：%v\n", err)
			return cli.ExitRuntime
		}
		base = loaded
	}

	// 3) 生成（与 usbsetup 向导共用同一份实现）。
	res, err := clientgen.Build(clientgen.Options{
		PublicKeyPEM: pubRaw,
		Template:     *template,
		Output:       *out,
		BaseConfig:   base,
		ClientName:   *name,
		OutputDir:    *outDir,
		SourceDir:    *srcDir,
		Threshold:    *threshold,
		MaxTotal:     *maxTotal,
		Force:        *force,
	})
	if err != nil {
		fmt.Fprintf(stderr, "错误：生成客户端失败：%v\n", err)
		return cli.ExitRuntime
	}

	fmt.Fprintln(stdout, "客户端已生成。")
	fmt.Fprintf(stdout, "  输出        : %s\n", res.OutputPath)
	if res.ClientName != "" {
		fmt.Fprintf(stdout, "  客户端标识  : %s\n", res.ClientName)
	}
	fmt.Fprintf(stdout, "  模板        : %s\n", res.TemplatePath)
	fmt.Fprintf(stdout, "  内嵌公钥    : %d 位，指纹 %s\n", res.KeyBits, res.Fingerprint)
	fmt.Fprintf(stdout, "  产物输出目录: %s\n", res.OutputDir)
	fmt.Fprintf(stdout, "  容量门控阈值: %s\n", res.ThresholdText)
	fmt.Fprintf(stdout, "  打包体积上限: %s\n", res.MaxTotalText)
	fmt.Fprintf(stdout, "  生成时间    : %s（生成器 %s）\n", res.BuiltAt, res.BuilderVer)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  内嵌内容只有配置与公钥；私钥不在其中，也不应随客户端分发。")
	fmt.Fprintln(stdout, "  客户端运行后产出的 .usbk 只能用对应私钥解密（usbunseal）。")
	return cli.ExitOK
}
