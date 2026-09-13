package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/immml/UsbBackUP/internal/agreement"
	"github.com/immml/UsbBackUP/internal/cli"
	"github.com/immml/UsbBackUP/internal/version"
)

// cmdAccept 处理「首次知情同意」：确认一次，写成本机记录，之后 run/once 静默运行。
//
// 用法：
//
//	usbbackup accept             展示完整安全警告与免责声明，要求输入 I AGREE
//	usbbackup accept --yes       供部署脚本使用：不交互，直接记录（等同"已知情"）
//	usbbackup accept --check     只查看当前是否已确认（未确认退出码 2）
//	usbbackup accept --revoke    撤销确认，恢复首次确认流程
//	usbbackup accept --force     已确认时重新确认（版本升级或条款变更时用）
func cmdAccept(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("accept", flag.ContinueOnError)
	fs.SetOutput(stderr)
	yes := fs.Bool("yes", false, "非交互确认（供部署脚本使用）")
	check := fs.Bool("check", false, "只检查是否已确认")
	revoke := fs.Bool("revoke", false, "撤销确认")
	force := fs.Bool("force", false, "已确认时也重新确认")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}

	// --check：只看状态。
	if *check {
		rec, ok, err := agreement.Load()
		if err != nil {
			fmt.Fprintf(stderr, "读取确认记录失败：%v\n", err)
			fmt.Fprintf(stderr, "（记录文件：%s）\n", agreement.Path())
			return cli.ExitRuntime
		}
		if !ok {
			fmt.Fprintln(stdout, "状态：未确认（首次运行 run/once 会要求确认）")
			return cli.ExitNotAgreed
		}
		fmt.Fprintln(stdout, "状态：已确认，run/once 将静默运行")
		fmt.Fprintf(stdout, "  确认时间  : %s\n", rec.AcceptedAt)
		fmt.Fprintf(stdout, "  当时版本  : %s\n", rec.Version)
		fmt.Fprintf(stdout, "  许可协议  : %s\n", rec.Policy)
		if rec.ClientName != "" {
			fmt.Fprintf(stdout, "  客户端标识: %s\n", rec.ClientName)
		}
		fmt.Fprintf(stdout, "  记录文件  : %s\n", agreement.Path())
		return cli.ExitOK
	}

	// --revoke：撤销。
	if *revoke {
		if err := agreement.Revoke(); err != nil {
			fmt.Fprintf(stderr, "撤销失败：%v\n", err)
			return cli.ExitRuntime
		}
		fmt.Fprintln(stdout, "已撤销确认：下次运行 run/once 会重新要求确认。")
		return cli.ExitOK
	}

	// 已确认且未要求重新确认。
	if agreement.Accepted() && !*force {
		rec, _, _ := agreement.Load()
		fmt.Fprintln(stdout, "本机已确认过，run/once 将静默运行。")
		fmt.Fprintf(stdout, "  确认时间  : %s（版本 %s）\n", rec.AcceptedAt, rec.Version)
		fmt.Fprintf(stdout, "  记录文件  : %s\n", agreement.Path())
		fmt.Fprintln(stdout, "  如需重新确认：accept --force；撤销：accept --revoke")
		return cli.ExitOK
	}

	// 完整展示安全警告与免责声明。
	cli.RenderBanner(stdout, toolName)
	fmt.Fprintf(stdout, "  许可协议    : %s（非商业性使用）\n", agreement.Policy)
	fmt.Fprintf(stdout, "  程序版本    : %s\n", version.Version)
	fmt.Fprintln(stdout)

	if *yes {
		// 部署脚本路径：不交互，但明确打印"视为已知情"，不静悄悄记一笔。
		fmt.Fprintln(stdout, "  已通过 --yes 记录确认（请确认操作人员已阅读并同意上述条款）。")
	} else {
		if err := cli.ConfirmAgreement(stdin, stdout); err != nil {
			fmt.Fprintln(stderr, "\n未确认，未写入任何记录。")
			return cli.ExitNotAgreed
		}
	}

	name := ""
	if clientBuild.ok {
		name = clientBuild.name
	}
	rec, err := agreement.Save(name)
	if err != nil {
		fmt.Fprintf(stderr, "写入确认记录失败：%v\n", err)
		return cli.ExitRuntime
	}

	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "已记录确认，后续 run/once 将静默运行（不再重复提示）。")
	fmt.Fprintf(stdout, "  确认时间  : %s\n", rec.AcceptedAt)
	if rec.ClientName != "" {
		fmt.Fprintf(stdout, "  客户端标识: %s\n", rec.ClientName)
	}
	fmt.Fprintf(stdout, "  记录文件  : %s\n", agreement.Path())
	fmt.Fprintln(stdout, "  撤销方式  : accept --revoke")
	return cli.ExitOK
}
