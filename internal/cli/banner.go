// Package cli 提供命令行程序共用组件：安全警告横幅、免责声明确认、无回显口令输入。
//
// 对应需求 F-901 / F-902 / F-706 / F-906。
package cli

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/immml/UsbBackup/internal/version"
)

// 退出码约定（供全部子命令统一使用）。
const (
	// ExitOK 表示成功。
	ExitOK = 0
	// ExitUsage 表示命令行用法错误。
	ExitUsage = 1
	// ExitNotAgreed 表示用户未接受免责声明。
	ExitNotAgreed = 2
	// ExitNotImplemented 表示该功能尚未实现。
	ExitNotImplemented = 3
	// ExitRuntime 表示运行期错误。
	ExitRuntime = 4
	// ExitPartial 表示部分成功。
	ExitPartial = 5
)

// WarningBanner 是必须显著展示的安全警告与免责声明摘要（F-901）。
//
// 文案要点（G-01 / G-04 / G-06 / G-07）：
//   - 仅限自有或已获授权的设备与介质；
//   - 不读取、不复制、不外传任何私钥内容；
//   - 不删除、不改写源介质上的任何文件；
//   - 无网络、无隐蔽能力、无免杀处理；
//   - 私钥一旦丢失，密文不可恢复。
const WarningBanner = `================================================================================
                        安  全  警  告   /   SECURITY WARNING
================================================================================

  [1] 使用范围
      本工具仅限用于你【本人自有】的计算机与存储介质，或你已获得【明确书面
      授权】可进行数据处理的介质。严禁用于未授权获取他人数据。

  [2] 关于"私钥检测"的真实行为
      本工具只做【存在性判定】：比对文件名特征与文件开头 4 KiB 的内容特征，
      用来判断该介质是否可以走"已授权"分支。
      它【不会】读取、解析、复制、缓存、写日志或外传任何私钥内容。
      判定过程读入的缓冲区在用完后会立即清零。

  [3] 关于数据写入
      · 已授权分支：只向该介质的 \backup\ 目录【写入】，不删除、不改写、
        不移动该目录之外的任何文件。
      · 未授权分支：只【读取】该介质内容用于打包加密，源文件一律保留。
        绝不删除源介质上的任何文件。

  [4] 关于密钥
      加密采用混合加密：AES-256-GCM 加密数据，RSA-4096-OAEP 仅包装会话密钥。
      私钥一旦丢失或口令遗忘，密文【无法恢复】。本工具不提供任何后门、
      密钥托管或找回机制。请务必自行离线备份私钥与口令。

  [5] 关于隐蔽性
      本工具【不包含】加壳、免杀、反调试、隐藏进程/窗口/端口、绕过安全软件
      等任何能力；【不进行】任何网络通信。若安全软件告警，请自行判断。

================================================================================
                        免  责  声  明  摘要   /   DISCLAIMER
================================================================================

  本软件按"现状"（AS IS）提供，不附带任何明示或默示担保，包括但不限于对
  适销性、特定用途适用性及不侵权的担保。作者与贡献者不对因使用本软件产生
  的任何直接、间接、附带、特殊、惩罚性或后果性损害承担责任，包括但不限于
  数据丢失、数据损坏、数据泄露、业务中断、设备损坏或利润损失。

  使用者须自行确保其使用行为符合所在国家/地区的法律法规，并自行承担全部
  法律后果。在将本工具用于重要数据之前，请务必先在非生产环境中验证。

  完整条款见随附的 DISCLAIMER.md 文件。

  本作品采用知识共享 署名-非商业性使用-相同方式共享 4.0 国际 协议
  （CC BY-NC-SA 4.0）进行许可。
      · 署名（BY）        —— 必须保留原作者署名
      · 非商业性使用（NC）—— 不得用于任何商业目的
      · 相同方式共享（SA）—— 改编作品须以相同协议分发
  协议全文：https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode

================================================================================
`

// RenderBanner 输出安全警告横幅，并在末尾附上程序名与版本。
func RenderBanner(w io.Writer, toolName string) {
	fmt.Fprint(w, WarningBanner)
	fmt.Fprintf(w, "  程序：%s   版本：%s\n", toolName, version.Version)
	fmt.Fprint(w, "================================================================================"+"\n\n")
}

// NoticeShort 是自动化模式（--yes）下的简短提示。
//
// 交互式启动仍会完整展示 WarningBanner（F-901）；--yes 面向脚本，
// 这里保留最关键的几条约束，避免把整屏警告重复刷进日志。
const NoticeShort = `[安全提示] 本工具仅限用于你本人自有或已获明确授权的设备与存储介质。
  · 私钥检测只判定"是否存在"，不读取、不复制、不缓存、不外传任何私钥内容；
  · 不删除、不改写源介质上的任何文件（授权分支只在 \backup\ 内写入）；
  · 无网络通信、无加壳免杀、无隐藏行为；
  · 私钥与口令一旦丢失，密文不可恢复。
  完整条款见随附 DISCLAIMER.md。本作品采用 CC BY-NC-SA 4.0 许可（非商业性使用）。`

// RenderNotice 输出简短提示（配合 --yes 使用）。
func RenderNotice(w io.Writer, toolName string) {
	fmt.Fprintln(w, NoticeShort)
	fmt.Fprintf(w, "  程序：%s   版本：%s（--yes 已跳过完整警告与确认）\n\n", toolName, version.Version)
}

// RegisterGlobalFlags 在子命令的 FlagSet 上注册全局开关。
//
// 为什么需要：`--config` 与 `--yes` 是全局开关，但每个子命令各自持有 FlagSet，
// 未注册的 flag 会直接报 "flag provided but not defined" 而中断。
// 这里统一注册，取值由 ExtractGlobalFlags 负责读取，避免各处重复解析。
func RegisterGlobalFlags(fs *flag.FlagSet) {
	fs.String("config", "", "配置文件路径（全局开关）")
	fs.Bool("yes", false, "跳过免责声明确认（全局开关，仅供自动化使用）")
}

// ParseArgs 解析子命令参数：先重排 flag 顺序，再交给 flag 包解析。
//
// 统一入口，保证所有子命令都：（1）接受全局开关；（2）允许 flag 写在位置参数之后。
func ParseArgs(fs *flag.FlagSet, args []string) error {
	RegisterGlobalFlags(fs)
	return fs.Parse(ReorderArgs(fs, args))
}

// ExtractGlobalFlags 从参数中读出全局开关的值（全局开关可出现在任意位置）。
//
// 只读值、不改动参数，因此可以被多个 FlagSet 各取所需而互不影响。
// 支持 `--config x` / `--config=x` / `-config x` / `--yes` 等写法。
func ExtractGlobalFlags(args []string) (configPath string, yes bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--yes" || a == "-yes":
			yes = true
		case a == "--config" || a == "-config":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--config="):
			configPath = strings.TrimPrefix(a, "--config=")
		case strings.HasPrefix(a, "-config="):
			configPath = strings.TrimPrefix(a, "-config=")
		}
	}
	return configPath, yes
}

// ReorderArgs 把参数重排为「所有 flag 在前，所有位置参数在后」。
//
// 为什么需要：Go 标准库的 flag 包在遇到第一个非 flag 参数后会**停止解析**，
// 因此下面这种自然写法会失效：
//
//	usbkeygen use C:\keys\usbguard.pub.pem --config D:\cfg\config.json
//	usbcomp   pack D:\data -o D:\out\x.usbk
//
// 这里依据 FlagSet 中已注册的 flag 定义做一次重排（知道哪些 flag 需要取值），
// 让 flag 写在位置参数之后同样生效，不改变任何 flag 的语义。
//
// `--` 语义：其后的参数全部视为位置参数。重排后会保留一个 `--` 放在 flag 之后，
// 这样 flag 包同样会在该处分界，不会把 `--foo` 误当成 flag。
func ReorderArgs(fs *flag.FlagSet, args []string) []string {
	isBool := make(map[string]bool)
	fs.VisitAll(func(f *flag.Flag) {
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			isBool[f.Name] = true
		}
	})

	flags := make([]string, 0, len(args))
	positional := make([]string, 0, len(args))
	sawTerminator := false
	endOfFlags := false

	for i := 0; i < len(args); {
		a := args[i]
		switch {
		case endOfFlags:
			positional = append(positional, a)
			i++
		case a == "--":
			sawTerminator = true
			endOfFlags = true
			i++
		case len(a) > 1 && a[0] == '-':
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if strings.ContainsRune(name, '=') {
				// `--flag=value` 形式自带取值。
				i++
				continue
			}
			if !isBool[name] && i+1 < len(args) {
				// 该 flag 需要取值，把下一个参数一并搬过去。
				flags = append(flags, args[i+1])
				i += 2
				continue
			}
			i++
		default:
			positional = append(positional, a)
			i++
		}
	}

	out := make([]string, 0, len(args)+1)
	out = append(out, flags...)
	if sawTerminator {
		// 保留分隔符，避免位置参数中的 `-xxx` 被重新解释成 flag。
		out = append(out, "--")
	}
	out = append(out, positional...)
	return out
}

// ConfirmAgreement 要求用户输入 I AGREE 才继续（F-902）。
//
// 返回 nil 表示已同意；返回 ErrNotAgreed 表示未同意。
func ConfirmAgreement(r io.Reader, w io.Writer) error {
	fmt.Fprint(w, "  继续操作前请输入 I AGREE（不区分大小写）表示你已阅读并同意上述条款：\n  > ")
	sc := bufio.NewScanner(r)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return fmt.Errorf("读取确认输入失败: %w", err)
		}
		fmt.Fprintln(w, "\n  未收到输入，已退出。")
		return ErrNotAgreed
	}
	answer := strings.TrimSpace(sc.Text())
	// 统一空格，容忍 "I  AGREE" 这类多空格写法。
	normalized := strings.Join(strings.Fields(strings.ToUpper(answer)), " ")
	if normalized != "I AGREE" {
		fmt.Fprintf(w, "\n  输入为 %q，未通过确认，已退出。\n", answer)
		return ErrNotAgreed
	}
	fmt.Fprintln(w, "\n  已确认。")
	return nil
}

// ErrNotAgreed 表示用户未接受免责声明。
var ErrNotAgreed = errNotAgreed{}

type errNotAgreed struct{}

func (errNotAgreed) Error() string { return "用户未接受免责声明" }

// PrintHelp 以统一格式输出子命令帮助。
func PrintHelp(w io.Writer, usage string, lines []string) {
	fmt.Fprintf(w, "%s\n\n", usage)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}
