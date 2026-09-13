// usbsetup —— 交互式客户端生成向导（控制台程序）。
//
// 存在意义：`usbkeygen build-client` 的参数较多，记不住也容易敲错。
// 这个向导把生成过程变成一问一答：选密钥 → 填几个路径与阈值 → 确认 → 产出。
//
// 生成逻辑与 `usbkeygen build-client` 完全相同（共用 internal/clientgen），
// 两种入口产出的客户端行为一致，不存在"向导版"和"命令行版"的差异。
//
// 它是**控制台**程序（不带 windowsgui），双击会打开黑窗口——这是刻意的：
// 生成客户端是"你自己的机器上、需要你逐项确认"的操作，不该静默完成。
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/immml/UsbBackUP/internal/cli"
	"github.com/immml/UsbBackUP/internal/clientgen"
	"github.com/immml/UsbBackUP/internal/keystore"
	"github.com/immml/UsbBackUP/internal/version"
)

const toolName = "usbsetup"

func main() {
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr))
}

func run(stdin io.Reader, stdout, stderr io.Writer) int {
	// 全程共用同一个 bufio.Reader。
	//
	// 切忌把 stdin 与包装后的 reader 混用：bufio 会一次预读一整块，
	// 之后再从原始 stdin 读就会错位（实测表现为"位数 2048 被读成默认的 4096"）。
	r := bufio.NewReader(stdin)

	printHeader(stdout)

	// 免责声明：与生成器一致，必须显式同意。
	cli.RenderBanner(stdout, toolName)
	fmt.Fprintf(stdout, "  许可协议    : %s（非商业性使用）\n", "CC BY-NC-SA 4.0")
	fmt.Fprintln(stdout)
	if err := cli.ConfirmAgreementBuf(r, stdout); err != nil {
		fmt.Fprintln(stderr, "\n未确认，已退出。")
		return cli.ExitNotAgreed
	}

	// ---- 步骤 1：密钥 ----
	pubPEM, keyNote, code := askKey(r, stdout, stderr)
	if code != cli.ExitOK {
		return code
	}

	// ---- 步骤 2：产物输出目录 ----
	fmt.Fprintf(stdout, "\n[2/5] 客户端把备份写到哪个目录\n")
	defOut := filepath.Join(os.TempDir(), "backup")
	outDir, _ := ask(r, stdout, "  备份产物输出目录", defOut)

	// ---- 步骤 3：容量阈值 ----
	fmt.Fprintf(stdout, "\n[3/5] 容量门控（U 盘已占用超过这个值就不备份）\n")
	threshold, _ := ask(r, stdout, "  阈值（支持 10GiB/10GB/500MiB）", "10GiB")

	// ---- 步骤 4：打包上限 ----
	fmt.Fprintf(stdout, "\n[4/5] 打包体积上限（0 表示不限制）\n")
	maxTotal, _ := ask(r, stdout, "  上限", "10GiB")

	// ---- 步骤 5：回写分支与输出 ----
	fmt.Fprintf(stdout, "\n[5/5] 回写分支与输出（可直接回车跳过）\n")
	srcDir, _ := ask(r, stdout, "  本地备份源目录（检测到私钥时回写到 U 盘）", "")
	name, _ := ask(r, stdout, "  客户端标识", "usbbackup-client")
	out, _ := ask(r, stdout, "  客户端输出路径", defaultOutput())
	tpl, _ := ask(r, stdout, "  客户端模板（默认同目录 usbbackup.exe）", clientgen.DefaultTemplate())

	// ---- 确认 ----
	fmt.Fprintln(stdout, "\n================ 请确认 ================")
	fmt.Fprintf(stdout, "  公钥        : %s\n", keyNote)
	fmt.Fprintf(stdout, "  产物输出目录: %s\n", outDir)
	fmt.Fprintf(stdout, "  容量阈值    : %s\n", threshold)
	fmt.Fprintf(stdout, "  打包上限    : %s\n", maxTotal)
	if strings.TrimSpace(srcDir) == "" {
		fmt.Fprintln(stdout, "  回写分支    : 未启用")
	} else {
		fmt.Fprintf(stdout, "  本地备份源  : %s\n", srcDir)
	}
	fmt.Fprintf(stdout, "  客户端标识  : %s\n", name)
	fmt.Fprintf(stdout, "  输出        : %s\n", out)
	fmt.Fprintln(stdout, "========================================")

	if !askYesNo(r, stdout, "确认生成？", true) {
		fmt.Fprintln(stdout, "已取消，未生成任何文件。")
		return cli.ExitOK
	}

	// 输出已存在时先问一次，避免覆盖掉正在使用的客户端。
	force := false
	if _, err := os.Stat(out); err == nil {
		if !askYesNo(r, stdout, fmt.Sprintf("  %s 已存在，覆盖它？", out), false) {
			fmt.Fprintln(stdout, "已取消，未生成任何文件。")
			return cli.ExitOK
		}
		force = true
	}

	fmt.Fprintln(stdout, "\n正在生成…")
	res, err := clientgen.Build(clientgen.Options{
		PublicKeyPEM: pubPEM,
		Template:     tpl,
		Output:       out,
		ClientName:   name,
		OutputDir:    outDir,
		SourceDir:    srcDir,
		Threshold:    threshold,
		MaxTotal:     maxTotal,
		Force:        force,
	})
	if err != nil {
		fmt.Fprintf(stderr, "生成失败：%v\n", err)
		return cli.ExitRuntime
	}

	printResult(stdout, res)
	return cli.ExitOK
}

// askKey 处理密钥环节：生成新的，或使用已有公钥。
func askKey(r *bufio.Reader, stdout, stderr io.Writer) (pem []byte, note string, code int) {
	fmt.Fprintln(stdout, "\n[1/5] 密钥")
	fmt.Fprintln(stdout, "  1) 生成新的密钥对（推荐，首次使用选这个）")
	fmt.Fprintln(stdout, "  2) 使用已有的公钥文件")
	for {
		choice, eof := ask(r, stdout, "  选择", "1")
		switch strings.TrimSpace(choice) {
		case "1", "":
			return generateNew(r, stdout, stderr)
		case "2":
			return useExisting(r, stdout, stderr)
		default:
			if eof {
				fmt.Fprintln(stdout, "  输入已结束，按默认（生成新密钥）继续。")
				return generateNew(r, stdout, stderr)
			}
			fmt.Fprintln(stdout, "  请输入 1 或 2。")
			continue
		}
	}
}

func generateNew(r *bufio.Reader, stdout, stderr io.Writer) ([]byte, string, int) {
	bitsStr, _ := ask(r, stdout, "  RSA 位数（2048/3072/4096）", strconv.Itoa(keystore.DefaultRSAKeyBits))
	bits, err := strconv.Atoi(bitsStr)
	if err != nil || bits < keystore.MinRSAKeyBits || bits > keystore.MaxRSAKeyBits {
		fmt.Fprintf(stderr, "位数非法：%s（应在 %d..%d 之间）\n", bitsStr, keystore.MinRSAKeyBits, keystore.MaxRSAKeyBits)
		return nil, "", cli.ExitUsage
	}
	dir, _ := ask(r, stdout, "  密钥输出目录", "keys")

	var pass []byte
	if askYesNo(r, stdout, "  给私钥加口令保护？", true) {
		for {
			p1, err := cli.ReadPassphrase("  私钥口令（至少 8 位，输入不回显）: ")
			if err != nil {
				fmt.Fprintf(stderr, "读取口令失败：%v\n", err)
				return nil, "", cli.ExitRuntime
			}
			p2, err := cli.ReadPassphrase("  再输入一次: ")
			if err != nil {
				fmt.Fprintf(stderr, "读取口令失败：%v\n", err)
				return nil, "", cli.ExitRuntime
			}
			if string(p1) != string(p2) {
				fmt.Fprintln(stdout, "  两次不一致，请重来。")
				continue
			}
			pass = p1
			break
		}
		defer func() {
			for i := range pass {
				pass[i] = 0
			}
		}()
	}

	fmt.Fprintf(stdout, "  正在生成 %d 位密钥对，请稍候…\n", bits)
	kp, err := keystore.Generate(keystore.GenerateOptions{
		Bits:       bits,
		OutDir:     dir,
		Passphrase: pass,
	})
	if err != nil {
		fmt.Fprintf(stderr, "生成密钥失败：%v\n", err)
		return nil, "", cli.ExitRuntime
	}
	raw, err := os.ReadFile(kp.PublicPath)
	if err != nil {
		fmt.Fprintf(stderr, "读取生成的公钥失败：%v\n", err)
		return nil, "", cli.ExitRuntime
	}
	note := fmt.Sprintf("新建 %d 位，指纹 %s", kp.Bits, kp.Fingerprint)
	fmt.Fprintf(stdout, "  私钥：%s\n", kp.PrivatePath)
	fmt.Fprintf(stdout, "  公钥：%s\n", kp.PublicPath)
	fmt.Fprintln(stdout, "  [重要] 请立即把私钥与口令备份到离线介质，丢失后密文不可恢复。")
	return raw, note, cli.ExitOK
}

func useExisting(r *bufio.Reader, stdout, stderr io.Writer) ([]byte, string, int) {
	for {
		p, eof := ask(r, stdout, "  公钥文件路径", "")
		p = strings.TrimSpace(p)
		if p == "" {
			// 输入已耗尽还在空转，只会把用户卡在一个退不出的循环里。
			if eof {
				fmt.Fprintln(stderr, "  未获得公钥路径（输入已结束），已退出。")
				return nil, "", cli.ExitUsage
			}
			fmt.Fprintln(stdout, "  路径不能为空。")
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(stderr, "  读取失败：%v\n", err)
			if eof {
				return nil, "", cli.ExitUsage
			}
			continue
		}
		pub, err := keystore.ParsePublicKeyPEM(raw)
		if err != nil {
			fmt.Fprintf(stderr, "  %v\n", err)
			fmt.Fprintln(stderr, "  提示：这里只能选公钥（usbbackup.pub.pem）。私钥不会也不能内嵌。")
			if eof {
				return nil, "", cli.ExitUsage
			}
			continue
		}
		_, fp, err := keystore.PublicKeyFingerprint(pub)
		if err != nil {
			fmt.Fprintf(stderr, "  %v\n", err)
			if eof {
				return nil, "", cli.ExitUsage
			}
			continue
		}
		return raw, fmt.Sprintf("已有 %d 位，指纹 %s", pub.N.BitLen(), fp), cli.ExitOK
	}
}

// ---- 输入辅助 ----

// ask 提一个问题，直接回车取默认值；默认值非空时会在提示里显示。
//
// 第二返回值表示**输入是否已结束**（EOF）。调用方据此决定是否继续循环——
// 输入耗尽时若还反复重试，交互式程序会退不出、也占着 CPU 空转。
func ask(r *bufio.Reader, stdout io.Writer, prompt, def string) (string, bool) {
	if def != "" {
		fmt.Fprintf(stdout, "%s [%s]: ", prompt, def)
	} else {
		fmt.Fprintf(stdout, "%s: ", prompt)
	}
	line, err := r.ReadString('\n')
	if err != nil {
		// EOF（管道/重定向输入结束）：退回默认值，保证脚本化可用。
		fmt.Fprintln(stdout)
		if v := strings.TrimSpace(line); v != "" {
			return v, true
		}
		return def, true
	}
	v := strings.TrimSpace(line)
	if v == "" {
		return def, false
	}
	return v, false
}

// askYesNo 提一个是/否问题，直接回车取默认值。
func askYesNo(r *bufio.Reader, stdout io.Writer, prompt string, def bool) bool {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	for {
		fmt.Fprintf(stdout, "%s [%s]: ", prompt, hint)
		line, err := r.ReadString('\n')
		if err != nil && strings.TrimSpace(line) == "" {
			// 输入结束：直接用默认值，不再空转。
			fmt.Fprintln(stdout)
			return def
		}
		v := strings.ToLower(strings.TrimSpace(line))
		switch v {
		case "":
			return def
		case "y", "yes":
			return true
		case "n", "no":
			return false
		default:
			if err != nil {
				fmt.Fprintln(stdout)
				return def
			}
			fmt.Fprintln(stdout, "  请输入 y 或 n。")
		}
	}
}

func defaultOutput() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "client.exe"
	}
	return filepath.Join(cwd, "client.exe")
}

func printHeader(stdout io.Writer) {
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  usbbackup 客户端生成向导")
	fmt.Fprintf(stdout, "  版本 %s —— 一问一答，产出一个配置与公钥已内嵌的客户端\n", version.Version)
	fmt.Fprintln(stdout, "  （每一步直接回车即采用方括号里的默认值；Ctrl+C 可随时退出）")
}

func printResult(stdout io.Writer, res clientgen.Result) {
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "客户端已生成。")
	fmt.Fprintf(stdout, "  输出        : %s\n", res.OutputPath)
	fmt.Fprintf(stdout, "  客户端标识  : %s\n", res.ClientName)
	fmt.Fprintf(stdout, "  内嵌公钥    : %d 位，指纹 %s\n", res.KeyBits, res.Fingerprint)
	fmt.Fprintf(stdout, "  产物输出目录: %s\n", res.OutputDir)
	fmt.Fprintf(stdout, "  容量阈值    : %s\n", res.ThresholdText)
	fmt.Fprintf(stdout, "  打包上限    : %s\n", res.MaxTotalText)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "下一步：")
	fmt.Fprintf(stdout, "  1) 把 %s 拷到目标机器（只需这一个文件）\n", filepath.Base(res.OutputPath))
	fmt.Fprintln(stdout, "  2) 在那台机器上执行：accept      ← 首次确认，之后不再提示")
	fmt.Fprintln(stdout, "  3) 然后执行：run                 ← 常驻监控；或 once 处理当前已插入的盘")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  私钥留在你这台机器上，不要随客户端分发；")
	fmt.Fprintln(stdout, "  取回 .usbk 后用 usbunseal 解密还原。")
}
