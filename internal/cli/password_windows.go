//go:build windows

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// enableEchoInput 对应 ENABLE_ECHO_INPUT 控制台模式位。
const enableEchoInput = 0x0004

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

// setConsoleMode 包装 SetConsoleMode。
// Go 标准库的 syscall 包只导出了 GetConsoleMode，因此这里直接走 kernel32。
func setConsoleMode(h syscall.Handle, mode uint32) error {
	r, _, callErr := procSetConsoleMode.Call(uintptr(h), uintptr(mode))
	if r == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return callErr
		}
		return errors.New("SetConsoleMode 调用失败")
	}
	return nil
}

// ReadPassphrase 在控制台上无回显地读取口令（F-706）。
//
// 优先关闭终端回显；若 stdin 被重定向（非控制台），则退化为普通读取并提示用户，
// 以保证在脚本/服务场景下仍可用，同时不让用户误以为输入被隐藏。
func ReadPassphrase(prompt string) ([]byte, error) {
	h, err := syscall.GetStdHandle(int(syscall.Stdin))
	if err != nil {
		return readPlainPassphrase(prompt)
	}
	var mode uint32
	if err := syscall.GetConsoleMode(h, &mode); err != nil {
		// 非控制台（管道/文件重定向）。
		return readPlainPassphrase(prompt)
	}
	restore := mode | enableEchoInput
	if err := setConsoleMode(h, mode&^enableEchoInput); err != nil {
		return readPlainPassphrase(prompt)
	}
	defer func() {
		_ = setConsoleMode(h, restore)
		fmt.Fprintln(os.Stderr)
	}()

	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读取口令失败: %w", err)
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

func readPlainPassphrase(prompt string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "%s（注意：当前输入未隐藏）", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读取口令失败: %w", err)
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

// ReadPassphraseFromFile 从文件读取口令，适合无人值守场景（F-706）。
// 文件内容的首行（去除行尾换行）即为口令。
func ReadPassphraseFromFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取口令文件失败 %s: %w", path, err)
	}
	s := string(raw)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return []byte(s), nil
}
