//go:build !windows

package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// ReadPassphrase 的非 Windows 兜底实现（仅用于让工具链在其它平台上可编译，
// 不属于交付能力）。
func ReadPassphrase(prompt string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "%s（注意：当前输入未隐藏）", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读取口令失败: %w", err)
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

// ReadPassphraseFromFile 从文件读取口令。
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
