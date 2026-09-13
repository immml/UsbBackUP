//go:build !windows

package fsutil

import (
	"fmt"
	"strings"
	"syscall"
)

// FreeBytes 的非 Windows 兜底实现（仅用于让工具链在其它平台可编译）。
// 本项目仅针对 Windows，此实现不属于交付能力。
func FreeBytes(path string) (int64, error) {
	if strings.TrimSpace(path) == "" {
		return 0, fmt.Errorf("路径为空")
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
