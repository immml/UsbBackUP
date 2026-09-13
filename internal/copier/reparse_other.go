//go:build !windows

package copier

import "os"

// isReparsePoint 的非 Windows 兜底实现（仅为让工具链在其它平台可编译）。
func isReparsePoint(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSymlink != 0
}
