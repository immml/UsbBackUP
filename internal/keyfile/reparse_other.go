//go:build !windows

package keyfile

import "os"

// isReparsePoint 的非 Windows 兜底实现。
//
// 本项目仅针对 Windows，此文件仅为让 go vet / 开发者工具链在其它平台上
// 也能完成语法与类型检查而存在，不参与任何交付产物。
func isReparsePoint(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSymlink != 0
}
