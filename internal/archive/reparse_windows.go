//go:build windows

package archive

import (
	"os"
	"syscall"
)

// fileAttributeReparsePoint 对应 FILE_ATTRIBUTE_REPARSE_POINT。
const fileAttributeReparsePoint = 0x00000400

// isReparsePoint 判断路径是否为重解析点（符号链接、目录联接点、挂载点）。
// 打包时一律不跟随，防递归循环与越界读取（F-506）。
//
// 注意：Go 的 os.FileMode 不会把 Windows 目录联接点标记为 ModeSymlink，
// 必须直接检查文件属性位。
func isReparsePoint(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return true
	}
	if data, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok {
		return data.FileAttributes&fileAttributeReparsePoint != 0
	}
	return false
}
