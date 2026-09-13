//go:build windows

package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32fs              = syscall.NewLazyDLL("kernel32.dll")
	procGetDiskFreeSpaceExW = kernel32fs.NewProc("GetDiskFreeSpaceExW")
)

// FreeBytes 返回 path 所在卷的剩余可用字节数（TotalNumberOfFreeBytes）。
//
// 这是只读查询，无副作用。取不到时返回错误，由调用方决定是否降级。
func FreeBytes(path string) (int64, error) {
	if strings.TrimSpace(path) == "" {
		return 0, fmt.Errorf("路径为空")
	}
	// GetDiskFreeSpaceExW 以目录为入参；目录不存在时退化为其父目录。
	dir := path
	if st, err := os.Stat(LongPath(dir)); err != nil || !st.IsDir() {
		dir = filepath.Dir(path)
	}
	if dir == "" {
		return 0, fmt.Errorf("无法确定目标目录")
	}

	p, err := syscall.UTF16PtrFromString(LongPath(dir))
	if err != nil {
		return 0, fmt.Errorf("路径编码失败: %w", err)
	}
	var freeToCaller, total, totalFree uint64
	r, _, callErr := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&freeToCaller)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return 0, fmt.Errorf("GetDiskFreeSpaceExW 失败: %w", callErr)
		}
		return 0, fmt.Errorf("GetDiskFreeSpaceExW 返回失败")
	}
	return int64(totalFree), nil
}
