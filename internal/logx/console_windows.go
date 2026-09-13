//go:build windows

package logx

import "syscall"

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
	procSetConsoleCP       = kernel32.NewProc("SetConsoleCP")
)

// utf8CodePage 是 Windows 的 UTF-8 代码页编号。
const utf8CodePage = 65001

// init 在包加载时把控制台切到 UTF-8，保证中文日志不乱码。
func init() {
	initConsoleUTF8()
}

// initConsoleUTF8 把控制台输入输出代码页切到 UTF-8，
// 避免中文日志在 legacy cmd.exe 下变成乱码。
// 在 Windows Terminal / 已设置 chcp 65001 的环境下是幂等的。
func initConsoleUTF8() {
	_, _, _ = procSetConsoleOutputCP.Call(uintptr(utf8CodePage))
	_, _, _ = procSetConsoleCP.Call(uintptr(utf8CodePage))
}
