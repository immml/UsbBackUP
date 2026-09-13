//go:build windows

package cli

import "syscall"

var (
	kernel32CLI               = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleOutputCPCLI = kernel32CLI.NewProc("SetConsoleOutputCP")
	procSetConsoleCPCLI       = kernel32CLI.NewProc("SetConsoleCP")
)

// utf8CodePage 是 Windows 的 UTF-8 代码页编号。
const utf8CodePage = 65001

// init 在包加载时把控制台输入输出代码页切到 UTF-8。
//
// 所有四个可执行文件都导入本包，因此这一步能统一保证中文提示在
// legacy cmd.exe 下不乱码（Windows Terminal 默认已是 UTF-8，此调用幂等）。
func init() {
	if stdinIsConsole() {
		_, _, _ = procSetConsoleOutputCPCLI.Call(uintptr(utf8CodePage))
		_, _, _ = procSetConsoleCPCLI.Call(uintptr(utf8CodePage))
	}
}

// stdinIsConsole 判断当前进程是否挂在真实控制台上。
// 被重定向时不做任何事，避免影响管道/脚本场景的字节流。
func stdinIsConsole() bool {
	h, err := syscall.GetStdHandle(int(syscall.Stdout))
	if err != nil {
		return false
	}
	var mode uint32
	return syscall.GetConsoleMode(h, &mode) == nil
}
