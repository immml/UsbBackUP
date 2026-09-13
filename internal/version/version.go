// Package version 保存构建期注入的版本信息。
// 通过 -ldflags "-X github.com/immml/UsbBackUP/internal/version.Version=..." 注入。
package version

import (
	"fmt"
	"runtime"
)

// 构建期通过 -ldflags 注入的变量。默认值为开发构建标记。
var (
	// Version 语义化版本号。
	Version = "0.1.0-dev"
	// Commit Git 提交短哈希。
	Commit = "unknown"
	// BuildTime 构建时间（RFC3339）。
	BuildTime = "unknown"
	// BuildUser 构建者，便于产物溯源。
	BuildUser = "unknown"
)

// AppName 是程序集名称，用于产物命名、日志与互斥体名。
const AppName = "usbbackup"

// String 返回单行版本描述。
func String() string {
	return fmt.Sprintf("%s %s (commit %s, built %s by %s, %s/%s, %s)",
		AppName, Version, Commit, BuildTime, BuildUser,
		runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// MultiLine 返回多行版本详情，程序名取产品名 AppName。
func MultiLine() string {
	return MultiLineFor(AppName)
}

// MultiLineFor 返回指定程序名的多行版本详情。
//
// 四个可执行文件共用同一个 version 包，但各自有独立的可执行名
// （usbbackup / usbkeygen / usbcomp / usbunseal）。若统一打印 AppName，
// 用户无法从 version 输出判断自己跑的是哪一个工具，排查问题时容易误判。
// 版本与构建信息仍然共享，只有展示用的程序名不同。
func MultiLineFor(tool string) string {
	if tool == "" {
		tool = AppName
	}
	return fmt.Sprintf(`%s
  产品      : %s
  版本      : %s
  提交      : %s
  构建时间  : %s
  构建者    : %s
  Go 版本   : %s
  目标平台  : %s/%s
  协议      : CC BY-NC-SA 4.0（非商业性使用）`,
		tool, AppName, Version, Commit, BuildTime, BuildUser,
		runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
