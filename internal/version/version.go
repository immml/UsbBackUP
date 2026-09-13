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

// MultiLine 返回多行版本详情，供 `version` 子命令使用。
func MultiLine() string {
	return fmt.Sprintf(`%s
  版本      : %s
  提交      : %s
  构建时间  : %s
  构建者    : %s
  Go 版本   : %s
  目标平台  : %s/%s
  协议      : CC BY-NC-SA 4.0（非商业性使用）`,
		AppName, Version, Commit, BuildTime, BuildUser,
		runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
