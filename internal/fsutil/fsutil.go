// Package fsutil 提供 Windows 路径处理工具：长路径前缀、文件名净化、
// 路径包含关系判定。全部实现不依赖任何第三方库。
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// maxPathBeforePrefix 是触发 \\?\ 前缀的路径长度阈值。
// Windows MAX_PATH 为 260，预留卷根与文件名余量。
const maxPathBeforePrefix = 240

// longPathPrefix 表示已带扩展长度前缀。
const longPathPrefix = `\\?\`

// reservedNames 是 Windows 保留设备名，作为文件名（含扩展名前的主体）时非法。
var reservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// invalidNameChars 是 Windows 文件名禁用字符。
const invalidNameChars = `<>:"/\|?*`

// LongPath 在路径可能超过 MAX_PATH 时补上 \\?\ 扩展长度前缀。
// 短路径原样返回，避免对其他工具造成干扰。
func LongPath(p string) string {
	if p == "" || strings.HasPrefix(p, longPathPrefix) {
		return p
	}
	if len([]rune(p)) < maxPathBeforePrefix {
		return p
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = p
	}
	// UNC 路径需要 \\?\UNC\server\share 形式。
	if strings.HasPrefix(abs, `\\`) {
		return longPathPrefix + "UNC" + strings.TrimPrefix(abs, `\\`)
	}
	return longPathPrefix + abs
}

// SanitizeName 把任意字符串净化成一个安全的 Windows 单层文件名。
// 净化后为空则返回空串，由调用方决定兜底名。
func SanitizeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 32:
			b.WriteRune('_')
		case strings.ContainsRune(invalidNameChars, r):
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), " .")
	if out == "" {
		return ""
	}
	const maxRunes = 120
	if rs := []rune(out); len(rs) > maxRunes {
		out = string(rs[:maxRunes])
		out = strings.Trim(out, " .")
		if out == "" {
			return ""
		}
	}
	// 保留设备名判定以扩展名前的主体为准。
	base := out
	if i := strings.IndexByte(out, '.'); i > 0 {
		base = out[:i]
	}
	if reservedNames[strings.ToUpper(base)] {
		return "_" + out
	}
	return out
}

// VolumeRoot 返回路径所属卷的根，例如 `E:\`。
func VolumeRoot(p string) string {
	v := filepath.VolumeName(p)
	if v == "" {
		return ""
	}
	return v + `\`
}

// normalRoot 归一化卷根以便比较：大写、去掉尾部反斜杠。
func normalRoot(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = p
	}
	abs = strings.TrimRight(abs, `\/`)
	if len(abs) == 2 && abs[1] == ':' {
		abs += `\`
	}
	return strings.ToUpper(abs)
}

// SameVolume 判断两个路径是否落在同一个卷上。
func SameVolume(a, b string) bool {
	ra := normalRoot(VolumeRoot(a))
	rb := normalRoot(VolumeRoot(b))
	return ra != "" && ra == rb
}

// IsSubPath 判断 child 是否等于 parent 或位于 parent 之内。
// 比较不区分大小写，与 Windows 语义一致。
func IsSubPath(parent, child string) bool {
	if parent == "" || child == "" {
		return false
	}
	pa := normalRoot(parent)
	ca := normalRoot(child)
	if pa == ca {
		return true
	}
	sep := string(os.PathSeparator)
	// 注意：卷根本身已以分隔符结尾（如 `E:\`），此时不能再追加分隔符，
	// 否则 "E:\" + "\" 会拼成 "E:\\"，前缀比较永远失败。
	if !strings.HasSuffix(pa, sep) {
		pa += sep
	}
	return strings.HasPrefix(ca, pa)
}

// HumanBytes 把字节数格式化为便于阅读的字符串。
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	v := float64(n)
	i := -1
	for v >= unit && i < len(units)-1 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.2f %s", v, units[i])
}

// EnsureLongPathParent 返回 dir 的扩展长度形式（存在时用于创建子项）。
func EnsureLongPathParent(dir string) string {
	return LongPath(dir)
}
