// Package archive 实现整盘流式 zip 打包与安全解包。
//
// 状态：路径守卫（本文件）**已实现并测试**；流式打包/解包执行器计划于 M2。
//
// 对应需求 F-501 ~ F-509（打包）与 F-B05（解包防 Zip Slip）。
//
// 安全红线：
//   - 打包侧：源盘全程只读，不创建/修改/删除源盘任何文件（G-05）；
//   - 打包侧：输出目录不得位于扫描源之内，防递归套娃（F-507 / G-08）；
//   - 解包侧：拒绝一切可能逃逸目标目录的条目名（F-B05）。
package archive

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/immml/UsbBackup/internal/fsutil"
)

// ErrNotImplemented 表示该能力尚未实现。
var ErrNotImplemented = errors.New("archive: 打包/解包执行器尚未实现（计划于 M2）")

// DefaultExcludes 是默认排除的目录名与文件名（F-505）。
// 全部为系统元数据，不含用户数据。
var DefaultExcludes = []string{
	"System Volume Information",
	"$RECYCLE.BIN",
	"$SysReset",
	"$Windows.~BT",
	"$Windows.~WS",
	"found.000",
	"found.001",
	"pagefile.sys",
	"hiberfil.sys",
	"swapfile.sys",
	"desktop.ini",
	"Thumbs.db",
}

// ErrUnsafeArchiveName 表示归档条目名不安全，必须拒绝（F-B05）。
var ErrUnsafeArchiveName = errors.New("归档条目名不安全，已拒绝")

// errOutsideRoot 表示路径不在预期根之内。
var errOutsideRoot = errors.New("路径不在预期根目录之内")

// ArchiveName 计算文件在归档内的相对路径（F-503）。
//
// root 是扫描源根（如 `E:\`），full 是该根之下的绝对路径。
// 返回形如 `dir/sub/file.txt`（正斜杠、无前导斜杠）。
//
// 拒绝情形：不在 root 之下、含 `..`、含盘符、含 NUL。
func ArchiveName(root, full string) (string, error) {
	if root == "" || full == "" {
		return "", errOutsideRoot
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(full))
	if err != nil {
		return "", fmt.Errorf("%w: %v", errOutsideRoot, err)
	}
	name := filepath.ToSlash(rel)

	if name == "." || name == "" {
		return "", errOutsideRoot
	}
	if strings.HasPrefix(name, "../") || name == ".." || strings.Contains(name, "/../") {
		return "", fmt.Errorf("%w: 路径逃逸（%s）", errOutsideRoot, name)
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) {
		return "", fmt.Errorf("%w: 绝对路径（%s）", errOutsideRoot, name)
	}
	// 盘符形态（如 C:/x）或 UNC 形态。
	if len(name) >= 2 && name[1] == ':' {
		return "", fmt.Errorf("%w: 含盘符（%s）", errOutsideRoot, name)
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: 含 NUL 字节", errOutsideRoot)
	}
	// 统一清理 ./ 等冗余，保证归档内路径规范化。
	cleaned := path.Clean(name)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("%w: 规范化后仍逃逸（%s）", errOutsideRoot, cleaned)
	}
	return cleaned, nil
}

// SafeExtractPath 把归档条目名映射为目标目录下的绝对路径，并阻断一切逃逸尝试（F-B05）。
//
// 拒绝：绝对路径、盘符、UNC、`..`、前导分隔符、NUL、NTFS 备用数据流（`:`）、
// 以及规范化后越出 destDir 的结果。
func SafeExtractPath(destDir, name string) (string, error) {
	if destDir == "" {
		return "", fmt.Errorf("%w: 目标目录为空", ErrUnsafeArchiveName)
	}
	raw := name
	if raw == "" {
		return "", fmt.Errorf("%w: 条目名为空", ErrUnsafeArchiveName)
	}
	// 归档内统一用正斜杠；先把反斜杠也视为分隔符，防止仅判断一种写法被绕过。
	norm := strings.ReplaceAll(raw, `\`, "/")

	if strings.ContainsRune(norm, 0) {
		return "", fmt.Errorf("%w: 含 NUL 字节", ErrUnsafeArchiveName)
	}
	if strings.ContainsRune(norm, ':') {
		// 阻断 "file.txt:evil" 形式的 NTFS 备用数据流与 "C:" 盘符写法。
		return "", fmt.Errorf("%w: 含冒号，疑似盘符或备用数据流（%s）", ErrUnsafeArchiveName, raw)
	}
	if strings.HasPrefix(norm, "/") || strings.HasPrefix(norm, "//") {
		return "", fmt.Errorf("%w: 绝对路径或 UNC（%s）", ErrUnsafeArchiveName, raw)
	}
	if strings.HasPrefix(norm, "~/") {
		return "", fmt.Errorf("%w: 疑似家目录引用（%s）", ErrUnsafeArchiveName, raw)
	}

	cleaned := path.Clean(norm)
	if cleaned == "." || cleaned == "" {
		return "", fmt.Errorf("%w: 条目名为当前目录（%s）", ErrUnsafeArchiveName, raw)
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("%w: 目录穿越（%s）", ErrUnsafeArchiveName, raw)
	}
	if path.IsAbs(cleaned) {
		return "", fmt.Errorf("%w: 规范化后仍为绝对路径（%s）", ErrUnsafeArchiveName, raw)
	}

	full := filepath.Join(destDir, filepath.FromSlash(cleaned))
	// 兜底：确保结果确实位于目标目录之内（Windows 大小写不敏感，用统一比较）。
	destClean := filepath.Clean(destDir)
	rel, err := filepath.Rel(destClean, filepath.Clean(full))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnsafeArchiveName, err)
	}
	relSlash := filepath.ToSlash(rel)
	if relSlash == ".." || strings.HasPrefix(relSlash, "../") {
		return "", fmt.Errorf("%w: 解析结果越出目标目录（%s）", ErrUnsafeArchiveName, raw)
	}
	return full, nil
}

// IsExcluded 判断某个文件名或目录名是否在排除表内（F-505）。
func IsExcluded(name string, extra []string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, e := range DefaultExcludes {
		if strings.EqualFold(e, name) {
			return true
		}
	}
	for _, e := range extra {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.EqualFold(e, name) {
			return true
		}
		// 支持简单通配，如 "*.tmp"。
		if strings.ContainsAny(e, "*?") {
			if ok, err := path.Match(strings.ToLower(e), lower); err == nil && ok {
				return true
			}
		}
	}
	return false
}

// alreadyCompressedExts 是"压缩收益极低"的扩展名集合（F-502）。
var alreadyCompressedExts = map[string]bool{
	".zip": true, ".7z": true, ".rar": true, ".gz": true, ".bz2": true, ".xz": true,
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true, ".heic": true,
	".mp4": true, ".mkv": true, ".avi": true, ".mov": true, ".webm": true,
	".mp3": true, ".aac": true, ".m4a": true, ".flac": true, ".ogg": true,
	".docx": true, ".xlsx": true, ".pptx": true, ".pdf": true,
}

// ShouldStore 判断该文件是否应使用 Store（不压缩）方式写入 zip（F-502）。
func ShouldStore(name string) bool {
	return alreadyCompressedExts[strings.ToLower(path.Ext(name))]
}

// CheckSourceGuard 校验输出路径不得位于扫描源之内（F-507 / G-08）。
//
// 这条守卫是为了防住"把产物写回被扫描的盘"导致的递归套娃膨胀。
//
// 复用 fsutil 的路径归一化，避免 Windows "drive-relative" 写法
// （`E:` 与 `E:\` 语义不同）带来的比较漏洞。
func CheckSourceGuard(sourceRoot, outputDir string) error {
	if sourceRoot == "" || outputDir == "" {
		return errors.New("源根与输出目录都不能为空")
	}
	if _, err := filepath.Abs(sourceRoot); err != nil {
		return fmt.Errorf("解析源根失败: %w", err)
	}
	if _, err := filepath.Abs(outputDir); err != nil {
		return fmt.Errorf("解析输出目录失败: %w", err)
	}
	// 输出位于源之内（含与源相同）→ 拒绝。
	if fsutil.IsSubPath(sourceRoot, outputDir) {
		return fmt.Errorf("输出目录位于扫描源之内（%s ⊂ %s），拒绝执行以防递归膨胀", outputDir, sourceRoot)
	}
	return nil
}
