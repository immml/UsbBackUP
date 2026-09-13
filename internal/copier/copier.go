// Package copier 实现"授权分支"：把本地备份文件夹内容复制到 U 盘的 `\backup\` 目录。
//
// 状态：守卫校验（本文件已实现并测试）；复制执行器计划于 M2。
//
// 对应需求 F-401 ~ F-410。
//
// 安全红线（G-04 / G-05 / G-06）：
//   - **只在 `<USB>:\<subdir>\` 之内写入**，绝不触碰该目录以外的任何对象；
//   - 绝不删除、移动、改名、改写 U 盘上的既有文件；
//   - 默认不覆盖同名文件，需显式 --overwrite；
//   - 拒绝"源目录位于目标盘之内"的自复制（防套娃，F-406）。
package copier

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackUP/internal/fsutil"
)

// ErrNotImplemented 表示该能力尚未实现。
var ErrNotImplemented = errors.New("copier: 复制执行器尚未实现（计划于 M2）")

// 错误。
var (
	// ErrSourceMissing 表示备份源目录不存在或不是目录。
	ErrSourceMissing = errors.New("备份源目录不存在或不是目录")
	// ErrSelfCopy 表示源目录位于目标盘之内，属自复制，拒绝执行（F-406）。
	ErrSelfCopy = errors.New("备份源目录位于目标盘之内，拒绝自复制以防套娃")
	// ErrBadSubDir 表示回写子目录名非法。
	ErrBadSubDir = errors.New("回写子目录名非法（必须是单层目录名且不含 Windows 禁用字符）")
	// ErrNoSpace 表示目标卷剩余空间不足（F-306）。
	ErrNoSpace = errors.New("目标卷剩余空间不足")
)

// Options 是复制参数。
type Options struct {
	// SourceDir 是本地备份文件夹（F-401）。
	SourceDir string
	// DestRoot 是目标卷根，形如 `E:\`。
	DestRoot string
	// SubDir 是目标卷内的子目录名，默认 `backup`（F-401）。
	SubDir string
	// Overwrite 为 true 时覆盖同名文件，默认跳过（F-403）。
	Overwrite bool
	// DryRun 为 true 时只输出计划动作，不做任何写入（F-409）。
	DryRun bool
	// VerifyHash 为 true 时逐文件比对 SHA-256，否则只比对大小（F-407）。
	VerifyHash bool
	// MarginPercent 是剩余空间预留百分比（F-306）。
	MarginPercent int
	// Progress 是进度回调。
	Progress func(Stats)
}

// Stats 是复制统计（F-410）。
type Stats struct {
	DirsCreated  int
	FilesCopied  int
	FilesSkipped int
	FilesFailed  int
	BytesCopied  int64
	// VerifyFailures 是复制后校验不一致的文件数。
	VerifyFailures int
	// ManifestWritten 表示是否写出了清单文件（F-408）。
	ManifestWritten bool
	Duration        time.Duration
}

// TargetDir 计算并校验目标目录（`<DestRoot>\<SubDir>`）。
func TargetDir(destRoot, subDir string) (string, error) {
	if strings.TrimSpace(destRoot) == "" {
		return "", errors.New("目标卷根为空")
	}
	sub := strings.TrimSpace(subDir)
	if sub == "" {
		sub = "backup"
	}
	// 子目录名必须是单层安全的目录名：不能含路径分隔符、盘符、禁用字符、. 或 ..
	if sub == "." || sub == ".." ||
		strings.ContainsAny(sub, `/\:*?"<>|`) ||
		strings.HasSuffix(sub, ".") || strings.HasSuffix(sub, " ") {
		return "", fmt.Errorf("%w: %q", ErrBadSubDir, subDir)
	}
	return filepath.Join(destRoot, sub), nil
}

// Check 做全部前置校验：源目录、子目录、自复制守卫（F-401 / F-406）。
//
// 这是**只读**检查，不创建任何目录、不写任何文件。
func Check(opt Options) (targetDir string, err error) {
	if strings.TrimSpace(opt.SourceDir) == "" {
		return "", errors.New("备份源目录为空，请先配置 backup_source_dir")
	}
	src, err := filepath.Abs(opt.SourceDir)
	if err != nil {
		return "", fmt.Errorf("解析备份源目录失败: %w", err)
	}

	target, err := TargetDir(opt.DestRoot, opt.SubDir)
	if err != nil {
		return "", err
	}

	// 自复制守卫：源目录若位于目标卷之内（含等于目标目录），一律拒绝。
	if fsutil.SameVolume(src, target) && fsutil.IsSubPath(fsutil.VolumeRoot(target), src) {
		return "", fmt.Errorf("%w: 源 %s ⊂ 目标卷 %s", ErrSelfCopy, src, fsutil.VolumeRoot(target))
	}
	// 反向：目标目录位于源目录之内，同样会造成递归复制。
	if fsutil.IsSubPath(src, target) {
		return "", fmt.Errorf("%w: 目标 %s ⊂ 源 %s", ErrSelfCopy, target, src)
	}

	st, err := os.Stat(fsutil.LongPath(src))
	if err != nil {
		return "", fmt.Errorf("%w: %s (%v)", ErrSourceMissing, src, err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%w: %s", ErrSourceMissing, src)
	}
	return target, nil
}

// Copy 执行复制（实现计划见 M2）。
//
// 实现计划：
//  1. 调用 Check 完成全部守卫校验；
//  2. 遍历源目录，跳过重解析点，经 fsutil.LongPath 处理超长路径；
//  3. 目标已存在且 size+mtime 一致 → 跳过（F-402）；
//  4. 目标已存在但不一致 → 按 Overwrite 决定跳过或覆盖（F-403）；
//  5. 单文件失败记入 FilesFailed 并 WARN，不中断整体；
//  6. 写出清单 `.usbguard-manifest.json`（F-408），其中**不含私钥与文件内容**。
func Copy(ctx context.Context, opt Options) (Stats, error) {
	return Stats{}, ErrNotImplemented
}
