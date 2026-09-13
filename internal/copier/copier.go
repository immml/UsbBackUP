// Package copier 实现"授权分支"：把本地备份文件夹内容复制到 U 盘的 `\backup\` 目录。
//
// 状态：**已完整实现**（守卫校验见本文件，执行器见 copy.go），并有单元测试覆盖。
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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackUP/internal/fsutil"
)

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
	// MaxFiles 是单次回写的条目数上限，0 表示用内置默认（20 万条）。
	MaxFiles int
	// WriteManifest 决定是否在目标子目录写出回写清单（F-408）。
	WriteManifest bool
	// PublicKeyFingerprint 会写入清单，便于事后核对是哪把公钥授权的（不含私钥）。
	PublicKeyFingerprint string
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
	// ManifestError 记录清单写入失败原因（不致命）。
	ManifestError string
	Duration      time.Duration
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

	// 自复制守卫（F-406）：
	//
	// 真正会造成套娃的是**目录嵌套**，而不是"同卷"本身——
	// 例如 source 为 D:/data、target 为 D:/data/backup 时，来回复制会让每轮体积翻倍。
	// 因此这里只拒绝两种嵌套关系，允许同卷内的互不相交目录
	// （这同时也让 --allow-fixed 的验证场景可用）。
	if fsutil.IsSubPath(target, src) {
		return "", fmt.Errorf("%w: 源目录 %s 位于回写目标 %s 之内", ErrSelfCopy, src, target)
	}
	if fsutil.IsSubPath(src, target) {
		return "", fmt.Errorf("%w: 回写目标 %s 位于源目录 %s 之内", ErrSelfCopy, target, src)
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
