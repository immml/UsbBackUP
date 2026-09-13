package copier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackUP/internal/fsutil"
	"github.com/immml/UsbBackUP/internal/version"
)

// defaultMaxFiles 是单次回写的条目数上限，防误配超大目录把 U 盘写爆。
const defaultMaxFiles = 200000

// Copy 执行回写：本地备份文件夹 → `<DestRoot>\<SubDir>\`（F-401 ~ F-410）。
//
// 硬性行为约束：
//
//   - **只写目标子目录之内**，绝不触碰该目录以外的任何对象（G-04）；
//   - **绝不删除、移动、改名**目标盘上的既有文件（G-04）；
//   - 默认不覆盖同名文件，`Overwrite` 才覆盖（F-403）；
//   - 全程只读源目录（G-05）；
//   - 单文件失败不中断整体，记入 FilesFailed 后继续。
func Copy(ctx context.Context, opt Options) (Stats, error) {
	start := time.Now()
	var st Stats

	// 前置校验：源目录存在、子目录名合法、拒绝自复制（F-401 / F-406）。
	target, err := Check(opt)
	if err != nil {
		return st, err
	}
	src, err := filepath.Abs(opt.SourceDir)
	if err != nil {
		return st, fmt.Errorf("解析备份源目录失败: %w", err)
	}

	maxFiles := opt.MaxFiles
	if maxFiles <= 0 {
		maxFiles = defaultMaxFiles
	}

	// ---- 第一遍：统计总量，用于空间预检与进度 ----
	plan, totalBytes, err := collectSource(ctx, src, maxFiles)
	if err != nil {
		return st, err
	}

	// 剩余空间预检（F-306）：不确定时保守拒绝，避免写坏介质。
	if !opt.DryRun {
		if free, ferr := fsutil.FreeBytes(target); ferr == nil {
			margin := opt.MarginPercent
			if margin < 0 {
				margin = 0
			}
			need := totalBytes + totalBytes*int64(margin)/100
			if free < need {
				return st, fmt.Errorf("%w: 需要约 %s，目标盘可用 %s",
					ErrNoSpace, fsutil.HumanBytes(need), fsutil.HumanBytes(free))
			}
		}
	}

	// ---- 第二遍：逐个复制 ----
	if !opt.DryRun {
		if err := os.MkdirAll(fsutil.LongPath(target), 0o755); err != nil {
			return st, fmt.Errorf("创建目标目录 %s 失败: %w", target, err)
		}
	}

	for _, rel := range plan {
		if err := ctx.Err(); err != nil {
			st.Duration = time.Since(start)
			return st, fmt.Errorf("回写作业被取消: %w", err)
		}

		srcPath := filepath.Join(src, rel)
		dstPath := filepath.Join(target, rel)

		// 双保险：目标路径必须仍在 `<DestRoot>\<SubDir>\` 之内（G-04）。
		if !fsutil.IsSubPath(target, dstPath) {
			st.FilesFailed++
			continue
		}

		action, err := decide(srcPath, dstPath, opt)
		if err != nil {
			st.FilesFailed++
			continue
		}
		switch action {
		case actionSkip:
			st.FilesSkipped++
			continue
		case actionMkdir:
			// 目录只影响 DirsCreated 统计，不计入文件计数。
			if !opt.DryRun {
				if err := os.MkdirAll(fsutil.LongPath(dstPath), 0o755); err != nil {
					st.FilesFailed++
					continue
				}
			}
			st.DirsCreated++
			continue
		case actionDryRun:
			st.FilesCopied++
			continue
		}

		n, cerr := copyFile(ctx, srcPath, dstPath)
		if cerr != nil {
			st.FilesFailed++
			continue
		}
		st.FilesCopied++
		st.BytesCopied += n

		// 复制后校验（F-407）：默认比对大小，VerifyHash 时再比 SHA-256。
		if !opt.DryRun {
			ok, verr := verifyCopy(srcPath, dstPath, n, opt.VerifyHash)
			if verr != nil || !ok {
				st.VerifyFailures++
			}
		}
		if opt.Progress != nil {
			opt.Progress(st)
		}
	}

	// ---- 清单文件（F-408）：只记统计与公钥指纹，不含文件清单与内容 ----
	if !opt.DryRun && opt.WriteManifest {
		if err := writeManifest(target, st, opt); err != nil {
			st.ManifestError = err.Error()
		} else {
			st.ManifestWritten = true
		}
	}

	st.Duration = time.Since(start)
	return st, nil
}

type actionKind int

const (
	actionCopy actionKind = iota
	actionSkip
	actionMkdir
	actionDryRun
)

// collectSource 遍历源目录，返回相对路径清单与总字节数（第一遍，只读）。
//
// 跳过重解析点（防目录穿越与循环），不跟随符号链接。
func collectSource(ctx context.Context, src string, maxFiles int) ([]string, int64, error) {
	var out []string
	var total int64

	type node struct{ path, rel string }
	stack := []node{{path: src, rel: ""}}

	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, 0, fmt.Errorf("回写作业被取消: %w", err)
		}
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := os.ReadDir(fsutil.LongPath(cur.path))
		if err != nil {
			continue
		}
		for _, e := range entries {
			rel := filepath.Join(cur.rel, e.Name())
			full := filepath.Join(cur.path, e.Name())

			if isReparsePoint(full) {
				continue
			}
			if e.IsDir() {
				out = append(out, rel)
				stack = append(stack, node{path: full, rel: rel})
				continue
			}
			if e.Type()&os.ModeSymlink != 0 {
				continue
			}
			fi, err := e.Info()
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			total += fi.Size()
			out = append(out, rel)
			if len(out) > maxFiles {
				return nil, 0, fmt.Errorf("源目录条目数超过上限 %d，请检查备份文件夹是否配置有误", maxFiles)
			}
		}
	}
	return out, total, nil
}

// decide 判断单个条目的处理动作。
func decide(srcPath, dstPath string, opt Options) (actionKind, error) {
	si, err := os.Stat(fsutil.LongPath(srcPath))
	if err != nil {
		return actionSkip, err
	}
	if si.IsDir() {
		// 目录一律走 actionMkdir：只影响 DirsCreated 统计，
		// 不计入 FilesCopied / FilesSkipped（那些只统计文件）。
		return actionMkdir, nil
	}

	di, err := os.Stat(fsutil.LongPath(dstPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if opt.DryRun {
				return actionDryRun, nil
			}
			return actionCopy, nil
		}
		return actionSkip, err
	}

	// 已存在：size + mtime 一致视为同一版本，跳过（F-402）。
	if di.Size() == si.Size() && di.ModTime().Equal(si.ModTime()) {
		return actionSkip, nil
	}
	// 内容可能不同：默认不覆盖，防误伤 U 盘既有数据（F-403）。
	if !opt.Overwrite {
		return actionSkip, nil
	}
	if opt.DryRun {
		return actionDryRun, nil
	}
	return actionCopy, nil
}

// copyFile 复制单个文件，返回写入字节数。
//
// 先写 `.part` 再改名：即使中途拔盘/断电，也不会留下"看起来完整"的半成品。
func copyFile(ctx context.Context, srcPath, dstPath string) (int64, error) {
	in, err := os.Open(fsutil.LongPath(srcPath))
	if err != nil {
		return 0, err
	}
	defer in.Close()

	si, err := in.Stat()
	if err != nil {
		return 0, err
	}

	tmp := dstPath + ".part"
	out, err := os.OpenFile(fsutil.LongPath(tmp), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}

	buf := make([]byte, 512<<10)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			_ = out.Close()
			_ = os.Remove(fsutil.LongPath(tmp))
			return written, err
		}
		n, rerr := in.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				_ = out.Close()
				_ = os.Remove(fsutil.LongPath(tmp))
				return written, werr
			}
			written += int64(n)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			_ = out.Close()
			_ = os.Remove(fsutil.LongPath(tmp))
			return written, rerr
		}
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(fsutil.LongPath(tmp))
		return written, err
	}
	if err := os.Rename(fsutil.LongPath(tmp), fsutil.LongPath(dstPath)); err != nil {
		_ = os.Remove(fsutil.LongPath(tmp))
		return written, fmt.Errorf("重命名 %s 失败: %w", dstPath, err)
	}
	// 保留源文件时间戳，使下次增量判断（size+mtime）能正确命中。
	_ = os.Chtimes(fsutil.LongPath(dstPath), si.ModTime(), si.ModTime())
	return written, nil
}

// verifyCopy 校验复制结果（F-407）。默认只比对大小。
func verifyCopy(srcPath, dstPath string, expect int64, withHash bool) (bool, error) {
	di, err := os.Stat(fsutil.LongPath(dstPath))
	if err != nil {
		return false, err
	}
	if di.Size() != expect {
		return false, fmt.Errorf("大小不一致：目标 %d，期望 %d", di.Size(), expect)
	}
	if !withHash {
		return true, nil
	}
	sh, err := sha256Of(srcPath)
	if err != nil {
		return false, err
	}
	dh, err := sha256Of(dstPath)
	if err != nil {
		return false, err
	}
	return sh == dh, nil
}

func sha256Of(path string) (string, error) {
	f, err := os.Open(fsutil.LongPath(path))
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// manifest 是回写清单（F-408）。
//
// 刻意**不含文件清单与内容**，只记统计与公钥指纹——清单本身会留在 U 盘上，
// 不应成为泄露"这台机器备份了哪些文件"的渠道（G-02）。
type manifest struct {
	Time         string `json:"time"`
	Tool         string `json:"tool"`
	ToolVersion  string `json:"tool_version"`
	TargetDir    string `json:"target_subdir"`
	FilesCopied  int    `json:"files_copied"`
	FilesSkipped int    `json:"files_skipped"`
	BytesCopied  int64  `json:"bytes_copied"`
	PublicKeyFP  string `json:"public_key_fingerprint,omitempty"`
}

// writeManifest 把清单写入目标子目录（路径固定，不随源目录结构变化）。
func writeManifest(target string, st Stats, opt Options) error {
	m := manifest{
		Time:         time.Now().Format(time.RFC3339),
		Tool:         version.AppName,
		ToolVersion:  version.Version,
		TargetDir:    filepath.Base(target),
		FilesCopied:  st.FilesCopied,
		FilesSkipped: st.FilesSkipped,
		BytesCopied:  st.BytesCopied,
		PublicKeyFP:  strings.TrimSpace(opt.PublicKeyFingerprint),
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	p := filepath.Join(target, ".usbbackup-manifest.json")
	return os.WriteFile(fsutil.LongPath(p), data, 0o600)
}
