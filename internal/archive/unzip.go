package archive

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackUP/internal/fsutil"
)

// 解包默认上限。用于抵御"解压炸弹"：一个几十 KiB 的 zip 可以声明数 TB 的
// 解压后体积，若不设限会把目标盘写满。
const (
	// DefaultMaxEntryBytes 是单个条目解压后的上限（4 GiB）。
	DefaultMaxEntryBytes int64 = 4 << 30
	// DefaultMaxTotalBytes 是整次解压的明文总量上限（64 GiB）。
	DefaultMaxTotalBytes int64 = 64 << 30
)

// UnzipStream 从 zip 流解包到 opt.DestDir（F-B03 ~ F-B07）。
//
// 安全处理顺序（每一步失败都不落盘）：
//
//  1. 读 zip 目录，逐条做 Zip Slip 校验（SafeExtractPath）；
//  2. 拒绝符号链接/重解析点条目；
//  3. 累计声明体积，与目标盘可用空间比对（含余量），不足则整体拒绝；
//  4. 逐条写出，写出过程中再次按实际字节数封顶，防止声明值撒谎；
//  5. 已存在文件默认跳过，--force 才覆盖。
func UnzipStream(ctx context.Context, src io.ReaderAt, size int64, opt UnzipOptions) (UnzipStats, error) {
	start := time.Now()
	var st UnzipStats

	if opt.DestDir == "" {
		return st, errors.New("archive: 必须显式指定解包目标目录")
	}
	dest, err := filepath.Abs(opt.DestDir)
	if err != nil {
		return st, fmt.Errorf("archive: 解析目标目录失败: %w", err)
	}
	if src == nil {
		return st, errors.New("archive: 未提供 zip 数据源")
	}

	maxEntry := opt.MaxEntryBytes
	if maxEntry <= 0 {
		maxEntry = DefaultMaxEntryBytes
	}
	maxTotal := opt.MaxTotalBytes
	if maxTotal <= 0 {
		maxTotal = DefaultMaxTotalBytes
	}

	zr, err := zip.NewReader(src, size)
	if err != nil {
		return st, fmt.Errorf("archive: 不是合法的 zip 归档: %w", err)
	}

	// ---- 第一遍：只做校验与体积统计，不写任何文件 ----
	type plan struct {
		file      *zip.File
		target    string
		isDir     bool
		needBytes int64
	}
	plans := make([]plan, 0, len(zr.File))
	var declaredTotal int64
	unsafeCount := 0

	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return st, fmt.Errorf("archive: 作业被取消: %w", err)
		}

		// 符号链接条目直接拒绝（F-B05）：它可以让解包结果指向目录之外。
		if f.Mode()&os.ModeSymlink != 0 {
			unsafeCount++
			st.Skipped++
			continue
		}

		name := f.Name
		isDir := strings.HasSuffix(name, "/") || strings.HasSuffix(name, `\`)
		trimmed := strings.TrimRight(strings.TrimRight(name, "/"), `\`)
		if trimmed == "" {
			st.Skipped++
			continue
		}

		target, err := SafeExtractPath(dest, trimmed)
		if err != nil {
			// 命中 Zip Slip 等不安全条目：拒绝并计数（F-B05）。
			unsafeCount++
			st.Skipped++
			continue
		}

		need := int64(f.UncompressedSize64)
		if need < 0 || need > maxEntry {
			unsafeCount++
			st.Skipped++
			continue
		}
		declaredTotal += need
		if declaredTotal > maxTotal {
			return st, fmt.Errorf("archive: 归档声明的解压总量 %.1f GiB 超过上限 %.1f GiB，已拒绝",
				float64(declaredTotal)/(1<<30), float64(maxTotal)/(1<<30))
		}
		plans = append(plans, plan{file: f, target: target, isDir: isDir, needBytes: need})
	}

	if len(plans) == 0 {
		st.RejectedUnsafe = unsafeCount
		st.Duration = time.Since(start)
		if unsafeCount > 0 {
			return st, fmt.Errorf("archive: 全部 %d 个条目均被安全守卫拒绝", unsafeCount)
		}
		return st, errors.New("archive: 归档为空")
	}

	// ---- 空间预检（F-B07）----
	if !opt.DryRun {
		if err := ensureFreeSpace(dest, declaredTotal); err != nil {
			return st, err
		}
	}

	// ---- 第二遍：写出 ----
	if !opt.DryRun {
		if err := os.MkdirAll(fsutil.LongPath(dest), 0o755); err != nil {
			return st, fmt.Errorf("archive: 创建目标目录失败: %w", err)
		}
	}

	var written int64
	for _, p := range plans {
		if err := ctx.Err(); err != nil {
			st.Duration = time.Since(start)
			st.Bytes = written
			return st, fmt.Errorf("archive: 作业被取消: %w", err)
		}

		if p.isDir {
			if !opt.DryRun {
				if err := os.MkdirAll(fsutil.LongPath(p.target), 0o755); err != nil {
					st.Skipped++
					continue
				}
			}
			continue
		}

		if opt.DryRun {
			st.Files++
			continue
		}

		if _, err := os.Stat(fsutil.LongPath(p.target)); err == nil && !opt.Force {
			// 默认不覆盖（F-B06）。
			st.Skipped++
			continue
		}

		if err := os.MkdirAll(fsutil.LongPath(filepath.Dir(p.target)), 0o755); err != nil {
			st.Skipped++
			continue
		}

		n, err := extractOne(ctx, p.file, p.target, maxEntry)
		if err != nil {
			st.Skipped++
			continue
		}
		written += n
		st.Files++
		st.Bytes = written
		if opt.Progress != nil {
			opt.Progress(st)
		}
	}

	st.RejectedUnsafe = unsafeCount
	st.Bytes = written
	st.Duration = time.Since(start)
	return st, nil
}

// extractOne 解出单个条目。
//
// 用 io.LimitReader 按**实际**字节数封顶，而不是信任 zip 头里声明的
// UncompressedSize64（后者由攻击者控制，可以撒谎）。
func extractOne(ctx context.Context, f *zip.File, target string, maxEntry int64) (int64, error) {
	rc, err := f.Open()
	if err != nil {
		return 0, err
	}
	defer rc.Close()

	out, err := os.OpenFile(fsutil.LongPath(target), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}

	limited := io.LimitReader(rc, maxEntry+1)
	buf := make([]byte, 256<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			_ = out.Close()
			_ = os.Remove(target)
			return total, err
		}
		n, rerr := limited.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > maxEntry {
				// 实际体积超过上限：删除半成品，拒绝该条目。
				_ = out.Close()
				_ = os.Remove(target)
				return 0, errors.New("archive: 条目实际解压体积超过上限")
			}
			if _, werr := out.Write(buf[:n]); werr != nil {
				_ = out.Close()
				_ = os.Remove(target)
				return total, werr
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			_ = out.Close()
			_ = os.Remove(target)
			return total, rerr
		}
	}
	if err := out.Close(); err != nil {
		return total, err
	}
	// 保留归档内记录的时间戳（尽力而为，失败不影响结果）。
	_ = os.Chtimes(fsutil.LongPath(target), f.Modified, f.Modified)
	return total, nil
}

// ensureFreeSpace 检查 dest 所在卷是否有足够空间写入 need 字节（含 5% 余量，F-B07）。
//
// 复用 fsutil 的只读容量查询，不写探测文件、不污染目标目录。
func ensureFreeSpace(dest string, need int64) error {
	if need <= 0 {
		return nil
	}
	free, err := fsutil.FreeBytes(dest)
	if err != nil {
		// 取不到剩余空间时不阻塞解包，交由写入阶段报错。
		return nil
	}
	required := need + need/20 // +5%
	if free < required {
		return fmt.Errorf("archive: 目标卷可用空间不足（需要约 %s，可用 %s）",
			humanBytes(required), humanBytes(free))
	}
	return nil
}

func humanBytes(n int64) string { return fsutil.HumanBytes(n) }
