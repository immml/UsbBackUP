package archive

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/immml/UsbBackUP/internal/fsutil"
)

// prefetchMinSize 是启用"读取/压缩流水线重叠"的最小文件大小。
// 小于该值的文件直接同步复制，避免为小文件额外创建 goroutine。
const prefetchMinSize = 4 << 20 // 4 MiB

// ZipStream 把 SourceRoot 下的内容以流式 zip 写入 dst（F-501 ~ F-509）。
//
// 设计要点：
//
//   - **单遍遍历**：不预扫全树，边遍历边写，磁盘 IO 只走一遍；
//   - **只读源盘**：绝不创建、修改、删除源盘任何文件（G-05）；
//   - **流式**：调用方通常把 dst 接到加密器输入，明文 zip 不落盘（决策 D-03）；
//   - **大文件读写重叠**：超过 4 MiB 的文件用管道让"磁盘读"与"deflate 压缩"
//     在两个 goroutine 中并行，内存占用仍为常数级（管道缓冲约几十 KiB）；
//   - **单文件失败不致命**：记入 Skipped 并继续，整体仍产出可用的归档。
//
// dst 若由 NewCountingWriter 包装，返回值中的 ZipBytes 即为归档体积。
func ZipStream(ctx context.Context, dst io.Writer, opt ZipOptions) (ZipStats, error) {
	start := time.Now()
	var st ZipStats

	if opt.SourceRoot == "" {
		return st, errors.New("archive: 源根为空")
	}
	root, err := filepath.Abs(opt.SourceRoot)
	if err != nil {
		return st, fmt.Errorf("archive: 解析源根失败: %w", err)
	}
	fi, err := os.Stat(fsutil.LongPath(root))
	if err != nil {
		return st, fmt.Errorf("archive: 源根不可访问 %s: %w", root, err)
	}
	if !fi.IsDir() {
		return st, fmt.Errorf("archive: 源根不是目录 %s", root)
	}

	// 默认排除表 + 调用方追加项（F-505）。
	excludes := append(append([]string{}, DefaultExcludes...), opt.Excludes...)

	zw := zip.NewWriter(dst)
	closed := false
	closeZip := func() error {
		if closed {
			return nil
		}
		closed = true
		return zw.Close()
	}

	type dirNode struct {
		path  string
		depth int
	}
	stack := []dirNode{{path: root, depth: 0}}

	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			_ = closeZip()
			st.Duration = time.Since(start)
			return st, fmt.Errorf("archive: 作业被取消: %w", err)
		}

		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := os.ReadDir(fsutil.LongPath(cur.path))
		if err != nil {
			// 权限不足或介质被拔出：跳过该目录，不中断整体。
			st.Skipped++
			continue
		}
		st.Dirs++

		for _, e := range entries {
			if err := ctx.Err(); err != nil {
				break
			}
			name := e.Name()
			if IsExcluded(name, excludes) {
				st.Skipped++
				continue
			}
			full := filepath.Join(cur.path, name)

			// 重解析点一律不跟随（F-506）。
			if isReparsePoint(full) {
				st.Skipped++
				continue
			}
			if e.IsDir() {
				// 目录本身不写条目：zip 会依据文件路径自动建父目录。
				stack = append(stack, dirNode{path: full, depth: cur.depth + 1})
				continue
			}
			if e.Type()&os.ModeSymlink != 0 {
				st.Skipped++
				continue
			}

			arcName, err := ArchiveName(root, full)
			if err != nil {
				// 路径越界或含盘符：拒绝写入（F-503）。
				st.Skipped++
				continue
			}

			n, werr := writeFileEntry(ctx, zw, full, arcName, opt)
			if werr != nil {
				st.Skipped++
				continue
			}
			st.Files++
			st.RawBytes += n
			if opt.Progress != nil {
				opt.Progress(st)
			}
		}
	}

	// Close 会写出 zip 中央目录，必须发生在读取 ZipBytes 之前。
	if err := closeZip(); err != nil {
		return st, fmt.Errorf("archive: 写出 zip 中央目录失败: %w", err)
	}
	if cw, ok := dst.(interface{ BytesWritten() int64 }); ok {
		st.ZipBytes = cw.BytesWritten()
	}
	st.Duration = time.Since(start)
	return st, nil
}

// writeFileEntry 把一个文件写入 zip 归档，返回写入的原始字节数。
func writeFileEntry(ctx context.Context, zw *zip.Writer, full, arcName string, opt ZipOptions) (int64, error) {
	fi, err := os.Stat(fsutil.LongPath(full))
	if err != nil {
		return 0, err
	}
	if !fi.Mode().IsRegular() {
		return 0, errors.New("archive: 非常规文件，跳过")
	}
	n := fi.Size()
	if n > int64(^uint32(0)) {
		// zip 传统格式单文件上限 4 GiB；超出则跳过并计数（调用方会 WARN）。
		return 0, errors.New("archive: 单文件超过 4 GiB，zip 传统格式不支持，已跳过")
	}

	method := zip.Deflate
	if opt.StoreAlreadyCompressed && ShouldStore(arcName) {
		method = zip.Store
	}

	hdr := &zip.FileHeader{
		Name:     arcName,
		Method:   method,
		Modified: fi.ModTime(),
	}
	// 归档内不保留只读/系统属性，避免解包后行为异常。
	hdr.SetMode(0o644)

	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return 0, fmt.Errorf("archive: 创建归档条目失败: %w", err)
	}

	if n < prefetchMinSize {
		f, err := os.Open(fsutil.LongPath(full))
		if err != nil {
			return 0, err
		}
		defer f.Close()
		copied, cerr := io.Copy(w, f)
		return copied, cerr
	}
	return copyWithPrefetch(ctx, w, full)
}

// copyWithPrefetch 用管道把"读文件"与"压缩写入"放到两个 goroutine 中并行。
//
// 内存占用仅为管道缓冲区级别，与文件大小无关。
func copyWithPrefetch(ctx context.Context, w io.Writer, full string) (int64, error) {
	f, err := os.Open(fsutil.LongPath(full))
	if err != nil {
		return 0, err
	}
	defer f.Close()

	pr, pw := io.Pipe()
	readErr := make(chan error, 1)

	go func() {
		defer func() { _ = pw.Close() }()
		buf := make([]byte, 128<<10)
		for {
			if cerr := ctx.Err(); cerr != nil {
				readErr <- cerr
				return
			}
			rn, rerr := f.Read(buf)
			if rn > 0 {
				if _, werr := pw.Write(buf[:rn]); werr != nil {
					readErr <- werr
					return
				}
			}
			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					readErr <- nil
				} else {
					readErr <- rerr
				}
				return
			}
		}
	}()

	copied, copyErr := io.Copy(w, pr)
	// io.Copy 返回后必须关闭读端，否则读 goroutine 可能阻塞在 Write 上泄漏。
	_ = pr.Close()
	genErr := <-readErr
	if genErr != nil {
		return copied, genErr
	}
	return copied, copyErr
}

// countingWriter 统计已写字节数，用于在流式场景下获得归档体积。
type countingWriter struct {
	inner io.Writer
	n     int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.inner.Write(p)
	c.n += int64(n)
	return n, err
}

// BytesWritten 返回累计写入字节数，ZipStream 会通过接口断言识别它。
func (c *countingWriter) BytesWritten() int64 { return c.n }

// NewCountingWriter 包装 dst，使 ZipStream 能回报 ZipBytes。
func NewCountingWriter(dst io.Writer) io.Writer {
	return &countingWriter{inner: dst}
}
