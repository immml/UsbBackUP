package archive

import (
	"context"
	"io"
	"time"
)

// ZipOptions 是整盘打包参数。
type ZipOptions struct {
	// SourceRoot 是扫描源根，如 `E:\`。
	SourceRoot string
	// Excludes 是追加的排除项（F-505）。
	Excludes []string
	// StoreAlreadyCompressed 对已压缩格式用 Store（F-502）。
	StoreAlreadyCompressed bool
	// Threads 是压缩并发度，0 表示自动。
	Threads int
	// Progress 是进度回调（按文件粒度）。
	Progress func(ZipStats)
}

// ZipStats 是打包统计（F-508）。
type ZipStats struct {
	Files    int
	Dirs     int
	Skipped  int
	RawBytes int64
	ZipBytes int64
	Duration time.Duration
}

// ZipStream 把 SourceRoot 下的内容以流式 zip 写入 dst。
//
// 实现计划（M2）：
//   - 预热遍历一次统计文件数与总字节（供进度与空间预检）；
//   - 逐文件写入，路径经 ArchiveName 归一化，条目名一律相对路径（F-503）；
//   - 超长路径经 fsutil.LongPath 处理（F-504）；
//   - 命中排除表 / 重解析点 / 无法读取的文件 → 记入 Skipped 并 WARN，不中断整体；
//   - 全程只读源盘（G-05）。
//
// 调用方须保证 dst 是一个可流式写入的目标（通常是加密器的输入管道），
// 这样明文 zip 不需要落到磁盘（决策 D-03）。
func ZipStream(ctx context.Context, dst io.Writer, opt ZipOptions) (ZipStats, error) {
	return ZipStats{}, ErrNotImplemented
}

// UnzipOptions 是解包参数。
type UnzipOptions struct {
	// DestDir 是解包目标目录（必须显式指定，F-B03）。
	DestDir string
	// Force 为 true 时覆盖已存在文件（F-B06）。
	Force bool
	// DryRun 只列出将要写出的条目，不实际写入。
	DryRun bool
	// Progress 是进度回调。
	Progress func(UnzipStats)
}

// UnzipStats 是解包统计。
type UnzipStats struct {
	// Files 是写出的文件数。
	Files int
	// Skipped 是跳过的条目数。
	Skipped int
	// Bytes 是写出的字节数。
	Bytes int64
	// RejectedUnsafe 是被安全守卫拒绝的条目数（F-B05）。
	RejectedUnsafe int
	// Duration 是耗时。
	Duration time.Duration
}

// UnzipStream 从 src 读取 zip 流并解包到 opt.DestDir。
//
// 实现计划（M2）：
//   - 每个条目先经 SafeExtractPath 校验，不合格即拒绝并计数（F-B05）；
//   - 拒绝符号链接/重解析点条目（F-B05）；
//   - 已存在文件默认跳过，--force 才覆盖（F-B06）；
//   - 写出前做磁盘空间预检（F-B07）。
func UnzipStream(ctx context.Context, src io.ReaderAt, size int64, opt UnzipOptions) (UnzipStats, error) {
	return UnzipStats{}, ErrNotImplemented
}
