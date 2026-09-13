package archive

import "time"

// ZipOptions 是整盘打包参数。
type ZipOptions struct {
	// SourceRoot 是扫描源根，如 `E:\`。
	SourceRoot string
	// Excludes 是追加的排除项，支持 `*` / `?` 通配（F-505）。
	Excludes []string
	// StoreAlreadyCompressed 对已压缩格式用 Store 方式写入（F-502）。
	StoreAlreadyCompressed bool
	// Threads 保留为并发度提示：0/1 表示自动，
	// 实现上通过"读取与压缩流水线重叠"获得 IO/CPU 并行，内存占用与文件大小无关。
	Threads int
	// Progress 是进度回调（每次成功写入一个文件后触发）。
	Progress func(ZipStats)
}

// ZipStats 是打包统计（F-508）。
type ZipStats struct {
	// Files 是成功写入归档的文件数。
	Files int
	// Dirs 是遍历过的目录数。
	Dirs int
	// Skipped 是跳过的条目数（排除项、重解析点、读取失败、超限文件等）。
	Skipped int
	// RawBytes 是写入归档的原始字节数。
	RawBytes int64
	// ZipBytes 是归档体积（仅当 dst 由 NewCountingWriter 包装时可用）。
	ZipBytes int64
	// Duration 是耗时。
	Duration time.Duration
}

// UnzipOptions 是解包参数。
type UnzipOptions struct {
	// DestDir 是解包目标目录（必须显式指定，F-B03）。
	DestDir string
	// Force 为 true 时覆盖已存在文件（F-B06）。
	Force bool
	// DryRun 只校验并列出，不实际写入。
	DryRun bool
	// MaxEntryBytes 是单条目解压上限，0 表示用 DefaultMaxEntryBytes。
	MaxEntryBytes int64
	// MaxTotalBytes 是整次解压的明文总量上限，0 表示用 DefaultMaxTotalBytes。
	MaxTotalBytes int64
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
