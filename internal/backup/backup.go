// Package backup 是流水线编排层，把各模块串成一条作业链。
//
// 状态：产物命名与审计落盘**已实现并测试**；完整流水线执行器计划于 M4。
//
// 对应需求 F-801 ~ F-809。
//
// 分支判定：
//
//	插入事件 → 就绪等待 → 卷类型检查 → 关键检测（keyfile.Scan）
//	    ├─ authorized = true  → 分支 A：回写本地备份到 <USB>:\backup\   （copier）
//	    └─ authorized = false → 容量门控（winvol.EvaluateGate）
//	                              ├─ used > 阈值 → 跳过
//	                              └─ 否则        → 分支 B：整盘打包 + 混合加密（archive + crypto）
//
// 审计约束（G-02）：审计记录**只包含**盘符、卷标、容量、分支、布尔判定与计数，
// 绝不包含私钥内容、私钥文件名、文件清单或任何文件内容。
package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackUP/internal/config"
	"github.com/immml/UsbBackUP/internal/fsutil"
	"github.com/immml/UsbBackUP/internal/keyfile"
	"github.com/immml/UsbBackUP/internal/winvol"
)

// ErrNotImplemented 表示该能力尚未实现。
var ErrNotImplemented = errors.New("backup: 流水线执行器尚未实现（计划于 M4）")

// Branch 是作业走的分支。
type Branch string

// 分支常量。
const (
	// BranchAuthorized 表示检测到私钥，执行本地备份回写。
	BranchAuthorized Branch = "authorized-writeback"
	// BranchArchive 表示未检测到私钥，执行整盘打包加密。
	BranchArchive Branch = "archive-encrypt"
	// BranchSkipped 表示因门控或异常而跳过。
	BranchSkipped Branch = "skipped"
	// BranchFailed 表示作业失败。
	BranchFailed Branch = "failed"
)

// 门控跳过原因（写入审计，便于事后复盘）。
const (
	// SkipReasonOverThreshold 表示已占用容量超过阈值（F-304）。
	SkipReasonOverThreshold = "used-over-threshold"
	// SkipReasonNotRemovable 表示不是可移动卷（F-301）。
	SkipReasonNotRemovable = "not-removable"
	// SkipReasonNotReady 表示卷未就绪（F-305）。
	SkipReasonNotReady = "volume-not-ready"
	// SkipReasonNoKeyOnTarget 表示分支 A 的目标卷无授权。
	SkipReasonNoKeyOnTarget = "no-key-and-gate-skip"
)

// Deps 是流水线依赖。
type Deps struct {
	Cfg *config.Config
	Log *slog.Logger
	// Matcher 是私钥判定器（由 keyfile.NewMatcher 构造）。
	Matcher *keyfile.Matcher
	// AllowedFingerprint 是已配置公钥的指纹，用于显式授权标记判定。
	AllowedFingerprint string
}

// AuditRecord 是写入 audit.jsonl 的一行。
//
// 字段经过刻意裁剪：**不含任何路径清单、文件名或文件内容**（G-02）。
type AuditRecord struct {
	Time         string `json:"time"`
	Tool         string `json:"tool"`
	ToolVersion  string `json:"tool_version,omitempty"`
	Root         string `json:"root"`
	Label        string `json:"label,omitempty"`
	FileSystem   string `json:"fs,omitempty"`
	SerialNumber uint32 `json:"serial,omitempty"`
	TotalBytes   int64  `json:"total_bytes"`
	FreeBytes    int64  `json:"free_bytes"`
	UsedBytes    int64  `json:"used_bytes"`
	Branch       Branch `json:"branch"`
	// HasKeyfile 只记录布尔值与计数，不记录命中文件名（G-02）。
	HasKeyfile    bool     `json:"has_keyfile"`
	KeyfileHits   int      `json:"keyfile_hits"`
	KeyfileKinds  []string `json:"keyfile_kinds,omitempty"`
	ScannedFiles  int      `json:"scanned_files"`
	DetectSeconds float64  `json:"detect_seconds"`
	// SkipReason 仅在跳过时有值。
	SkipReason string `json:"skip_reason,omitempty"`
	// Product 是产物相对文件名（只含净化后的卷标与扩展名，不含完整路径）。
	Product string `json:"product,omitempty"`
	// Files / RawBytes / CipherBytes 是打包或复制的统计。
	Files       int     `json:"files,omitempty"`
	RawBytes    int64   `json:"raw_bytes,omitempty"`
	CipherBytes int64   `json:"cipher_bytes,omitempty"`
	OK          bool    `json:"ok"`
	Err         string  `json:"error,omitempty"`
	DurationSec float64 `json:"duration_sec,omitempty"`
}

// ProductName 依据卷标生成产物文件名（F-602）。
//
// 形态：`{净化后的卷标}.zip.usbk`；卷标为空则用 `VOL_<盘符>`。
// 净化保证结果不含任何路径分隔符，防路径穿越。
func ProductName(v winvol.Volume) string {
	base := fsutil.SanitizeName(winvol.LabelOrFallback(v))
	if base == "" {
		base = "VOL_UNKNOWN"
	}
	// 去掉可能残留的扩展名混淆点（如 "x.zip" 之类的卷标）。
	base = strings.TrimSuffix(base, ".zip")
	if base == "" {
		base = "VOL_UNKNOWN"
	}
	return base + ".zip.usbk"
}

// UniqueProductPath 在目标目录下为产物取一个不冲突的路径。
// 冲突时追加 `_YYYYMMDD_HHMMSS`（F-602）。
func UniqueProductPath(outputDir string, v winvol.Volume, at time.Time) string {
	name := ProductName(v)
	full := filepath.Join(outputDir, name)
	if _, err := os.Stat(full); errors.Is(err, os.ErrNotExist) {
		return full
	}
	stem := strings.TrimSuffix(name, ".zip.usbk")
	return filepath.Join(outputDir, fmt.Sprintf("%s_%s.zip.usbk", stem, at.Format("20060102_150405")))
}

// AppendAudit 以 JSON Lines 形式追加一条审计记录（F-807）。
//
// 写失败不致命：返回错误由调用方降级为 WARN，不阻断备份本身。
func AppendAudit(path string, rec AuditRecord) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("审计文件路径为空")
	}
	if rec.Time == "" {
		rec.Time = time.Now().Format(time.RFC3339)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("创建审计目录失败: %w", err)
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("序列化审计记录失败: %w", err)
	}
	line = append(line, '\n')

	f, err := os.OpenFile(fsutil.LongPath(path), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("打开审计文件失败: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("写入审计记录失败: %w", err)
	}
	return nil
}

// Result 是一次作业的结果。
type Result struct {
	Root       string
	Volume     winvol.Volume
	Branch     Branch
	SkipReason string
	Authorized bool
	Detect     keyfile.Result
	Gate       winvol.Policy
	// ProductPath 是产物绝对路径（分支 B）。
	ProductPath string
	// CopiedStats 是分支 A 的复制统计。
	CopiedStats any
	OK          bool
	Err         string
	Duration    time.Duration
}

// Run 执行一次完整的单盘作业（实现计划见 M4）。
//
// 实现计划：
//  1. winvol.Query 等待就绪并取卷信息（失败 → 跳过，不报错）；
//  2. 卷类型非可移动 → 跳过（F-301）；
//  3. keyfile.Scan 判定是否持有私钥（F-2xx）；
//  4. 授权 → copier.Copy 到 `\backup\`（F-401~F-410）；
//  5. 未授权 → winvol.EvaluateGate 门控（F-304）；
//  6. 通过门控 → archive.ZipStream 管道直送 crypto.EncryptStream → 落盘
//     `%TEMP%\backup\{卷标}.zip.usbk`（F-501 / F-601 / F-803 / D-03）；
//  7. 无论走哪个分支，最后都写一条审计记录（F-807）。
//
// 任一分支全过程都只读源盘；失败时清理半成品（F-801）。
func Run(ctx context.Context, deps Deps, root string) (Result, error) {
	return Result{Root: root, Branch: BranchFailed, Err: "尚未实现（M4）"}, ErrNotImplemented
}
