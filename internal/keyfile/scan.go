// Package keyfile 实现「U 盘上是否存在疑似私钥文件」的**存在性判定**。
//
// # 职责边界（必须严格遵守）
//
// 本包只回答一个问题：该介质看起来是否持有私钥。
// 它**绝不**解析私钥、复制私钥、缓存私钥内容、把私钥内容写入日志或文件，
// 也不产生任何派生文件（需求 G-01 / G-02 / G-03）。
//
// 判定分三路（决策 D-07）：
//
//	A. 文件名特征匹配（F-201）—— 只比对文件名，不打开文件；
//	B. 内容特征匹配（F-202）—— 只读取文件开头最多 N 字节（默认 4 KiB），读完即清零；
//	C. 显式授权标记（F-203）—— 比对 `<USB>\.usbguard-allow` 中的**公钥指纹**。
//
// 一旦命中即立即返回，不再继续扫描：既省 IO，也最小化数据接触面。
package keyfile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackup/internal/config"
	"github.com/immml/UsbBackup/internal/fsutil"
)

// skipDirs 是扫描时跳过的目录名（小写比较），对应 F-205。
var skipDirs = map[string]bool{
	"system volume information": true,
	"$recycle.bin":              true,
	"$sysreset":                 true,
	"$windows.~bt":              true,
	"$windows.~ws":              true,
	"found.000":                 true,
	"found.001":                 true,
	"recycler":                  true,
	".trash-1000":               true,
	".trash-0":                  true,
	"lost+found":                true,
}

// Options 是一次检测的输入参数。
type Options struct {
	// Root 是待检测的卷根，例如 `E:\`。
	Root string
	// Matcher 是判定器，由 NewMatcher 构造。
	Matcher *Matcher
	// Detect 是检测相关配置。
	Detect config.DetectConfig
	// AllowedFingerprint 是已配置公钥的指纹（用于 C 路判定），可为空。
	AllowedFingerprint string
	// AllowMarkerOverride 允许 marker 模式在无法提供指纹时，
	// 仅凭标记文件存在即判定为授权（默认关闭，避免误判）。
	AllowMarkerOverride bool
}

// Result 是检测结论。
//
// 刻意只包含布尔值与计数：**不包含任何文件名、路径或内容**，
// 因此可以安全地写入审计日志（G-02）。
type Result struct {
	// Authorized 为 true 表示判定该介质持有私钥（即"已授权"分支）。
	Authorized bool
	// Kinds 是命中类型集合（去重），例如 ["pem-header"]。
	Kinds []string
	// HitCount 是命中次数。
	HitCount int
	// FilesScanned 是实际检查过的文件数。
	FilesScanned int
	// DirsScanned 是实际进入过的目录数。
	DirsScanned int
	// BytesRead 是累计读取的字节数（用于证明"只读了极少数据"）。
	BytesRead int64
	// Truncated 表示因触及深度/数量/耗时上限而提前结束。
	Truncated bool
	// Duration 是本次检测耗时。
	Duration time.Duration
}

// ErrRootUnavailable 表示卷根不可访问。
var ErrRootUnavailable = errors.New("卷根不可访问")

// Scan 对 Root 执行一次有界的存在性检测（F-201 ~ F-206）。
//
// 边界约束：最大深度 detect.MaxDepth、最多 detect.MaxFiles 个文件、
// 总耗时不超过 detect.TimeoutSec。命中即返回。
func Scan(ctx context.Context, opt Options) (Result, error) {
	start := time.Now()
	res := Result{}

	if opt.Matcher == nil {
		return res, errors.New("keyfile: Matcher 为空")
	}
	root := opt.Root
	if root == "" {
		return res, ErrRootUnavailable
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		if err == nil {
			err = errors.New("路径不是目录")
		}
		return res, fmt.Errorf("%w: %s (%v)", ErrRootUnavailable, root, err)
	}

	mode := strings.ToLower(strings.TrimSpace(opt.Detect.Mode))
	if mode == "" {
		mode = "both"
	}
	maxDepth := opt.Detect.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 4
	}
	maxFiles := opt.Detect.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 5000
	}
	maxHeader := opt.Detect.MaxHeadersBytes
	if maxHeader <= 0 {
		maxHeader = opt.Matcher.MaxHeaderBytes()
	}
	timeout := time.Duration(opt.Detect.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 20 * time.Second
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	hits := map[string]int{}
	recordHit := func(k Kind) {
		res.Authorized = true
		res.HitCount++
		hits[string(k)]++
	}

	// C 路：显式授权标记（最便宜，先做）。
	if mode == "marker" || mode == "both" {
		ok, checked, readBytes := checkAllowMarker(root, opt)
		res.BytesRead += readBytes
		if checked {
			res.FilesScanned++
		}
		if ok {
			recordHit(KindAllowMark)
			res.Kinds = sortedKinds(hits)
			res.Duration = time.Since(start)
			return res, nil
		}
	}

	// A/B 路：有界遍历。
	type node struct {
		path  string
		depth int
	}
	stack := []node{{path: root, depth: 0}}
	var lastErr error

walk:
	for len(stack) > 0 {
		if err := scanCtx.Err(); err != nil {
			res.Truncated = true
			break walk
		}
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := os.ReadDir(cur.path)
		if err != nil {
			// 权限不足/介质被拔出等：跳过该目录，不中断整体检测。
			lastErr = err
			continue
		}
		res.DirsScanned++

		for _, e := range entries {
			if scanCtx.Err() != nil {
				res.Truncated = true
				break walk
			}
			name := e.Name()

			// 目录：深度允许则入栈；重解析点不跟随（F-206）。
			if e.IsDir() {
				if skipDirs[strings.ToLower(name)] {
					continue
				}
				if cur.depth+1 > maxDepth {
					res.Truncated = true
					continue
				}
				full := filepath.Join(cur.path, name)
				if isReparsePoint(full) {
					continue
				}
				stack = append(stack, node{path: full, depth: cur.depth + 1})
				continue
			}

			// 符号链接文件一律不跟随。
			if e.Type()&os.ModeSymlink != 0 {
				continue
			}
			if res.FilesScanned >= maxFiles {
				res.Truncated = true
				break walk
			}

			// A 路：文件名特征。
			if mode == "heuristic" || mode == "both" {
				if k, ok := opt.Matcher.MatchName(name); ok {
					res.FilesScanned++
					recordHit(k)
					break walk
				}
			}

			// B 路：内容特征（只读头部，读完即清零）。
			if opt.Detect.ScanContents && (mode == "heuristic" || mode == "both") {
				if !opt.Matcher.ShouldReadHeader(name) {
					continue
				}
				full := filepath.Join(cur.path, name)
				if isReparsePoint(full) {
					continue
				}
				kind, n, ok, err := probeHeader(full, opt.Matcher, maxHeader)
				res.FilesScanned++
				res.BytesRead += n
				if err != nil {
					lastErr = err
					continue
				}
				if ok {
					recordHit(kind)
					break walk
				}
			}
		}
	}

	res.Kinds = sortedKinds(hits)
	res.Duration = time.Since(start)
	_ = lastErr // 单个文件/目录的错误不影响结论，仅由调用方按需记录。
	return res, nil
}

// probeHeader 读取文件头部 maxHeader 字节并做特征匹配。
// 缓冲区在用完后立即清零（G-01）。
func probeHeader(path string, m *Matcher, maxHeader int) (Kind, int64, bool, error) {
	f, err := os.Open(fsutil.LongPath(path))
	if err != nil {
		return KindNone, 0, false, err
	}
	defer f.Close()

	buf := make([]byte, maxHeader)
	defer Zero(buf)

	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return KindNone, 0, false, err
	}
	if n <= 0 {
		return KindNone, 0, false, nil
	}
	k, ok := m.MatchHeader(buf[:n])
	return k, int64(n), ok, nil
}

// checkAllowMarker 检查显式授权标记文件。
// 返回 (是否授权, 是否真的读了文件, 读取字节数)。
func checkAllowMarker(root string, opt Options) (authorized bool, checked bool, readBytes int64) {
	name := strings.TrimSpace(opt.Detect.MarkerFile)
	if name == "" {
		name = ".usbguard-allow"
	}
	p := filepath.Join(root, name)
	st, err := os.Stat(p)
	if err != nil || st.IsDir() || st.Size() > 64*1024 {
		return false, false, 0
	}
	raw, err := os.ReadFile(fsutil.LongPath(p))
	if err != nil {
		return false, false, 0
	}
	defer Zero(raw)

	if opt.AllowedFingerprint != "" {
		return MatchAllowMarker(raw, opt.AllowedFingerprint), true, int64(len(raw))
	}
	// 无指纹可比对时，默认不凭"标记文件存在"就放行（避免误判为已授权）。
	return opt.AllowMarkerOverride, true, int64(len(raw))
}

func sortedKinds(hits map[string]int) []string {
	if len(hits) == 0 {
		return nil
	}
	out := make([]string, 0, len(hits))
	for k := range hits {
		out = append(out, k)
	}
	// 结果数量极小（<10），插入排序足够且无额外依赖。
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
