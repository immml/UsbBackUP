// Package logx 提供分级日志：控制台 + 按大小轮转的文件双写。
// 基于标准库 log/slog，无第三方依赖。
package logx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Options 定义日志初始化参数。
type Options struct {
	Level      string // debug / info / warn / error
	File       string // 日志文件路径，空表示不写文件
	MaxSizeMB  int    // 单文件大小上限
	MaxBackups int    // 轮转保留份数
	Console    bool   // 是否输出到控制台
}

// Handle 持有日志器与其需要释放的资源。
type Handle struct {
	Logger *slog.Logger
	closer io.Closer
	level  slog.Level
}

// ParseLevel 把字符串解析为 slog 级别。
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("未知日志级别 %q（可用 debug/info/warn/error）", s)
	}
}

// New 构造日志器。文件不可写时降级为仅控制台，不返回致命错误。
func New(o Options) (*Handle, error) {
	lvl, err := ParseLevel(o.Level)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: lvl}
	handlers := make([]slog.Handler, 0, 2)
	var closer io.Closer

	if o.Console {
		// 控制台用较紧凑的输出，去掉重复的时间戳噪音由 ReplaceAttr 控制。
		handlers = append(handlers, slog.NewTextHandler(os.Stdout, opts))
	}
	if o.File != "" {
		if err := os.MkdirAll(filepath.Dir(o.File), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "[warn] 创建日志目录失败，仅输出到控制台: %v\n", err)
		} else {
			rot, rerr := NewRotator(o.File, o.MaxSizeMB, o.MaxBackups)
			if rerr != nil {
				fmt.Fprintf(os.Stderr, "[warn] 打开日志文件失败，仅输出到控制台: %v\n", rerr)
			} else {
				handlers = append(handlers, slog.NewTextHandler(rot, opts))
				closer = rot
			}
		}
	}
	if len(handlers) == 0 {
		handlers = append(handlers, slog.NewTextHandler(io.Discard, opts))
	}
	return &Handle{
		Logger: slog.New(fanoutHandler{handlers: handlers}),
		closer: closer,
		level:  lvl,
	}, nil
}

// Level 返回生效级别。
func (h *Handle) Level() slog.Level { return h.level }

// Close 释放文件句柄。
func (h *Handle) Close() error {
	if h.closer != nil {
		return h.closer.Close()
	}
	return nil
}

// fanoutHandler 把一个日志记录同时投递给多个 handler。
type fanoutHandler struct {
	handlers []slog.Handler
}

func (f fanoutHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range f.handlers {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (f fanoutHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range f.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.Handle(ctx, r.Clone()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (f fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		next[i] = h.WithAttrs(attrs)
	}
	return fanoutHandler{handlers: next}
}

func (f fanoutHandler) WithGroup(name string) slog.Handler {
	next := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		next[i] = h.WithGroup(name)
	}
	return fanoutHandler{handlers: next}
}

// Rotator 是带大小轮转的 io.WriteCloser。
type Rotator struct {
	mu         sync.Mutex
	path       string
	maxBytes   int64
	maxBackups int
	f          *os.File
	size       int64
}

// NewRotator 打开（或创建）日志文件并读取当前大小。
func NewRotator(path string, maxMB, maxBackups int) (*Rotator, error) {
	if maxMB <= 0 {
		maxMB = 10
	}
	if maxBackups <= 0 {
		maxBackups = 5
	}
	r := &Rotator{
		path:       path,
		maxBytes:   int64(maxMB) << 20,
		maxBackups: maxBackups,
	}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Rotator) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	r.f = f
	r.size = st.Size()
	return nil
}

func (r *Rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	if r.size > 0 && r.size+int64(len(p)) > r.maxBytes {
		// 轮转失败不阻断写入，继续追加。
		if err := r.rotate(); err != nil {
			fmt.Fprintf(os.Stderr, "[warn] 日志轮转失败: %v\n", err)
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// rotate 关闭当前文件，把 .N 依次后移，然后重建空文件。
func (r *Rotator) rotate() error {
	if r.f != nil {
		_ = r.f.Close()
		r.f = nil
	}
	// 丢弃最旧一份，其余顺移。
	oldest := fmt.Sprintf("%s.%d", r.path, r.maxBackups)
	_ = os.Remove(oldest)
	for i := r.maxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", r.path, i)
		dst := fmt.Sprintf("%s.%d", r.path, i+1)
		if _, err := os.Stat(src); err == nil {
			_ = os.Rename(src, dst)
		}
	}
	if _, err := os.Stat(r.path); err == nil {
		_ = os.Rename(r.path, r.path+".1")
	}
	r.size = 0
	return r.open()
}

// Close 关闭底层文件。
func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
