// Package winmon 实现 USB 存储设备插入事件的实时监控。
//
// 状态：**契约已定义，实现计划于 M4**（见 REQUIREMENTS.md 第 7 节）。
// 本文件先固化对外接口与边界，避免后续实现时改动调用方。
//
// 对应需求 F-101 ~ F-107。实现要点：
//
//   - 首选事件驱动：创建 `HWND_MESSAGE` 消息专用窗口，`RegisterDeviceNotificationW`
//     注册 `DBT_DEVTYP_VOLUME`，在 `WM_DEVICECHANGE` 中取 `DBT_DEVICEARRIVAL`（F-102）。
//   - 兜底轮询：`GetLogicalDrives` 差分（默认 5s），见 winvol.RemovableRoots（F-103）。
//   - 去抖与串行化：同盘符 5s 内事件合并为一次作业（F-104）。
//
// 安全边界（G-07 / G-01）：
//   - 只监听卷到达，**不注册、不解析任何 HID / 输入设备接口**；
//   - 窗口不可见、不进任务栏、无输入焦点；
//   - 不修改注册表、不写自启动项。
package winmon

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// ErrNotImplemented 表示该能力尚未实现。
var ErrNotImplemented = errors.New("winmon: 设备监控尚未实现（计划于 M4）")

// EventKind 是设备事件类型。
type EventKind int

// 事件类型。
const (
	// EventArrival 表示卷到达（插入）。
	EventArrival EventKind = iota
	// EventRemoval 表示卷移除（拔出）。
	EventRemoval
)

// String 返回事件类型名。
func (k EventKind) String() string {
	switch k {
	case EventArrival:
		return "arrival"
	case EventRemoval:
		return "removal"
	default:
		return "unknown"
	}
}

// Event 是一次设备事件。
type Event struct {
	// Root 是卷根，形如 `E:\`。
	Root string
	// Kind 是事件类型。
	Kind EventKind
	// At 是事件发生时间。
	At time.Time
}

// Options 是监控器参数。
type Options struct {
	// PollInterval 是轮询兜底间隔（F-103）。
	PollInterval time.Duration
	// Debounce 是同盘符事件合并窗口（F-104）。
	Debounce time.Duration
	// PollOnly 为 true 时禁用事件通道，只用轮询。
	PollOnly bool
	// ProcessMountedOnStart 决定启动时是否枚举已挂载可移动盘（F-105）。
	ProcessMountedOnStart bool
	// QueueSize 是作业队列容量，队列满时丢弃并告警（F-104）。
	QueueSize int
	// Logger 是日志器。
	Logger *slog.Logger
}

// Monitor 是设备监控器。
type Monitor struct {
	opt Options
	// usedEventChannel 记录本次是否成功建立事件通道（失败则降级轮询）。
	usedEventChannel bool
}

// New 构造监控器。构造本身不产生副作用，不创建窗口。
func New(opt Options) *Monitor {
	if opt.PollInterval <= 0 {
		opt.PollInterval = 5 * time.Second
	}
	if opt.Debounce <= 0 {
		opt.Debounce = 5 * time.Second
	}
	if opt.QueueSize <= 0 {
		opt.QueueSize = 64
	}
	return &Monitor{opt: opt}
}

// UsedEventChannel 返回是否使用事件驱动通道（未运行时为 false）。
func (m *Monitor) UsedEventChannel() bool { return m.usedEventChannel }

// Run 开始监控，直到 ctx 被取消。
//
// 实现计划（M4）：
//  1. 尝试建立消息专用窗口并注册设备通知；失败则记录 WARN 并降级轮询。
//  2. 启动轮询差分协程（P-103）。
//  3. 去抖后把事件投递给 handler；handler 必须快速返回，耗时工作交给作业队列。
func (m *Monitor) Run(ctx context.Context, handler func(Event)) error {
	return ErrNotImplemented
}
