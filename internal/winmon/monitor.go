// Package winmon 实现 USB 存储设备插入事件的实时监控。
//
// 对应需求 F-101 ~ F-107。两条通道：
//
//	通道 1（首选，事件驱动）：创建 `HWND_MESSAGE` 消息专用窗口，
//	  用 `RegisterDeviceNotificationW` 注册 `DBT_DEVTYP_VOLUME`，
//	  在 `WM_DEVICECHANGE` 中解析 `DBT_DEVICEARRIVAL` 的 unitmask 得到盘符。
//	通道 2（兜底，轮询）：`GetLogicalDrives` 差分，默认 5 秒一轮。
//
// 之所以保留轮询：在受限环境（某些服务会话、被安全软件挂钩的进程）中
// 消息窗口可能创建失败，轮询能保证功能仍可用，只是延迟变大。
//
// 安全边界（G-07）：
//   - 只监听卷到达/移除，**不注册、不解析任何 HID 或输入设备接口**；
//   - 窗口不可见、不进任务栏、无输入焦点；
//   - 不修改注册表、不写自启动项。
package winmon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/immml/UsbBackUP/internal/winvol"
)

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
	// Source 记录事件来源：event（设备通知）或 poll（轮询差分）。
	Source string
}

// Options 是监控器参数。
type Options struct {
	// PollInterval 是轮询兜底间隔（F-103）。
	PollInterval time.Duration
	// Debounce 是同盘符事件合并窗口（F-104）。
	Debounce time.Duration
	// PollOnly 为 true 时禁用事件通道，只用轮询（排障用）。
	PollOnly bool
	// ProcessMountedOnStart 决定启动时是否枚举已挂载可移动盘（F-105）。
	ProcessMountedOnStart bool
	// QueueSize 是作业队列容量，队列满时丢弃并告警（F-104）。
	QueueSize int
	// Logger 是日志器，可为 nil。
	Logger *slog.Logger
}

// Monitor 是设备监控器。
type Monitor struct {
	opt Options

	mu               sync.Mutex
	usedEventChannel bool
	eventErr         error
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

// UsedEventChannel 返回本次运行是否成功使用事件驱动通道。
func (m *Monitor) UsedEventChannel() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.usedEventChannel
}

// EventError 返回事件通道建立失败的原因（成功时为 nil）。
func (m *Monitor) EventError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eventErr
}

func (m *Monitor) log() *slog.Logger {
	if m.opt.Logger != nil {
		return m.opt.Logger
	}
	return slog.Default()
}

// Run 开始监控，直到 ctx 被取消。
//
// handler 在**单一 worker goroutine** 中被串行调用（F-104），因此实现必须
// 快速返回；耗时工作（打包、复制）应交给调用方自己的串行队列。
func (m *Monitor) Run(ctx context.Context, handler func(Event)) error {
	if handler == nil {
		return errors.New("winmon: handler 不能为空")
	}

	events := make(chan Event, m.opt.QueueSize)

	// 串行化 + 去抖的唯一消费者。
	var workerWG sync.WaitGroup
	workerWG.Add(1)
	go func() {
		defer workerWG.Done()
		last := make(map[string]time.Time)
		for ev := range events {
			if ev.Kind == EventArrival {
				if prev, ok := last[ev.Root]; ok && time.Since(prev) < m.opt.Debounce {
					m.log().Debug("winmon: 去抖合并重复到达事件", "root", ev.Root)
					continue
				}
				last[ev.Root] = time.Now()
			} else {
				delete(last, ev.Root)
			}
			handler(ev)
		}
	}()

	emit := func(ev Event) {
		select {
		case events <- ev:
		default:
			// 队列满时丢弃，绝不阻塞事件线程（F-104）。
			m.log().Warn("winmon: 事件队列已满，丢弃事件", "root", ev.Root, "kind", ev.Kind.String())
		}
	}

	// 启动时枚举已挂载的可移动盘（F-105）+ 建立轮询基线。
	known := map[string]bool{}
	if roots, err := winvol.RemovableRoots(); err == nil {
		for _, r := range roots {
			known[r] = true
			if m.opt.ProcessMountedOnStart {
				emit(Event{Root: r, Kind: EventArrival, At: time.Now(), Source: "startup"})
			}
		}
	} else {
		m.log().Warn("winmon: 启动时枚举可移动卷失败", "err", err)
	}

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	// startPoller 启动轮询兜底通道（F-103）。
	startPoller := func() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pollLoop(childCtx, m.opt.PollInterval, known, emit, m.log())
		}()
	}

	if m.opt.PollOnly {
		m.log().Info("winmon: 已按配置仅使用轮询通道", "interval", m.opt.PollInterval.String())
		startPoller()
	} else {
		started := make(chan error, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runDeviceNotifications(childCtx, emit, m.log(), started); err != nil {
				m.log().Warn("winmon: 设备通知通道退出", "err", err)
			}
		}()

		select {
		case err := <-started:
			if err == nil {
				m.mu.Lock()
				m.usedEventChannel = true
				m.mu.Unlock()
				m.log().Info("winmon: 已启用设备通知通道（事件驱动，空闲态零轮询）")
			} else {
				m.mu.Lock()
				m.eventErr = err
				m.mu.Unlock()
				m.log().Warn("winmon: 设备通知通道不可用，降级为轮询通道", "err", err)
				startPoller()
			}
		case <-time.After(5 * time.Second):
			// 事件循环启动超时：保守起见同时启用轮询，避免完全失聪。
			m.mu.Lock()
			m.eventErr = errors.New("等待设备通知通道就绪超时")
			m.mu.Unlock()
			m.log().Warn("winmon: 等待设备通知通道就绪超时，启用轮询兜底")
			startPoller()
		case <-ctx.Done():
			// 调用方已要求退出，直接走收尾流程。
		}
	}

	wg.Wait()
	close(events)
	workerWG.Wait()
	return nil
}

// pollLoop 是轮询差分实现（F-103）。
func pollLoop(ctx context.Context, interval time.Duration, known map[string]bool, emit func(Event), log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			roots, err := winvol.RemovableRoots()
			if err != nil {
				// 取盘符失败时保留上次快照，避免误报大批移除。
				log.Debug("winmon: 轮询枚举盘符失败，保留上次快照", "err", err)
				continue
			}
			cur := make(map[string]bool, len(roots))
			for _, r := range roots {
				cur[r] = true
				if !known[r] {
					log.Info("winmon: 轮询检测到新可移动卷", "root", r)
					emit(Event{Root: r, Kind: EventArrival, At: time.Now(), Source: "poll"})
				}
			}
			for r := range known {
				if !cur[r] {
					emit(Event{Root: r, Kind: EventRemoval, At: time.Now(), Source: "poll"})
				}
			}
			// 用新快照替换旧快照（就地更新，保持 map 引用不变）。
			for r := range known {
				delete(known, r)
			}
			for r := range cur {
				known[r] = true
			}
		}
	}
}

// NormalizeEventRoot 把 unitmask 推出的盘符统一成 `X:\` 形式。
func NormalizeEventRoot(letter byte) string {
	if letter >= 'a' && letter <= 'z' {
		letter -= 'a' - 'A'
	}
	return fmt.Sprintf("%c:\\", letter)
}

// isAlphaUpper 判断字节是否为大写字母。
func isAlphaUpper(c byte) bool { return c >= 'A' && c <= 'Z' }

// unitMaskToRoots 把 DEV_BROADCAST_VOLUME.dbcv_unitmask 位掩码解析成盘符列表。
// bit0 = A:，bit25 = Z:。这是纯函数，便于单测。
func unitMaskToRoots(mask uint32) []string {
	var out []string
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := NormalizeEventRoot(byte('A' + i))
		if !isAlphaUpper(root[0]) {
			continue
		}
		out = append(out, root)
	}
	return out
}

// trimRoot 去掉卷根末尾的分隔符，用于日志展示。
func trimRoot(root string) string { return strings.TrimRight(root, `\`) }
