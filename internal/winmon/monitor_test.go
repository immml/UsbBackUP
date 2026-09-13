package winmon

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestUnitMaskToRoots(t *testing.T) {
	cases := []struct {
		name string
		mask uint32
		want []string
	}{
		{"A 盘", 1 << 0, []string{`A:\`}},
		{"E 盘", 1 << 4, []string{`E:\`}},
		{"Z 盘", 1 << 25, []string{`Z:\`}},
		{"多盘同时到达", 1<<4 | 1<<7, []string{`E:\`, `H:\`}},
		{"空掩码", 0, nil},
		{"忽略越界位", 1 << 31, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := unitMaskToRoots(tc.mask)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("unitMaskToRoots(%#x) = %v, want %v", tc.mask, got, tc.want)
			}
		})
	}
}

func TestNormalizeEventRoot(t *testing.T) {
	if got := NormalizeEventRoot('e'); got != `E:\` {
		t.Fatalf("小写字母应转成大写盘符，实际 %q", got)
	}
	if got := NormalizeEventRoot('Z'); got != `Z:\` {
		t.Fatalf("NormalizeEventRoot('Z') = %q", got)
	}
}

func TestEventKindString(t *testing.T) {
	if EventArrival.String() != "arrival" {
		t.Fatalf("EventArrival.String() = %q", EventArrival.String())
	}
	if EventRemoval.String() != "removal" {
		t.Fatalf("EventRemoval.String() = %q", EventRemoval.String())
	}
	if EventKind(99).String() != "unknown" {
		t.Fatal("未知类型应返回 unknown")
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	m := New(Options{})
	if m.opt.PollInterval != 5*time.Second {
		t.Fatalf("默认轮询间隔应为 5s，实际 %s", m.opt.PollInterval)
	}
	if m.opt.Debounce != 5*time.Second {
		t.Fatalf("默认去抖窗口应为 5s，实际 %s", m.opt.Debounce)
	}
	if m.opt.QueueSize != 64 {
		t.Fatalf("默认队列容量应为 64，实际 %d", m.opt.QueueSize)
	}
	if m.UsedEventChannel() {
		t.Fatal("未运行时不应报告使用了事件通道")
	}
	if m.EventError() != nil {
		t.Fatal("未运行时不应有事件通道错误")
	}
}

func TestNewKeepsExplicitOptions(t *testing.T) {
	m := New(Options{
		PollInterval: 2 * time.Second,
		Debounce:     time.Second,
		QueueSize:    8,
		PollOnly:     true,
	})
	if m.opt.PollInterval != 2*time.Second || m.opt.Debounce != time.Second || m.opt.QueueSize != 8 {
		t.Fatalf("显式参数未被保留: %+v", m.opt)
	}
	if !m.opt.PollOnly {
		t.Fatal("PollOnly 未被保留")
	}
}

func TestRunRequiresHandler(t *testing.T) {
	m := New(Options{})
	if err := m.Run(nil, nil); err == nil {
		t.Fatal("handler 为空时应报错")
	}
}

func TestRunPollOnlyDeliversStartupAndStops(t *testing.T) {
	// 只读路径：PollOnly 模式下应能正常启动、枚举、并在 ctx 取消后干净退出。
	m := New(Options{PollInterval: 50 * time.Millisecond, PollOnly: true, ProcessMountedOnStart: true})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 让 Run 有极短时间走完启动分支，再取消。
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	done := make(chan struct{})
	events := make(chan Event, 64)

	go func() {
		defer close(done)
		_ = m.Run(ctx, func(ev Event) {
			select {
			case events <- ev:
			default:
			}
		})
	}()

	select {
	case <-done:
		// 正常退出即可；本机可能没有可移动介质，因此不强制要求收到事件。
	case <-time.After(3 * time.Second):
		t.Fatal("PollOnly 模式下 Run 未在上下文取消后及时退出")
	}
}
