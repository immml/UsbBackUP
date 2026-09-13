//go:build windows

package winmon

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Windows 消息与设备通知常量。
const (
	wmDeviceChange = 0x0219 // WM_DEVICECHANGE
	wmClose        = 0x0010 // WM_CLOSE
	wmDestroy      = 0x0002 // WM_DESTROY

	dbtDeviceArrival         = 0x8000 // DBT_DEVICEARRIVAL
	dbtDeviceRemoveComplete  = 0x8004 // DBT_DEVICEREMOVECOMPLETE
	dbtDevTypVolume          = 0x0002 // DBT_DEVTYP_VOLUME
	deviceNotifyWindowHandle = 0x0000 // DEVICE_NOTIFY_WINDOW_HANDLE

	wsPopup = 0x80000000 // WS_POPUP：无边框弹窗，且不显示（未设 WS_VISIBLE）
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostMessageW     = user32.NewProc("PostMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
)

// wndClassExW 对应 WNDCLASSEXW。
type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     syscall.Handle
	hIcon         syscall.Handle
	hCursor       syscall.Handle
	hbrBackground syscall.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       syscall.Handle
}

// devBroadcastVolumeSize 是 C 结构 DEV_BROADCAST_VOLUME 的真实大小：
// 4 个 DWORD + 1 个 WORD = 4*4 + 2 = 18 字节。
//
// 注意：Go 结构体会因 4 字节对齐把尾部补齐到 20 字节，
// 因此**绝不能**用 unsafe.Sizeof 去填 dbcv_size——
// 传 20 给 RegisterDeviceNotificationW 会直接返回 ERROR_INVALID_DATA(13)。
const devBroadcastVolumeSize = 18

// devBroadcastVolume 对应 DEV_BROADCAST_VOLUME。
//
// 布局（全部小端）：
//
//	偏移 0  DWORD dbcv_size
//	偏移 4  DWORD dbcv_devicetype
//	偏移 8  DWORD dbcv_reserved
//	偏移 12 DWORD dbcv_unitmask
//	偏移 16 WORD  dbcv_flags
type devBroadcastVolume struct {
	size       uint32
	deviceType uint32
	reserved   uint32
	unitMask   uint32
	flags      uint16
}

// msg 对应 MSG。
type msg struct {
	hwnd    syscall.Handle
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      struct{ x, y int32 }
}

// runDeviceNotifications 在独立 OS 线程上创建消息专用窗口并处理设备通知。
//
// 就绪后向 started 发送 nil；任何环节失败则发送错误并返回。
// 直到 ctx 被取消才返回（返回 nil）。
func runDeviceNotifications(ctx context.Context, emit func(Event), log *slog.Logger, started chan<- error) error {
	// 消息循环必须固定在一个 OS 线程上。
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// 窗口过程是 C 回调，无法捕获闭包，因此通过包级钩子转发事件。
	restore := setEmitHook(emit)
	defer restore()

	hInst, _, _ := procGetModuleHandleW.Call(0)

	// 注册窗口类。类名带进程 ID，避免与其它实例冲突。
	className := fmt.Sprintf("usbbackup-monitor-%d", syscall.Getpid())
	classPtr, err := syscall.UTF16PtrFromString(className)
	if err != nil {
		started <- err
		return err
	}

	var wc wndClassExW
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	wc.lpfnWndProc = syscall.NewCallback(wndProc)
	wc.hInstance = syscall.Handle(hInst)
	wc.lpszClassName = classPtr

	atom, _, callErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		e := fmt.Errorf("RegisterClassExW 失败: %v", callErr)
		started <- e
		return e
	}

	// 必须是**顶层窗口**才能收到 WM_DEVICECHANGE 广播：
	// 消息专用窗口（HWND_MESSAGE）不在广播范围内，这是常见坑。
	// WS_POPUP 且不带 WS_VISIBLE → 不可见、不进任务栏、不获得输入焦点。
	hwnd, _, callErr := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(classPtr)),
		uintptr(unsafe.Pointer(classPtr)),
		wsPopup,
		0, 0, 0, 0,
		0, // 无父窗口：顶层
		0,
		hInst,
		0,
	)
	if hwnd == 0 {
		e := fmt.Errorf("CreateWindowExW 失败: %v", callErr)
		started <- e
		return e
	}
	defer func() { _, _, _ = procDestroyWindow.Call(hwnd) }()

	// 这里**不调用** RegisterDeviceNotificationW：
	//
	// DBT_DEVTYP_VOLUME 不是 RegisterDeviceNotification 支持的过滤器类型
	// （合法类型只有 DEVICEINTERFACE / HANDLE 等），传卷过滤器会直接返回
	// ERROR_INVALID_DATA(13)。而卷到达/移除事件本身就由系统**默认广播**给
	// 所有顶层窗口，因此只要有一个顶层窗口就能收到，无需注册。
	//
	// 这样也顺带满足 G-07：不注册任何设备接口，尤其不碰 HID。

	// 通知就绪，开始投递事件。
	started <- nil

	// ctx 取消时向窗口投递 WM_CLOSE，让阻塞中的 GetMessageW 返回。
	go func() {
		<-ctx.Done()
		_, _, _ = procPostMessageW.Call(hwnd, wmClose, 0, 0)
	}()

	var m msg
	for {
		r, _, err := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) == -1 {
			return fmt.Errorf("GetMessageW 失败: %v", err)
		}
		if r == 0 {
			// WM_QUIT
			return nil
		}
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// wndProc 是窗口过程，处理 WM_DEVICECHANGE。
func wndProc(hwnd syscall.Handle, message uint32, wParam uintptr, lParam unsafe.Pointer) uintptr {
	switch message {
	case wmDeviceChange:
		switch wParam {
		case dbtDeviceArrival, dbtDeviceRemoveComplete:
			kind := EventArrival
			if wParam == dbtDeviceRemoveComplete {
				kind = EventRemoval
			}
			if lParam != nil {
				// lParam 指向系统在本次回调期间分配并保持有效的
				// DEV_BROADCAST_VOLUME 结构；回调返回后即失效。
				// 把 lParam 声明为 unsafe.Pointer 而非 uintptr，既符合语义，
				// 也避免 uintptr→Pointer 转换触发的静态检查告警。
				v := (*devBroadcastVolume)(lParam)
				if v.deviceType == dbtDevTypVolume {
					now := nowFunc()
					for _, root := range unitMaskToRoots(v.unitMask) {
						deliver(Event{Root: root, Kind: kind, At: now, Source: "event"})
					}
				}
			}
		}
	case wmClose:
		_, _, _ = procDestroyWindow.Call(uintptr(hwnd))
	case wmDestroy:
		_, _, _ = procPostQuitMessage.Call(0)
	}
	r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(message), wParam, uintptr(lParam))
	return r
}

// deliver 由窗口过程调用（运行在消息线程上），把事件转交 Run 里的消费者。
//
// 通过包级函数指针转发：窗口过程是 C 回调，无法捕获闭包，
// 因此用一次性的全局钩子把 emit 注入进来。
var (
	emitHook   func(Event)
	nowFunc    = func() time.Time { return time.Now() }
	emitHookMu sync.RWMutex
)

func deliver(ev Event) {
	emitHookMu.RLock()
	fn := emitHook
	emitHookMu.RUnlock()
	if fn != nil {
		fn(ev)
	}
}

// setEmitHook 注册事件转发目标，返回恢复函数。
func setEmitHook(fn func(Event)) func() {
	emitHookMu.Lock()
	prev := emitHook
	emitHook = fn
	emitHookMu.Unlock()
	return func() {
		emitHookMu.Lock()
		emitHook = prev
		emitHookMu.Unlock()
	}
}
