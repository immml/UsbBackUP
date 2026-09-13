//go:build windows

// Package winsvc 提供 Windows 服务化能力与单实例互斥。
//
// 对应需求 F-808（单实例）与 F-D02（服务注册）。
//
// 实现说明：不引入 `golang.org/x/sys/windows/svc`，而是直接用
// advapi32 / kernel32 的少量导出函数。代价是要自己处理 SCM 协议细节，
// 收益是保住"零第三方依赖"这条硬约束（N-104）。
//
// 安全边界（G-07）：服务注册**只由用户显式命令触发**，
// 不在安装/启动时静默写自启动项，也不修改任何注册表键值以外的东西；
// 卸载时一并删除服务项，不留残留。
package winsvc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// serviceName 是注册到 SCM 的服务名。
const serviceName = "usbbackup"

// 服务控制常量。
const (
	serviceWin32OwnProcess = 0x00000010
	serviceStartPending    = 0x00000002
	serviceStopPending     = 0x00000003
	serviceRunning         = 0x00000004
	serviceStopped         = 0x00000001
	serviceAcceptStop      = 0x00000001
	serviceAcceptShutdown  = 0x00000004
	serviceControlStop     = 0x00000001
	serviceControlShutdown = 0x00000005
	serviceControlInterrog = 0x00000004
	noError                = 0x00000000
)

// errorAlreadyExists 对应 ERROR_ALREADY_EXISTS。
const errorAlreadyExists = 183

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procCreateMutexW                  = kernel32.NewProc("CreateMutexW")
	procCloseHandle                   = kernel32.NewProc("CloseHandle")
	procStartServiceCtrlDispatcherW   = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerExW = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus              = advapi32.NewProc("SetServiceStatus")
)

// serviceStatus 对应 SERVICE_STATUS。
type serviceStatus struct {
	serviceType             uint32
	currentState            uint32
	controlsAccepted        uint32
	win32ExitCode           uint32
	serviceSpecificExitCode uint32
	checkPoint              uint32
	waitHint                uint32
}

// serviceTableEntry 对应 SERVICE_TABLE_ENTRYW。
type serviceTableEntry struct {
	name *uint16
	proc uintptr
}

// AcquireSingleInstance 用命名互斥体保证同一时间只有一个实例在运行（F-808）。
//
// 返回的 release 函数必须在退出时调用（可 defer）。
// 若已有实例在运行，返回 ErrAlreadyRunning。
func AcquireSingleInstance(name string) (release func(), err error) {
	if strings.TrimSpace(name) == "" {
		name = serviceName
	}
	mutexName := `Local\` + name + `-singleton`
	p, err := syscall.UTF16PtrFromString(mutexName)
	if err != nil {
		return nil, fmt.Errorf("互斥体名编码失败: %w", err)
	}

	h, _, callErr := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(p)))
	if h == 0 {
		return nil, fmt.Errorf("创建互斥体失败: %v", callErr)
	}
	// CreateMutexW 在已存在同名互斥体时返回句柄并置 ERROR_ALREADY_EXISTS。
	if errno, ok := callErr.(syscall.Errno); ok && errno == syscall.Errno(errorAlreadyExists) {
		_, _, _ = procCloseHandle.Call(h)
		return nil, ErrAlreadyRunning
	}
	release = func() {
		if h != 0 {
			_, _, _ = procCloseHandle.Call(h)
			h = 0
		}
	}
	return release, nil
}

// ErrAlreadyRunning 表示已有实例在运行。
var ErrAlreadyRunning = errors.New("已有 usbbackup 实例在运行（单实例互斥体已被占用）")

// RunBody 是服务主体函数：ctx 被取消即表示收到停止指令。
type RunBody func(ctx context.Context) error

// serviceState 保存服务运行期状态。
type serviceState struct {
	mu      sync.Mutex
	status  serviceStatus
	handle  syscall.Handle
	cancel  context.CancelFunc
	done    chan struct{}
	body    RunBody
	bodyErr error
}

var current *serviceState

// RunAsService 以 Windows 服务方式运行，接管 SCM 的控制请求。
//
// 必须在服务控制管理器的启动路径下调用（即由 SCM 拉起本进程）。
// 直接双击运行会立即返回错误，这是 SCM 协议的正常行为。
func RunAsService(body RunBody) error {
	if body == nil {
		return errors.New("winsvc: 服务主体不能为空")
	}
	namePtr, err := syscall.UTF16PtrFromString(serviceName)
	if err != nil {
		return err
	}

	st := &serviceState{done: make(chan struct{}), body: body}
	current = st

	table := []serviceTableEntry{{name: namePtr, proc: syscall.NewCallback(serviceMain)}}
	r, _, callErr := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&table[0])))
	if r == 0 {
		return fmt.Errorf("StartServiceCtrlDispatcherW 失败（通常表示进程不是由 SCM 启动的）: %v", callErr)
	}
	<-st.done
	if st.bodyErr != nil {
		return st.bodyErr
	}
	return nil
}

// serviceMain 是 SCM 调用的入口，运行在 SCM 创建的线程上。
func serviceMain(argc uint32, argv uintptr) uintptr {
	st := current
	if st == nil {
		return 0
	}

	handlerPtr := syscall.NewCallback(serviceHandler)
	namePtr, _ := syscall.UTF16PtrFromString(serviceName)
	h, _, _ := procRegisterServiceCtrlHandlerExW.Call(
		uintptr(unsafe.Pointer(namePtr)), handlerPtr, 0,
	)
	if h == 0 {
		return 0
	}
	st.handle = syscall.Handle(h)

	st.setStatus(serviceStartPending, 0, 3000)

	ctx, cancel := context.WithCancel(context.Background())
	st.mu.Lock()
	st.cancel = cancel
	st.mu.Unlock()

	st.setStatus(serviceRunning, serviceAcceptStop|serviceAcceptShutdown, 0)

	// 服务主体在独立 goroutine 中运行，本线程只负责响应 SCM 控制。
	go func() {
		err := st.runBodySafely(ctx)
		st.mu.Lock()
		st.bodyErr = err
		st.mu.Unlock()
		st.setStatus(serviceStopPending, 0, 3000)
		st.setStatus(serviceStopped, 0, 0)
		close(st.done)
	}()

	// 阻塞直到服务主体结束：SCM 要求 serviceMain 在服务存活期间不返回。
	<-st.done
	return 0
}

// runBodySafely 调用服务主体并兜住 panic，避免把整个服务进程带崩。
func (s *serviceState) runBodySafely(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("服务主体 panic: %v", r)
		}
	}()
	return s.body(ctx)
}

// setStatus 向 SCM 上报状态。
func (s *serviceState) setStatus(state, accepted, waitHint uint32) {
	if s.handle == 0 {
		return
	}
	s.mu.Lock()
	s.status.serviceType = serviceWin32OwnProcess
	s.status.currentState = state
	s.status.controlsAccepted = accepted
	s.status.win32ExitCode = noError
	s.status.waitHint = waitHint
	st := s.status
	s.mu.Unlock()
	_, _, _ = procSetServiceStatus.Call(uintptr(s.handle), uintptr(unsafe.Pointer(&st)))
}

// serviceHandler 处理 SCM 控制请求（停止 / 关机 / 询问）。
func serviceHandler(ctrl, eventType uint32, eventData, context uintptr) uintptr {
	st := current
	switch ctrl {
	case serviceControlStop, serviceControlShutdown:
		if st != nil {
			st.setStatus(serviceStopPending, 0, 3000)
			st.mu.Lock()
			if st.cancel != nil {
				st.cancel()
			}
			st.mu.Unlock()
		}
	case serviceControlInterrog:
		if st != nil {
			st.mu.Lock()
			cur := st.status.currentState
			st.mu.Unlock()
			st.setStatus(cur, serviceAcceptStop|serviceAcceptShutdown, 0)
		}
	}
	return noError
}

// ---- 服务注册 / 卸载 / 控制（通过 sc.exe，需管理员权限）----

// scExitMessage 把 sc.exe 的常见退出码翻译成中文提示。
//
// 为什么不直接展示 sc.exe 的输出：它是本地化工具，在中文系统上输出 GBK 字节，
// 而本程序按 UTF-8 解码，直接转述会得到乱码。翻译退出码既准确又无编码问题。
func scExitMessage(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		switch ee.ExitCode() {
		case 5:
			return "权限不足，请以管理员身份运行"
		case 1056:
			return "服务已经在运行"
		case 1058:
			return "服务已被禁用"
		case 1060:
			return "服务未安装"
		case 1062:
			return "服务未在运行"
		case 1072:
			return "服务已被标记删除，请稍后重试"
		}
		return fmt.Sprintf("sc.exe 退出码 %d", ee.ExitCode())
	}
	return err.Error()
}

// asciiOnly 只保留纯 ASCII 行。
//
// sc.exe 的输出里，真正有用且与本机语言无关的信息（如 STATE : 4 RUNNING）都是 ASCII；
// 其余本地化文本按原样转述会乱码，这里直接丢弃。
func asciiOnly(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		ok := true
		for i := 0; i < len(line); i++ {
			if line[i] > 127 {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// Install 注册服务，binPath 指向当前可执行文件的 `run` 子命令。
//
// 只注册服务，不设置任何自启动之外的持久化，也不改注册表其它键。
func Install(displayName string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法确定可执行文件路径: %w", err)
	}
	if displayName == "" {
		displayName = "UsbBackUP - USB 自动备份与加密"
	}
	// sc.exe 要求选项形如 `name= value`，参数之间用空格分隔。
	args := []string{
		"create", serviceName,
		"binPath=", fmt.Sprintf("%q run --service", exe),
		"start=", "demand",
		"DisplayName=", displayName,
		"type=", "own",
	}
	if out, err := runSC(args...); err != nil {
		return fmt.Errorf("注册服务失败（需要管理员权限）: %v\n%s", err, out)
	}
	return nil
}

// Uninstall 停止并删除服务项。
func Uninstall() error {
	_, _ = runSC("stop", serviceName)
	if out, err := runSC("delete", serviceName); err != nil {
		return fmt.Errorf("删除服务失败（需要管理员权限）: %v\n%s", err, out)
	}
	return nil
}

// Start 启动服务。
func Start() error {
	if out, err := runSC("start", serviceName); err != nil {
		return fmt.Errorf("启动服务失败（需要管理员权限）: %v\n%s", err, out)
	}
	return nil
}

// Stop 停止服务。
func Stop() error {
	if out, err := runSC("stop", serviceName); err != nil {
		return fmt.Errorf("停止服务失败（需要管理员权限）: %v\n%s", err, out)
	}
	return nil
}

// Status 查询服务状态文本。
func Status() (string, error) {
	out, err := runSC("query", serviceName)
	if err != nil {
		return "", fmt.Errorf("查询服务状态失败：%s", scExitMessage(err))
	}
	// 只回传 ASCII 行（STATE 行等），避免本地化文本乱码。
	return asciiOnly(out), nil
}

// runSC 调用 sc.exe 并返回合并输出。
func runSC(args ...string) (string, error) {
	cmd := exec.Command("sc.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
