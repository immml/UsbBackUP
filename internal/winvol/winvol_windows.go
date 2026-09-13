//go:build windows

// Package winvol 提供 Windows 卷信息查询与容量门控。
//
// 对应需求 F-301 ~ F-306。全部为**只读**查询，不写注册表、不修改卷状态。
//
// 实现说明：直接调用 kernel32.dll，不引入任何第三方绑定库；
// 也刻意不使用 WMI（需 COM 初始化，在服务环境下易挂，见决策 D-01）。
package winvol

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// Windows 卷类型常量（GetDriveTypeW 返回值）。
const (
	DriveUnknown   = 0
	DriveNoRootDir = 1
	DriveRemovable = 2
	DriveFixed     = 3
	DriveRemote    = 4
	DriveCDROM     = 5
	DriveRAMDisk   = 6
)

// 文件系统标志位（GetVolumeInformationW 的 lpFileSystemFlags）。
const (
	fsCaseSensitiveSearch = 0x00000001
	fsUnicodeOnDisk       = 0x00000004
)

// 错误。
var (
	// ErrNotRemovable 表示该盘符不是可移动卷（F-301）。
	ErrNotRemovable = errors.New("该盘符不是可移动卷（非 DRIVE_REMOVABLE）")
	// ErrNotReady 表示卷尚未挂载完成或不可访问（F-305）。
	ErrNotReady = errors.New("卷尚未就绪或不可访问")
	// ErrQueryFailed 表示底层 API 调用失败。
	ErrQueryFailed = errors.New("卷信息查询失败")
)

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procGetDriveTypeW        = kernel32.NewProc("GetDriveTypeW")
	procGetDiskFreeSpaceExW  = kernel32.NewProc("GetDiskFreeSpaceExW")
	procGetVolumeInformation = kernel32.NewProc("GetVolumeInformationW")
	procGetLogicalDrives     = kernel32.NewProc("GetLogicalDrives")
)

// Volume 描述一个卷的只读信息快照。
//
// 审计与产物命名只会用到 Label 与 SerialNumber；容量字段用于门控判定。
// 本结构不含任何用户内容，可安全写入日志。
type Volume struct {
	// Root 是卷根路径，形如 `E:\`。
	Root string
	// DriveType 是 GetDriveTypeW 返回值。
	DriveType uint32
	// Removable 表示是否为 DRIVE_REMOVABLE（F-301）。
	Removable bool
	// Ready 表示卷当前可访问（F-305）。
	Ready bool
	// Label 是卷标，空卷标由调用方兜底为 VOL_<盘符>（F-303）。
	Label string
	// FileSystem 是文件系统名，如 NTFS / exFAT / FAT32（F-303）。
	FileSystem string
	// SerialNumber 是卷序列号，用于产物命名与审计（F-303 / F-107）。
	SerialNumber uint32
	// TotalBytes 是卷总容量。
	TotalBytes int64
	// FreeBytes 是剩余可用容量（TotalNumberOfFreeBytes）。
	FreeBytes int64
	// UsedBytes = TotalBytes - FreeBytes，即"已占用容量"（F-302）。
	UsedBytes int64
}

// DriveTypeName 返回卷类型的可读名。
func DriveTypeName(t uint32) string {
	switch t {
	case DriveUnknown:
		return "未知"
	case DriveNoRootDir:
		return "无根目录"
	case DriveRemovable:
		return "可移动"
	case DriveFixed:
		return "固定磁盘"
	case DriveRemote:
		return "网络驱动器"
	case DriveCDROM:
		return "光驱"
	case DriveRAMDisk:
		return "内存盘"
	default:
		return fmt.Sprintf("未知(%d)", t)
	}
}

// NormalizeRoot 把各种写法的盘符统一为 `X:\` 形式。
// 接受 "e" / "e:" / "e:\" / "E:/" 等输入。
func NormalizeRoot(drive string) (string, error) {
	s := strings.TrimSpace(drive)
	if s == "" {
		return "", errors.New("盘符为空")
	}
	// 先去掉尾部所有分隔符，再去掉冒号，避免 "e:\" 被误判为长度 3。
	s = strings.TrimRight(s, `\/`)
	s = strings.TrimSuffix(s, ":")
	if len(s) != 1 || !isAlpha(s[0]) {
		return "", fmt.Errorf("无法识别的盘符写法 %q（应为 e / e: / e:\\ 之一）", drive)
	}
	return strings.ToUpper(s) + `:\`, nil
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// DriveType 返回指定卷的 GetDriveTypeW 结果。
func DriveType(root string) (uint32, error) {
	p, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return 0, fmt.Errorf("%w: 路径编码失败: %v", ErrQueryFailed, err)
	}
	r, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(p)))
	return uint32(r), nil
}

// Query 查询单个卷信息。
//
// 无论卷是否为可移动介质，都会尽力读取容量与卷标：这些信息对诊断与审计
// 同样有价值（例如 `usbbackup list --all`）。非可移动卷返回 ErrNotRemovable，
// 调用方据此判定"非候选"（F-301）。
func Query(root string) (Volume, error) {
	norm, err := NormalizeRoot(root)
	if err != nil {
		return Volume{}, err
	}
	v := Volume{Root: norm}

	dt, err := DriveType(norm)
	if err != nil {
		return v, err
	}
	v.DriveType = dt
	v.Removable = dt == DriveRemovable

	spaceErr := fillDiskSpace(&v)
	v.Ready = spaceErr == nil
	fillVolumeInfo(&v)

	if !v.Removable {
		return v, ErrNotRemovable
	}
	if spaceErr != nil {
		// 可移动卷但读不到容量：通常是介质未插入或卷未挂载完成（F-305）。
		return v, fmt.Errorf("%w: %v", ErrNotReady, spaceErr)
	}
	return v, nil
}

// fillDiskSpace 读取总容量与剩余容量，推导已占用容量（F-302）。
func fillDiskSpace(v *Volume) error {
	p, err := syscall.UTF16PtrFromString(v.Root)
	if err != nil {
		return err
	}
	var freeToCaller, total, totalFree uint64
	r, _, callErr := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&freeToCaller)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return fmt.Errorf("%w: GetDiskFreeSpaceExW: %v", ErrQueryFailed, callErr)
		}
		return fmt.Errorf("%w: GetDiskFreeSpaceExW 返回失败", ErrQueryFailed)
	}
	if total == 0 {
		return fmt.Errorf("%w: 卷报告总容量为 0", ErrNotReady)
	}

	// 用 TotalNumberOfFreeBytes 而非 FreeBytesAvailable：
	// 后者受配额限制，前者才是"物理剩余"。已占用容量按需求定义为 总容量 - 剩余容量。
	v.TotalBytes = int64(total)
	v.FreeBytes = int64(totalFree)
	used := int64(total) - int64(totalFree)
	if used < 0 {
		// 数值异常一律保守处理，由上层跳过该盘（F-304）。
		used = -1
	}
	v.UsedBytes = used
	return nil
}

// fillVolumeInfo 读取卷标、文件系统与序列号（F-303）。失败时静默保留零值。
func fillVolumeInfo(v *Volume) {
	p, err := syscall.UTF16PtrFromString(v.Root)
	if err != nil {
		return
	}
	labelBuf := make([]uint16, 256)
	fsBuf := make([]uint16, 256)
	var serial, maxComponent, flags uint32

	r, _, _ := procGetVolumeInformation.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&labelBuf[0])), uintptr(len(labelBuf)),
		uintptr(unsafe.Pointer(&serial)),
		uintptr(unsafe.Pointer(&maxComponent)),
		uintptr(unsafe.Pointer(&flags)),
		uintptr(unsafe.Pointer(&fsBuf[0])), uintptr(len(fsBuf)),
	)
	if r == 0 {
		return
	}
	v.Label = syscall.UTF16ToString(labelBuf)
	v.FileSystem = syscall.UTF16ToString(fsBuf)
	v.SerialNumber = serial
}

// Policy 描述容量门控的判定结果（F-304）。
type Policy struct {
	// Proceed 为 true 表示允许对该卷执行整盘打包。
	Proceed bool
	// Reason 是人类可读的判定理由，写入日志与审计。
	Reason string
}

// EvaluateGate 执行容量门控：已占用容量 > 阈值 → 跳过（F-304）。
//
// 阈值单位为字节。`maxTotalBytes` 为 0 表示不限制整盘总体积。
// 任何数值异常都返回 Proceed=false（保守优先）。
func EvaluateGate(v Volume, thresholdBytes, maxTotalBytes int64) Policy {
	if !v.Ready {
		return Policy{Proceed: false, Reason: "卷未就绪，保守跳过"}
	}
	if v.UsedBytes < 0 {
		return Policy{Proceed: false, Reason: "已占用容量读数异常（负数），保守跳过"}
	}
	if v.TotalBytes <= 0 {
		return Policy{Proceed: false, Reason: "总容量读数异常，保守跳过"}
	}
	if v.UsedBytes > thresholdBytes {
		return Policy{Proceed: false, Reason: fmt.Sprintf("已占用容量超过阈值，按配置跳过整盘打包")}
	}
	if maxTotalBytes > 0 && v.UsedBytes > maxTotalBytes {
		// 比较对象是**待打包的数据量**（已占用容量），不是卷总容量。
		//
		// 若拿卷总容量来比，一块 64 GiB 的 U 盘哪怕只用了 500 MiB 也会被跳过，
		// 等于把"打包体积上限"误变成"介质容量上限"，与意图完全相反。
		return Policy{Proceed: false, Reason: "待打包数据量超过上限，按配置跳过整盘打包"}
	}
	return Policy{Proceed: true, Reason: "已占用容量在阈值以内，执行整盘打包"}
}

// LabelOrFallback 返回卷标；卷标为空或净化后为空时返回 `VOL_<盘符>`
// 形态的兜底名（F-303 / F-602）。
func LabelOrFallback(v Volume) string {
	l := strings.TrimSpace(v.Label)
	if l != "" {
		return l
	}
	letter := strings.TrimSuffix(v.Root, `:\`)
	if letter == "" {
		return "VOL_UNKNOWN"
	}
	return "VOL_" + strings.ToUpper(letter)
}

// FreeSpaceEnough 判断目标卷剩余空间是否足够写入 need 字节，
// 并额外预留 marginPercent 百分比余量（F-306）。
func FreeSpaceEnough(v Volume, need int64, marginPercent int) bool {
	if !v.Ready || v.FreeBytes <= 0 || need < 0 {
		return false
	}
	if marginPercent < 0 {
		marginPercent = 0
	}
	required := need + need*int64(marginPercent)/100
	return v.FreeBytes >= required
}

// LogicalDrives 返回当前存在的盘符位掩码（bit0 = A:），对应 GetLogicalDrives。
//
// 这是轮询兜底与启动扫描的基础原语（F-103 / F-105）。只读查询，无副作用。
func LogicalDrives() (uint32, error) {
	r, _, callErr := procGetLogicalDrives.Call()
	if r == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return 0, fmt.Errorf("%w: GetLogicalDrives: %v", ErrQueryFailed, callErr)
		}
		return 0, fmt.Errorf("%w: GetLogicalDrives 返回 0", ErrQueryFailed)
	}
	return uint32(r), nil
}

// Roots 返回当前所有盘符的卷根列表，形如 ["C:\\", "D:\\", "E:\\"]。
func Roots() ([]string, error) {
	mask, err := LogicalDrives()
	if err != nil {
		return nil, err
	}
	var out []string
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		out = append(out, fmt.Sprintf("%c:\\", 'A'+i))
	}
	return out, nil
}

// RemovableRoots 只返回类型为 DRIVE_REMOVABLE 的卷根。
// 这是轮询差分与启动扫描的候选集来源（F-103 / F-105）。
//
// 注意：此处只做类型判定，不读取容量，避免对未插入介质的读卡器槽位做多余 IO。
func RemovableRoots() ([]string, error) {
	roots, err := Roots()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range roots {
		dt, err := DriveType(r)
		if err != nil || dt != DriveRemovable {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}
