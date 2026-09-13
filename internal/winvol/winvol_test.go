//go:build windows

package winvol

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeRoot(t *testing.T) {
	ok := map[string]string{
		"e":    `E:\`,
		"e:":   `E:\`,
		`e:\`:  `E:\`,
		"E:/":  `E:\`,
		" e: ": `E:\`,
		"D":    `D:\`,
	}
	for in, want := range ok {
		got, err := NormalizeRoot(in)
		if err != nil {
			t.Fatalf("NormalizeRoot(%q) 报错: %v", in, err)
		}
		if got != want {
			t.Fatalf("NormalizeRoot(%q) = %q, want %q", in, got, want)
		}
	}
	bad := []string{"", "AB", "1:", `\\server\share`, "盘符", "e:\\extra"}
	for _, in := range bad {
		if got, err := NormalizeRoot(in); err == nil {
			t.Fatalf("NormalizeRoot(%q) 期望报错，实际 %q", in, got)
		}
	}
}

func TestDriveTypeName(t *testing.T) {
	if DriveTypeName(DriveRemovable) != "可移动" {
		t.Fatal("可移动类型名不符")
	}
	if DriveTypeName(DriveFixed) != "固定磁盘" {
		t.Fatal("固定磁盘类型名不符")
	}
	if !strings.Contains(DriveTypeName(999), "999") {
		t.Fatal("未知类型应回显编号")
	}
}

func TestEvaluateGate(t *testing.T) {
	const gib = int64(1024 * 1024 * 1024)
	base := Volume{Root: `E:\`, Removable: true, Ready: true, TotalBytes: 64 * gib}

	cases := []struct {
		name      string
		used      int64
		threshold int64
		wantGo    bool
	}{
		{"零占用", 0, 10 * gib, true},
		{"阈值内", 9 * gib, 10 * gib, true},
		{"恰好等于阈值", 10 * gib, 10 * gib, true},
		{"超阈值一字节", 10*gib + 1, 10 * gib, false},
		{"远超阈值", 40 * gib, 10 * gib, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := base
			v.UsedBytes = tc.used
			v.FreeBytes = v.TotalBytes - tc.used
			p := EvaluateGate(v, tc.threshold, 0)
			if p.Proceed != tc.wantGo {
				t.Fatalf("used=%d threshold=%d: Proceed=%v want %v（理由：%s）",
					tc.used, tc.threshold, p.Proceed, tc.wantGo, p.Reason)
			}
			if p.Reason == "" {
				t.Fatal("判定理由不应为空")
			}
		})
	}
}

func TestEvaluateGateConservativeOnBadNumbers(t *testing.T) {
	gib := int64(1024 * 1024 * 1024)

	v := Volume{Root: `E:\`, Removable: true, Ready: true, TotalBytes: 64 * gib, UsedBytes: -1}
	if EvaluateGate(v, 10*gib, 0).Proceed {
		t.Fatal("已占用容量为负数时应保守跳过")
	}

	notReady := Volume{Root: `E:\`, Removable: true, Ready: false}
	if EvaluateGate(notReady, 10*gib, 0).Proceed {
		t.Fatal("卷未就绪时应保守跳过")
	}

	zeroTotal := Volume{Root: `E:\`, Removable: true, Ready: true, TotalBytes: 0}
	if EvaluateGate(zeroTotal, 10*gib, 0).Proceed {
		t.Fatal("总容量为 0 时应保守跳过")
	}

	// 上限比的是**待打包的数据量**（已占用），不是卷总容量：
	// 这块盘容量 128 GiB、已占用 100 GiB，超过 64 GiB 上限 → 跳过。
	overMax := Volume{Root: `E:\`, Removable: true, Ready: true, TotalBytes: 128 * gib, UsedBytes: 100 * gib}
	if EvaluateGate(overMax, 200*gib, 64*gib).Proceed {
		t.Fatal("待打包数据量超过上限时应跳过")
	}
}

func TestFreeSpaceEnough(t *testing.T) {
	v := Volume{Ready: true, FreeBytes: 1000}
	if !FreeSpaceEnough(v, 1000, 0) {
		t.Fatal("刚好够用应通过")
	}
	if FreeSpaceEnough(v, 1000, 5) {
		t.Fatal("含 5% 余量时 1000 字节应不足")
	}
	if !FreeSpaceEnough(v, 900, 5) {
		t.Fatal("900 + 5% = 945 应通过")
	}
	if FreeSpaceEnough(v, -1, 0) {
		t.Fatal("需求字节为负应返回 false")
	}
	if FreeSpaceEnough(Volume{Ready: false, FreeBytes: 1000}, 1, 0) {
		t.Fatal("未就绪应返回 false")
	}
}

func TestLabelOrFallback(t *testing.T) {
	if got := LabelOrFallback(Volume{Root: `E:\`, Label: " MYUSB "}); got != "MYUSB" {
		t.Fatalf("卷标应被裁剪空格，实际 %q", got)
	}
	if got := LabelOrFallback(Volume{Root: `E:\`}); got != "VOL_E" {
		t.Fatalf("空卷标应兜底为 VOL_E，实际 %q", got)
	}
	if got := LabelOrFallback(Volume{Root: ""}); got != "VOL_UNKNOWN" {
		t.Fatalf("无盘符应兜底为 VOL_UNKNOWN，实际 %q", got)
	}
}

func TestQueryOnSystemDrive(t *testing.T) {
	// 系统盘必然是固定磁盘，应返回 ErrNotRemovable。
	v, err := Query("C:")
	if err == nil {
		t.Fatalf("C: 不应被判定为可移动卷")
	}
	if !errors.Is(err, ErrNotRemovable) {
		t.Fatalf("期望 ErrNotRemovable，实际 %v", err)
	}
	if v.DriveType == DriveUnknown {
		t.Fatal("卷类型不应为未知")
	}
	if v.Removable {
		t.Fatal("Removable 应为 false")
	}
	// 回归防护：非可移动卷同样要读到容量与就绪状态（否则 list --all 全是 0）。
	if !v.Ready {
		t.Fatal("系统盘应处于可访问（就绪）状态")
	}
	if v.TotalBytes <= 0 {
		t.Fatalf("系统盘总容量应大于 0，实际 %d", v.TotalBytes)
	}
	if v.UsedBytes <= 0 || v.FreeBytes <= 0 {
		t.Fatalf("已占用/剩余容量应大于 0：used=%d free=%d", v.UsedBytes, v.FreeBytes)
	}
	if v.UsedBytes+v.FreeBytes != v.TotalBytes {
		t.Fatalf("used + free 应等于 total：%d + %d != %d", v.UsedBytes, v.FreeBytes, v.TotalBytes)
	}
	if v.FileSystem == "" {
		t.Fatal("文件系统名不应为空")
	}
}

func TestRootsAndRemovableRoots(t *testing.T) {
	roots, err := Roots()
	if err != nil {
		t.Fatalf("Roots 失败: %v", err)
	}
	if len(roots) == 0 {
		t.Fatal("至少应枚举到一个盘符")
	}
	for _, r := range roots {
		if len(r) != 3 || r[1] != ':' || r[2] != '\\' {
			t.Fatalf("盘符格式异常: %q", r)
		}
	}
	// 只要求不报错；多数 CI/开发机上没有可移动介质。
	if _, err := RemovableRoots(); err != nil {
		t.Fatalf("RemovableRoots 失败: %v", err)
	}
}

func TestGateMaxTotalComparesUsedNotCapacity(t *testing.T) {
	// 一块 64 GiB 的 U 盘只用了 500 MiB：应当放行。
	// 若上限误与"卷总容量"比较，这里会被错误跳过（回归测试）。
	v := Volume{
		Root:       `E:\`,
		Ready:      true,
		TotalBytes: 64 * 1024 * 1024 * 1024,
		UsedBytes:  500 * 1024 * 1024,
		FreeBytes:  64*1024*1024*1024 - 500*1024*1024,
	}
	p := EvaluateGate(v, 10*1024*1024*1024, 10*1024*1024*1024)
	if !p.Proceed {
		t.Fatalf("已占用 500MiB 的 64GiB 盘应放行，实际跳过：%s", p.Reason)
	}

	// 已占用超过上限 → 跳过。
	v.UsedBytes = 12 * 1024 * 1024 * 1024
	p = EvaluateGate(v, 20*1024*1024*1024, 10*1024*1024*1024)
	if p.Proceed {
		t.Fatal("已占用 12GiB 超过 10GiB 上限时应跳过")
	}
	if !strings.Contains(p.Reason, "待打包数据量") {
		t.Fatalf("跳过原因应指向待打包数据量，实际：%s", p.Reason)
	}

	// 上限为 0 表示不限制：大容量小占用的盘同样放行。
	p = EvaluateGate(v, 20*1024*1024*1024, 0)
	if !p.Proceed {
		t.Fatalf("上限为 0（不限制）时应放行，实际：%s", p.Reason)
	}
}
