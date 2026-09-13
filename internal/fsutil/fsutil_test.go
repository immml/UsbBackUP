package fsutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsSubPath(t *testing.T) {
	root := `E:\`
	cases := []struct {
		parent, child string
		want          bool
	}{
		{root, `E:\`, true},       // 相等（卷根）
		{root, `E:\backup`, true}, // 卷根的直接子项
		{root, `E:\a\b\c`, true},  // 深层子项
		{root, `e:\A\B`, true},    // 大小写不敏感
		{root, `F:\x`, false},     // 另一个卷
		{`E:\a`, `E:\a\b`, true},  // 普通目录的子项
		{`E:\a`, `E:\ab`, false},  // 前缀相同但不是子项（关键回归点）
		{`E:\a`, `E:\a`, true},    // 相等
		{`E:\a\b`, `E:\a`, false}, // 反向不是子项
		{"", `E:\a`, false},       // 空参数
		{`E:\a`, "", false},       // 空参数
		{`C:\tmp\out`, `C:\tmp\out2`, false},
	}
	for _, tc := range cases {
		if got := IsSubPath(tc.parent, tc.child); got != tc.want {
			t.Errorf("IsSubPath(%q, %q) = %v, want %v", tc.parent, tc.child, got, tc.want)
		}
	}
}

func TestSameVolume(t *testing.T) {
	if !SameVolume(`E:\a\b`, `E:\c`) {
		t.Fatal("同卷应判定为 true")
	}
	if SameVolume(`E:\a`, `F:\a`) {
		t.Fatal("不同卷应判定为 false")
	}
	if SameVolume("", `E:\a`) {
		t.Fatal("空路径应判定为 false")
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"normal":      "normal",
		`a/b\c:d*e?f`: "a_b_c_d_e_f",
		"  spaced  ":  "spaced",
		"trailing...": "trailing",
		"CON":         "_CON",
		"nul.txt":     "_nul.txt",
		"中文卷标":        "中文卷标",
	}
	for in, want := range cases {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
	// 控制字符应被替换。
	if got := SanitizeName("a\x00b\x1fc"); strings.ContainsAny(got, "\x00\x1f") {
		t.Errorf("控制字符未被清除: %q", got)
	}
	// 纯非法输入：所有非法字符被替换为下划线，结果必须是可安全使用的名字。
	if got := SanitizeName("///"); strings.ContainsAny(got, `/\:*?"<>|`) {
		t.Errorf("净化后仍含非法字符: %q", got)
	}
	// 超长输入应被截断。
	long := SanitizeName(strings.Repeat("x", 400))
	if len([]rune(long)) > 121 {
		t.Errorf("超长输入未截断: %d", len([]rune(long)))
	}
}

func TestVolumeRoot(t *testing.T) {
	if got := VolumeRoot(`E:\a\b`); got != `E:\` {
		t.Fatalf("VolumeRoot = %q, want %q", got, `E:\`)
	}
	if got := VolumeRoot("relative/path"); got != "" {
		t.Fatalf("相对路径应返回空串，实际 %q", got)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0:             "0 B",
		1023:          "1023 B",
		1024:          "1.00 KiB",
		1024 * 1024:   "1.00 MiB",
		10 << 30:      "10.00 GiB",
		3 * (1 << 40): "3.00 TiB",
	}
	for in, want := range cases {
		if got := HumanBytes(in); got != want {
			t.Errorf("HumanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestLongPath(t *testing.T) {
	short := `E:\a\b.txt`
	if got := LongPath(short); got != short {
		t.Fatalf("短路径不应加前缀，实际 %q", got)
	}
	// 构造超长路径。
	long := `C:\` + strings.Repeat("verylongdir\\", 30) + "file.txt"
	got := LongPath(long)
	if !strings.HasPrefix(got, `\\?\`) {
		t.Fatalf("超长路径应加 \\\\?\\ 前缀，实际 %q", got)
	}
	// 已带前缀的应原样返回，避免重复叠加。
	if again := LongPath(got); again != got {
		t.Fatalf("重复调用不应叠加前缀: %q", again)
	}
}

func TestEnsureLongPathParent(t *testing.T) {
	dir := t.TempDir()
	if got := EnsureLongPathParent(dir); got == "" {
		t.Fatal("返回空路径")
	}
	if _, err := os.Stat(filepath.Clean(dir)); err != nil {
		t.Fatalf("目录应存在: %v", err)
	}
}
