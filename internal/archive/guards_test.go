package archive

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestArchiveName(t *testing.T) {
	root := filepath.FromSlash(`E:\`)

	ok := []struct {
		full string
		want string
	}{
		{filepath.Join(root, "a.txt"), "a.txt"},
		{filepath.Join(root, "dir", "b.txt"), "dir/b.txt"},
		{filepath.Join(root, "dir", "sub", "c.bin"), "dir/sub/c.bin"},
	}
	for _, tc := range ok {
		got, err := ArchiveName(root, tc.full)
		if err != nil {
			t.Fatalf("ArchiveName(%q) 意外报错: %v", tc.full, err)
		}
		if got != tc.want {
			t.Fatalf("ArchiveName(%q) = %q, want %q", tc.full, got, tc.want)
		}
	}

	bad := []string{
		"",
		".",
		filepath.FromSlash(`C:\Windows\notepad.exe`), // 另一个卷 → Rel 失败
		"..",
	}
	for _, b := range bad {
		if got, err := ArchiveName(root, b); err == nil {
			t.Fatalf("ArchiveName(%q) 期望报错，实际得到 %q", b, got)
		}
	}

	// 含 ".." 的输入在 Windows 上会被 Clean 归一到卷根之内（无法越过卷根），
	// 因此这里断言的是"结果必须安全"，而不是"必须报错"。
	for _, in := range []string{
		filepath.FromSlash(`E:\..\..\Windows\system32\cmd.exe`),
		filepath.FromSlash(`E:\a\..\..\..\b\c.txt`),
	} {
		got, err := ArchiveName(root, in)
		if err != nil {
			continue // 报错也是可接受的处置
		}
		if strings.HasPrefix(got, "../") || strings.Contains(got, "/../") ||
			strings.HasPrefix(got, "/") || filepath.IsAbs(got) {
			t.Fatalf("ArchiveName(%q) 返回了不安全路径 %q", in, got)
		}
		if len(got) >= 2 && got[1] == ':' {
			t.Fatalf("ArchiveName(%q) 返回了含盘符的路径 %q", in, got)
		}
	}
}

func TestSafeExtractPathRejectsZipSlip(t *testing.T) {
	dest := filepath.FromSlash(`C:\tmp\out`)

	unsafe := []string{
		"../evil.txt",
		"..\\evil.txt",
		"../../evil.txt",
		"a/../../evil.txt",
		"/abs/evil.txt",
		"\\\\server\\share\\evil.txt",
		"C:/Windows/evil.txt",
		`C:\Windows\evil.txt`,
		"file.txt:stream",
		"..",
		".",
		"",
		"a/b/../../../evil.txt",
		"~/evil.txt",
	}
	for _, name := range unsafe {
		if got, err := SafeExtractPath(dest, name); err == nil {
			t.Fatalf("SafeExtractPath(%q) 期望被拒绝，实际放行到 %q", name, got)
		}
	}

	safe := map[string]string{
		"a.txt":         filepath.Join(dest, "a.txt"),
		"dir/b.txt":     filepath.Join(dest, "dir", "b.txt"),
		"./dir/c.txt":   filepath.Join(dest, "dir", "c.txt"),
		"dir//d.txt":    filepath.Join(dest, "dir", "d.txt"),
		"a/./b/./c.txt": filepath.Join(dest, "a", "b", "c.txt"),
		"中文目录/文件.txt":   filepath.Join(dest, "中文目录", "文件.txt"),
	}
	for name, want := range safe {
		got, err := SafeExtractPath(dest, name)
		if err != nil {
			t.Fatalf("SafeExtractPath(%q) 意外报错: %v", name, err)
		}
		if !strings.EqualFold(got, want) {
			t.Fatalf("SafeExtractPath(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestSafeExtractPathResultStaysInsideDest(t *testing.T) {
	dest := filepath.FromSlash(`C:\tmp\out`)
	// 逐条把安全条目解析出来，再次确认结果确实位于目标目录之内。
	for _, name := range []string{"a/b.txt", "x.txt", "deep/er/f.txt"} {
		got, err := SafeExtractPath(dest, name)
		if err != nil {
			t.Fatalf("意外报错: %v", err)
		}
		rel, err := filepath.Rel(filepath.Clean(dest), got)
		if err != nil {
			t.Fatalf("Rel 失败: %v", err)
		}
		if strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			t.Fatalf("解析结果逃出目标目录: %q", got)
		}
	}
}

func TestIsExcluded(t *testing.T) {
	yes := []string{
		"System Volume Information", "$RECYCLE.BIN", "pagefile.sys",
		"hiberfil.sys", "swapfile.sys", "found.000", "Thumbs.db",
		"system volume information",
	}
	for _, n := range yes {
		if !IsExcluded(n, nil) {
			t.Fatalf("%q 应被排除", n)
		}
	}
	no := []string{"我的文档", "photo.jpg", "config.json"}
	for _, n := range no {
		if IsExcluded(n, nil) {
			t.Fatalf("%q 不应被排除", n)
		}
	}
	if !IsExcluded("debug.tmp", []string{"*.tmp"}) {
		t.Fatal("自定义通配排除未生效")
	}
	if !IsExcluded("secret.txt", []string{"secret.txt"}) {
		t.Fatal("自定义精确排除未生效")
	}
}

func TestShouldStore(t *testing.T) {
	for _, n := range []string{"a.zip", "b.7z", "c.JPG", "d.mp4", "e.pdf", "f.docx"} {
		if !ShouldStore(n) {
			t.Fatalf("%q 应使用 Store", n)
		}
	}
	for _, n := range []string{"a.txt", "b.log", "c.json", "d.sql"} {
		if ShouldStore(n) {
			t.Fatalf("%q 不应使用 Store", n)
		}
	}
}

func TestCheckSourceGuard(t *testing.T) {
	src := filepath.FromSlash(`E:\`)

	// 输出在源之外 → 允许。
	for _, out := range []string{filepath.FromSlash(`C:\Users\x\AppData\Local\Temp\backup`), filepath.FromSlash(`D:\backup`)} {
		if err := CheckSourceGuard(src, out); err != nil {
			t.Fatalf("CheckSourceGuard(%q) 期望通过，实际 %v", out, err)
		}
	}
	// 输出等于源或在源之内 → 拒绝（防递归套娃）。
	for _, out := range []string{
		filepath.FromSlash(`E:\`),
		filepath.FromSlash(`E:\backup`),
		filepath.FromSlash(`E:\a\b\c`),
	} {
		if err := CheckSourceGuard(src, out); err == nil {
			t.Fatalf("CheckSourceGuard(%q) 期望被拒绝", out)
		}
	}
	if err := CheckSourceGuard("", ""); err == nil {
		t.Fatal("空参数应被拒绝")
	}
}
