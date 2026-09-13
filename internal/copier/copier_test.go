package copier

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetDir(t *testing.T) {
	got, err := TargetDir(`E:\`, "backup")
	if err != nil {
		t.Fatalf("TargetDir 报错: %v", err)
	}
	if want := filepath.FromSlash(`E:\backup`); got != want {
		t.Fatalf("TargetDir = %q, want %q", got, want)
	}
	// 空子目录名应兜底为 backup。
	got, err = TargetDir(`E:\`, "")
	if err != nil {
		t.Fatalf("空子目录名应兜底: %v", err)
	}
	if filepath.Base(got) != "backup" {
		t.Fatalf("兜底子目录名错误: %q", got)
	}
	// 空卷根应报错。
	if _, err := TargetDir("", "backup"); err == nil {
		t.Fatal("空卷根应报错")
	}

	// 非法子目录名（含分隔符 / 盘符 / 穿越）一律拒绝。
	bad := []string{"..", ".", `a\b`, "a/b", "C:", "a:b", `a?b`, `a*b`, `a"b`, "a<b", "a|b", "dir."}
	for _, sub := range bad {
		if got, err := TargetDir(`E:\`, sub); err == nil {
			t.Fatalf("TargetDir(%q) 期望被拒绝，实际得到 %q", sub, got)
		}
	}
}

func TestCheckRejectsSelfCopy(t *testing.T) {
	// 情形 1：源目录位于回写目标之内 → 拒绝（F-406，防套娃）。
	base := t.TempDir()
	srcInsideTarget := filepath.Join(base, "backup", "inner")
	if err := os.MkdirAll(srcInsideTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(Options{SourceDir: srcInsideTarget, DestRoot: base, SubDir: "backup"}); err == nil {
		t.Fatal("源目录位于目标目录之内时应拒绝")
	} else if !strings.Contains(err.Error(), "自复制") {
		t.Fatalf("错误信息应说明是自复制: %v", err)
	}

	// 情形 2：回写目标位于源目录之内 → 同样拒绝。
	srcDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(srcDir, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(Options{SourceDir: srcDir, DestRoot: srcDir, SubDir: "inner"}); err == nil {
		t.Fatal("目标位于源之内时应拒绝")
	}

	// 情形 3：源目录恰好等于目标目录 → 拒绝。
	eq := t.TempDir()
	if _, err := Check(Options{SourceDir: eq, DestRoot: filepath.Dir(eq), SubDir: filepath.Base(eq)}); err == nil {
		t.Fatal("源与目标相同时应拒绝")
	}
}

func TestCheckRequiresExistingSource(t *testing.T) {
	if _, err := Check(Options{SourceDir: "", DestRoot: `E:\`}); err == nil {
		t.Fatal("空源目录应报错")
	}
	if _, err := Check(Options{SourceDir: filepath.Join(t.TempDir(), "不存在"), DestRoot: `E:\`}); err == nil {
		t.Fatal("不存在的源目录应报错")
	}
	// 传入文件（非目录）也应报错。
	f := filepath.Join(t.TempDir(), "afile.txt")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(Options{SourceDir: f, DestRoot: `E:\`}); err == nil {
		t.Fatal("源为普通文件时应报错")
	}
}

func TestCheckAcceptsDisjointDirs(t *testing.T) {
	// 同卷但互不相交的目录应通过（这才是 --allow-fixed 验证场景的常用形态）。
	src := t.TempDir()
	dst := t.TempDir()
	got, err := Check(Options{SourceDir: src, DestRoot: dst, SubDir: "backup"})
	if err != nil {
		t.Fatalf("互不相交的目录应通过校验: %v", err)
	}
	if !strings.HasSuffix(got, "backup") {
		t.Fatalf("目标目录不正确: %q", got)
	}
	// 跨卷同样是允许的。
	if _, err := Check(Options{SourceDir: src, DestRoot: `Z:\`, SubDir: "backup"}); err != nil {
		t.Fatalf("跨卷目标应通过校验: %v", err)
	}
}

func TestCopyRejectsUncheckedOptions(t *testing.T) {
	// 未通过 Check 的参数必须直接失败，不能静默成功。
	if _, err := Copy(context.Background(), Options{}); err == nil {
		t.Fatal("空参数应返回错误")
	}
}
