package copier

import (
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
	// 源目录位于目标盘之内 → 必须拒绝（F-406，防套娃）。
	src := filepath.FromSlash(`E:\mybackup`)

	if _, err := Check(Options{SourceDir: src, DestRoot: `E:\`, SubDir: "backup"}); err == nil {
		t.Fatal("源目录与目标在同一卷时应拒绝")
	} else if !strings.Contains(err.Error(), "自复制") {
		t.Fatalf("错误信息应说明是自复制: %v", err)
	}

	// 目标目录位于源目录之内 → 同样拒绝。
	srcDir := t.TempDir()
	nested := filepath.Join(srcDir, "inner")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(Options{SourceDir: srcDir, DestRoot: srcDir, SubDir: "inner"}); err == nil {
		t.Fatal("目标位于源之内时应拒绝")
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

func TestCheckAcceptsCrossVolume(t *testing.T) {
	src := t.TempDir()
	// 用不存在的目标卷只是进行字符串级校验，Check 不访问目标卷。
	got, err := Check(Options{SourceDir: src, DestRoot: `Z:\`, SubDir: "backup"})
	if err != nil {
		t.Fatalf("跨卷源目录应通过校验: %v", err)
	}
	if !strings.HasSuffix(got, "backup") {
		t.Fatalf("目标目录不正确: %q", got)
	}
}

func TestCopyNotImplementedYet(t *testing.T) {
	if _, err := Copy(nil, Options{}); err == nil {
		t.Fatal("未实现的执行器应返回错误而不是静默成功")
	}
}
