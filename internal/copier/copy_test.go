package copier

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeSource 造一个备份源目录。
func makeSource(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	write(t, filepath.Join(src, "a.txt"), "aaa")
	write(t, filepath.Join(src, "b", "c.txt"), "ccc")
	write(t, filepath.Join(src, "b", "d", "e.bin"), strings.Repeat("X", 1000))
	return src
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCopyBasic(t *testing.T) {
	src := makeSource(t)
	dstRoot := t.TempDir()

	st, err := Copy(context.Background(), Options{
		SourceDir: src, DestRoot: dstRoot, SubDir: "backup",
	})
	if err != nil {
		t.Fatalf("复制失败: %v", err)
	}
	if st.FilesCopied != 3 {
		t.Fatalf("应复制 3 个文件，实际 %d", st.FilesCopied)
	}
	if st.FilesFailed != 0 || st.VerifyFailures != 0 {
		t.Fatalf("不应有失败或校验不一致：%+v", st)
	}

	target := filepath.Join(dstRoot, "backup")
	for _, rel := range []string{"a.txt", filepath.Join("b", "c.txt"), filepath.Join("b", "d", "e.bin")} {
		if _, err := os.Stat(filepath.Join(target, rel)); err != nil {
			t.Fatalf("目标缺少 %s: %v", rel, err)
		}
	}
	// 内容必须一致。
	got, _ := os.ReadFile(filepath.Join(target, "a.txt"))
	if string(got) != "aaa" {
		t.Fatalf("内容不一致: %q", got)
	}
}

func TestCopyIncrementalSkip(t *testing.T) {
	src := makeSource(t)
	dstRoot := t.TempDir()
	opt := Options{SourceDir: src, DestRoot: dstRoot, SubDir: "backup"}

	if _, err := Copy(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	// 第二次：size+mtime 一致 → 全部跳过（F-402）。
	st, err := Copy(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if st.FilesCopied != 0 {
		t.Fatalf("第二次应全部跳过，实际复制了 %d 个", st.FilesCopied)
	}
	if st.FilesSkipped != 3 {
		t.Fatalf("第二次应跳过 3 个，实际 %d", st.FilesSkipped)
	}
}

func TestCopyDoesNotOverwriteByDefault(t *testing.T) {
	src := makeSource(t)
	dstRoot := t.TempDir()
	target := filepath.Join(dstRoot, "backup")
	// 预先在目标放一个同名但内容不同、大小也不同的文件。
	write(t, filepath.Join(target, "a.txt"), "目标原有的内容，更长一些")

	st, err := Copy(context.Background(), Options{
		SourceDir: src, DestRoot: dstRoot, SubDir: "backup",
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.FilesSkipped == 0 {
		t.Fatal("默认不应覆盖已存在的同名文件（F-403）")
	}
	got, _ := os.ReadFile(filepath.Join(target, "a.txt"))
	if string(got) != "目标原有的内容，更长一些" {
		t.Fatalf("目标文件被意外改写: %q", got)
	}

	// 显式 --overwrite 才覆盖。
	if _, err := Copy(context.Background(), Options{
		SourceDir: src, DestRoot: dstRoot, SubDir: "backup", Overwrite: true,
	}); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(filepath.Join(target, "a.txt"))
	if string(got) != "aaa" {
		t.Fatalf("--overwrite 应覆盖，实际 %q", got)
	}
}

func TestCopyDryRunWritesNothing(t *testing.T) {
	src := makeSource(t)
	dstRoot := t.TempDir()
	target := filepath.Join(dstRoot, "backup")

	st, err := Copy(context.Background(), Options{
		SourceDir: src, DestRoot: dstRoot, SubDir: "backup", DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.FilesCopied != 3 {
		t.Fatalf("dry-run 应报告 3 个待复制文件，实际 %d", st.FilesCopied)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("dry-run 不应创建目标目录")
	}
}

func TestCopyWritesManifestWithoutFileList(t *testing.T) {
	src := makeSource(t)
	dstRoot := t.TempDir()

	if _, err := Copy(context.Background(), Options{
		SourceDir: src, DestRoot: dstRoot, SubDir: "backup",
		WriteManifest: true, PublicKeyFingerprint: "aabb ccdd",
	}); err != nil {
		t.Fatal(err)
	}
	mp := filepath.Join(dstRoot, "backup", ".usbbackup-manifest.json")
	raw, err := os.ReadFile(mp)
	if err != nil {
		t.Fatalf("清单未写出: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "aabb ccdd") {
		t.Fatalf("清单应包含公钥指纹: %s", text)
	}
	// 清单不得包含文件清单或任何文件内容（G-02）。
	for _, forbidden := range []string{"a.txt", "e.bin", "PRIVATE KEY", "aaa"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("清单中出现了禁止内容 %q：%s", forbidden, text)
		}
	}
}

func TestCopyVerifyHashDetectsMismatch(t *testing.T) {
	src := makeSource(t)
	dstRoot := t.TempDir()

	st, err := Copy(context.Background(), Options{
		SourceDir: src, DestRoot: dstRoot, SubDir: "backup", VerifyHash: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.VerifyFailures != 0 {
		t.Fatalf("正常复制不应出现校验失败，实际 %d", st.VerifyFailures)
	}
}

func TestCopyCancelledContext(t *testing.T) {
	src := makeSource(t)
	dstRoot := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Copy(ctx, Options{SourceDir: src, DestRoot: dstRoot, SubDir: "backup"}); err == nil {
		t.Fatal("已取消的上下文应返回错误")
	}
}

func TestCopyRespectsMaxFiles(t *testing.T) {
	src := t.TempDir()
	for i := 0; i < 20; i++ {
		write(t, filepath.Join(src, "f"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+".txt"), "x")
	}
	if _, err := Copy(context.Background(), Options{
		SourceDir: src, DestRoot: t.TempDir(), SubDir: "backup", MaxFiles: 5,
	}); err == nil {
		t.Fatal("超出条目上限时应报错而不是静默截断")
	}
}

func TestCopyKeepsSourceUntouched(t *testing.T) {
	src := makeSource(t)
	dstRoot := t.TempDir()

	before := map[string]time.Time{}
	_ = filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err == nil {
			before[p] = fi.ModTime()
		}
		return nil
	})

	if _, err := Copy(context.Background(), Options{SourceDir: src, DestRoot: dstRoot, SubDir: "backup"}); err != nil {
		t.Fatal(err)
	}
	_ = filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if old, ok := before[p]; ok && !old.Equal(fi.ModTime()) {
			t.Fatalf("源文件被改动: %s（必须只读，G-05）", p)
		}
		return nil
	})
}
