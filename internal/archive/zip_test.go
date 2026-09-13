package archive

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildTree 造一棵测试目录树，返回根路径。
func buildTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.txt"), strings.Repeat("hello world\n", 500))
	if err := os.MkdirAll(filepath.Join(root, "sub", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "sub", "b.bin"), strings.Repeat("\x00\x01\x02", 2000))
	mustWrite(t, filepath.Join(root, "sub", "deep", "c.txt"), "深目录内容")
	// 二进制"已压缩"格式：应走 Store。
	mustWrite(t, filepath.Join(root, "photo.jpg"), strings.Repeat("JPEGDATA", 1000))
	// 排除项。
	if err := os.MkdirAll(filepath.Join(root, "System Volume Information"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "System Volume Information", "secret.dat"), "should be excluded")
	mustWrite(t, filepath.Join(root, "Thumbs.db"), "excluded")
	// 大文件：触发读写流水线重叠路径。
	mustWrite(t, filepath.Join(root, "big.dat"), strings.Repeat("ABCDEFGH", 800000)) // ~6.4 MB
	return root
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("写入 %s 失败: %v", path, err)
	}
}

func TestZipStreamRoundTrip(t *testing.T) {
	root := buildTree(t)

	var buf bytes.Buffer
	cw := NewCountingWriter(&buf)
	st, err := ZipStream(context.Background(), cw, ZipOptions{
		SourceRoot:             root,
		StoreAlreadyCompressed: true,
	})
	if err != nil {
		t.Fatalf("打包失败: %v", err)
	}
	if st.Files != 5 {
		t.Fatalf("应打包 5 个文件（含 photo.jpg / big.dat），实际 %d", st.Files)
	}
	if st.RawBytes <= 0 || st.ZipBytes <= 0 {
		t.Fatalf("统计异常: raw=%d zip=%d", st.RawBytes, st.ZipBytes)
	}
	if st.ZipBytes != int64(buf.Len()) {
		t.Fatalf("ZipBytes(%d) 与实际写入(%d) 不一致", st.ZipBytes, buf.Len())
	}
	if st.Skipped < 2 {
		t.Fatalf("系统目录与 Thumbs.db 应被排除，Skipped=%d", st.Skipped)
	}

	// 归档内容必须是相对路径，且不含排除项。
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("产物不是合法 zip: %v", err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
		if filepath.IsAbs(f.Name) || strings.Contains(f.Name, `\`) ||
			strings.Contains(f.Name, "..") || strings.Contains(f.Name, ":") {
			t.Fatalf("归档条目名不安全: %q", f.Name)
		}
	}
	for _, want := range []string{"a.txt", "sub/b.bin", "sub/deep/c.txt", "photo.jpg", "big.dat"} {
		if !names[want] {
			t.Fatalf("归档缺少 %q（实际：%v）", want, names)
		}
	}
	for _, bad := range []string{"Thumbs.db", "System Volume Information/secret.dat"} {
		if names[bad] {
			t.Fatalf("归档不应包含被排除项 %q", bad)
		}
	}

	// 解包回来，逐字节比对（覆盖读写流水线重叠的那条路径）。
	dest := t.TempDir()
	ust, err := UnzipStream(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), UnzipOptions{
		DestDir: dest,
	})
	if err != nil {
		t.Fatalf("解包失败: %v", err)
	}
	if ust.Files != st.Files {
		t.Fatalf("解出文件数 %d != 打包文件数 %d", ust.Files, st.Files)
	}
	for _, rel := range []string{"a.txt", "sub/b.bin", "sub/deep/c.txt", "photo.jpg", "big.dat"} {
		got, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("读取解出的 %s 失败: %v", rel, err)
		}
		want, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s 内容不一致（解出 %d 字节，原始 %d 字节）", rel, len(got), len(want))
		}
	}
}

func TestZipStreamSourceReadOnly(t *testing.T) {
	root := buildTree(t)
	before := snapshot(t, root)

	var buf bytes.Buffer
	if _, err := ZipStream(context.Background(), &buf, ZipOptions{SourceRoot: root}); err != nil {
		t.Fatalf("打包失败: %v", err)
	}
	after := snapshot(t, root)

	if len(before) != len(after) {
		t.Fatalf("源盘文件数发生变化：%d → %d（必须只读，G-05）", len(before), len(after))
	}
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("源文件被改动：%s", k)
		}
	}
}

// snapshot 记录目录树的相对路径 → 大小+mtime 快照，用于验证"源盘只读"。
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		out[rel] = fi.ModTime().String() + "|" + itoa(fi.Size()) + "|" + string(rune(fi.Mode()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func TestZipStreamCancel(t *testing.T) {
	root := buildTree(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	var buf bytes.Buffer
	if _, err := ZipStream(ctx, &buf, ZipOptions{SourceRoot: root}); err == nil {
		t.Fatal("已取消的上下文应当返回错误")
	}
}

func TestZipStreamRejectsBadRoot(t *testing.T) {
	if _, err := ZipStream(context.Background(), io.Discard, ZipOptions{}); err == nil {
		t.Fatal("空源根应报错")
	}
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ZipStream(context.Background(), io.Discard, ZipOptions{SourceRoot: f}); err == nil {
		t.Fatal("源根为普通文件时应报错")
	}
}

func TestUnzipRejectsZipSlipAndSymlink(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	entries := []struct {
		name string
		body string
	}{
		{"safe.txt", "ok"},
		{"../evil.txt", "escape"},
		{"a/../../evil2.txt", "escape"},
		{"/abs.txt", "escape"},
		{"C:/win.txt", "escape"},
		{"ads.txt:stream", "escape"},
		{"sub/ok2.txt", "ok"},
	}
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	// 追加一个符号链接条目（通过设置 Mode 位模拟）。
	hdr := &zip.FileHeader{Name: "link"}
	hdr.SetMode(os.ModeSymlink | 0o777)
	if w, err := zw.CreateHeader(hdr); err == nil {
		_, _ = w.Write([]byte("../../outside"))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	ust, err := UnzipStream(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), UnzipOptions{
		DestDir: dest,
	})
	if err != nil {
		t.Fatalf("解包失败: %v", err)
	}
	if ust.RejectedUnsafe < 4 {
		t.Fatalf("应拒绝至少 4 个不安全条目，实际 %d", ust.RejectedUnsafe)
	}
	if ust.Files != 2 {
		t.Fatalf("应只写出 2 个安全文件，实际 %d", ust.Files)
	}
	// 确认没有任何文件被写到目标目录之外。
	parent := filepath.Dir(dest)
	for _, name := range []string{"evil.txt", "evil2.txt", "abs.txt", "win.txt"} {
		if _, err := os.Stat(filepath.Join(parent, name)); err == nil {
			t.Fatalf("发生了目录穿越：%s 被写到目标目录之外", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, "safe.txt")); err != nil {
		t.Fatalf("安全条目未被解出: %v", err)
	}
}

func TestUnzipSkipAndForce(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("f.txt")
	_, _ = w.Write([]byte("new-content"))
	_ = zw.Close()

	dest := t.TempDir()
	existing := filepath.Join(dest, "f.txt")
	if err := os.WriteFile(existing, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 默认跳过，不覆盖（F-B06）。
	ust, err := UnzipStream(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), UnzipOptions{DestDir: dest})
	if err != nil {
		t.Fatal(err)
	}
	if ust.Files != 0 || ust.Skipped != 1 {
		t.Fatalf("默认应跳过已存在文件：files=%d skipped=%d", ust.Files, ust.Skipped)
	}
	if got, _ := os.ReadFile(existing); string(got) != "old" {
		t.Fatalf("默认不应覆盖，实际内容 %q", got)
	}

	// --force 覆盖。
	if _, err := UnzipStream(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), UnzipOptions{DestDir: dest, Force: true}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(existing); string(got) != "new-content" {
		t.Fatalf("--force 应覆盖，实际内容 %q", got)
	}
}

func TestUnzipDryRunWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("x/y.txt")
	_, _ = w.Write([]byte("data"))
	_ = zw.Close()

	dest := filepath.Join(t.TempDir(), "not-created")
	ust, err := UnzipStream(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), UnzipOptions{
		DestDir: dest, DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ust.Files != 1 {
		t.Fatalf("dry-run 应报告 1 个条目，实际 %d", ust.Files)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Fatal("dry-run 不应创建目录")
	}
}

func TestUnzipRequiresDestAndRejectsBadZip(t *testing.T) {
	if _, err := UnzipStream(context.Background(), bytes.NewReader(nil), 0, UnzipOptions{}); err == nil {
		t.Fatal("未指定目标目录应报错")
	}
	junk := []byte("this is not a zip file at all")
	if _, err := UnzipStream(context.Background(), bytes.NewReader(junk), int64(len(junk)), UnzipOptions{DestDir: t.TempDir()}); err == nil {
		t.Fatal("非法 zip 应报错")
	}
}

func TestUnzipEnforcesEntryLimit(t *testing.T) {
	// 声称解压后 1 MiB，但用很小上限强制拒绝（防解压炸弹）。
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("big.bin")
	_, _ = w.Write(bytes.Repeat([]byte{0}, 1<<20))
	_ = zw.Close()

	dest := t.TempDir()
	ust, err := UnzipStream(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), UnzipOptions{
		DestDir: dest, MaxEntryBytes: 1024,
	})
	// 声明值超限 → 条目被拒绝；若全部被拒绝则返回错误。
	if err == nil && ust.RejectedUnsafe == 0 {
		t.Fatalf("超限条目应被拒绝：%+v", ust)
	}
	if _, statErr := os.Stat(filepath.Join(dest, "big.bin")); statErr == nil {
		t.Fatal("超限条目不应落盘")
	}
}

func TestZipStreamProgressCallback(t *testing.T) {
	root := buildTree(t)
	var calls int
	var buf bytes.Buffer
	if _, err := ZipStream(context.Background(), &buf, ZipOptions{
		SourceRoot: root,
		Progress:   func(ZipStats) { calls++ },
	}); err != nil {
		t.Fatal(err)
	}
	if calls == 0 {
		t.Fatal("进度回调未被调用")
	}
}
