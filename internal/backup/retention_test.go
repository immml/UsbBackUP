package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/immml/UsbBackUP/internal/winvol"
)

// touchProduct 造一个产物文件并设置修改时间。
func touchProduct(t *testing.T, dir, name string, mod time.Time, size int) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mod, mod); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProductBase(t *testing.T) {
	if got := ProductBase(winvol.Volume{Root: `E:\`, Label: "MyUSB"}); got != "MyUSB" {
		t.Fatalf("ProductBase = %q", got)
	}
	if got := ProductBase(winvol.Volume{Root: `E:\`}); got != "VOL_E" {
		t.Fatalf("空卷标应兜底为 VOL_E，实际 %q", got)
	}
}

func TestEnforceRetentionKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	base := "MyUSB"
	now := time.Now()

	// 5 个同卷产物：最旧 → 最新。
	var paths []string
	for i := 0; i < 5; i++ {
		name := base
		mod := now.Add(time.Duration(i) * time.Hour)
		if i > 0 {
			name = base + "_" + mod.Format("20060102_150405")
		}
		paths = append(paths, touchProduct(t, dir, name+".zip.usbk", mod, 10))
	}
	// 另一个卷的产物与无关文件：绝不能被删。
	other := touchProduct(t, dir, "OtherUSB.zip.usbk", now, 10)
	unrelated := touchProduct(t, dir, "important.txt", now, 10)

	removed, err := EnforceRetention(dir, base, 2, nil)
	if err != nil {
		t.Fatalf("保留策略失败: %v", err)
	}
	if removed != 3 {
		t.Fatalf("应删除 3 份最旧产物，实际 %d", removed)
	}
	// 最新的 2 份必须还在。
	for _, p := range paths[3:] {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("应保留的产物被删除: %s", p)
		}
	}
	for _, p := range paths[:3] {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("应删除的旧产物仍然存在: %s", p)
		}
	}
	// 别的卷与无关文件必须原样保留（只删自己生成的产物）。
	for _, p := range []string{other, unrelated} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("不应触碰非本卷产物或无关文件: %s", p)
		}
	}
}

func TestEnforceRetentionNoopWhenUnderLimit(t *testing.T) {
	dir := t.TempDir()
	touchProduct(t, dir, "MyUSB.zip.usbk", time.Now(), 10)
	n, err := EnforceRetention(dir, "MyUSB", 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("未超限时不应删除任何文件，实际删了 %d", n)
	}
}

func TestEnforceRetentionHandlesZeroKeep(t *testing.T) {
	dir := t.TempDir()
	touchProduct(t, dir, "MyUSB.zip.usbk", time.Now(), 10)
	touchProduct(t, dir, "MyUSB_20260101_000000.zip.usbk", time.Now().Add(-time.Hour), 10)
	// keep=0 应被夹到 1，至少保留一份，绝不把产物清空。
	n, err := EnforceRetention(dir, "MyUSB", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("keep=0 时应只删 1 份，实际 %d", n)
	}
	files, _ := productFilesFor(dir, "MyUSB")
	if len(files) != 1 {
		t.Fatalf("应恰好保留 1 份，实际 %d", len(files))
	}
}

func TestProductFilesForIgnoresOtherNames(t *testing.T) {
	dir := t.TempDir()
	touchProduct(t, dir, "MyUSB.zip.usbk", time.Now(), 1)
	touchProduct(t, dir, "MyUSB_20260101_010101.zip.usbk", time.Now(), 1)
	touchProduct(t, dir, "MyUSB.zip", time.Now(), 1)       // 扩展名不符
	touchProduct(t, dir, "MyUSB2.zip.usbk", time.Now(), 1) // 前缀相似但不是同卷
	files, err := productFilesFor(dir, "MyUSB")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("应只匹配 2 个同卷产物，实际 %d：%v", len(files), files)
	}
}

func TestCleanupPartialsOnlyRemovesOwnTempFiles(t *testing.T) {
	dir := t.TempDir()
	part1 := touchProduct(t, dir, "MyUSB.zip.usbk.part", time.Now(), 5)
	part2 := touchProduct(t, dir, "Other.zip.usbk.part", time.Now(), 5)
	keep1 := touchProduct(t, dir, "MyUSB.zip.usbk", time.Now(), 5)
	keep2 := touchProduct(t, dir, "用户文件.part", time.Now(), 5)

	n, err := CleanupPartials(dir)
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if n != 2 {
		t.Fatalf("应清理 2 个本工具的半成品，实际 %d", n)
	}
	for _, p := range []string{part1, part2} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("半成品未被清理: %s", p)
		}
	}
	for _, p := range []string{keep1, keep2} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("不应删除: %s", p)
		}
	}
}

func TestCleanupPartialsMissingDirIsFine(t *testing.T) {
	n, err := CleanupPartials(filepath.Join(t.TempDir(), "不存在"))
	if err != nil {
		t.Fatalf("目录不存在不应报错: %v", err)
	}
	if n != 0 {
		t.Fatalf("不应删除任何文件，实际 %d", n)
	}
}

func TestResultToAuditOmitsSensitiveFields(t *testing.T) {
	res := Result{
		Root:        `E:\`,
		Volume:      winvol.Volume{Label: "MyUSB", FileSystem: "exFAT", SerialNumber: 0x1234, TotalBytes: 100, FreeBytes: 40, UsedBytes: 60},
		Branch:      BranchArchive,
		Authorized:  false,
		ProductPath: filepath.FromSlash(`C:\tmp\backup\MyUSB.zip.usbk`),
		OK:          true,
		Duration:    time.Second,
	}
	rec := ResultToAudit(res, time.Now())
	if rec.Product != "MyUSB.zip.usbk" {
		t.Fatalf("审计只应记录产物文件名，实际 %q", rec.Product)
	}
	if rec.Root != `E:\` || rec.UsedBytes != 60 || rec.Branch != BranchArchive {
		t.Fatalf("审计字段不完整: %+v", rec)
	}
	if rec.HasKeyfile {
		t.Fatal("未授权时 HasKeyfile 应为 false")
	}
	// 审计结构里不得有文件清单或内容字段。
	if rec.KeyfileKinds != nil && len(rec.KeyfileKinds) > 0 {
		t.Fatalf("不应记录命中类型之外的细节: %v", rec.KeyfileKinds)
	}
}
