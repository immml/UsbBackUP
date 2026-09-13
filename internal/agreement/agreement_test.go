package agreement

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withHome 把配置目录临时指向 t.TempDir()，返回确认记录路径。
//
// DefaultConfigPath 依赖 LOCALAPPDATA，测试里直接改这个环境变量最省事，
// 也顺带验证了"路径随配置目录走"这一约定。
func withHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("LOCALAPPDATA", dir)
	return filepath.Join(dir, "usbbackup", fileName)
}

func TestNotAcceptedByDefault(t *testing.T) {
	withHome(t)
	if Accepted() {
		t.Fatal("全新环境应为未确认")
	}
	if _, ok, err := Load(); ok || err != nil {
		t.Fatalf("未确认时 Load 应返回 ok=false 且无错误，实际 ok=%v err=%v", ok, err)
	}
}

func TestSaveThenAccepted(t *testing.T) {
	p := withHome(t)
	rec, err := Save("demo-client")
	if err != nil {
		t.Fatalf("Save 失败: %v", err)
	}
	if rec.Phrase != Phrase {
		t.Fatalf("记录短语应为 %q，实际 %q", Phrase, rec.Phrase)
	}
	if rec.AcceptedAt == "" {
		t.Error("应记录确认时间")
	}
	if rec.ClientName != "demo-client" {
		t.Errorf("客户端标识未写入: %q", rec.ClientName)
	}
	if !Accepted() {
		t.Fatal("保存后应为已确认")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("记录文件应存在于 %s: %v", p, err)
	}
}

func TestRevoke(t *testing.T) {
	withHome(t)
	if _, err := Save(""); err != nil {
		t.Fatal(err)
	}
	if !Accepted() {
		t.Fatal("撤销前应为已确认")
	}
	if err := Revoke(); err != nil {
		t.Fatalf("Revoke 失败: %v", err)
	}
	if Accepted() {
		t.Fatal("撤销后应为未确认")
	}
	// 重复撤销不应报错（幂等）。
	if err := Revoke(); err != nil {
		t.Fatalf("重复撤销不应报错: %v", err)
	}
}

func TestForgedRecordIsRejected(t *testing.T) {
	// 手工伪造一个缺少确认短语的文件：必须按"未确认"处理，
	// 否则随便放个 json 就能让程序静默运行。
	p := withHome(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"tool":"usbbackup","version":"0.3.0","accepted_at":"2026-01-01T00:00:00+08:00"}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if Accepted() {
		t.Fatal("缺少有效短语的记录必须视为未确认")
	}
}

func TestCorruptedRecordIsNotAccepted(t *testing.T) {
	p := withHome(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if Accepted() {
		t.Fatal("损坏的记录必须视为未确认，不能静默运行")
	}
	if _, _, err := Load(); err == nil {
		t.Fatal("损坏记录应返回错误")
	}
}

func TestPathLivesBesideConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LOCALAPPDATA", dir)
	got := Path()
	if !strings.HasSuffix(filepath.ToSlash(got), "/usbbackup/"+fileName) {
		t.Fatalf("确认记录应与配置文件同目录，实际 %s", got)
	}
}

func TestRecordCarriesPolicyAndVersion(t *testing.T) {
	withHome(t)
	rec, err := Save("")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Policy != "CC BY-NC-SA 4.0" {
		t.Fatalf("许可协议应写入记录，实际 %q", rec.Policy)
	}
	if rec.Version == "" {
		t.Error("应记录确认时的版本")
	}
}
