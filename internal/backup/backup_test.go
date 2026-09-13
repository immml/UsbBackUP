package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/immml/UsbBackup/internal/winvol"
)

func TestProductNameSanitizes(t *testing.T) {
	cases := []struct {
		name  string
		vol   winvol.Volume
		want  string
		check func(t *testing.T, got string)
	}{
		{"普通卷标", winvol.Volume{Root: `E:\`, Label: "MyUSB"}, "MyUSB.zip.usbk", nil},
		{"空卷标兜底", winvol.Volume{Root: `E:\`}, "VOL_E.zip.usbk", nil},
		{"含非法字符", winvol.Volume{Root: `E:\`, Label: `a/b:c*d?e"f<g>h|i`}, "a_b_c_d_e_f_g_h_i.zip.usbk", nil},
		{"含路径穿越尝试", winvol.Volume{Root: `E:\`, Label: `..\..\Windows`}, "", func(t *testing.T, got string) {
			// 净化后必须不含任何路径分隔符，且拼接结果仍位于输出目录之内。
			if strings.ContainsAny(got, `\/`) {
				t.Fatalf("产物名不得含路径分隔符: %q", got)
			}
			joined := filepath.Join(`C:\tmp\backup`, got)
			if filepath.Dir(joined) != `C:\tmp\backup` {
				t.Fatalf("拼接后逃出输出目录: %q", joined)
			}
		}},
		{"卷标本身就是 zip 名", winvol.Volume{Root: `E:\`, Label: "backup.zip"}, "backup.zip.usbk", nil},
		{"超长卷标", winvol.Volume{Root: `E:\`, Label: strings.Repeat("x", 500)}, "", func(t *testing.T, got string) {
			if len(got) > 140 {
				t.Fatalf("产物名过长: %d", len(got))
			}
			if !strings.HasSuffix(got, ".zip.usbk") {
				t.Fatalf("后缀错误: %q", got)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ProductName(tc.vol)
			if tc.want != "" && got != tc.want {
				t.Fatalf("ProductName = %q, want %q", got, tc.want)
			}
			if !strings.HasSuffix(got, ".zip.usbk") {
				t.Fatalf("产物名后缀应为 .zip.usbk：%q", got)
			}
			if strings.ContainsAny(got, `\/:*?"<>|`) {
				t.Fatalf("产物名含 Windows 禁用字符：%q", got)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

func TestUniqueProductPath(t *testing.T) {
	dir := t.TempDir()
	vol := winvol.Volume{Root: `E:\`, Label: "MyUSB"}
	at := time.Date(2026, 9, 13, 18, 30, 0, 0, time.UTC)

	first := UniqueProductPath(dir, vol, at)
	if filepath.Base(first) != "MyUSB.zip.usbk" {
		t.Fatalf("首次命名应为 MyUSB.zip.usbk，实际 %q", filepath.Base(first))
	}
	if err := os.WriteFile(first, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := UniqueProductPath(dir, vol, at)
	want := "MyUSB_20260913_183000.zip.usbk"
	if filepath.Base(second) != want {
		t.Fatalf("冲突时命名应为 %q，实际 %q", want, filepath.Base(second))
	}
	if first == second {
		t.Fatal("冲突时应返回不同路径")
	}
}

func TestAppendAudit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "audit.jsonl")

	rec := AuditRecord{
		Time:         "2026-09-13T18:39:00+08:00",
		Tool:         "usbguard",
		ToolVersion:  "0.1.0",
		Root:         `E:\`,
		Label:        "MyUSB",
		FileSystem:   "exFAT",
		SerialNumber: 0x12345678,
		TotalBytes:   64 << 30,
		FreeBytes:    60 << 30,
		UsedBytes:    4 << 30,
		Branch:       BranchArchive,
		HasKeyfile:   false,
		KeyfileHits:  0,
		ScannedFiles: 123,
		Product:      "MyUSB.zip.usbk",
		OK:           true,
	}
	if err := AppendAudit(path, rec); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	if err := AppendAudit(path, rec); err != nil {
		t.Fatalf("追加写入失败: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("应为 JSON Lines 两行，实际 %d 行", len(lines))
	}
	var decoded AuditRecord
	if err := json.Unmarshal([]byte(lines[0]), &decoded); err != nil {
		t.Fatalf("审计行不是合法 JSON: %v", err)
	}
	if decoded.Root != rec.Root || decoded.Branch != BranchArchive {
		t.Fatalf("字段丢失: %+v", decoded)
	}

	// G-02 回归防护：审计记录中不得出现文件名清单或内容字段。
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{"private_key", "filename", "filelist", "file_list", "pathlist", "content", "id_rsa", "-----begin"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("审计记录含禁止字段或内容：%q", forbidden)
		}
	}
}

func TestAppendAuditRejectsEmptyPath(t *testing.T) {
	if err := AppendAudit("", AuditRecord{}); err == nil {
		t.Fatal("空路径应报错")
	}
}

func TestBranchConstants(t *testing.T) {
	seen := map[Branch]bool{}
	for _, b := range []Branch{BranchAuthorized, BranchArchive, BranchSkipped, BranchFailed} {
		if seen[b] {
			t.Fatalf("分支常量重复: %s", b)
		}
		seen[b] = true
		if b == "" {
			t.Fatal("分支常量不应为空")
		}
	}
}
