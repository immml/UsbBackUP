package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultIsValid(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("内置默认配置应通过校验: %v", err)
	}
	if c.Gate.UsedThresholdBytes != DefaultUsedThresholdBytes {
		t.Fatalf("默认阈值应为 10 GiB，实际 %d", c.Gate.UsedThresholdBytes)
	}
	if c.Gate.UsedThresholdBytes != 10*GiB {
		t.Fatalf("GiB 常量定义错误")
	}
	if c.Archive.KeepPlainZip {
		t.Fatal("默认不应保留明文 zip（决策 D-03）")
	}
	if c.AuthorizedBackupSubdir != "backup" {
		t.Fatalf("回写子目录默认应为 backup，实际 %q", c.AuthorizedBackupSubdir)
	}
	if !strings.HasSuffix(c.OutputDir, filepath.Join("", "backup")) {
		t.Fatalf("默认输出目录应以 backup 结尾: %q", c.OutputDir)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "不存在.json")
	cfg, loaded, err := Load(missing)
	if err != nil {
		t.Fatalf("文件不存在不应视为错误: %v", err)
	}
	if loaded {
		t.Fatal("loaded 应为 false")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("默认配置应通过校验: %v", err)
	}
}

func TestLoadSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := Default()
	cfg.Detect.Mode = "heuristic"
	cfg.Gate.UsedThresholdBytes = 5 * GiB
	cfg.Archive.Excludes = []string{"*.tmp", "临时"}
	cfg.Log.Level = "debug"
	if err := Save(path, cfg); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	// 不应留下 .part 临时文件。
	if _, err := os.Stat(path + ".part"); err == nil {
		t.Fatal("残留了 .part 临时文件")
	}

	got, loaded, err := Load(path)
	if err != nil || !loaded {
		t.Fatalf("加载失败: loaded=%v err=%v", loaded, err)
	}
	if got.Detect.Mode != "heuristic" || got.Gate.UsedThresholdBytes != 5*GiB {
		t.Fatalf("字段未正确往返: %+v", got.Gate)
	}
	if len(got.Archive.Excludes) != 2 || got.Log.Level != "debug" {
		t.Fatalf("切片或标量字段未正确往返")
	}
	// 未出现的字段应保留默认值。
	if got.Monitor.PollIntervalSec != Default().Monitor.PollIntervalSec {
		t.Fatal("未出现的字段未保留默认值")
	}
}

func TestLoadRejectsMalformedAndUnknownFields(t *testing.T) {
	dir := t.TempDir()

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(bad); err == nil {
		t.Fatal("非法 JSON 应报错")
	}

	unknown := filepath.Join(dir, "unknown.json")
	if err := os.WriteFile(unknown, []byte(`{"nope":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(unknown); err == nil {
		t.Fatal("未知字段应报错（DisallowUnknownFields）")
	}

	// 字段值非法应被校验拦下。
	invalid := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalid, []byte(`{"detect":{"mode":"乱写"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(invalid); err == nil {
		t.Fatal("非法 detect.mode 应报错")
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	mutators := map[string]func(*Config){
		"轮询间隔为 0":   func(c *Config) { c.Monitor.PollIntervalSec = 0 },
		"超时为 0":     func(c *Config) { c.Monitor.JobTimeoutMin = 0 },
		"阈值负数":      func(c *Config) { c.Gate.UsedThresholdBytes = -1 },
		"检测模式非法":    func(c *Config) { c.Detect.Mode = "whatever" },
		"扫描深度为 0":   func(c *Config) { c.Detect.MaxDepth = 0 },
		"扫描深度过大":    func(c *Config) { c.Detect.MaxDepth = 99 },
		"头部字节过大":    func(c *Config) { c.Detect.MaxHeadersBytes = 1 << 21 },
		"回写子目录含分隔符": func(c *Config) { c.AuthorizedBackupSubdir = `a\b` },
		"回写子目录为空":   func(c *Config) { c.AuthorizedBackupSubdir = "  " },
		"保留份数为 0":   func(c *Config) { c.Retention.KeepPerVolume = 0 },
		"线程数为负":     func(c *Config) { c.Archive.Threads = -1 },
	}
	for name, mut := range mutators {
		t.Run(name, func(t *testing.T) {
			c := Default()
			mut(c)
			if err := c.Validate(); err == nil {
				t.Fatalf("期望校验失败")
			}
		})
	}
}

func TestValidateNormalizesLogDefaults(t *testing.T) {
	c := Default()
	c.Log.MaxSizeMB = 0
	c.Log.MaxBackups = -5
	if err := c.Validate(); err != nil {
		t.Fatalf("日志字段应被静默修正而不是报错: %v", err)
	}
	if c.Log.MaxSizeMB != 10 || c.Log.MaxBackups != 5 {
		t.Fatalf("日志默认值未修正: %d / %d", c.Log.MaxSizeMB, c.Log.MaxBackups)
	}
}

func TestApplyEnv(t *testing.T) {
	t.Setenv("USBBACKUP_BACKUP_SOURCE_DIR", `D:\mybackup`)
	t.Setenv("USBBACKUP_OUTPUT_DIR", `D:\out`)
	t.Setenv("USBBACKUP_PUBLIC_KEY", `D:\keys\pub.pem`)
	t.Setenv("USBBACKUP_LOG_LEVEL", "warn")
	t.Setenv("USBBACKUP_USED_THRESHOLD_BYTES", "1073741824")
	t.Setenv("USBBACKUP_POLL_INTERVAL_SEC", "7")

	c := Default()
	applied := c.ApplyEnv()
	if len(applied) != 6 {
		t.Fatalf("应记录 6 个生效变量，实际 %d: %v", len(applied), applied)
	}
	if c.BackupSourceDir != `D:\mybackup` || c.OutputDir != `D:\out` {
		t.Fatalf("路径变量未生效: %+v", c)
	}
	if c.Gate.UsedThresholdBytes != 1<<30 {
		t.Fatalf("阈值变量未生效: %d", c.Gate.UsedThresholdBytes)
	}
	if c.Monitor.PollIntervalSec != 7 || c.Log.Level != "warn" {
		t.Fatalf("标量变量未生效")
	}

	// 非法数值应被忽略而不是污染配置。
	t.Setenv("USBBACKUP_USED_THRESHOLD_BYTES", "不是数字")
	t.Setenv("USBBACKUP_POLL_INTERVAL_SEC", "-1")
	c2 := Default()
	c2.ApplyEnv()
	if c2.Gate.UsedThresholdBytes != DefaultUsedThresholdBytes {
		t.Fatal("非法阈值不应覆盖默认值")
	}
	if c2.Monitor.PollIntervalSec != Default().Monitor.PollIntervalSec {
		t.Fatal("非法轮询间隔不应覆盖默认值")
	}
}

func TestExpandPath(t *testing.T) {
	t.Setenv("USBBACKUP_TEST_ROOT", `D:\root`)
	if got := ExpandPath(`%USBBACKUP_TEST_ROOT%\a\b`); got != filepath.FromSlash(`D:\root\a\b`) {
		t.Fatalf("百分号变量未展开: %q", got)
	}
	if got := ExpandPath(""); got != "" {
		t.Fatalf("空路径应返回空串，实际 %q", got)
	}
	if got := ExpandPath("relative"); !filepath.IsAbs(got) {
		t.Fatalf("相对路径应转为绝对路径: %q", got)
	}
	// TEMP 单变量写法应能用（Windows 上大小写与语义差异常见）。
	t.Setenv("TEMP", `D:\temp`)
	if got := ExpandPath(`%TEMP%\backup`); !strings.HasSuffix(got, "backup") {
		t.Fatalf("TEMP 展开异常: %q", got)
	}
}

func TestSummaryHasNoSecrets(t *testing.T) {
	c := Default()
	lines := strings.Join(c.Summary(), "\n")
	if lines == "" {
		t.Fatal("摘要不应为空")
	}
	for _, forbidden := range []string{"PRIVATE KEY", "BEGIN RSA", "passphrase", "口令"} {
		if strings.Contains(lines, forbidden) {
			t.Fatalf("配置摘要中出现敏感字样: %q", forbidden)
		}
	}
}
