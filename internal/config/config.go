// Package config 负责运行配置的加载、校验、合并与展示。
//
// 配置优先级（高 → 低）：命令行 flag > 环境变量 USBBACKUP_* > config.json > 内置默认值。
// 对应需求 F-C03 / F-C04 / F-C05。
//
// 安全约束：本包定义的配置结构中**不包含任何私钥字段**（见 G-01 / F-C03）。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/immml/UsbBackUP/internal/version"
)

// GiB 是一个 Gibibyte（1024^3）。容量阈值统一按 GiB 计（决策 D-02）。
const GiB int64 = 1024 * 1024 * 1024

// DefaultUsedThresholdBytes 是容量门控默认阈值：10 GiB（F-304 / Q-01）。
const DefaultUsedThresholdBytes int64 = 10 * GiB

// MonitorConfig 是设备监控配置（F-1xx）。
type MonitorConfig struct {
	// PollIntervalSec 是轮询兜底间隔秒数（F-103）。
	PollIntervalSec int `json:"poll_interval_sec"`
	// DebounceSec 是同盘符重复事件合并窗口秒数（F-104）。
	DebounceSec int `json:"debounce_sec"`
	// ReadyTimeoutSec 是卷就绪等待上限秒数（F-305）。
	ReadyTimeoutSec int `json:"ready_timeout_sec"`
	// JobTimeoutMin 是单盘作业超时分钟数（F-106）。
	JobTimeoutMin int `json:"job_timeout_min"`
	// ProcessMountedOnStart 决定启动时是否处理已挂载的可移动盘（F-105）。
	ProcessMountedOnStart bool `json:"process_mounted_on_start"`
	// PollOnly 为 true 时禁用事件通道，只用轮询（排障用）。
	PollOnly bool `json:"poll_only"`
}

// DetectConfig 是私钥存在性检测配置（F-2xx）。
//
// 注意：这里只配置"如何判定存在"，不涉及任何私钥内容的读取或保存。
type DetectConfig struct {
	// Mode 取值：heuristic（默认）/ marker / both。
	Mode string `json:"mode"`
	// MaxDepth 是扫描最大目录深度（F-204）。
	MaxDepth int `json:"max_depth"`
	// MaxFiles 是扫描文件数上限（F-204）。
	MaxFiles int `json:"max_files"`
	// MaxHeadersBytes 是每个候选文件最多读取的头部字节数（F-202），默认 4096。
	MaxHeadersBytes int `json:"max_headers_bytes"`
	// TimeoutSec 是单次检测总耗时上限秒数（F-204）。
	TimeoutSec int `json:"timeout_sec"`
	// MarkerFile 是显式授权标记文件名（F-203）。
	MarkerFile string `json:"marker_file"`
	// ScanContents 为 false 时只按文件名判定（更快，更少 IO）。
	ScanContents bool `json:"scan_contents"`
	// ExtraNamePatterns 是追加的文件名模式（F-207），大小写不敏感，支持 * 通配。
	ExtraNamePatterns []string `json:"extra_name_patterns"`
	// ExtraContentMarkers 是追加的内容特征（F-207），按子串匹配。
	ExtraContentMarkers []string `json:"extra_content_markers"`
}

// GateConfig 是容量门控配置（F-304）。
type GateConfig struct {
	// UsedThresholdBytes 是"已占用容量"阈值，超过则跳过整盘打包。
	UsedThresholdBytes int64 `json:"used_threshold_bytes"`
	// MaxTotalBytes 是整盘打包体积上限（Q-07），0 表示不限制。
	MaxTotalBytes int64 `json:"max_total_bytes"`
	// FreeSpaceMarginPercent 是回写前剩余空间预留百分比（F-306），默认 5。
	FreeSpaceMarginPercent int `json:"free_space_margin_percent"`
}

// ArchiveConfig 是打包配置（F-5xx / F-Axx）。
type ArchiveConfig struct {
	// StoreAlreadyCompressed 对已压缩格式用 Store（F-502）。
	StoreAlreadyCompressed bool `json:"store_already_compressed"`
	// KeepPlainZip 保留明文 zip（默认 false，见决策 D-03 / Q-02）。
	KeepPlainZip bool `json:"keep_plain_zip"`
	// Excludes 是额外排除的顶层目录名或文件名（F-505）。
	Excludes []string `json:"excludes"`
	// Threads 是压缩并发度，0 表示自动（CPU-1，上限 8）。
	Threads int `json:"threads"`
}

// RetentionConfig 是产物保留策略（F-806）。
type RetentionConfig struct {
	// KeepPerVolume 是同卷保留份数，默认 5（Q-05）。
	KeepPerVolume int `json:"keep_per_volume"`
	// DedupEnabled 开启树指纹去重（F-805）。
	DedupEnabled bool `json:"dedup_enabled"`
}

// LogConfig 是日志配置（F-C01 / F-C02）。
type LogConfig struct {
	Level      string `json:"level"`
	File       string `json:"file"`
	MaxSizeMB  int    `json:"max_size_mb"`
	MaxBackups int    `json:"max_backups"`
	Console    bool   `json:"console"`
}

// Config 是运行期生效配置。
type Config struct {
	// BackupSourceDir 是本地「备份文件夹」路径，授权分支的复制源（F-401 / Q-03）。
	BackupSourceDir string `json:"backup_source_dir"`
	// OutputDir 是加密产物落盘目录，默认 %TEMP%\backup（F-803 / D-06）。
	OutputDir string `json:"output_dir"`
	// PublicKeyPath 是用于包装会话密钥的公钥文件路径（F-703）。
	PublicKeyPath string `json:"public_key_path"`
	// AuthorizedBackupSubdir 是回写到 U 盘的子目录名，固定语义为 `backup`（F-401 / G-04）。
	AuthorizedBackupSubdir string `json:"authorized_backup_subdir"`
	// AuditFile 是审计日志文件路径（F-807）。
	AuditFile string `json:"audit_file"`

	Monitor   MonitorConfig   `json:"monitor"`
	Detect    DetectConfig    `json:"detect"`
	Gate      GateConfig      `json:"gate"`
	Archive   ArchiveConfig   `json:"archive"`
	Retention RetentionConfig `json:"retention"`
	Log       LogConfig       `json:"log"`
}

// Default 返回内置默认配置。
func Default() *Config {
	appData := os.Getenv("LOCALAPPDATA")
	if appData == "" {
		appData = os.TempDir()
	}
	base := filepath.Join(appData, version.AppName)

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.TempDir()
	}

	return &Config{
		BackupSourceDir:        filepath.Join(home, version.AppName, "local-backup"),
		OutputDir:              filepath.Join(os.TempDir(), "backup"),
		PublicKeyPath:          filepath.Join(base, "keys", "usbbackup.pub.pem"),
		AuthorizedBackupSubdir: "backup",
		AuditFile:              filepath.Join(base, "audit.jsonl"),
		Monitor: MonitorConfig{
			PollIntervalSec:       5,
			DebounceSec:           5,
			ReadyTimeoutSec:       10,
			JobTimeoutMin:         30,
			ProcessMountedOnStart: true,
			PollOnly:              false,
		},
		Detect: DetectConfig{
			Mode:            "both",
			MaxDepth:        4,
			MaxFiles:        5000,
			MaxHeadersBytes: 4096,
			TimeoutSec:      20,
			MarkerFile:      ".usbbackup-allow",
			ScanContents:    true,
		},
		Gate: GateConfig{
			UsedThresholdBytes:     DefaultUsedThresholdBytes,
			MaxTotalBytes:          0,
			FreeSpaceMarginPercent: 5,
		},
		Archive: ArchiveConfig{
			StoreAlreadyCompressed: true,
			KeepPlainZip:           false,
			Threads:                0,
		},
		Retention: RetentionConfig{
			KeepPerVolume: 5,
			DedupEnabled:  true,
		},
		Log: LogConfig{
			Level:      "info",
			File:       filepath.Join(base, "logs", version.AppName+".log"),
			MaxSizeMB:  10,
			MaxBackups: 5,
			Console:    true,
		},
	}
}

// DefaultConfigPath 返回默认配置文件路径：%LOCALAPPDATA%\usbbackup\config.json。
func DefaultConfigPath() string {
	appData := os.Getenv("LOCALAPPDATA")
	if appData == "" {
		appData = os.TempDir()
	}
	return filepath.Join(appData, version.AppName, "config.json")
}

// Load 读取配置文件。文件不存在时返回内置默认值与 loaded=false，不算错误，
// 以便首次运行时零配置启动。
func Load(path string) (cfg *Config, loaded bool, err error) {
	if path == "" {
		path = DefaultConfigPath()
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		if errors.Is(readErr, os.ErrNotExist) {
			return Default(), false, nil
		}
		return nil, false, fmt.Errorf("读取配置文件 %s 失败: %w", path, readErr)
	}

	// 以默认值打底再反序列化，未出现的字段自动保留默认值。
	cfg = Default()
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, false, fmt.Errorf("解析配置文件 %s 失败（JSON 格式或字段名有误）: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, false, fmt.Errorf("配置文件 %s 校验未通过: %w", path, err)
	}
	return cfg, true, nil
}

// Save 原子写入配置文件（先写临时文件再改名）。
func Save(path string, cfg *Config) error {
	if path == "" {
		path = DefaultConfigPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}
	data = append(data, '\n')
	tmp := path + ".part"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("写入临时配置失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("替换配置文件失败: %w", err)
	}
	return nil
}

// ApplyEnv 用 USBBACKUP_* 环境变量覆盖配置（F-C04）。
// 支持的变量：USBBACKUP_BACKUP_SOURCE_DIR / USBBACKUP_OUTPUT_DIR /
// USBBACKUP_PUBLIC_KEY / USBBACKUP_LOG_LEVEL / USBBACKUP_USED_THRESHOLD_BYTES /
// USBBACKUP_POLL_INTERVAL_SEC / USBBACKUP_AUDIT_FILE。
func (c *Config) ApplyEnv() []string {
	var applied []string
	set := func(env string, dst *string) {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			*dst = v
			applied = append(applied, env)
		}
	}
	set("USBBACKUP_BACKUP_SOURCE_DIR", &c.BackupSourceDir)
	set("USBBACKUP_OUTPUT_DIR", &c.OutputDir)
	set("USBBACKUP_PUBLIC_KEY", &c.PublicKeyPath)
	set("USBBACKUP_LOG_LEVEL", &c.Log.Level)
	set("USBBACKUP_AUDIT_FILE", &c.AuditFile)
	if v := strings.TrimSpace(os.Getenv("USBBACKUP_USED_THRESHOLD_BYTES")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			c.Gate.UsedThresholdBytes = n
			applied = append(applied, "USBBACKUP_USED_THRESHOLD_BYTES")
		}
	}
	if v := strings.TrimSpace(os.Getenv("USBBACKUP_POLL_INTERVAL_SEC")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.Monitor.PollIntervalSec = n
			applied = append(applied, "USBBACKUP_POLL_INTERVAL_SEC")
		}
	}
	return applied
}

// ExpandPath 展开路径中的 %VAR% 与 ${VAR}，并转为绝对路径。
func ExpandPath(p string) string {
	if p == "" {
		return ""
	}
	p = expandPercentVars(p)
	p = os.ExpandEnv(p)
	if !filepath.IsAbs(p) {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
	}
	return filepath.Clean(p)
}

var percentVarRe = regexp.MustCompile(`%([A-Za-z_][A-Za-z0-9_]*)%`)

func expandPercentVars(s string) string {
	return percentVarRe.ReplaceAllStringFunc(s, func(m string) string {
		name := m[1 : len(m)-1]
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
		// Windows 上 TEMP/TMP 两者常混用，做一次同义映射增强健壮性。
		if name == "TEMP" {
			return os.TempDir()
		}
		return m
	})
}

// Validate 校验配置的合法性与一致性（F-C05）。
func (c *Config) Validate() error {
	if c.Monitor.PollIntervalSec <= 0 {
		return errors.New("monitor.poll_interval_sec 必须 > 0")
	}
	if c.Monitor.DebounceSec < 0 {
		return errors.New("monitor.debounce_sec 不能为负")
	}
	if c.Monitor.ReadyTimeoutSec <= 0 {
		return errors.New("monitor.ready_timeout_sec 必须 > 0")
	}
	if c.Monitor.JobTimeoutMin <= 0 {
		return errors.New("monitor.job_timeout_min 必须 > 0")
	}
	if c.Gate.UsedThresholdBytes < 0 {
		return errors.New("gate.used_threshold_bytes 不能为负")
	}
	if m := strings.ToLower(strings.TrimSpace(c.Detect.Mode)); m != "heuristic" && m != "marker" && m != "both" {
		return fmt.Errorf("detect.mode 取值非法 %q（可用 heuristic/marker/both）", c.Detect.Mode)
	}
	if c.Detect.MaxDepth <= 0 || c.Detect.MaxDepth > 32 {
		return errors.New("detect.max_depth 需在 1..32 之间")
	}
	if c.Detect.MaxFiles <= 0 {
		return errors.New("detect.max_files 必须 > 0")
	}
	if c.Detect.MaxHeadersBytes <= 0 || c.Detect.MaxHeadersBytes > 1<<20 {
		return errors.New("detect.max_headers_bytes 需在 1..1048576 之间")
	}
	if c.Detect.TimeoutSec <= 0 {
		return errors.New("detect.timeout_sec 必须 > 0")
	}
	if sub := strings.TrimSpace(c.AuthorizedBackupSubdir); sub == "" || strings.ContainsAny(sub, `/\:*?"<>|`) {
		return fmt.Errorf("authorized_backup_subdir 非法 %q：必须是单层目录名且不含 Windows 禁用字符", c.AuthorizedBackupSubdir)
	}
	if c.Retention.KeepPerVolume < 1 {
		return errors.New("retention.keep_per_volume 至少为 1")
	}
	if c.Archive.Threads < 0 || c.Archive.Threads > 64 {
		return errors.New("archive.threads 需在 0..64 之间")
	}
	if c.Log.MaxSizeMB <= 0 {
		c.Log.MaxSizeMB = 10
	}
	if c.Log.MaxBackups <= 0 {
		c.Log.MaxBackups = 5
	}
	return nil
}

// Summary 返回用于启动日志的关键配置摘要。
// 刻意不包含任何密钥材料。
func (c *Config) Summary() []string {
	return []string{
		fmt.Sprintf("备份源目录      = %s", c.BackupSourceDir),
		fmt.Sprintf("产物输出目录    = %s", c.OutputDir),
		fmt.Sprintf("公钥路径        = %s", c.PublicKeyPath),
		fmt.Sprintf("检测模式        = %s", c.Detect.Mode),
		fmt.Sprintf("容量门控阈值    = %d 字节 (%s)", c.Gate.UsedThresholdBytes, humanGiB(c.Gate.UsedThresholdBytes)),
		fmt.Sprintf("轮询间隔        = %ds（事件驱动为主，轮询兜底）", c.Monitor.PollIntervalSec),
		fmt.Sprintf("作业超时        = %d 分钟", c.Monitor.JobTimeoutMin),
		fmt.Sprintf("日志级别/文件   = %s / %s", c.Log.Level, c.Log.File),
	}
}

func humanGiB(n int64) string {
	return fmt.Sprintf("%.2f GiB", float64(n)/float64(GiB))
}
