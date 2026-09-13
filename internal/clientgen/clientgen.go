// Package clientgen 把「配置 + 公钥」打包成一个内嵌式的客户端可执行文件。
//
// `usbkeygen build-client`（命令行）与 `usbsetup`（交互式向导）共用这一份实现，
// 避免出现两套生成逻辑、产物行为不一致。
//
// 产出的客户端只内嵌**公钥**——任何私钥特征都会在 EnsureNoSecret 中被拒绝，
// 因为客户端会落在他人可控的机器上，内嵌即等于公开。
package clientgen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackUP/internal/config"
	"github.com/immml/UsbBackUP/internal/embedcfg"
	"github.com/immml/UsbBackUP/internal/fsutil"
	"github.com/immml/UsbBackUP/internal/keystore"
	"github.com/immml/UsbBackUP/internal/version"
)

// Options 是生成客户端的全部输入。
type Options struct {
	// PublicKeyPEM 是公钥 PEM 的**文件内容**（必填）。
	PublicKeyPEM []byte
	// Template 是客户端模板 exe 路径；为空时取与本程序同目录的 usbbackup.exe。
	Template string
	// Output 是客户端输出路径（必填）。
	Output string
	// BaseConfig 是基础配置；为 nil 时用内置默认配置。
	BaseConfig *config.Config
	// ClientName 是客户端标识，写入内嵌配置便于溯源。
	ClientName string
	// OutputDir / SourceDir / Threshold / MaxTotal 是对配置的覆盖项，空串表示不覆盖。
	OutputDir string
	SourceDir string
	Threshold string
	MaxTotal  string
	// Force 允许覆盖已存在的输出文件。
	Force bool
}

// Result 描述生成结果，供命令行与向导打印摘要。
type Result struct {
	OutputPath    string
	TemplatePath  string
	ClientName    string
	KeyBits       int
	Fingerprint   string
	OutputDir     string
	ThresholdText string
	MaxTotalText  string
	SourceDir     string
	BuiltAt       string
	BuilderVer    string
	Config        *config.Config
}

// Build 校验输入并生成客户端。
//
// 步骤：解析公钥 → 组装配置 → 校验模板 → 追加内嵌块 → 回读自检。
// 回读自检是必要的：产物一旦生成就会被拷到别的机器上，
// 在这里多花几毫秒验证，胜过事后发现内嵌块损坏。
func Build(opt Options) (Result, error) {
	var zero Result
	if len(opt.PublicKeyPEM) == 0 {
		return zero, fmt.Errorf("缺少公钥内容")
	}
	if strings.TrimSpace(opt.Output) == "" {
		return zero, fmt.Errorf("缺少客户端输出路径")
	}

	pubKey, err := keystore.ParsePublicKeyPEM(opt.PublicKeyPEM)
	if err != nil {
		return zero, err
	}
	fpBytes, fpText, err := keystore.PublicKeyFingerprint(pubKey)
	if err != nil {
		return zero, fmt.Errorf("计算公钥指纹失败: %w", err)
	}

	cfg := opt.BaseConfig
	if cfg == nil {
		cfg = config.Default()
	}
	if strings.TrimSpace(opt.OutputDir) != "" {
		cfg.OutputDir = opt.OutputDir
	}
	if strings.TrimSpace(opt.SourceDir) != "" {
		cfg.BackupSourceDir = opt.SourceDir
	}
	if strings.TrimSpace(opt.Threshold) != "" {
		n, err := config.ParseSize(opt.Threshold)
		if err != nil {
			return zero, fmt.Errorf("容量阈值无法解析: %w", err)
		}
		cfg.Gate.UsedThresholdBytes = n
		cfg.Gate.UsedThreshold = opt.Threshold
	}
	if strings.TrimSpace(opt.MaxTotal) != "" {
		n, err := config.ParseSize(opt.MaxTotal)
		if err != nil {
			return zero, fmt.Errorf("打包上限无法解析: %w", err)
		}
		cfg.Gate.MaxTotalBytes = n
	}
	// 客户端不读取外部配置文件，这里只作展示用途。
	cfg.PublicKeyPath = "<内嵌于客户端>"
	if err := cfg.Validate(); err != nil {
		return zero, fmt.Errorf("配置校验失败: %w", err)
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return zero, fmt.Errorf("序列化配置失败: %w", err)
	}

	tpl := strings.TrimSpace(opt.Template)
	if tpl == "" {
		tpl = DefaultTemplate()
	}
	if fi, err := os.Stat(tpl); err != nil {
		return zero, fmt.Errorf("找不到客户端模板 %s: %w", tpl, err)
	} else if fi.IsDir() {
		return zero, fmt.Errorf("模板 %s 是目录，应指向 usbbackup.exe", tpl)
	}

	outPath, err := filepath.Abs(opt.Output)
	if err != nil {
		return zero, fmt.Errorf("解析输出路径失败: %w", err)
	}
	if _, err := os.Stat(outPath); err == nil && !opt.Force {
		return zero, fmt.Errorf("%s 已存在（如需覆盖请显式确认）", outPath)
	}

	payload := embedcfg.Payload{
		ConfigJSON:     cfgJSON,
		PublicKeyPEM:   string(opt.PublicKeyPEM),
		ClientName:     strings.TrimSpace(opt.ClientName),
		BuiltAt:        time.Now().Format(time.RFC3339),
		BuilderVersion: version.Version,
	}
	if err := embedcfg.Append(tpl, outPath, payload); err != nil {
		return zero, err
	}

	// 回读自检。
	got, err := embedcfg.Read(outPath)
	if err != nil {
		return zero, fmt.Errorf("客户端自检失败（读回内嵌配置时出错）: %w", err)
	}
	gotPub, err := keystore.ParsePublicKeyPEM([]byte(got.PublicKeyPEM))
	if err != nil {
		return zero, fmt.Errorf("客户端自检失败（内嵌公钥不可用）: %w", err)
	}
	gotFP, _, err := keystore.PublicKeyFingerprint(gotPub)
	if err != nil || gotFP != fpBytes {
		return zero, fmt.Errorf("客户端自检失败（回读的公钥指纹与源不一致）")
	}

	return Result{
		OutputPath:    outPath,
		TemplatePath:  tpl,
		ClientName:    got.ClientName,
		KeyBits:       pubKey.N.BitLen(),
		Fingerprint:   fpText,
		OutputDir:     cfg.OutputDir,
		ThresholdText: humanThreshold(cfg),
		MaxTotalText:  humanLimit(cfg.Gate.MaxTotalBytes),
		SourceDir:     cfg.BackupSourceDir,
		BuiltAt:       got.BuiltAt,
		BuilderVer:    got.BuilderVersion,
		Config:        cfg,
	}, nil
}

// DefaultTemplate 返回默认模板路径：与本程序同目录的 usbbackup.exe。
func DefaultTemplate() string {
	exe, err := os.Executable()
	if err != nil {
		return "usbbackup.exe"
	}
	return filepath.Join(filepath.Dir(exe), "usbbackup.exe")
}

// humanThreshold 把阈值显示成人类可读形式。
func humanThreshold(c *config.Config) string {
	if s := strings.TrimSpace(c.Gate.UsedThreshold); s != "" {
		return fmt.Sprintf("%s（%d 字节）", s, c.Gate.UsedThresholdBytes)
	}
	return fmt.Sprintf("%d 字节", c.Gate.UsedThresholdBytes)
}

// humanLimit 把上限显示成人类可读形式；0 表示不限制。
func humanLimit(n int64) string {
	if n <= 0 {
		return "不限制"
	}
	return fsutil.HumanBytes(n)
}
