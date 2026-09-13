package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/immml/UsbBackUP/internal/archive"
	"github.com/immml/UsbBackUP/internal/cli"
	"github.com/immml/UsbBackUP/internal/config"
	"github.com/immml/UsbBackUP/internal/copier"
	"github.com/immml/UsbBackUP/internal/embedcfg"
	"github.com/immml/UsbBackUP/internal/keystore"
)

// loadPubFingerprint 读取并计算已配置公钥的指纹文本。
// 供显式授权标记（F-203）比对使用；失败时返回错误由调用方降级。
func loadPubFingerprint(path string) (string, error) {
	pub, err := keystore.LoadPublicKey(config.ExpandPath(path))
	if err != nil {
		return "", fmt.Errorf("读取公钥失败: %w", err)
	}
	_, fp, err := keystore.PublicKeyFingerprint(pub)
	if err != nil {
		return "", err
	}
	return fp, nil
}

// keystoreLoadPub 仅校验公钥可加载，用于 config-check。
func keystoreLoadPub(path string) (any, error) {
	if path == "" {
		return nil, errors.New("未配置公钥路径")
	}
	pub, err := keystore.LoadPublicKey(path)
	if err != nil {
		return nil, err
	}
	if pub.N.BitLen() < keystore.MinRSAKeyBits {
		return nil, fmt.Errorf("公钥仅 %d 位，低于下限 %d 位", pub.N.BitLen(), keystore.MinRSAKeyBits)
	}
	return pub, nil
}

// copierTarget 校验并返回授权分支的回写目标目录（F-401 / F-406）。
func copierTarget(cfg *config.Config, destRoot string) (string, error) {
	return copier.Check(copier.Options{
		SourceDir: config.ExpandPath(cfg.BackupSourceDir),
		DestRoot:  destRoot,
		SubDir:    cfg.AuthorizedBackupSubdir,
	})
}

// archiveCheckSourceGuard 校验输出目录不在扫描源之内（G-08 防递归套娃）。
func archiveCheckSourceGuard(source, output string) error {
	if source == "" || output == "" {
		return errors.New("扫描源与输出目录都必须可解析")
	}
	return archive.CheckSourceGuard(source, output)
}

// loadConfig 加载配置，优先级：内嵌配置（客户端模式）> 命令行 --config > 默认路径 > 内置默认。
//
// cfgPath 由 cli.ExtractGlobalFlags 在入口统一取出，此处不再自行解析参数。
//
// 客户端模式下配置已硬编码进可执行文件，**忽略外部配置文件与环境变量**：
// 客户端会运行在他人可控的机器上，若允许外部文件覆盖，
// "硬编码"就失去意义（改配置即可改行为）。
func loadConfig(cfgPath string, stderr io.Writer) (*config.Config, string, int) {
	if clientBuild.ok {
		if strings.TrimSpace(cfgPath) != "" {
			fmt.Fprintf(stderr, "提示：本程序为生成器产出的客户端，配置已内嵌，--config %s 已忽略。\n", cfgPath)
		}
		return clientBuild.cfg, "<内嵌于可执行文件>", cli.ExitOK
	}

	cfg, loaded, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return nil, "", cli.ExitRuntime
	}
	cfg.ApplyEnv()
	resolved := cfgPath
	if resolved == "" {
		resolved = config.DefaultConfigPath()
	}
	if !loaded {
		fmt.Fprintf(stderr, "提示：未找到配置文件 %s，本次使用内置默认值。\n", resolved)
	}
	return cfg, resolved, cli.ExitOK
}

// clientBuild 保存从自身可执行文件尾部读到的内嵌内容（客户端模式）。
var clientBuild struct {
	ok      bool
	cfg     *config.Config
	pub     *rsa.PublicKey
	name    string
	builtAt string
	builder string
}

// loadEmbedded 尝试读取自身可执行文件尾部的内嵌配置。
//
// 普通构建（非生成器产出）没有这个块，直接返回，行为与之前完全一致。
// 读取失败只警告不中断：配置损坏时宁可退回常规路径让人排障，
// 也不要静默使用一个来源不明的配置。
func loadEmbedded(stderr io.Writer) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	p, err := embedcfg.Read(exe)
	if err != nil {
		if !errors.Is(err, embedcfg.ErrNotEmbedded) {
			fmt.Fprintf(stderr, "警告：读取内嵌配置失败，已退回常规配置路径：%v\n", err)
		}
		return
	}
	cfg := config.Default()
	if len(p.ConfigJSON) > 0 {
		// 以默认值打底再覆盖，未写到的字段保留默认。
		if err := json.Unmarshal(p.ConfigJSON, cfg); err != nil {
			fmt.Fprintf(stderr, "警告：内嵌配置解析失败，已退回常规配置路径：%v\n", err)
			return
		}
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "警告：内嵌配置校验失败，已退回常规配置路径：%v\n", err)
		return
	}
	pub, err := keystore.ParsePublicKeyPEM([]byte(p.PublicKeyPEM))
	if err != nil {
		fmt.Fprintf(stderr, "警告：内嵌公钥解析失败，已退回常规配置路径：%v\n", err)
		return
	}
	clientBuild.ok = true
	clientBuild.cfg = cfg
	clientBuild.pub = pub
	clientBuild.name = p.ClientName
	clientBuild.builtAt = p.BuiltAt
	clientBuild.builder = p.BuilderVersion
}

// clientInfoLines 返回客户端模式的标识信息，用于启动摘要。
func clientInfoLines() []string {
	if !clientBuild.ok {
		return nil
	}
	lines := []string{"运行模式        = 客户端（配置与公钥已内嵌，忽略外部配置文件）"}
	if clientBuild.name != "" {
		lines = append(lines, fmt.Sprintf("客户端标识      = %s", clientBuild.name))
	}
	if clientBuild.builtAt != "" {
		lines = append(lines, fmt.Sprintf("生成时间        = %s", clientBuild.builtAt))
	}
	if clientBuild.builder != "" {
		lines = append(lines, fmt.Sprintf("生成器版本      = %s", clientBuild.builder))
	}
	return lines
}
