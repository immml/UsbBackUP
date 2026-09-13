package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/immml/UsbBackUP/internal/archive"
	"github.com/immml/UsbBackUP/internal/cli"
	"github.com/immml/UsbBackUP/internal/config"
	"github.com/immml/UsbBackUP/internal/copier"
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

// loadConfig 加载配置：命令行 --config > 默认路径 > 内置默认，并叠加环境变量。
//
// cfgPath 由 cli.ExtractGlobalFlags 在入口统一取出，此处不再自行解析参数。
func loadConfig(cfgPath string, stderr io.Writer) (*config.Config, string, int) {
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
