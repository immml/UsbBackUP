package main

import (
	"context"
	"fmt"

	"github.com/immml/UsbBackup/internal/config"
	"github.com/immml/UsbBackup/internal/copier"
	"github.com/immml/UsbBackup/internal/keystore"
)

// osCtx 返回一个未附加取消信号的上下文，供单次只读诊断使用。
func osCtx() context.Context { return context.Background() }

// loadPubFingerprint 读取并计算已配置公钥的指纹文本。
// 供显式授权标记（F-203）比对使用；失败时返回空串由调用方降级。
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

// copierTarget 校验并返回授权分支的回写目标目录（F-401 / F-406）。
func copierTarget(cfg *config.Config, destRoot string) (string, error) {
	return copier.Check(copier.Options{
		SourceDir: config.ExpandPath(cfg.BackupSourceDir),
		DestRoot:  destRoot,
		SubDir:    cfg.AuthorizedBackupSubdir,
	})
}
