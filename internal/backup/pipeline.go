package backup

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackUP/internal/archive"
	"github.com/immml/UsbBackUP/internal/config"
	"github.com/immml/UsbBackUP/internal/copier"
	"github.com/immml/UsbBackUP/internal/crypto"
	"github.com/immml/UsbBackUP/internal/fsutil"
	"github.com/immml/UsbBackUP/internal/keyfile"
	"github.com/immml/UsbBackUP/internal/keystore"
	"github.com/immml/UsbBackUP/internal/version"
	"github.com/immml/UsbBackUP/internal/winvol"
)

// Run 执行一次完整的单盘作业（F-801）。
//
// 流程：
//
//	就绪等待 → 卷类型检查 → 私钥存在性检测
//	    ├─ 授权   → 分支 A：本地备份文件夹 → <USB>:\backup\
//	    └─ 未授权 → 容量门控
//	                  ├─ 超阈值 → 跳过
//	                  └─ 否则   → 分支 B：整盘 zip 流式直送混合加密 → %TEMP%\backup\*.zip.usbk
//
// 无论走哪个分支、成功或失败，最后都会写一条审计记录（F-807）。
// 全过程对源盘只读；分支 A 仅向 `<USB>:\backup\` 写入（G-04 / G-05）。
func Run(ctx context.Context, deps Deps, root string) (Result, error) {
	start := time.Now()
	res := Result{Root: root, Branch: BranchFailed}

	if deps.Cfg == nil {
		return res, errors.New("backup: 缺少配置")
	}
	cfg := deps.Cfg
	log := deps.Log

	// 作业级超时（F-106）：防挂起盘把队列拖死。
	timeout := time.Duration(cfg.Monitor.JobTimeoutMin) * time.Minute
	jobCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	norm, err := winvol.NormalizeRoot(root)
	if err != nil {
		res.Err = err.Error()
		auditBestEffort(cfg, log, res, start)
		return res, err
	}
	res.Root = norm

	// ---- 1) 就绪等待（F-305）----
	vol, err := waitReady(jobCtx, norm, time.Duration(cfg.Monitor.ReadyTimeoutSec)*time.Second)
	res.Volume = vol
	if err != nil {
		res.Branch = BranchSkipped
		res.SkipReason = SkipReasonNotReady
		res.Err = err.Error()
		auditBestEffort(cfg, log, res, start)
		return res, nil
	}

	// ---- 2) 卷类型检查（F-301）----
	if !vol.Removable && !deps.AllowFixed {
		res.Branch = BranchSkipped
		res.SkipReason = SkipReasonNotRemovable
		log.Info("作业跳过：非可移动卷", "root", norm, "type", winvol.DriveTypeName(vol.DriveType))
		auditBestEffort(cfg, log, res, start)
		return res, nil
	}

	// ---- 3) 私钥存在性检测（F-2xx）----
	if deps.Matcher != nil {
		det, derr := keyfile.Scan(jobCtx, keyfile.Options{
			Root:               norm,
			Matcher:            deps.Matcher,
			Detect:             cfg.Detect,
			AllowedFingerprint: deps.AllowedFingerprint,
		})
		res.Detect = det
		res.Authorized = det.Authorized
		if derr != nil {
			// 检测失败不致命：按"未授权"处理，即保守地走只读打包分支。
			log.Warn("私钥存在性检测失败，按未授权处理", "root", norm, "err", derr)
		}
	} else {
		log.Warn("未提供检测器，本次按未授权处理", "root", norm)
	}

	if res.Authorized {
		return runAuthorized(jobCtx, deps, norm, vol, res, start)
	}
	return runArchive(jobCtx, deps, norm, vol, res, start)
}

// waitReady 轮询等待卷就绪（刚插入时卷可能尚未挂载完成）。
func waitReady(ctx context.Context, root string, timeout time.Duration) (winvol.Volume, error) {
	deadline := time.Now().Add(timeout)
	var last winvol.Volume
	var lastErr error

	for {
		v, err := winvol.Query(root)
		last, lastErr = v, err
		if err == nil && v.Ready {
			return v, nil
		}
		// 非可移动卷不必等就绪：直接带着信息返回，由上层决定跳过。
		if errors.Is(err, winvol.ErrNotRemovable) {
			return v, nil
		}
		if time.Now().After(deadline) {
			if lastErr == nil {
				lastErr = winvol.ErrNotReady
			}
			return last, fmt.Errorf("等待卷就绪超时: %w", lastErr)
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// runAuthorized 执行分支 A：把本地备份文件夹回写到 `<USB>:\backup\`（F-401 ~ F-410）。
func runAuthorized(ctx context.Context, deps Deps, root string, vol winvol.Volume, res Result, start time.Time) (Result, error) {
	cfg := deps.Cfg
	log := deps.Log

	opt := copier.Options{
		SourceDir:            config.ExpandPath(cfg.BackupSourceDir),
		DestRoot:             root,
		SubDir:               cfg.AuthorizedBackupSubdir,
		Overwrite:            deps.CopyOverwrite,
		DryRun:               deps.DryRun,
		VerifyHash:           deps.CopyVerifyHash,
		MarginPercent:        cfg.Gate.FreeSpaceMarginPercent,
		MaxFiles:             deps.CopyMaxFiles,
		WriteManifest:        !deps.DryRun,
		PublicKeyFingerprint: deps.AllowedFingerprint,
	}

	target, err := copier.Check(opt)
	if err != nil {
		res.Branch = BranchFailed
		res.Err = err.Error()
		log.Error("分支 A 前置校验未通过", "root", root, "err", err)
		auditBestEffort(cfg, log, res, start)
		return res, err
	}
	log.Info("检测到私钥 → 执行分支 A（本地备份回写）",
		"root", root, "source", opt.SourceDir, "target", target)

	st, err := copier.Copy(ctx, opt)
	res.Copy = &st
	if err != nil {
		res.Branch = BranchFailed
		res.Err = err.Error()
		log.Error("分支 A 失败", "root", root, "err", err)
		auditBestEffort(cfg, log, res, start)
		return res, err
	}

	res.Branch = BranchAuthorized
	res.OK = st.FilesFailed == 0 && st.VerifyFailures == 0
	res.Duration = time.Since(start)

	log.Info("分支 A 完成",
		"root", root,
		"copied", st.FilesCopied,
		"skipped", st.FilesSkipped,
		"failed", st.FilesFailed,
		"verify_failures", st.VerifyFailures,
		"bytes", fsutil.HumanBytes(st.BytesCopied),
		"duration", st.Duration.String())
	if st.VerifyFailures > 0 {
		log.Warn("分支 A 存在复制后校验不一致的文件", "root", root, "count", st.VerifyFailures)
	}
	auditBestEffort(cfg, log, res, start)
	return res, nil
}

// runArchive 执行分支 B：容量门控 + 整盘打包 + 混合加密（F-304 / F-501 / F-601）。
func runArchive(ctx context.Context, deps Deps, root string, vol winvol.Volume, res Result, start time.Time) (Result, error) {
	cfg := deps.Cfg
	log := deps.Log

	// ---- 容量门控（F-304）----
	policy := winvol.EvaluateGate(vol, cfg.Gate.UsedThresholdBytes, cfg.Gate.MaxTotalBytes)
	res.Gate = policy
	if !policy.Proceed {
		res.Branch = BranchSkipped
		res.SkipReason = SkipReasonOverThreshold
		res.OK = true
		res.Duration = time.Since(start)
		log.Info("未检测到私钥，容量门控跳过",
			"root", root,
			"used", fsutil.HumanBytes(vol.UsedBytes),
			"threshold", fsutil.HumanBytes(cfg.Gate.UsedThresholdBytes),
			"reason", policy.Reason)
		auditBestEffort(cfg, log, res, start)
		return res, nil
	}

	if deps.DryRun {
		res.Branch = BranchArchive
		res.OK = true
		res.Duration = time.Since(start)
		log.Info("dry-run：将通过门控并执行整盘打包加密", "root", root, "product", ProductName(vol))
		return res, nil
	}

	// ---- 载入公钥（F-601）----
	pub, fp, err := loadEncryptionKey(cfg, deps.EmbeddedPublicKey)
	if err != nil {
		res.Branch = BranchFailed
		res.Err = err.Error()
		log.Error("无法载入公钥，分支 B 中止", "root", root, "err", err)
		auditBestEffort(cfg, log, res, start)
		return res, err
	}

	// ---- 产物路径（F-602 / F-603）----
	outDir := config.ExpandPath(cfg.OutputDir)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		res.Branch = BranchFailed
		res.Err = err.Error()
		auditBestEffort(cfg, log, res, start)
		return res, err
	}
	// 源守卫（F-507）：产物目录不得位于被扫描的卷之内，否则会递归套娃。
	if err := archive.CheckSourceGuard(root, outDir); err != nil {
		res.Branch = BranchFailed
		res.Err = err.Error()
		log.Error("源守卫拒绝执行", "root", root, "output", outDir, "err", err)
		auditBestEffort(cfg, log, res, start)
		return res, err
	}
	finalPath := UniqueProductPath(outDir, vol, start)
	tmpPath := finalPath + ".part"
	res.ProductPath = finalPath

	log.Info("未检测到私钥且容量在阈值内 → 执行分支 B（整盘打包 + 混合加密）",
		"root", root,
		"used", fsutil.HumanBytes(vol.UsedBytes),
		"product", filepath.Base(finalPath))

	// ---- 打包与加密以管道串联：明文 zip 不落盘（决策 D-03）----
	out, err := os.OpenFile(fsutil.LongPath(tmpPath), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		res.Branch = BranchFailed
		res.Err = err.Error()
		auditBestEffort(cfg, log, res, start)
		return res, err
	}

	pr, pw := io.Pipe()
	type zipOutcome struct {
		stats archive.ZipStats
		err   error
	}
	zipDone := make(chan zipOutcome, 1)

	go func() {
		cw := archive.NewCountingWriter(pw)
		st, zerr := archive.ZipStream(ctx, cw, archive.ZipOptions{
			SourceRoot:             root,
			Excludes:               cfg.Archive.Excludes,
			StoreAlreadyCompressed: cfg.Archive.StoreAlreadyCompressed,
			Threads:                cfg.Archive.Threads,
		})
		// 必须用 CloseWithError 把错误带给加密侧，否则加密侧会一直阻塞在 Read 上。
		_ = pw.CloseWithError(zerr)
		zipDone <- zipOutcome{stats: st, err: zerr}
	}()

	sum, encErr := crypto.EncryptStream(out, pr, crypto.EncryptOptions{
		PublicKey:            pub,
		PublicKeyFingerprint: fp,
		ChunkSize:            crypto.DefaultChunkSize,
	})

	zs := <-zipDone
	res.Zip = zs.stats
	res.Encrypt = sum

	closeErr := out.Close()
	_ = pr.Close()

	if encErr != nil || zs.err != nil {
		// 失败：清理半成品，绝不留一个看起来完整的坏容器（F-801）。
		_ = os.Remove(fsutil.LongPath(tmpPath))
		res.Branch = BranchFailed
		if encErr != nil {
			res.Err = encErr.Error()
			log.Error("分支 B 加密失败", "root", root, "err", encErr)
		} else {
			res.Err = zs.err.Error()
			log.Error("分支 B 打包失败", "root", root, "err", zs.err)
		}
		auditBestEffort(cfg, log, res, start)
		return res, fmt.Errorf("分支 B 失败: %s", res.Err)
	}
	if closeErr != nil {
		_ = os.Remove(fsutil.LongPath(tmpPath))
		res.Branch = BranchFailed
		res.Err = closeErr.Error()
		auditBestEffort(cfg, log, res, start)
		return res, closeErr
	}

	// ---- 落盘：临时文件改名，保证原子性 ----
	if err := os.Rename(fsutil.LongPath(tmpPath), fsutil.LongPath(finalPath)); err != nil {
		_ = os.Remove(fsutil.LongPath(tmpPath))
		res.Branch = BranchFailed
		res.Err = fmt.Sprintf("重命名产物失败: %v", err)
		auditBestEffort(cfg, log, res, start)
		return res, err
	}

	res.Branch = BranchArchive
	res.OK = true
	res.Duration = time.Since(start)

	log.Info("分支 B 完成",
		"root", root,
		"files", zs.stats.Files,
		"skipped", zs.stats.Skipped,
		"raw", fsutil.HumanBytes(zs.stats.RawBytes),
		"zip", fsutil.HumanBytes(sum.PlainBytes),
		"cipher", fsutil.HumanBytes(sum.CipherBytes),
		"product", filepath.Base(finalPath))

	// 保留策略（F-806）：只清理本工具生成的同类产物。
	if n, rerr := EnforceRetention(outDir, ProductBase(vol), cfg.Retention.KeepPerVolume, log); rerr != nil {
		log.Warn("保留策略执行失败（不影响本次备份）", "err", rerr)
	} else if n > 0 {
		log.Info("保留策略已清理旧产物", "removed", n, "keep", cfg.Retention.KeepPerVolume)
	}

	auditBestEffort(cfg, log, res, start)
	return res, nil
}

// loadEncryptionKey 取得加密用公钥与指纹。
//
// 客户端模式下公钥内嵌在可执行文件里（deps.EmbeddedPublicKey），
// 优先于配置里的路径——客户端不能依赖外部公钥文件。
func loadEncryptionKey(cfg *config.Config, embedded *rsa.PublicKey) (*rsa.PublicKey, [32]byte, error) {
	var zero [32]byte
	if embedded != nil {
		if embedded.N.BitLen() < keystore.MinRSAKeyBits {
			return nil, zero, fmt.Errorf("内嵌公钥仅 %d 位，低于下限 %d 位", embedded.N.BitLen(), keystore.MinRSAKeyBits)
		}
		fp, _, err := keystore.PublicKeyFingerprint(embedded)
		if err != nil {
			return nil, zero, err
		}
		return embedded, fp, nil
	}
	p := config.ExpandPath(cfg.PublicKeyPath)
	if strings.TrimSpace(p) == "" {
		return nil, zero, errors.New("未配置公钥路径，无法执行加密（请先运行 usbkeygen generate 与 use）")
	}
	pub, err := keystore.LoadPublicKey(p)
	if err != nil {
		return nil, zero, fmt.Errorf("读取公钥 %s 失败: %w", p, err)
	}
	fp, _, err := keystore.PublicKeyFingerprint(pub)
	if err != nil {
		return nil, zero, err
	}
	return pub, fp, nil
}

// auditBestEffort 写审计记录，失败只记录日志（F-807）。
func auditBestEffort(cfg *config.Config, log interface {
	Warn(string, ...any)
}, res Result, start time.Time) {
	if cfg == nil {
		return
	}
	rec := ResultToAudit(res, start)
	if err := AppendAudit(config.ExpandPath(cfg.AuditFile), rec); err != nil {
		log.Warn("写入审计记录失败（不影响作业结果）", "err", err)
	}
}

// ResultToAudit 把作业结果转成审计记录。
//
// 注意：这里**不含**任何文件名清单、私钥文件名或文件内容（G-02）。
func ResultToAudit(res Result, start time.Time) AuditRecord {
	rec := AuditRecord{
		Time:         start.Format(time.RFC3339),
		Tool:         version.AppName,
		ToolVersion:  version.Version,
		Root:         res.Root,
		Label:        res.Volume.Label,
		FileSystem:   res.Volume.FileSystem,
		SerialNumber: res.Volume.SerialNumber,
		TotalBytes:   res.Volume.TotalBytes,
		FreeBytes:    res.Volume.FreeBytes,
		UsedBytes:    res.Volume.UsedBytes,
		Branch:       res.Branch,
		HasKeyfile:   res.Detect.Authorized,
		KeyfileHits:  res.Detect.HitCount,
		KeyfileKinds: res.Detect.Kinds,
		ScannedFiles: res.Detect.FilesScanned,
		SkipReason:   res.SkipReason,
		OK:           res.OK,
		Err:          res.Err,
		DurationSec:  res.Duration.Seconds(),
	}
	if res.Detect.Duration > 0 {
		rec.DetectSeconds = res.Detect.Duration.Seconds()
	}
	if res.ProductPath != "" {
		rec.Product = filepath.Base(res.ProductPath)
	}
	if res.Copy != nil {
		rec.Files = res.Copy.FilesCopied + res.Copy.FilesSkipped
		rec.RawBytes = res.Copy.BytesCopied
	}
	if res.Zip.Files > 0 {
		rec.Files = res.Zip.Files
		rec.RawBytes = res.Zip.RawBytes
	}
	if res.Encrypt.CipherBytes > 0 {
		rec.CipherBytes = res.Encrypt.CipherBytes
	}
	return rec
}

// CleanupPartials 清理输出目录中的 `.part` 半成品（F-809）。
//
// 只删除本工具自己命名的临时文件，绝不触碰其它文件。
func CleanupPartials(outputDir string) (int, error) {
	dir := config.ExpandPath(outputDir)
	entries, err := os.ReadDir(fsutil.LongPath(dir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".usbk.part") && !strings.HasSuffix(name, ".zip.usbk.part") {
			continue
		}
		if err := os.Remove(fsutil.LongPath(filepath.Join(dir, name))); err == nil {
			removed++
		}
	}
	return removed, nil
}
