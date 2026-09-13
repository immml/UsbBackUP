package backup

import (
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/immml/UsbBackUP/internal/config"
	"github.com/immml/UsbBackUP/internal/fsutil"
	"github.com/immml/UsbBackUP/internal/winvol"
)

// ProductBase 返回某卷的产物基名（不含扩展名），用于同卷产物归组。
//
// 例：卷标 "MyUSB" → "MyUSB"；空卷标 → "VOL_E"。
func ProductBase(v winvol.Volume) string {
	name := ProductName(v)
	return strings.TrimSuffix(name, ".zip.usbk")
}

// productFilesFor 列出目录中属于同一卷基名的产物文件（只认本工具自己的命名规则）。
//
// 匹配形态：
//
//	{base}.zip.usbk
//	{base}_YYYYMMDD_HHMMSS.zip.usbk
func productFilesFor(dir, base string) ([]string, error) {
	entries, err := os.ReadDir(fsutil.LongPath(dir))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".zip.usbk") {
			continue
		}
		stem := strings.TrimSuffix(name, ".zip.usbk")
		if stem == base || strings.HasPrefix(stem, base+"_") {
			out = append(out, filepath.Join(dir, name))
		}
	}
	return out, nil
}

// EnforceRetention 对同一卷的产物执行保留策略（F-806）：
// 只保留最近 keep 份，删除最旧的若干份。
//
// 安全约束：**只删除符合本工具命名规则的产物文件**，
// 绝不删除目录中的其它任何文件，也绝不触碰源盘（G-04）。
func EnforceRetention(dir, base string, keep int, log *slog.Logger) (int, error) {
	if keep < 1 {
		keep = 1
	}
	files, err := productFilesFor(dir, base)
	if err != nil {
		return 0, err
	}
	if len(files) <= keep {
		return 0, nil
	}

	type item struct {
		path string
		mod  time.Time
	}
	items := make([]item, 0, len(files))
	for _, p := range files {
		fi, err := os.Stat(fsutil.LongPath(p))
		if err != nil {
			continue
		}
		items = append(items, item{path: p, mod: fi.ModTime()})
	}
	// 新 → 旧排序，前 keep 份保留。
	sort.Slice(items, func(i, j int) bool { return items[i].mod.After(items[j].mod) })

	removed := 0
	for _, it := range items[min(keep, len(items)):] {
		if err := os.Remove(fsutil.LongPath(it.path)); err != nil {
			if log != nil {
				log.Warn("删除旧产物失败", "file", filepath.Base(it.path), "err", err)
			}
			continue
		}
		removed++
		if log != nil {
			log.Info("已清理旧产物", "file", filepath.Base(it.path))
		}
	}
	return removed, nil
}

// OutputDirOf 返回配置中生效的产物输出目录（已展开环境变量与绝对化）。
func OutputDirOf(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return config.ExpandPath(cfg.OutputDir)
}
