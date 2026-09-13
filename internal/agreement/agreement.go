// Package agreement 记录「已阅读并同意免责声明」这一本机状态。
//
// 用途：被部署的客户端需要无人值守运行，但项目要求首次使用必须显式知情同意。
// 两者用一次性的 `accept` 命令衔接——确认一次，写成本机记录，之后静默运行。
//
// 这**不是**"跳过免责声明"的开关：
//
//   - 记录只在本机产生，必须由 `accept` 命令显式写入（交互式输入 I AGREE，
//     或带 --yes 的部署脚本）；
//   - 内容是明文、可查看、可撤销（`accept --check` / `accept --revoke`）；
//   - 撤销后立刻恢复首次确认流程。
//
// 本包不参与任何隐蔽行为：不隐藏进程、不写自启动项。
package agreement

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/immml/UsbBackUP/internal/config"
	"github.com/immml/UsbBackUP/internal/fsutil"
	"github.com/immml/UsbBackUP/internal/version"
)

// Phrase 是确认短语，必须与用户输入完全一致。
const Phrase = "I AGREE"

// Policy 是当前免责声明所依据的许可协议，写入记录便于事后核对确认的是哪一版条款。
const Policy = "CC BY-NC-SA 4.0"

// fileName 是确认记录文件名。
const fileName = "agreement.json"

// Record 是确认记录的内容。
type Record struct {
	// Tool 是确认时使用的程序名。
	Tool string `json:"tool"`
	// Version 是确认时的程序版本。
	Version string `json:"version"`
	// Policy 是当时展示的许可协议。
	Policy string `json:"policy"`
	// Phrase 必须是 Phrase 常量，防止手工伪造一个看似有效的文件。
	Phrase string `json:"phrase"`
	// AcceptedAt 是确认时间（RFC3339）。
	AcceptedAt string `json:"accepted_at"`
	// ClientName 是客户端标识（客户端模式下有值），便于区分不同部署。
	ClientName string `json:"client_name,omitempty"`
}

// Path 返回确认记录文件路径：与配置文件同目录。
func Path() string {
	return filepath.Join(filepath.Dir(config.DefaultConfigPath()), fileName)
}

// Load 读取确认记录。文件不存在时返回 ok=false 且不报错。
func Load() (Record, bool, error) {
	raw, err := os.ReadFile(fsutil.LongPath(Path()))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, false, nil
		}
		return Record{}, false, err
	}
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return Record{}, false, fmt.Errorf("确认记录 %s 格式损坏: %w", Path(), err)
	}
	// 短语不符视为无效：宁可让用户重新确认一次，也不要承认来路不明的文件。
	if r.Phrase != Phrase {
		return Record{}, false, fmt.Errorf("确认记录 %s 缺少有效确认短语，视为未确认", Path())
	}
	return r, true, nil
}

// Accepted 报告本机是否已经确认过。
//
// 读取失败也按"未确认"处理：此时会走正常的首次确认流程，用户看得见提示，
// 不会出现"自以为静默、其实从未确认过"的状态。
func Accepted() bool {
	_, ok, err := Load()
	return ok && err == nil
}

// Save 写入确认记录，目录不存在时创建。
func Save(clientName string) (Record, error) {
	r := Record{
		Tool:       version.AppName,
		Version:    version.Version,
		Policy:     Policy,
		Phrase:     Phrase,
		AcceptedAt: time.Now().Format(time.RFC3339),
		ClientName: clientName,
	}
	dir := filepath.Dir(Path())
	if err := os.MkdirAll(fsutil.LongPath(dir), 0o755); err != nil {
		return Record{}, fmt.Errorf("创建配置目录失败 %s: %w", dir, err)
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return Record{}, err
	}
	if err := os.WriteFile(fsutil.LongPath(Path()), raw, 0o600); err != nil {
		return Record{}, fmt.Errorf("写入确认记录失败 %s: %w", Path(), err)
	}
	return r, nil
}

// Revoke 撤销确认（删除记录）。记录本就不存在时不报错。
func Revoke() error {
	err := os.Remove(fsutil.LongPath(Path()))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("撤销确认失败 %s: %w", Path(), err)
	}
	return nil
}
