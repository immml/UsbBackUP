// Package embedcfg 把「配置 + 公钥」硬编码进可执行文件尾部，
// 用于生成器产出的客户端：客户端无需 config.json、无需单独分发公钥，
// 双击即可按预设行为运行。
//
// # 为什么用尾部追加（overlay）而不是重新编译
//
// 生成器要在目标机器上直接产出可用的 exe，不能假设那里装了 Go 工具链。
// PE 文件尾部追加数据不影响程序加载运行（自解压安装包用的就是同一招），
// 因此做法是：复制一份客户端模板 exe，在末尾追加一个带校验和的配置块。
//
// # 块布局（从文件末尾往前）
//
//	[ payload ............ ]
//	[ 32B payload SHA-256  ]
//	[  4B version   LE     ]
//	[  8B payloadLen LE    ]
//	[  8B magic            ]  ← 文件最后 8 字节
//
// # 安全边界
//
// 内嵌内容只能是**配置与公钥**。任何把私钥塞进去的尝试都会在
// EnsureNoSecret 中被拒绝——客户端会落到别人机器上，私钥一旦内嵌
// 就等于公开，整个加密体系失效。
package embedcfg

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// magic 是尾部块标识，长度必须恰好 8 字节。
const magic = "USBBKCFG"

// Version 是当前块格式版本。
const Version uint32 = 1

// tailFixed 是 payload 之外的固定尾部字节数：sha256(32) + version(4) + len(8) + magic(8)。
const tailFixed = 32 + 4 + 8 + len(magic)

// ErrNotEmbedded 表示文件尾部没有配置块（普通构建，不是客户端）。
var ErrNotEmbedded = errors.New("embedcfg: 该文件不是生成器产出的客户端（尾部无配置块）")

// ErrCorrupted 表示配置块存在但内容损坏（校验和不符或被截断）。
var ErrCorrupted = errors.New("embedcfg: 内嵌配置块已损坏")

// ErrSecretRefused 表示待内嵌的内容里出现了私钥材料。
var ErrSecretRefused = errors.New("embedcfg: 拒绝内嵌疑似私钥内容（客户端只可内嵌公钥与配置）")

// Payload 是内嵌进客户端的内容。
type Payload struct {
	// ConfigJSON 是完整配置的 JSON 表示（字段与 config.Config 一致）。
	ConfigJSON json.RawMessage `json:"config"`
	// PublicKeyPEM 是公钥 PEM 文本（只能是公钥）。
	PublicKeyPEM string `json:"public_key_pem"`
	// ClientName 是客户端标识，用于日志与产物命名，可为空。
	ClientName string `json:"client_name,omitempty"`
	// BuiltAt 是生成时间（RFC3339）。
	BuiltAt string `json:"built_at"`
	// BuilderVersion 是生成该客户端的生成器版本，便于事后溯源。
	BuilderVersion string `json:"builder_version"`
}

// Marshal 序列化并做私钥守卫检查。
func (p Payload) Marshal() ([]byte, error) {
	if err := EnsureNoSecret(p); err != nil {
		return nil, err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("序列化内嵌配置失败: %w", err)
	}
	return b, nil
}

// Unmarshal 解析 payload 字节。
func Unmarshal(b []byte) (Payload, error) {
	var p Payload
	if err := json.Unmarshal(b, &p); err != nil {
		return Payload{}, fmt.Errorf("解析内嵌配置失败: %w", err)
	}
	if err := EnsureNoSecret(p); err != nil {
		return Payload{}, err
	}
	return p, nil
}

// EnsureNoSecret 拒绝任何疑似私钥的内容被内嵌。
//
// 客户端会被部署到他人可控的机器上，内嵌内容等同于公开。
// 这里做宁可误报也不可漏报的字面检查，挡住"顺手把 key.pem 一起塞进去"的误操作。
func EnsureNoSecret(p Payload) error {
	// 去空白与分隔符后做包含判断，避免 "PRIVATE  KEY" 之类变体绕过。
	probe := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", "-", "").Replace(p.PublicKeyPEM)
	if strings.Contains(strings.ToUpper(probe), "PRIVATEKEY") {
		return fmt.Errorf("%w: public_key_pem 中包含私钥特征", ErrSecretRefused)
	}
	if strings.Contains(strings.ToUpper(probe), "ENCRYPTEDPRIVATEKEY") {
		return fmt.Errorf("%w: public_key_pem 中包含加密私钥特征", ErrSecretRefused)
	}
	cfgText := strings.ToUpper(string(p.ConfigJSON))
	if strings.Contains(cfgText, "PRIVATE_KEY") && strings.Contains(cfgText, "BEGIN") {
		return fmt.Errorf("%w: config 中出现私钥 PEM", ErrSecretRefused)
	}
	return nil
}

// Append 复制 src 到 dst 并在尾部追加配置块。
//
// src 必须是一个尚未内嵌过配置块的客户端模板；重复追加会被拒绝，
// 否则同一文件里会有两个块，读取时无法确定该用哪个。
func Append(src, dst string, p Payload) error {
	if has, err := Has(src); err == nil && has {
		return fmt.Errorf("模板 %s 已经内嵌过配置，请换用未经处理的原始构建产物", src)
	}
	body, err := p.Marshal()
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("打开模板失败: %w", err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("创建客户端失败: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("复制模板失败: %w", err)
	}
	if err := writeBlock(out, body); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("写入客户端失败: %w", err)
	}
	return nil
}

// writeBlock 写出 [payload][sha256][version][len][magic]。
func writeBlock(w io.Writer, body []byte) error {
	sum := sha256.Sum256(body)
	var meta [tailFixed]byte
	copy(meta[0:32], sum[:])
	binary.LittleEndian.PutUint32(meta[32:36], Version)
	binary.LittleEndian.PutUint64(meta[36:44], uint64(len(body)))
	copy(meta[44:44+len(magic)], magic)

	if _, err := w.Write(body); err != nil {
		return err
	}
	_, err := w.Write(meta[:])
	return err
}

// Has 报告文件尾部是否存在配置块。
func Has(path string) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	_, err = readTail(f, st.Size())
	if errors.Is(err, ErrNotEmbedded) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Read 读取文件尾部的内嵌配置。文件不是客户端时返回 ErrNotEmbedded。
func Read(path string) (Payload, error) {
	st, err := os.Stat(path)
	if err != nil {
		return Payload{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return Payload{}, err
	}
	defer f.Close()
	body, err := readTail(f, st.Size())
	if err != nil {
		return Payload{}, err
	}
	return Unmarshal(body)
}

// readTail 从 io.ReaderAt 中取出 payload 字节。
func readTail(r io.ReaderAt, size int64) ([]byte, error) {
	if size < int64(tailFixed) {
		return nil, ErrNotEmbedded
	}
	meta := make([]byte, tailFixed)
	if _, err := r.ReadAt(meta, size-int64(tailFixed)); err != nil && err != io.EOF {
		return nil, err
	}
	if string(meta[44:44+len(magic)]) != magic {
		return nil, ErrNotEmbedded
	}
	ver := binary.LittleEndian.Uint32(meta[32:36])
	if ver != Version {
		return nil, fmt.Errorf("%w: 块版本 %d 不受支持（当前 %d）", ErrCorrupted, ver, Version)
	}
	n := binary.LittleEndian.Uint64(meta[36:44])
	if n == 0 || n > uint64(size-int64(tailFixed)) {
		return nil, fmt.Errorf("%w: payload 长度 %d 超出文件范围", ErrCorrupted, n)
	}
	body := make([]byte, n)
	start := size - int64(tailFixed) - int64(n)
	if _, err := r.ReadAt(body, start); err != nil && err != io.EOF {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if !bytes.Equal(sum[:], meta[0:32]) {
		return nil, fmt.Errorf("%w: 校验和不符（文件被截断或篡改）", ErrCorrupted)
	}
	return body, nil
}
