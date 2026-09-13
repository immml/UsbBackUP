// Package crypto 实现本工具的混合加密容器（`.usbk`）。
//
// # 加密模型（对应需求 F-601 ~ F-611）
//
//	       ┌─────────────────┐
//	明文流 │  AES-256-GCM    │ 密文块 → 容器
//	       └─────────────────┘
//	              ▲
//	              │ 32 字节随机会话密钥（仅存在于内存）
//	              │
//	       ┌─────────────────┐
//	公钥 → │ RSA-4096-OAEP   │ → 512 字节"包装密钥"（写入容器头）
//	       └─────────────────┘
//
// 关键性质：
//
//   - 非对称算法**只用于包装对称密钥**，不对数据本身做非对称运算（F-601）。
//   - 数据用 AES-256-GCM 分块加密，每块独立认证（F-604）。
//   - Nonce 由 8 字节随机前缀 + 4 字节块序号构成，绝不复用（F-605）。
//   - 分块 AAD 绑定容器头哈希与块序号，防块重排与跨文件拼接（F-608）。
//   - 末块为"元数据块"，承载明文 SHA-256 与明文长度，缺块即判定截断（F-607）。
//   - 内存占用 O(块大小)，默认 1 MiB 块 → 峰值约数 MiB（F-609）。
package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Magic 是容器魔数，固定 4 字节。
const Magic = "USBK"

// Version 是本实现写出的容器版本号。
const Version uint16 = 1

// HeaderFixedSize 是容器头固定部分的长度（不含包装密钥）。
const HeaderFixedSize = 96

// DefaultChunkSize 是默认分块大小：1 MiB。
const DefaultChunkSize uint32 = 1 << 20

// MinChunkSize / MaxChunkSize 限定分块大小范围，防恶意头部造成巨额内存分配。
const (
	MinChunkSize uint32 = 4 << 10  // 4 KiB
	MaxChunkSize uint32 = 64 << 20 // 64 MiB
)

// NoncePrefixLen 是 nonce 随机前缀长度。
const NoncePrefixLen = 8

// FrameDigestLen 是末块元数据固定长度：32B SHA-256 + 8B 明文长度。
const FrameDigestLen = 40

// KeyAlgID 标识包装会话密钥所用的非对称算法。
type KeyAlgID uint16

// 非对称算法编号。容器头携带该编号，便于后续平滑演进（F-603）。
const (
	// KeyAlgRSAOAEP 表示 RSA + OAEP(SHA-256) 密钥包装方案，当前默认。
	// 注意：该编号只描述**方案**，不绑定模数长度；实际模数长度由包装密钥
	// 的字节长度体现（RSA 密文长度等于模数长度），见 Header.RSAModulusBits。
	KeyAlgRSAOAEP KeyAlgID = 1
	// KeyAlgX25519HKDFSHA256 是 X25519 ECDH + HKDF-SHA256，预留（F-603，M1 后续）。
	KeyAlgX25519HKDFSHA256 KeyAlgID = 2
)

// String 返回算法可读名。
func (a KeyAlgID) String() string {
	switch a {
	case KeyAlgRSAOAEP:
		return "RSA-OAEP-SHA256"
	case KeyAlgX25519HKDFSHA256:
		return "X25519-HKDF-SHA256"
	default:
		return fmt.Sprintf("unknown-key-alg(%d)", uint16(a))
	}
}

// DataAlgID 标识对称数据加密算法。
type DataAlgID uint16

// 对称算法编号。
const (
	// DataAlgAES256GCM 是 AES-256-GCM，当前唯一实现。
	DataAlgAES256GCM DataAlgID = 1
)

// String 返回算法可读名。
func (a DataAlgID) String() string {
	switch a {
	case DataAlgAES256GCM:
		return "AES-256-GCM"
	default:
		return fmt.Sprintf("unknown-data-alg(%d)", uint16(a))
	}
}

// 帧标志位。
const (
	frameFlagData  byte = 0x00
	frameFlagFinal byte = 0x01
)

// OAEPLabel 是 RSA-OAEP 的域分隔 label。
//
// 这是**协议常量**：它标识本容器格式的域分隔上下文，与代码仓库路径、模块名
// 完全无关，不得随项目重命名而改动——改了就等于换了一种不兼容的容器格式。
// 如需变更，必须同时递增 Version 并保留旧算法编号的解析能力。
var OAEPLabel = []byte("usbbackup/v1")

// 统一错误：解密失败、密钥不匹配、数据被篡改、容器截断等多种原因
// 一律归为同一错误，避免向攻击者提供区分性 oracle（F-610）。
var (
	// ErrDecryptFailed 表示"无法解密或完整性校验失败"。
	ErrDecryptFailed = errors.New("解密或完整性校验失败（密钥不匹配、数据被篡改或文件不完整）")
	// ErrBadContainer 表示容器头不合法（魔数/版本/字段越界）。
	ErrBadContainer = errors.New("容器格式非法")
	// ErrTruncated 表示密文流缺少末块，判定为被截断。
	ErrTruncated = errors.New("密文流不完整：缺少末块（文件可能被截断）")
)

// Header 是容器头。除包装密钥外全部为定长字段，便于快速解析与展示。
//
// 头部为**明文**，不含任何密钥材料：包装密钥本身是被公钥加密后的密文。
type Header struct {
	// Version 容器版本。
	Version uint16
	// KeyAlg 包装密钥所用的非对称算法。
	KeyAlg KeyAlgID
	// DataAlg 数据所用的对称算法。
	DataAlg DataAlgID
	// ChunkSize 明文分块大小（字节）。
	ChunkSize uint32
	// PlainLength 明文总长度；为 0 表示"未知，见末块元数据"。
	PlainLength uint64
	// NoncePrefix 是 8 字节随机前缀，与块序号共同构成每块的 nonce。
	NoncePrefix [NoncePrefixLen]byte
	// PlainSHA256 是明文全量 SHA-256；未知时为零值。
	PlainSHA256 [32]byte
	// PubKeyFingerprint 是所用公钥的 SHA-256 指纹，便于运维核对（不含密钥本身）。
	PubKeyFingerprint [32]byte
	// WrappedKey 是被公钥包装后的会话密钥。
	WrappedKey []byte
}

// Marshal 把容器头序列化为字节。
//
// 布局（大端）：
//
//	0    magic(4)          4    version(2)      6    keyAlg(2)
//	8    dataAlg(2)        10   chunkSize(4)    14   plainLength(8)
//	22   noncePrefix(8)    30   plainSHA256(32) 62   pubKeyFP(32)
//	94   wrappedKeyLen(2)  96   wrappedKey(n)
func (h Header) Marshal() []byte {
	buf := make([]byte, HeaderFixedSize+len(h.WrappedKey))
	copy(buf[0:4], Magic)
	binary.BigEndian.PutUint16(buf[4:6], h.Version)
	binary.BigEndian.PutUint16(buf[6:8], uint16(h.KeyAlg))
	binary.BigEndian.PutUint16(buf[8:10], uint16(h.DataAlg))
	binary.BigEndian.PutUint32(buf[10:14], h.ChunkSize)
	binary.BigEndian.PutUint64(buf[14:22], h.PlainLength)
	copy(buf[22:30], h.NoncePrefix[:])
	copy(buf[30:62], h.PlainSHA256[:])
	copy(buf[62:94], h.PubKeyFingerprint[:])
	binary.BigEndian.PutUint16(buf[94:96], uint16(len(h.WrappedKey)))
	copy(buf[96:], h.WrappedKey)
	return buf
}

// ParseHeader 解析容器头。raw 必须恰好是头部字节（含包装密钥）。
func ParseHeader(raw []byte) (Header, error) {
	var h Header
	if len(raw) < HeaderFixedSize {
		return h, fmt.Errorf("%w: 头部长度不足（%d < %d）", ErrBadContainer, len(raw), HeaderFixedSize)
	}
	if string(raw[0:4]) != Magic {
		return h, fmt.Errorf("%w: 魔数不匹配（期望 %q）", ErrBadContainer, Magic)
	}
	h.Version = binary.BigEndian.Uint16(raw[4:6])
	if h.Version != Version {
		return h, fmt.Errorf("%w: 不支持的容器版本 %d（本程序支持 %d）", ErrBadContainer, h.Version, Version)
	}
	h.KeyAlg = KeyAlgID(binary.BigEndian.Uint16(raw[6:8]))
	h.DataAlg = DataAlgID(binary.BigEndian.Uint16(raw[8:10]))
	if h.KeyAlg != KeyAlgRSAOAEP {
		return h, fmt.Errorf("%w: 不支持的密钥算法编号 %d", ErrBadContainer, uint16(h.KeyAlg))
	}
	if h.DataAlg != DataAlgAES256GCM {
		return h, fmt.Errorf("%w: 不支持的数据算法编号 %d", ErrBadContainer, uint16(h.DataAlg))
	}
	h.ChunkSize = binary.BigEndian.Uint32(raw[10:14])
	if h.ChunkSize < MinChunkSize || h.ChunkSize > MaxChunkSize {
		return h, fmt.Errorf("%w: 分块大小 %d 超出允许范围 [%d, %d]",
			ErrBadContainer, h.ChunkSize, MinChunkSize, MaxChunkSize)
	}
	h.PlainLength = binary.BigEndian.Uint64(raw[14:22])
	copy(h.NoncePrefix[:], raw[22:30])
	copy(h.PlainSHA256[:], raw[30:62])
	copy(h.PubKeyFingerprint[:], raw[62:94])
	n := int(binary.BigEndian.Uint16(raw[94:96]))
	if len(raw) != HeaderFixedSize+n {
		return h, fmt.Errorf("%w: 包装密钥长度字段(%d)与实际长度(%d)不一致",
			ErrBadContainer, n, len(raw)-HeaderFixedSize)
	}
	if n == 0 {
		return h, fmt.Errorf("%w: 包装密钥为空", ErrBadContainer)
	}
	// RSA-4096 的密文固定 512 字节；此处只做上限保护，具体长度在解包时校验。
	if n > 1024 {
		return h, fmt.Errorf("%w: 包装密钥长度异常（%d）", ErrBadContainer, n)
	}
	h.WrappedKey = make([]byte, n)
	copy(h.WrappedKey, raw[HeaderFixedSize:])
	return h, nil
}

// Hash 返回头部全字节的 SHA-256，用作所有分块的 AAD 前缀。
//
// 这样任何对头部（含包装密钥、分块大小）的篡改都会导致全部分块认证失败（F-608）。
func (h Header) Hash() [32]byte {
	return sha256.Sum256(h.Marshal())
}

// RSAModulusBits 依据包装密钥长度推断 RSA 模数位数。
//
// RSA 密文长度等于模数长度，因此 len(WrappedKey)*8 即为密钥位数。
// 非 RSA 方案返回 0。
func (h Header) RSAModulusBits() int {
	if h.KeyAlg != KeyAlgRSAOAEP {
		return 0
	}
	return len(h.WrappedKey) * 8
}

// FingerprintHex 返回公钥指纹的分组长十六进制文本。
func (h Header) FingerprintHex() string {
	return GroupHex(h.PubKeyFingerprint[:])
}

// Describe 返回供 `list` 子命令展示的多行说明（不含任何密钥材料）。
func (h Header) Describe() string {
	lenText := fmt.Sprintf("%d 字节", h.PlainLength)
	if h.PlainLength == 0 {
		lenText = "未知（记录于末块元数据）"
	}
	return strings.Join([]string{
		fmt.Sprintf("容器版本        : %d", h.Version),
		fmt.Sprintf("密钥包装算法    : %s", h.KeyAlg),
		fmt.Sprintf("公钥模数位数    : %d", h.RSAModulusBits()),
		fmt.Sprintf("数据加密算法    : %s", h.DataAlg),
		fmt.Sprintf("分块大小        : %d 字节", h.ChunkSize),
		fmt.Sprintf("明文长度        : %s", lenText),
		fmt.Sprintf("公钥指纹        : %s", h.FingerprintHex()),
		fmt.Sprintf("包装密钥长度    : %d 字节", len(h.WrappedKey)),
	}, "\n")
}

// GroupHex 把字节切片格式化为 4 字符一组、以空格分隔的十六进制。
func GroupHex(b []byte) string {
	full := hex.EncodeToString(b)
	var sb strings.Builder
	for i := 0; i < len(full); i += 4 {
		end := i + 4
		if end > len(full) {
			end = len(full)
		}
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(full[i:end])
	}
	return sb.String()
}
