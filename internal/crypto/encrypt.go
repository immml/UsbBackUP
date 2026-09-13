package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// SessionKeyLen 是会话密钥长度（AES-256）。
const SessionKeyLen = 32

// MinRSAKeyBits 是允许用于包装会话密钥的最小 RSA 位数。
const MinRSAKeyBits = 2048

// EncryptOptions 是加密参数。
type EncryptOptions struct {
	// PublicKey 是用于包装会话密钥的 RSA 公钥（必需）。
	PublicKey *rsa.PublicKey
	// PublicKeyFingerprint 是公钥指纹，写入头部便于运维核对。
	PublicKeyFingerprint [32]byte
	// ChunkSize 是明文分块大小，0 表示使用 DefaultChunkSize。
	ChunkSize uint32
	// Progress 是可选的进度回调（参数为已处理明文字节数）。
	Progress func(plainBytes int64)
}

// EncryptSummary 是加密结果统计。
type EncryptSummary struct {
	Header      Header
	PlainBytes  int64
	CipherBytes int64
	Chunks      uint64
	PlainSHA256 [32]byte
}

// EncryptStream 把 src 的明文流加密写入 dst。
//
// 输出结构：[容器头][数据帧...][末块元数据帧]
//
// 全程只使用 O(chunkSize) 内存，不整份载入明文（F-609）。
// dst 写入失败或 src 读取失败都会立即返回，由调用方清理半成品。
func EncryptStream(dst io.Writer, src io.Reader, opt EncryptOptions) (EncryptSummary, error) {
	var sum EncryptSummary

	if opt.PublicKey == nil {
		return sum, errors.New("crypto: 未提供公钥，无法包装会话密钥")
	}
	if bits := opt.PublicKey.N.BitLen(); bits < MinRSAKeyBits {
		return sum, fmt.Errorf("crypto: 公钥模数仅 %d 位，低于下限 %d 位", bits, MinRSAKeyBits)
	}
	chunkSize := opt.ChunkSize
	if chunkSize == 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize < MinChunkSize || chunkSize > MaxChunkSize {
		return sum, fmt.Errorf("crypto: 分块大小 %d 超出允许范围 [%d, %d]",
			chunkSize, MinChunkSize, MaxChunkSize)
	}
	if bits := opt.PublicKey.N.BitLen(); bits > 8192 {
		return sum, fmt.Errorf("crypto: 公钥模数 %d 位过大（上限 8192）", bits)
	}

	// 1) 生成随机会话密钥。这是本次备份唯一的对称密钥，只存在于内存。
	sessionKey := make([]byte, SessionKeyLen)
	if _, err := io.ReadFull(rand.Reader, sessionKey); err != nil {
		return sum, fmt.Errorf("crypto: 生成会话密钥失败: %w", err)
	}
	defer zero(sessionKey)

	// 2) 用公钥包装会话密钥（非对称算法只做这一件事）。
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, opt.PublicKey, sessionKey, OAEPLabel)
	if err != nil {
		return sum, fmt.Errorf("crypto: 包装会话密钥失败: %w", err)
	}

	// 3) 组装并写出容器头。明文长度与明文哈希此时未知，记录在末块元数据中。
	hdr := Header{
		Version:           Version,
		KeyAlg:            KeyAlgRSAOAEP,
		DataAlg:           DataAlgAES256GCM,
		ChunkSize:         chunkSize,
		PlainLength:       0,
		PlainSHA256:       [32]byte{},
		PubKeyFingerprint: opt.PublicKeyFingerprint,
		WrappedKey:        wrapped,
	}
	if _, err := io.ReadFull(rand.Reader, hdr.NoncePrefix[:]); err != nil {
		return sum, fmt.Errorf("crypto: 生成 nonce 前缀失败: %w", err)
	}
	hdrBytes := hdr.Marshal()
	if _, err := dst.Write(hdrBytes); err != nil {
		return sum, fmt.Errorf("crypto: 写入容器头失败: %w", err)
	}
	sum.Header = hdr
	sum.CipherBytes = int64(len(hdrBytes))

	// 4) 构造 AEAD。
	aead, err := newAEAD(sessionKey)
	if err != nil {
		return sum, err
	}
	headerHash := hdr.Hash()

	// 5) 分块加密主循环。每块独立认证，内存恒定。
	plainBuf := make([]byte, chunkSize)
	defer zero(plainBuf)

	hasher := sha256.New()
	var frameIndex uint64
	var plainTotal int64

	for {
		n, readErr := io.ReadFull(src, plainBuf)
		if n > 0 {
			hasher.Write(plainBuf[:n])
			plainTotal += int64(n)
			written, err := writeFrame(dst, aead, hdr.NoncePrefix, headerHash, frameIndex, frameFlagData, plainBuf[:n])
			if err != nil {
				return sum, err
			}
			sum.CipherBytes += written
			frameIndex++
			sum.Chunks++
			if opt.Progress != nil {
				opt.Progress(plainTotal)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
				break
			}
			return sum, fmt.Errorf("crypto: 读取明文失败: %w", readErr)
		}
	}

	// 6) 末块元数据帧：32B 明文 SHA-256 + 8B 明文长度。
	//    它的存在本身就是"流完整"的证明；缺失即判定截断（F-607）。
	digest := hasher.Sum(nil)
	copy(sum.PlainSHA256[:], digest)
	meta := make([]byte, FrameDigestLen)
	copy(meta[0:32], digest)
	binary.BigEndian.PutUint64(meta[32:40], uint64(plainTotal))
	written, err := writeFrame(dst, aead, hdr.NoncePrefix, headerHash, frameIndex, frameFlagFinal, meta)
	if err != nil {
		return sum, err
	}
	sum.CipherBytes += written
	sum.Chunks++
	sum.PlainBytes = plainTotal

	// 回填已知信息，供调用方记录到审计日志（不落盘回改容器）。
	sum.Header.PlainLength = uint64(plainTotal)
	return sum, nil
}

// newAEAD 用会话密钥构造 AES-256-GCM。
func newAEAD(sessionKey []byte) (cipher.AEAD, error) {
	if len(sessionKey) != SessionKeyLen {
		return nil, errors.New("crypto: 会话密钥长度非法")
	}
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: 初始化 AES 失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: 初始化 GCM 失败: %w", err)
	}
	return aead, nil
}

// frameNonce 由 8 字节随机前缀 + 4 字节块序号构成，保证同一密钥下 nonce 绝不重复（F-605）。
func frameNonce(prefix [NoncePrefixLen]byte, index uint64) ([]byte, error) {
	if index > uint64(^uint32(0)) {
		return nil, errors.New("crypto: 分块序号溢出")
	}
	nonce := make([]byte, 12)
	copy(nonce[0:NoncePrefixLen], prefix[:])
	binary.BigEndian.PutUint32(nonce[NoncePrefixLen:], uint32(index))
	return nonce, nil
}

// frameAAD 绑定容器头哈希、块序号与帧标志，防块重排/跨文件拼接/截断重排（F-608）。
func frameAAD(headerHash [32]byte, index uint64, flag byte) []byte {
	aad := make([]byte, 32+8+1)
	copy(aad[0:32], headerHash[:])
	binary.BigEndian.PutUint64(aad[32:40], index)
	aad[40] = flag
	return aad
}

// writeFrame 组装并写出一个加密帧：[1B 标志][4B 密文长度][密文+16B Tag]。
// 返回写出的字节数。
func writeFrame(dst io.Writer, aead cipher.AEAD, prefix [NoncePrefixLen]byte,
	headerHash [32]byte, index uint64, flag byte, plaintext []byte) (int64, error) {

	nonce, err := frameNonce(prefix, index)
	if err != nil {
		return 0, err
	}
	aad := frameAAD(headerHash, index, flag)
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	frame := make([]byte, 5+len(ciphertext))
	frame[0] = flag
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(ciphertext)))
	copy(frame[5:], ciphertext)

	if _, err := dst.Write(frame); err != nil {
		return 0, fmt.Errorf("crypto: 写入密文帧失败: %w", err)
	}
	return int64(len(frame)), nil
}

// zero 覆盖切片内容，用于在敏感数据（会话密钥、明文缓冲）用完后立即清除。
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
