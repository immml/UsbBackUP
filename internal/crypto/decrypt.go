package crypto

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// DecryptOptions 是解密参数。
type DecryptOptions struct {
	// PrivateKey 是用于解开会话密钥的 RSA 私钥（必需）。
	PrivateKey *rsa.PrivateKey
	// PublicKeyFingerprint 若非零，则先与容器头记录的指纹核对；不一致时快速失败。
	// 指纹是公开信息，此处给出明确提示不构成信息泄露。
	PublicKeyFingerprint [32]byte
	// Progress 是可选的进度回调（参数为已输出明文字节数）。
	Progress func(plainBytes int64)
}

// DecryptSummary 是解密结果统计。
type DecryptSummary struct {
	Header      Header
	PlainBytes  int64
	CipherBytes int64
	Chunks      uint64
	PlainSHA256 [32]byte
}

// ReadHeader 从流中读取并解析容器头，返回头部与**紧随其后的密文偏移量**。
// 供 `list` / `verify` 等只读子命令复用。
func ReadHeader(r io.Reader) (Header, int64, error) {
	var h Header
	fixed := make([]byte, HeaderFixedSize)
	if _, err := io.ReadFull(r, fixed); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return h, 0, fmt.Errorf("%w: 文件过短，不足以容纳容器头", ErrBadContainer)
		}
		return h, 0, fmt.Errorf("读取容器头失败: %w", err)
	}
	extra := int(binary.BigEndian.Uint16(fixed[94:96]))
	if extra <= 0 || extra > 1024 {
		return h, 0, fmt.Errorf("%w: 包装密钥长度字段非法（%d）", ErrBadContainer, extra)
	}
	buf := make([]byte, HeaderFixedSize+extra)
	copy(buf, fixed)
	if _, err := io.ReadFull(r, buf[HeaderFixedSize:]); err != nil {
		return h, 0, fmt.Errorf("%w: 包装密钥数据不完整", ErrBadContainer)
	}
	h, err := ParseHeader(buf)
	if err != nil {
		return h, 0, err
	}
	return h, int64(len(buf)), nil
}

// DecryptStream 解密 src 并写入 dst，同时完成完整性校验。
//
// 校验层次：
//  1. 每块 GCM 认证（防篡改、防块重排）；
//  2. 末块元数据帧是否存在（防截断）；
//  3. 明文 SHA-256 与明文长度比对（F-611）。
//
// 任何失败都返回统一的 ErrDecryptFailed（或其派生），不区分具体原因（F-610）。
func DecryptStream(dst io.Writer, src io.Reader, opt DecryptOptions) (DecryptSummary, error) {
	var sum DecryptSummary

	if opt.PrivateKey == nil {
		return sum, errors.New("crypto: 未提供私钥，无法解开会话密钥")
	}

	hdr, headerBytes, err := ReadHeader(src)
	if err != nil {
		return sum, err
	}
	sum.Header = hdr
	sum.CipherBytes = headerBytes

	// 公钥指纹预检（仅比对公开信息，便于用户快速定位"用错密钥"）。
	if opt.PublicKeyFingerprint != ([32]byte{}) && hdr.PubKeyFingerprint != ([32]byte{}) {
		if hdr.PubKeyFingerprint != opt.PublicKeyFingerprint {
			return sum, fmt.Errorf("%w: 容器由另一把公钥加密（容器指纹 %s）",
				ErrDecryptFailed, hdr.FingerprintHex())
		}
	}

	// 1) 解开会话密钥。
	if len(hdr.WrappedKey) != opt.PrivateKey.Size() {
		return sum, fmt.Errorf("%w: 包装密钥长度与私钥模数不匹配", ErrDecryptFailed)
	}
	sessionKey, err := rsa.DecryptOAEP(sha256.New(), nil, opt.PrivateKey, hdr.WrappedKey, OAEPLabel)
	if err != nil {
		return sum, fmt.Errorf("%w: 会话密钥解包失败", ErrDecryptFailed)
	}
	defer zero(sessionKey)
	if len(sessionKey) != SessionKeyLen {
		return sum, fmt.Errorf("%w: 会话密钥长度异常", ErrDecryptFailed)
	}

	aead, err := newAEAD(sessionKey)
	if err != nil {
		return sum, fmt.Errorf("%w", ErrDecryptFailed)
	}
	headerHash := hdr.Hash()

	// 2) 逐块解密与认证。
	plainBuf := make([]byte, hdr.ChunkSize)
	defer zero(plainBuf)

	hasher := sha256.New()
	var frameIndex uint64
	var seenFinal bool
	var declaredLen uint64

	frameHdr := make([]byte, 5)
	maxDataCT := int(hdr.ChunkSize) + aead.Overhead()

	for {
		_, err := io.ReadFull(src, frameHdr)
		if err != nil {
			if errors.Is(err, io.EOF) {
				// 流在末块之前结束。
				break
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return sum, fmt.Errorf("%w", ErrDecryptFailed)
			}
			return sum, fmt.Errorf("读取密文帧失败: %w", err)
		}
		flag := frameHdr[0]
		ctLen := int(binary.BigEndian.Uint32(frameHdr[1:5]))

		var upper int
		switch flag {
		case frameFlagData:
			upper = maxDataCT
		case frameFlagFinal:
			upper = FrameDigestLen + aead.Overhead()
		default:
			return sum, fmt.Errorf("%w", ErrDecryptFailed)
		}
		if ctLen < aead.Overhead() || ctLen > upper {
			return sum, fmt.Errorf("%w", ErrDecryptFailed)
		}

		ciphertext := make([]byte, ctLen)
		if _, err := io.ReadFull(src, ciphertext); err != nil {
			return sum, fmt.Errorf("%w", ErrDecryptFailed)
		}
		sum.CipherBytes += int64(len(frameHdr) + ctLen)

		nonce, err := frameNonce(hdr.NoncePrefix, frameIndex)
		if err != nil {
			return sum, fmt.Errorf("%w", ErrDecryptFailed)
		}
		aad := frameAAD(headerHash, frameIndex, flag)
		plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return sum, fmt.Errorf("%w", ErrDecryptFailed)
		}

		switch flag {
		case frameFlagData:
			if _, err := dst.Write(plaintext); err != nil {
				return sum, fmt.Errorf("写入明文失败: %w", err)
			}
			hasher.Write(plaintext)
			sum.PlainBytes += int64(len(plaintext))
			sum.Chunks++
			if opt.Progress != nil {
				opt.Progress(sum.PlainBytes)
			}
		case frameFlagFinal:
			if len(plaintext) != FrameDigestLen {
				return sum, fmt.Errorf("%w", ErrDecryptFailed)
			}
			copy(sum.PlainSHA256[:], plaintext[0:32])
			declaredLen = binary.BigEndian.Uint64(plaintext[32:40])
			seenFinal = true
		}

		zero(ciphertext)
		zero(plaintext)
		frameIndex++

		if seenFinal {
			// 末块之后不应再有数据；若还有内容说明流被拼接。
			var probe [1]byte
			if n, _ := io.ReadFull(src, probe[:]); n > 0 {
				return sum, fmt.Errorf("%w: 末块之后存在额外数据", ErrDecryptFailed)
			}
			break
		}
	}

	if !seenFinal {
		return sum, ErrTruncated
	}

	// 3) 明文长度与哈希比对。
	if declaredLen != uint64(sum.PlainBytes) {
		return sum, fmt.Errorf("%w: 明文长度不符", ErrDecryptFailed)
	}
	actual := hasher.Sum(nil)
	if [32]byte(actual) != sum.PlainSHA256 {
		return sum, fmt.Errorf("%w: 明文校验和不符", ErrDecryptFailed)
	}
	return sum, nil
}

// UnwrapSessionKeyForTest 仅在测试中用于验证包装/解包往返。
// 生产代码不得调用：它会返回原始会话密钥材料。
func UnwrapSessionKeyForTest(priv *rsa.PrivateKey, hdr Header) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), nil, priv, hdr.WrappedKey, OAEPLabel)
}
