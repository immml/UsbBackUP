package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"strings"
	"testing"
)

// testKey 生成一把 2048 位测试密钥（生成 4096 位太慢，密钥强度由 keystore 保证）。
func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	return k
}

func TestHeaderRoundTrip(t *testing.T) {
	h := Header{
		Version:           Version,
		KeyAlg:            KeyAlgRSAOAEP,
		DataAlg:           DataAlgAES256GCM,
		ChunkSize:         DefaultChunkSize,
		PlainLength:       123456789,
		PubKeyFingerprint: [32]byte{1, 2, 3},
		WrappedKey:        bytes.Repeat([]byte{0xAB}, 512),
	}
	copy(h.NoncePrefix[:], []byte("12345678"))
	copy(h.PlainSHA256[:], bytes.Repeat([]byte{0x11}, 32))

	raw := h.Marshal()
	if len(raw) != HeaderFixedSize+512 {
		t.Fatalf("头部长度错误：got %d want %d", len(raw), HeaderFixedSize+512)
	}
	got, err := ParseHeader(raw)
	if err != nil {
		t.Fatalf("解析头部失败: %v", err)
	}
	if got.Version != h.Version || got.KeyAlg != h.KeyAlg || got.DataAlg != h.DataAlg {
		t.Fatalf("基础字段不一致: %+v", got)
	}
	if got.ChunkSize != h.ChunkSize || got.PlainLength != h.PlainLength {
		t.Fatalf("容量字段不一致: %+v", got)
	}
	if got.NoncePrefix != h.NoncePrefix || got.PlainSHA256 != h.PlainSHA256 {
		t.Fatalf("随机字段不一致")
	}
	if got.PubKeyFingerprint != h.PubKeyFingerprint {
		t.Fatalf("指纹不一致")
	}
	if !bytes.Equal(got.WrappedKey, h.WrappedKey) {
		t.Fatalf("包装密钥不一致")
	}
	if got.Hash() != h.Hash() {
		t.Fatalf("头部哈希不稳定")
	}
}

func TestParseHeaderRejectsBadInput(t *testing.T) {
	base := Header{
		Version: Version, KeyAlg: KeyAlgRSAOAEP, DataAlg: DataAlgAES256GCM,
		ChunkSize: DefaultChunkSize, WrappedKey: bytes.Repeat([]byte{1}, 512),
	}.Marshal()

	cases := []struct {
		name string
		mod  func([]byte) []byte
	}{
		{"过短", func(b []byte) []byte { return b[:40] }},
		{"魔数错误", func(b []byte) []byte { c := clone(b); c[0] = 'X'; return c }},
		{"版本过高", func(b []byte) []byte { c := clone(b); c[5] = 99; return c }},
		{"密钥算法未知", func(b []byte) []byte { c := clone(b); c[7] = 42; return c }},
		{"数据算法未知", func(b []byte) []byte { c := clone(b); c[9] = 42; return c }},
		{"分块过小", func(b []byte) []byte {
			c := clone(b)
			c[10], c[11], c[12], c[13] = 0, 0, 0, 8 // 8 字节 < MinChunkSize
			return c
		}},
		{"包装密钥长度为 0", func(b []byte) []byte {
			c := clone(b)
			c[94], c[95] = 0, 0
			return c[:HeaderFixedSize]
		}},
		{"包装密钥长度与实际不符", func(b []byte) []byte {
			c := clone(b)
			c[95] = 200
			return c
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseHeader(tc.mod(base)); err == nil {
				t.Fatalf("期望报错但解析成功")
			} else if !errors.Is(err, ErrBadContainer) {
				t.Fatalf("期望 ErrBadContainer，实际 %v", err)
			}
		})
	}
}

func clone(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := testKey(t)
	fp := [32]byte{9, 8, 7}

	sizes := []int{0, 1, 1024, 64*1024 - 1, 64 * 1024, 64*1024 + 1, 300 * 1024}
	for _, size := range sizes {
		t.Run(ioSizeName(size), func(t *testing.T) {
			plain := make([]byte, size)
			if _, err := rand.Read(plain); err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			esum, err := EncryptStream(&buf, bytes.NewReader(plain), EncryptOptions{
				PublicKey: &key.PublicKey, PublicKeyFingerprint: fp, ChunkSize: 64 << 10,
			})
			if err != nil {
				t.Fatalf("加密失败: %v", err)
			}
			if esum.PlainBytes != int64(size) {
				t.Fatalf("统计明文长度错误：got %d want %d", esum.PlainBytes, size)
			}
			// 短输入的"密文是否含明文"检查没有统计意义，只在有足够样本时执行。
			if size >= 64 && bytes.Contains(buf.Bytes(), plain[:32]) {
				t.Fatalf("密文中出现了明文片段")
			}

			var out bytes.Buffer
			dsum, err := DecryptStream(&out, bytes.NewReader(buf.Bytes()), DecryptOptions{
				PrivateKey: key, PublicKeyFingerprint: fp,
			})
			if err != nil {
				t.Fatalf("解密失败: %v", err)
			}
			if !bytes.Equal(out.Bytes(), plain) {
				t.Fatalf("明文不一致：got %d 字节 want %d 字节", out.Len(), len(plain))
			}
			if dsum.PlainSHA256 != esum.PlainSHA256 {
				t.Fatalf("明文哈希不一致")
			}
			if dsum.Header.PubKeyFingerprint != fp {
				t.Fatalf("头部指纹未保存")
			}
		})
	}
}

func ioSizeName(n int) string {
	switch n {
	case 0:
		return "空输入"
	case 1:
		return "单字节"
	case 64 * 1024:
		return "恰好一块"
	case 64*1024 - 1:
		return "差一字节满块"
	case 64*1024 + 1:
		return "一块多一字节"
	default:
		return "多块"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestDecryptRejectsTamperTruncateWrongKey(t *testing.T) {
	key := testKey(t)
	plain := bytes.Repeat([]byte("usbguard-tamper-test"), 5000)

	var buf bytes.Buffer
	if _, err := EncryptStream(&buf, bytes.NewReader(plain), EncryptOptions{
		PublicKey: &key.PublicKey, ChunkSize: 32 << 10,
	}); err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	ct := buf.Bytes()

	t.Run("篡改一个字节", func(t *testing.T) {
		bad := clone(ct)
		bad[len(bad)/2] ^= 0x01
		if _, err := DecryptStream(io.Discard, bytes.NewReader(bad), DecryptOptions{PrivateKey: key}); err == nil {
			t.Fatal("期望解密失败，实际成功")
		}
	})

	t.Run("截断尾部", func(t *testing.T) {
		trunc := ct[:len(ct)-24]
		if _, err := DecryptStream(io.Discard, bytes.NewReader(trunc), DecryptOptions{PrivateKey: key}); err == nil {
			t.Fatal("期望解密失败，实际成功")
		}
	})

	t.Run("尾部追加垃圾", func(t *testing.T) {
		extra := append(clone(ct), 0x00, 0x01, 0x02)
		if _, err := DecryptStream(io.Discard, bytes.NewReader(extra), DecryptOptions{PrivateKey: key}); err == nil {
			t.Fatal("期望解密失败，实际成功")
		}
	})

	t.Run("错误私钥", func(t *testing.T) {
		other := testKey(t)
		if _, err := DecryptStream(io.Discard, bytes.NewReader(ct), DecryptOptions{PrivateKey: other}); err == nil {
			t.Fatal("期望解密失败，实际成功")
		}
	})
}

func TestEncryptRejectsWeakAndMissingKey(t *testing.T) {
	if _, err := EncryptStream(io.Discard, bytes.NewReader(nil), EncryptOptions{}); err == nil {
		t.Fatal("未提供公钥时应当报错")
	}
	// Go 1.24+ 的 rsa.GenerateKey 已不允许小于 1024 位，因此用 1024 位验证本工具的下限。
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Skipf("无法生成 1024 位测试密钥（当前 Go 版本最小长度更严）: %v", err)
	}
	if _, err := EncryptStream(io.Discard, bytes.NewReader(nil), EncryptOptions{PublicKey: &weak.PublicKey}); err == nil {
		t.Fatal("1024 位公钥应当被拒绝（本工具下限 2048 位）")
	}
}

func TestReadHeaderFromStream(t *testing.T) {
	key := testKey(t)
	var buf bytes.Buffer
	if _, err := EncryptStream(&buf, bytes.NewReader([]byte("hello")), EncryptOptions{PublicKey: &key.PublicKey}); err != nil {
		t.Fatal(err)
	}
	hdr, n, err := ReadHeader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadHeader 失败: %v", err)
	}
	if n <= 0 || n >= int64(buf.Len()) {
		t.Fatalf("头部长度不合理: %d", n)
	}
	if hdr.WrappedKey == nil || len(hdr.WrappedKey) != key.Size() {
		t.Fatalf("包装密钥长度应等于私钥模数长度 %d，实际 %d", key.Size(), len(hdr.WrappedKey))
	}
}

func TestSessionKeyUnwrapMatches(t *testing.T) {
	key := testKey(t)
	var buf bytes.Buffer
	if _, err := EncryptStream(&buf, bytes.NewReader([]byte("x")), EncryptOptions{PublicKey: &key.PublicKey}); err != nil {
		t.Fatal(err)
	}
	hdr, _, err := ReadHeader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	sk, err := UnwrapSessionKeyForTest(key, hdr)
	if err != nil {
		t.Fatalf("解包会话密钥失败: %v", err)
	}
	if len(sk) != SessionKeyLen {
		t.Fatalf("会话密钥长度应为 %d，实际 %d", SessionKeyLen, len(sk))
	}
}

func TestOAEPLabelIsStableProtocolConstant(t *testing.T) {
	if got := string(OAEPLabel); got != "usbbackup/v1" {
		t.Fatalf("OAEP 域分隔 label 被改动（%q）：这会破坏容器格式兼容性", got)
	}
	if strings.Contains(string(OAEPLabel), "github.com") || strings.Contains(string(OAEPLabel), "usbguard") {
		t.Fatalf("label 不得由模块路径或旧产品名派生: %q", OAEPLabel)
	}
}

func TestRSAModulusBitsFromHeader(t *testing.T) {
	// 2048 位密钥 → 包装密钥 256 字节 → 推断 2048 位。
	key := testKey(t) // 2048 位
	var buf bytes.Buffer
	if _, err := EncryptStream(&buf, bytes.NewReader([]byte("x")), EncryptOptions{PublicKey: &key.PublicKey}); err != nil {
		t.Fatal(err)
	}
	hdr, _, err := ReadHeader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got := hdr.RSAModulusBits(); got != key.N.BitLen() {
		t.Fatalf("由头部推断的模数位数 %d != 实际 %d", got, key.N.BitLen())
	}
	// 非 RSA 方案应返回 0。
	hdr.KeyAlg = KeyAlgX25519HKDFSHA256
	if got := hdr.RSAModulusBits(); got != 0 {
		t.Fatalf("非 RSA 方案应返回 0，实际 %d", got)
	}
	// 算法名不应误导为固定 4096 位。
	if strings.Contains(KeyAlgRSAOAEP.String(), "4096") {
		t.Fatalf("算法名不应绑定模数长度: %q", KeyAlgRSAOAEP.String())
	}
}

func TestGroupHex(t *testing.T) {
	got := GroupHex([]byte{0x00, 0x11, 0x22, 0x33, 0x44})
	if got != "0011 2233 44" {
		t.Fatalf("分组格式错误: %q", got)
	}
}
