// Package keystore 负责非对称密钥对的生成、加载、指纹计算与公钥选择。
//
// 边界约定：
//   - 私钥只在本包内被读取用于**解密**或**生成**，永不写入日志、永不写入审计、永不外发；
//   - 配置文件中只保存**公钥**路径（F-703 / G-01）；
//   - 提供公钥指纹用于运维核对，指纹是公开信息（F-704）。
//
// 关于私钥口令保护（F-702）：
//
//	未加密私钥输出标准 PKCS#8 PEM（`-----BEGIN PRIVATE KEY-----`），与 openssl 互操作。
//	带口令保护时输出本工具自有格式（`USBGUARD ENCRYPTED PRIVATE KEY`）：
//
//	    body = salt(16) ‖ nonce(12) ‖ AES-256-GCM(PKCS#8 DER)
//	    密钥 = PBKDF2-HMAC-SHA256(passphrase, salt, 600000, 32)
//
//	之所以不用标准 PBES2：Go 标准库不支持解析 PBES2，而 `x509.EncryptPEMBlock`
//	的 KDF 基于 MD5（强度不足）。本工具优先保证密钥派生强度，代价是与 openssl
//	的口令格式不互通，已在 README 中明确标注。
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/immml/UsbBackup/internal/config"
	"github.com/immml/UsbBackup/internal/crypto"
	"github.com/immml/UsbBackup/internal/fsutil"
)

// PEM 块类型。
const (
	pemTypePKCS8Private   = "PRIVATE KEY"
	pemTypePKCS1Private   = "RSA PRIVATE KEY"
	pemTypeEncryptedStd   = "ENCRYPTED PRIVATE KEY"
	pemTypePublicPKIX     = "PUBLIC KEY"
	pemTypePublicPKCS1    = "RSA PUBLIC KEY"
	pemTypeCertificate    = "CERTIFICATE"
	pemTypeEncryptedLocal = "USBGUARD ENCRYPTED PRIVATE KEY"
)

// 口令保护参数。
const (
	// KDFIterations 是 PBKDF2 迭代次数。
	KDFIterations = 600000
	// saltLen 是 KDF 盐长度。
	saltLen = 16
	// MinPassphraseLen 是允许的最短口令长度。
	MinPassphraseLen = 8
	// MinRSAKeyBits 是允许生成的最小密钥位数（F-703）。
	MinRSAKeyBits = 2048
	// DefaultRSAKeyBits 是默认密钥位数。
	DefaultRSAKeyBits = 4096
	// MaxRSAKeyBits 是允许生成的最大密钥位数。
	MaxRSAKeyBits = 8192

	// DefaultPrivateKeyName 是默认私钥文件名。
	DefaultPrivateKeyName = "usbguard.key.pem"
	// DefaultPublicKeyName 是默认公钥文件名。
	DefaultPublicKeyName = "usbguard.pub.pem"
)

// 错误。
var (
	// ErrPrivateKeyDetected 表示输入文件是私钥（`use` 子命令必须拒绝，F-703）。
	ErrPrivateKeyDetected = errors.New("该文件是私钥，不能写入配置（配置只接受公钥）")
	// ErrUnsupportedPEM 表示 PEM 类型无法识别。
	ErrUnsupportedPEM = errors.New("无法识别的 PEM 内容")
	// ErrPassphraseRequired 表示私钥已加密但未提供口令。
	ErrPassphraseRequired = errors.New("私钥已被口令保护，需要提供口令")
	// ErrBadPassphrase 表示口令错误或数据损坏。
	ErrBadPassphrase = errors.New("口令错误或私钥文件已损坏")
)

// GenerateOptions 是密钥对生成参数。
type GenerateOptions struct {
	// Bits 是 RSA 模数位数，0 表示 4096。
	Bits int
	// PrivatePath 是私钥输出路径，空则用 OutDir/DefaultPrivateKeyName。
	PrivatePath string
	// PublicPath 是公钥输出路径，空则用 OutDir/DefaultPublicKeyName。
	PublicPath string
	// OutDir 是输出目录（PrivatePath/PublicPath 未指定时生效）。
	OutDir string
	// Force 为 true 时才允许覆盖已存在的文件。
	Force bool
	// Passphrase 非空时对私钥做口令保护。
	Passphrase []byte
}

// KeyPair 是生成结果。
type KeyPair struct {
	PrivatePath string
	PublicPath  string
	Bits        int
	// Fingerprint 是公钥指纹（分组长十六进制）。
	Fingerprint string
	// Encrypted 表示私钥是否带口令保护。
	Encrypted bool
}

// Generate 生成 RSA 密钥对并落盘（F-701 / F-702 / F-903）。
func Generate(opt GenerateOptions) (KeyPair, error) {
	var kp KeyPair

	bits := opt.Bits
	if bits == 0 {
		bits = DefaultRSAKeyBits
	}
	if bits < MinRSAKeyBits {
		return kp, fmt.Errorf("密钥位数 %d 低于下限 %d，拒绝生成", bits, MinRSAKeyBits)
	}
	if bits > MaxRSAKeyBits {
		return kp, fmt.Errorf("密钥位数 %d 超过上限 %d", bits, MaxRSAKeyBits)
	}
	if len(opt.Passphrase) > 0 && len(opt.Passphrase) < MinPassphraseLen {
		return kp, fmt.Errorf("口令长度 %d 少于下限 %d，拒绝生成", len(opt.Passphrase), MinPassphraseLen)
	}

	privPath := opt.PrivatePath
	pubPath := opt.PublicPath
	if privPath == "" || pubPath == "" {
		dir := opt.OutDir
		if dir == "" {
			dir = "."
		}
		if privPath == "" {
			privPath = filepath.Join(dir, DefaultPrivateKeyName)
		}
		if pubPath == "" {
			pubPath = filepath.Join(dir, DefaultPublicKeyName)
		}
	}
	if privPath == pubPath {
		return kp, errors.New("私钥与公钥输出路径不能相同")
	}

	// 覆盖保护：默认拒绝覆盖任何已存在文件，防止误毁旧密钥（F-701）。
	if !opt.Force {
		for _, p := range []string{privPath, pubPath} {
			if _, err := os.Stat(p); err == nil {
				return kp, fmt.Errorf("目标文件已存在：%s（如需覆盖请显式加 --force）", p)
			} else if !errors.Is(err, os.ErrNotExist) {
				return kp, fmt.Errorf("检查目标文件失败 %s: %w", p, err)
			}
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return kp, fmt.Errorf("生成 RSA 密钥失败: %w", err)
	}
	defer zeroPrivate(key)

	privPEM, err := MarshalPrivateKeyPEM(key, opt.Passphrase)
	if err != nil {
		return kp, err
	}
	defer zero(privPEM)
	pubPEM, err := MarshalPublicKeyPEM(&key.PublicKey)
	if err != nil {
		return kp, err
	}

	fpBytes, fpText, err := PublicKeyFingerprint(&key.PublicKey)
	if err != nil {
		return kp, err
	}
	_ = fpBytes

	for _, d := range []string{filepath.Dir(privPath), filepath.Dir(pubPath)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return kp, fmt.Errorf("创建密钥目录失败 %s: %w", d, err)
		}
	}
	// 私钥权限尽可能收紧（F-701）。
	if err := os.WriteFile(fsutil.LongPath(privPath), privPEM, 0o600); err != nil {
		return kp, fmt.Errorf("写入私钥失败 %s: %w", privPath, err)
	}
	if err := os.WriteFile(fsutil.LongPath(pubPath), pubPEM, 0o644); err != nil {
		// 公钥写失败时清掉刚写的私钥，避免留下孤立私钥造成困惑。
		_ = os.Remove(privPath)
		return kp, fmt.Errorf("写入公钥失败 %s: %w", pubPath, err)
	}

	kp = KeyPair{
		PrivatePath: privPath,
		PublicPath:  pubPath,
		Bits:        bits,
		Fingerprint: fpText,
		Encrypted:   len(opt.Passphrase) > 0,
	}
	return kp, nil
}

// LoadPublicKey 从 PEM 文件加载公钥，同时支持从 X.509 证书中提取公钥（F-703）。
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	raw, err := os.ReadFile(fsutil.LongPath(path))
	if err != nil {
		return nil, fmt.Errorf("读取公钥文件失败 %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%w: %s 不是 PEM 格式", ErrUnsupportedPEM, path)
	}
	switch block.Type {
	case pemTypePKCS1Private, pemTypePKCS8Private, pemTypeEncryptedStd, pemTypeEncryptedLocal:
		return nil, fmt.Errorf("%w（检测到 PEM 类型 %q）", ErrPrivateKeyDetected, block.Type)
	}

	switch block.Type {
	case pemTypePublicPKIX:
		ki, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析 PKIX 公钥失败: %w", err)
		}
		pub, ok := ki.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("公钥类型为 %T，本工具仅支持 RSA", ki)
		}
		return pub, nil
	case pemTypePublicPKCS1:
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析 PKCS#1 公钥失败: %w", err)
		}
		return pub, nil
	case pemTypeCertificate:
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析证书失败: %w", err)
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("证书公钥类型为 %T，本工具仅支持 RSA", cert.PublicKey)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("%w: 不支持的 PEM 类型 %q", ErrUnsupportedPEM, block.Type)
	}
}

// LoadPrivateKey 从 PEM 文件加载私钥，支持 PKCS#8 / PKCS#1 / 本工具口令保护格式。
//
// passphrase 为空且私钥受保护时返回 ErrPassphraseRequired。
func LoadPrivateKey(path string, passphrase []byte) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(fsutil.LongPath(path))
	if err != nil {
		return nil, fmt.Errorf("读取私钥文件失败 %s: %w", path, err)
	}
	defer zero(raw)

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%w: %s 不是 PEM 格式", ErrUnsupportedPEM, path)
	}

	switch block.Type {
	case pemTypeEncryptedLocal:
		if len(passphrase) == 0 {
			return nil, ErrPassphraseRequired
		}
		der, err := decryptLocal(block, passphrase)
		if err != nil {
			return nil, err
		}
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("%w: 解析 PKCS#8 失败", ErrBadPassphrase)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("私钥类型为 %T，本工具仅支持 RSA", key)
		}
		return rsaKey, nil
	case pemTypeEncryptedStd:
		return nil, errors.New("该私钥使用标准 PBES2 加密，Go 标准库不支持解析；" +
			"请先用 `openssl pkcs8 -in <file> -out plain.pem` 解密后再使用")
	case pemTypePKCS8Private:
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析 PKCS#8 私钥失败: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("私钥类型为 %T，本工具仅支持 RSA", key)
		}
		return rsaKey, nil
	case pemTypePKCS1Private:
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析 PKCS#1 私钥失败: %w", err)
		}
		return key, nil
	case pemTypePublicPKIX, pemTypePublicPKCS1, pemTypeCertificate:
		return nil, errors.New("该文件是公钥/证书，不能用于解密；请提供对应私钥")
	default:
		return nil, fmt.Errorf("%w: 不支持的 PEM 类型 %q", ErrUnsupportedPEM, block.Type)
	}
}

// MarshalPublicKeyPEM 把公钥序列化为 PKIX PEM。
func MarshalPublicKeyPEM(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("序列化公钥失败: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypePublicPKIX, Bytes: der}), nil
}

// MarshalPrivateKeyPEM 把私钥序列化为 PEM。
// passphrase 非空时使用本工具自有口令保护格式，否则输出明文 PKCS#8。
func MarshalPrivateKeyPEM(key *rsa.PrivateKey, passphrase []byte) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("序列化 PKCS#8 失败: %w", err)
	}
	if len(passphrase) == 0 {
		return pem.EncodeToMemory(&pem.Block{Type: pemTypePKCS8Private, Bytes: der}), nil
	}
	return encryptLocal(der, passphrase)
}

// encryptLocal 用 PBKDF2-HMAC-SHA256 + AES-256-GCM 保护 PKCS#8 DER。
func encryptLocal(der, passphrase []byte) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("生成盐失败: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, string(passphrase), salt, KDFIterations, 32)
	if err != nil {
		return nil, fmt.Errorf("密钥派生失败: %w", err)
	}
	defer zero(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("初始化 AES 失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化 GCM 失败: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("生成 nonce 失败: %w", err)
	}
	ct := aead.Seal(nil, nonce, der, []byte(pemTypeEncryptedLocal))

	body := make([]byte, 0, saltLen+len(nonce)+len(ct))
	body = append(body, salt...)
	body = append(body, nonce...)
	body = append(body, ct...)

	return pem.EncodeToMemory(&pem.Block{
		Type: pemTypeEncryptedLocal,
		Headers: map[string]string{
			"KDF":        "PBKDF2-HMAC-SHA256",
			"Iterations": fmt.Sprintf("%d", KDFIterations),
			"Cipher":     "AES-256-GCM",
		},
		Bytes: body,
	}), nil
}

// decryptLocal 解开本工具自有格式的口令保护私钥。
func decryptLocal(block *pem.Block, passphrase []byte) ([]byte, error) {
	if len(block.Bytes) < saltLen+12+16 {
		return nil, ErrBadPassphrase
	}
	salt := block.Bytes[:saltLen]
	rest := block.Bytes[saltLen:]
	key, err := pbkdf2.Key(sha256.New, string(passphrase), salt, KDFIterations, 32)
	if err != nil {
		return nil, fmt.Errorf("密钥派生失败: %w", err)
	}
	defer zero(key)

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrBadPassphrase
	}
	aead, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, ErrBadPassphrase
	}
	if len(rest) <= aead.NonceSize() {
		return nil, ErrBadPassphrase
	}
	nonce := rest[:aead.NonceSize()]
	ct := rest[aead.NonceSize():]
	der, err := aead.Open(nil, nonce, ct, []byte(pemTypeEncryptedLocal))
	if err != nil {
		// 不区分"口令错"与"文件损坏"（同 F-610 思路）。
		return nil, ErrBadPassphrase
	}
	return der, nil
}

// PublicKeyFingerprint 计算公钥的 SHA-256 指纹。
// 返回原始 32 字节与分组长十六进制文本两种形式。
func PublicKeyFingerprint(pub *rsa.PublicKey) ([32]byte, string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return [32]byte{}, "", fmt.Errorf("序列化公钥失败: %w", err)
	}
	sum := sha256.Sum256(der)
	return sum, GroupHex(sum[:]), nil
}

// PrivateKeyFingerprint 返回私钥对应公钥的指纹。
func PrivateKeyFingerprint(priv *rsa.PrivateKey) ([32]byte, string, error) {
	return PublicKeyFingerprint(&priv.PublicKey)
}

// GroupHex 把字节切片格式化为 4 字符一组的十六进制文本。
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

// PEMKind 判断 PEM 文件属于公钥、私钥还是无法识别（F-703 的前置判断）。
func PEMKind(data []byte) string {
	block, _ := pem.Decode(data)
	if block == nil {
		return "unknown"
	}
	switch block.Type {
	case pemTypePKCS8Private, pemTypePKCS1Private, pemTypeEncryptedStd, pemTypeEncryptedLocal:
		return "private"
	case pemTypePublicPKIX, pemTypePublicPKCS1, pemTypeCertificate:
		return "public"
	default:
		return "unknown"
	}
}

// SelectPublicKey 把已有公钥登记到配置文件（F-703 / F-904）。
// 若传入的是私钥则明确拒绝。
func SelectPublicKey(cfgPath, pubKeyPath string) (fingerprint string, cfg *config.Config, err error) {
	raw, err := os.ReadFile(fsutil.LongPath(pubKeyPath))
	if err != nil {
		return "", nil, fmt.Errorf("读取公钥文件失败 %s: %w", pubKeyPath, err)
	}
	switch PEMKind(raw) {
	case "private":
		return "", nil, fmt.Errorf("%w（文件：%s）", ErrPrivateKeyDetected, pubKeyPath)
	case "unknown":
		return "", nil, fmt.Errorf("%w：%s", ErrUnsupportedPEM, pubKeyPath)
	}

	pub, err := LoadPublicKey(pubKeyPath)
	if err != nil {
		return "", nil, err
	}
	bits := pub.N.BitLen()
	if bits < crypto.MinRSAKeyBits {
		return "", nil, fmt.Errorf("公钥模数仅 %d 位，低于加密容器要求的下限 %d 位，拒绝登记",
			bits, crypto.MinRSAKeyBits)
	}
	_, fpText, err := PublicKeyFingerprint(pub)
	if err != nil {
		return "", nil, err
	}

	cfg, _, err = config.Load(cfgPath)
	if err != nil {
		return "", nil, err
	}
	abs, err := filepath.Abs(pubKeyPath)
	if err != nil {
		abs = pubKeyPath
	}
	cfg.PublicKeyPath = abs
	if err := config.Save(cfgPath, cfg); err != nil {
		return "", nil, err
	}
	return fpText, cfg, nil
}

// zero 覆盖切片内容。
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroPrivate 尽力清除私钥中的大整数缓存。
//
// Go 的 rsa.PrivateKey 内部含 big.Int 与 precomputed 值，标准库不提供清零 API，
// 因此这里只做"能做的部分"：置零导出后的关键字段并释放引用。
// 真正的防护依赖操作系统内存隔离与进程生命周期（见 README 安全说明）。
func zeroPrivate(key *rsa.PrivateKey) {
	if key == nil {
		return
	}
	key.Precomputed = rsa.PrecomputedValues{}
	if key.Primes != nil {
		for i := range key.Primes {
			if key.Primes[i] != nil {
				key.Primes[i].SetInt64(0)
			}
		}
	}
	if key.D != nil {
		key.D.SetInt64(0)
	}
}
