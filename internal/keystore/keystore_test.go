package keystore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/immml/UsbBackup/internal/config"
)

// genForTest 生成一把 2048 位测试密钥（4096 位仅用于生产，测试中太慢）。
func genForTest(t *testing.T, dir string, passphrase []byte) KeyPair {
	t.Helper()
	kp, err := Generate(GenerateOptions{Bits: 2048, OutDir: dir, Passphrase: passphrase})
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}
	return kp
}

func TestGenerateAndLoad(t *testing.T) {
	dir := t.TempDir()
	kp := genForTest(t, dir, nil)

	if kp.Bits != 2048 {
		t.Fatalf("位数应为 2048，实际 %d", kp.Bits)
	}
	if kp.Encrypted {
		t.Fatal("未提供口令时不应标记为加密")
	}
	for _, p := range []string{kp.PrivatePath, kp.PublicPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("产物缺失 %s: %v", p, err)
		}
	}
	if filepath.Base(kp.PrivatePath) != DefaultPrivateKeyName {
		t.Fatalf("私钥默认名不符: %s", kp.PrivatePath)
	}
	if kp.Fingerprint == "" {
		t.Fatal("指纹不应为空")
	}

	pub, err := LoadPublicKey(kp.PublicPath)
	if err != nil {
		t.Fatalf("加载公钥失败: %v", err)
	}
	if pub.N.BitLen() != 2048 {
		t.Fatalf("公钥位数不符: %d", pub.N.BitLen())
	}
	_, fp2, err := PublicKeyFingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	if fp2 != kp.Fingerprint {
		t.Fatalf("指纹不稳定：%q vs %q", fp2, kp.Fingerprint)
	}

	priv, err := LoadPrivateKey(kp.PrivatePath, nil)
	if err != nil {
		t.Fatalf("加载私钥失败: %v", err)
	}
	if priv.N.Cmp(pub.N) != 0 {
		t.Fatal("私钥与公钥不配对")
	}
}

func TestGenerateRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	kp := genForTest(t, dir, nil)

	if _, err := Generate(GenerateOptions{Bits: 2048, OutDir: dir}); err == nil {
		t.Fatal("默认应拒绝覆盖已存在密钥")
	}
	// 加 --force 后应允许。
	if _, err := Generate(GenerateOptions{Bits: 2048, OutDir: dir, Force: true}); err != nil {
		t.Fatalf("Force 应允许覆盖: %v", err)
	}
	_ = kp
}

func TestGenerateRejectsWeakBitsAndShortPassphrase(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(GenerateOptions{Bits: 1024, OutDir: dir}); err == nil {
		t.Fatal("1024 位应被拒绝")
	}
	if _, err := Generate(GenerateOptions{Bits: 2048, OutDir: dir, Passphrase: []byte("123")}); err == nil {
		t.Fatal("过短口令应被拒绝")
	}
	if _, err := Generate(GenerateOptions{Bits: 1 << 20, OutDir: dir}); err == nil {
		t.Fatal("超大位数应被拒绝")
	}
}

func TestPassphraseProtectedPrivateKey(t *testing.T) {
	dir := t.TempDir()
	pass := []byte("correct horse battery staple")
	kp := genForTest(t, dir, pass)

	if !kp.Encrypted {
		t.Fatal("应标记为已加密")
	}
	raw, err := os.ReadFile(kp.PrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	if PEMKind(raw) != "private" {
		t.Fatalf("PEM 类型应为 private，实际 %s", PEMKind(raw))
	}
	if bytes.Contains(raw, []byte("BEGIN PRIVATE KEY")) && !bytes.Contains(raw, []byte(pemTypeEncryptedLocal)) {
		t.Fatal("加密私钥不应以明文 PKCS#8 形式出现")
	}
	// 明文私钥的 base64 主体不得出现在文件里：粗略检查 PKCS#8 头。
	if strings.Contains(string(raw), "-----BEGIN PRIVATE KEY-----") {
		t.Fatal("加密文件里不应出现明文 PKCS#8 头")
	}

	if _, err := LoadPrivateKey(kp.PrivatePath, nil); err == nil {
		t.Fatal("未提供口令时应报错")
	}
	if _, err := LoadPrivateKey(kp.PrivatePath, []byte("wrong passphrase")); err == nil {
		t.Fatal("错误口令应报错")
	}
	priv, err := LoadPrivateKey(kp.PrivatePath, pass)
	if err != nil {
		t.Fatalf("正确口令应能加载: %v", err)
	}
	if priv.N.BitLen() != 2048 {
		t.Fatalf("位数不符: %d", priv.N.BitLen())
	}
	_, fp, err := PrivateKeyFingerprint(priv)
	if err != nil {
		t.Fatal(err)
	}
	if fp != kp.Fingerprint {
		t.Fatal("加载后的私钥指纹与生成时不符")
	}
}

func TestLoadPublicKeyRejectsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	kp := genForTest(t, dir, nil)
	if _, err := LoadPublicKey(kp.PrivatePath); err == nil {
		t.Fatal("把私钥当公钥加载应被拒绝")
	}
}

func TestLoadPrivateKeyRejectsPublicKey(t *testing.T) {
	dir := t.TempDir()
	kp := genForTest(t, dir, nil)
	if _, err := LoadPrivateKey(kp.PublicPath, nil); err == nil {
		t.Fatal("把公钥当私钥加载应被拒绝")
	}
}

func TestSelectPublicKeyWritesConfig(t *testing.T) {
	dir := t.TempDir()
	kp := genForTest(t, dir, nil)
	cfgPath := filepath.Join(dir, "config.json")

	fp, cfg, err := SelectPublicKey(cfgPath, kp.PublicPath)
	if err != nil {
		t.Fatalf("登记公钥失败: %v", err)
	}
	if fp != kp.Fingerprint {
		t.Fatalf("指纹不符：%q vs %q", fp, kp.Fingerprint)
	}
	if cfg.PublicKeyPath == "" {
		t.Fatal("配置未写入公钥路径")
	}
	// 配置文件中不得出现私钥内容。
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("配置文件中出现了私钥材料")
	}
	reloaded, loaded, err := config.Load(cfgPath)
	if err != nil || !loaded {
		t.Fatalf("重新加载配置失败: loaded=%v err=%v", loaded, err)
	}
	if reloaded.PublicKeyPath != cfg.PublicKeyPath {
		t.Fatal("配置未持久化")
	}
}

func TestSelectPublicKeyRejectsPrivateKeyAndWeakKey(t *testing.T) {
	dir := t.TempDir()
	kp := genForTest(t, dir, nil)
	cfgPath := filepath.Join(dir, "config.json")

	if _, _, err := SelectPublicKey(cfgPath, kp.PrivatePath); err == nil {
		t.Fatal("私钥应被拒绝")
	} else if !strings.Contains(err.Error(), "私钥") {
		t.Fatalf("错误信息应明确指出是私钥：%v", err)
	}

	if _, _, err := SelectPublicKey(cfgPath, filepath.Join(dir, "不存在.pem")); err == nil {
		t.Fatal("不存在的文件应报错")
	}

	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SelectPublicKey(cfgPath, junk); err == nil {
		t.Fatal("非 PEM 文件应被拒绝")
	}
}

func TestPEMKind(t *testing.T) {
	dir := t.TempDir()
	kp := genForTest(t, dir, nil)
	priv, _ := os.ReadFile(kp.PrivatePath)
	pub, _ := os.ReadFile(kp.PublicPath)

	if PEMKind(priv) != "private" {
		t.Fatal("私钥类型判断错误")
	}
	if PEMKind(pub) != "public" {
		t.Fatal("公钥类型判断错误")
	}
	if PEMKind([]byte("hello")) != "unknown" {
		t.Fatal("非 PEM 应判为 unknown")
	}
}

func TestGroupHexInKeystore(t *testing.T) {
	if got := GroupHex([]byte{0xde, 0xad, 0xbe, 0xef}); got != "dead beef" {
		t.Fatalf("分组格式错误: %q", got)
	}
}
