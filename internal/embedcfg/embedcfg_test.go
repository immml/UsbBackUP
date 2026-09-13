package embedcfg

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testPayload 构造一个合法 payload。
func testPayload(t *testing.T) Payload {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return Payload{
		ConfigJSON:     []byte(`{"output_dir":"D:/out"}`),
		PublicKeyPEM:   string(pemBytes),
		ClientName:     "test-client",
		BuiltAt:        "2026-09-13T20:00:00+08:00",
		BuilderVersion: "0.3.0",
	}
}

// fakeExe 造一个"像 exe"的模板文件（内容无需真的可执行，只验证块读写）。
func fakeExe(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, bytes.Repeat([]byte("MZ-fake-pe"), 5000), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAppendAndReadRoundTrip(t *testing.T) {
	src := fakeExe(t, "usbbackup.exe")
	dst := filepath.Join(t.TempDir(), "client.exe")
	p := testPayload(t)

	if err := Append(src, dst, p); err != nil {
		t.Fatalf("Append 失败: %v", err)
	}
	got, err := Read(dst)
	if err != nil {
		t.Fatalf("Read 失败: %v", err)
	}
	if got.ClientName != p.ClientName {
		t.Errorf("客户端标识不符: %q", got.ClientName)
	}
	if got.PublicKeyPEM != p.PublicKeyPEM {
		t.Error("公钥内容不符")
	}
	if got.BuilderVersion != p.BuilderVersion {
		t.Errorf("生成器版本不符: %q", got.BuilderVersion)
	}
}

func TestAppendedClientKeepsTemplateBytes(t *testing.T) {
	// 追加块不能改动模板原有内容，否则 exe 就跑不起来了。
	src := fakeExe(t, "usbbackup.exe")
	orig, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "client.exe")
	if err := Append(src, dst, testPayload(t)); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) <= len(orig) {
		t.Fatalf("产物应大于模板: %d vs %d", len(out), len(orig))
	}
	if !bytes.Equal(out[:len(orig)], orig) {
		t.Fatal("模板前缀被改动，客户端将无法运行")
	}
}

func TestPlainFileReportsNotEmbedded(t *testing.T) {
	if _, err := Read(fakeExe(t, "plain.exe")); err != ErrNotEmbedded {
		t.Fatalf("普通文件应返回 ErrNotEmbedded，实际 %v", err)
	}
	if has, err := Has(fakeExe(t, "plain.exe")); err != nil || has {
		t.Fatalf("普通文件 Has 应为 false，实际 %v/%v", has, err)
	}
}

func TestCorruptedPayloadIsDetected(t *testing.T) {
	src := fakeExe(t, "usbbackup.exe")
	dst := filepath.Join(t.TempDir(), "client.exe")
	if err := Append(src, dst, testPayload(t)); err != nil {
		t.Fatal(err)
	}
	// 篡改 payload 区域的一个字节（文件前部即模板区，这里改模板区不影响块结构，
	// 改 payload 区才是关键：payload 位于倒数 tailFixed 之前）。
	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	payloadStart := len(raw) - tailFixed - 20 // 落在 payload 内
	raw[payloadStart] ^= 0xFF
	broken := filepath.Join(t.TempDir(), "broken.exe")
	if err := os.WriteFile(broken, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(broken); err == nil {
		t.Fatal("payload 被篡改后应报错")
	} else if !strings.Contains(err.Error(), "损坏") {
		t.Fatalf("错误信息应说明损坏: %v", err)
	}
}

func TestTruncatedTailIsDetected(t *testing.T) {
	src := fakeExe(t, "usbbackup.exe")
	dst := filepath.Join(t.TempDir(), "client.exe")
	if err := Append(src, dst, testPayload(t)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	cut := filepath.Join(t.TempDir(), "cut.exe")
	if err := os.WriteFile(cut, raw[:len(raw)-4], 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(cut); err == nil {
		t.Fatal("尾部被截断后应报错")
	}
}

func TestRefusesEmbeddingPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	// 常见误操作：把 key.pem 当成 pub.pem 传进来。
	if err := EnsureNoSecret(Payload{PublicKeyPEM: string(privPEM)}); err == nil {
		t.Fatal("内嵌私钥必须被拒绝")
	}
	p := testPayload(t)
	p.PublicKeyPEM = string(privPEM)
	if _, err := p.Marshal(); err == nil {
		t.Fatal("Marshal 应拒绝含私钥的 payload")
	}
	src := fakeExe(t, "usbbackup.exe")
	if err := Append(src, filepath.Join(t.TempDir(), "evil.exe"), p); err == nil {
		t.Fatal("Append 应拒绝含私钥的 payload")
	}
}

func TestRefusesEmbeddingEncryptedPrivateKey(t *testing.T) {
	enc := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n"
	if err := EnsureNoSecret(Payload{PublicKeyPEM: enc}); err == nil {
		t.Fatal("加密私钥同样必须被拒绝")
	}
}

func TestRefusesDoubleAppend(t *testing.T) {
	src := fakeExe(t, "usbbackup.exe")
	first := filepath.Join(t.TempDir(), "client1.exe")
	if err := Append(src, first, testPayload(t)); err != nil {
		t.Fatal(err)
	}
	// 拿已内嵌的产物再当模板，应被拒绝（否则同一文件会有两个块）。
	if err := Append(first, filepath.Join(t.TempDir(), "client2.exe"), testPayload(t)); err == nil {
		t.Fatal("重复追加应被拒绝")
	}
}

func TestHasDetectsClient(t *testing.T) {
	src := fakeExe(t, "usbbackup.exe")
	dst := filepath.Join(t.TempDir(), "client.exe")
	if err := Append(src, dst, testPayload(t)); err != nil {
		t.Fatal(err)
	}
	has, err := Has(dst)
	if err != nil || !has {
		t.Fatalf("Has 应为 true，实际 %v/%v", has, err)
	}
}
