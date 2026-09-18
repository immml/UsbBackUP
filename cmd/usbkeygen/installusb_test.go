package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/immml/UsbBackUP/internal/embedcfg"
	"github.com/immml/UsbBackUP/internal/keyfile"
	"github.com/immml/UsbBackUP/internal/keystore"
)

// writeTestKeys 生成一对测试密钥，返回 (目录, 公钥路径, 私钥路径)。
func writeTestKeys(t *testing.T) (dir, pub, priv string) {
	t.Helper()
	dir = t.TempDir()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pub = filepath.Join(dir, "usbbackup.pub.pem")
	priv = filepath.Join(dir, "usbbackup.key.pem")
	if err := os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(priv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, pub, priv
}

// fakeToolDir 造一个"工具目录"：一个假 exe + 一个假客户端模板。
func fakeToolDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	body := []byte(strings.Repeat("MZ", 4000))
	if err := os.WriteFile(filepath.Join(dir, "usbkeygen.exe"), body, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "usbunseal.exe"), body, 0o755); err != nil {
		t.Fatal(err)
	}
	// 客户端模板必须是一个能被 embedcfg 追加块的文件。
	if err := os.WriteFile(filepath.Join(dir, "usbbackup.exe"), body, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAssembleToolkitWritesExpectedLayout(t *testing.T) {
	_, pub, priv := writeTestKeys(t)
	tools := fakeToolDir(t)
	dest := t.TempDir()

	n, err := assembleToolkit(toolkitOptions{
		Dest:           dest,
		ToolDir:        tools,
		PublicKeyPath:  pub,
		PrivateKeyPath: priv,
		WithPrivate:    true,
		WithClient:     true,
		Force:          true,
	}, io.Discard)
	if err != nil {
		t.Fatalf("assembleToolkit 失败: %v", err)
	}
	if n < 6 {
		t.Errorf("写入项数偏少: %d", n)
	}

	must := []string{
		"usbkeygen.exe", "usbunseal.exe", "client.exe",
		filepath.Join("keys", "usbbackup.pub.pem"),
		filepath.Join("keys", "usbbackup.key.pem"),
		".usbbackup-allow", "README.txt",
	}
	for _, rel := range must {
		if _, err := os.Stat(filepath.Join(dest, rel)); err != nil {
			t.Errorf("缺少 %s: %v", rel, err)
		}
	}
}

func TestToolkitClientIsReallyEmbedded(t *testing.T) {
	// 盘里的 client.exe 必须是可用的内嵌客户端，而不是空壳。
	_, pub, priv := writeTestKeys(t)
	dest := t.TempDir()
	if _, err := assembleToolkit(toolkitOptions{
		Dest: dest, ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv,
		WithClient: true, Force: true,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := embedcfg.Read(filepath.Join(dest, "client.exe"))
	if err != nil {
		t.Fatalf("盘内 client.exe 无法读回内嵌配置: %v", err)
	}
	if got.ClientName != "usb-toolkit" {
		t.Errorf("客户端标识不符: %q", got.ClientName)
	}
}

func TestAllowMarkerMatchesConfiguredKey(t *testing.T) {
	// 盘里的授权标记必须能被 keyfile 认出来，否则这个盘会被打包带走。
	_, pub, priv := writeTestKeys(t)
	dest := t.TempDir()
	if _, err := assembleToolkit(toolkitOptions{
		Dest: dest, ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv, Force: true,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dest, ".usbbackup-allow"))
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := keystore.ParsePublicKeyPEM(mustRead(t, pub))
	if err != nil {
		t.Fatal(err)
	}
	_, fp, err := keystore.PublicKeyFingerprint(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if !keyfile.MatchAllowMarker(raw, fp) {
		t.Fatal("授权标记与公钥指纹不匹配，工具盘会被当成普通盘打包")
	}
}

func TestAssembleWithoutPrivateOmitsKey(t *testing.T) {
	_, pub, priv := writeTestKeys(t)
	dest := t.TempDir()
	if _, err := assembleToolkit(toolkitOptions{
		Dest: dest, ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv,
		WithPrivate: false, Force: true,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "keys", "usbbackup.key.pem")); err == nil {
		t.Fatal("--without-private 时不应写入私钥")
	}
	if _, err := os.Stat(filepath.Join(dest, "keys", "usbbackup.pub.pem")); err != nil {
		t.Error("公钥仍应写入")
	}
}

func TestAssembleRefusesOverwriteWithoutForce(t *testing.T) {
	_, pub, priv := writeTestKeys(t)
	dest := t.TempDir()
	opt := toolkitOptions{
		Dest: dest, ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv, Force: false,
	}
	if _, err := assembleToolkit(opt, io.Discard); err != nil {
		t.Fatal(err)
	}
	// 第二次不带 Force 应失败，而不是静默覆盖。
	if _, err := assembleToolkit(opt, io.Discard); err == nil {
		t.Fatal("未加 Force 时不应覆盖已存在的文件")
	}
}

func TestAssembleToolkitIntoSubDir(t *testing.T) {
	// 工具可以收进子目录，但授权标记必须留在盘根——
	// keyfile 只在 <盘根>\.usbbackup-allow 处检查标记，挪走就检测不到。
	_, pub, priv := writeTestKeys(t)
	dest := t.TempDir()

	n, err := assembleToolkit(toolkitOptions{
		Dest: dest, SubDir: filepath.Join("backup", "tools"), ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv,
		WithPrivate: true, WithClient: true, Force: true,
	}, io.Discard)
	if err != nil {
		t.Fatalf("assembleToolkit 失败: %v", err)
	}
	if n < 6 {
		t.Errorf("写入项数偏少: %d", n)
	}

	tools := filepath.Join(dest, "backup", "tools")
	for _, rel := range []string{"usbunseal.exe", "client.exe", "README.txt", filepath.Join("keys", "usbbackup.key.pem")} {
		if _, err := os.Stat(filepath.Join(tools, rel)); err != nil {
			t.Errorf("子目录内缺少 %s: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, ".usbbackup-allow")); err != nil {
		t.Errorf("授权标记必须在盘根: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "usbunseal.exe")); err == nil {
		t.Error("工具不应再出现在盘根")
	}
}

func TestCleanSubDirRejectsEscape(t *testing.T) {
	bad := []string{
		filepath.Join("..", "escape"),
		"..",
		`C:\Windows`,
		`\absolute`,
		"/etc",
	}
	for _, v := range bad {
		if got := cleanSubDir(v); got != "" {
			t.Errorf("cleanSubDir(%q) = %q，应被拒绝", v, got)
		}
	}
	good := map[string]string{
		filepath.Join("backup", "tools"): filepath.Join("backup", "tools"),
		"backup/tools":                   filepath.Join("backup", "tools"),
		"":                               "",
		"   ":                            "",
	}
	for in, want := range good {
		if got := cleanSubDir(in); got != want {
			t.Errorf("cleanSubDir(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func TestToolkitReadmeWarnsOnlyWhenPrivatePresent(t *testing.T) {
	withPriv := toolkitReadme("aa bb cc", true, false)
	if !strings.Contains(withPriv, "明文私钥") {
		t.Error("带明文私钥时应有风险提示")
	}
	without := toolkitReadme("aa bb cc", false, false)
	if strings.Contains(without, "明文私钥") {
		t.Error("不带私钥时不应出现私钥风险提示")
	}
	if !strings.Contains(without, "私钥未上盘") {
		t.Error("不带私钥时应说明如何取私钥")
	}
}

func TestToolkitReadmeDistinguishesEncryptedPrivate(t *testing.T) {
	// 带口令的私钥不能再被描述成"明文"——盘上写错风险等级会误导现场的人。
	enc := toolkitReadme("aa bb cc", true, true)
	if strings.Contains(enc, "明文私钥") {
		t.Error("口令保护的私钥不应被写成明文")
	}
	if !strings.Contains(enc, "口令保护") {
		t.Error("应说明私钥带口令保护")
	}
	plain := toolkitReadme("aa bb cc", true, false)
	if !strings.Contains(plain, "明文私钥") {
		t.Error("明文私钥应如实标注")
	}
}

func TestIsEncryptedPrivateKeyPEM(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := keystore.MarshalPrivateKeyPEM(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if keystore.IsEncryptedPrivateKeyPEM(plain) {
		t.Error("无口令私钥被误判为已加密")
	}
	enc, err := keystore.MarshalPrivateKeyPEM(key, []byte("correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	if !keystore.IsEncryptedPrivateKeyPEM(enc) {
		t.Error("带口令私钥未被识别")
	}
	if keystore.IsEncryptedPrivateKeyPEM([]byte("not a pem at all")) {
		t.Error("非 PEM 内容不应被判为已加密")
	}
}

func TestCopyFileAndHelpers(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	dst := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst, false); err != nil {
		t.Fatal(err)
	}
	got := string(mustRead(t, dst))
	if got != "hello" {
		t.Errorf("复制内容不符: %q", got)
	}
	// 已存在且不 force → 报错。
	if err := copyFile(src, dst, false); err == nil {
		t.Error("已存在时应报错")
	}
	// force → 可覆盖。
	if err := copyFile(src, dst, true); err != nil {
		t.Error("force 应可覆盖")
	}
	if got := firstNonEmpty("", "  ", "x", "y"); got != "x" {
		t.Errorf("firstNonEmpty 异常: %q", got)
	}
	if got := emptyOr("", "fallback"); got != "fallback" {
		t.Errorf("emptyOr 异常: %q", got)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
