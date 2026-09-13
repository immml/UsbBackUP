package clientgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeTemplate 造一个"像 exe"的模板（内容无需真可执行，只验证块读写与复制）。
func fakeTemplate(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "usbbackup.exe")
	if err := os.WriteFile(p, []byte(strings.Repeat("MZ", 5000)), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// pubPEM 生成一把测试公钥的 PEM。
func pubPEM(t *testing.T, bits int) (pemBytes []byte, key *rsa.PrivateKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), k
}

func okOptions(t *testing.T, out string) Options {
	t.Helper()
	p, _ := pubPEM(t, 2048)
	return Options{
		PublicKeyPEM: p,
		Template:     fakeTemplate(t),
		Output:       out,
		ClientName:   "unit-test",
		OutputDir:    "D:/out",
		Threshold:    "4GiB",
	}
}

func TestBuildProducesReadableClient(t *testing.T) {
	out := filepath.Join(t.TempDir(), "client.exe")
	res, err := Build(okOptions(t, out))
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if res.ClientName != "unit-test" {
		t.Errorf("客户端标识不符: %q", res.ClientName)
	}
	if res.KeyBits != 2048 {
		t.Errorf("位数不符: %d", res.KeyBits)
	}
	if res.OutputDir != "D:/out" {
		t.Errorf("输出目录不符: %q", res.OutputDir)
	}
	if !strings.Contains(res.ThresholdText, "4GiB") {
		t.Errorf("阈值展示异常: %q", res.ThresholdText)
	}
	if res.Fingerprint == "" {
		t.Error("应返回公钥指纹")
	}
	// 产物必须比模板大（追加了配置块）。
	tplSize := int64(10000)
	st, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() <= tplSize {
		t.Errorf("产物应大于模板: %d vs %d", st.Size(), tplSize)
	}
}

func TestBuildRejectsPrivateKey(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	priv := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	opt := okOptions(t, filepath.Join(t.TempDir(), "c.exe"))
	opt.PublicKeyPEM = priv
	if _, err := Build(opt); err == nil {
		t.Fatal("内嵌私钥必须被拒绝")
	}
}

func TestBuildValidatesInputs(t *testing.T) {
	base := okOptions(t, filepath.Join(t.TempDir(), "c.exe"))

	// 缺公钥。
	o := base
	o.PublicKeyPEM = nil
	if _, err := Build(o); err == nil {
		t.Error("缺公钥应报错")
	}
	// 缺输出路径。
	o = base
	o.Output = ""
	if _, err := Build(o); err == nil {
		t.Error("缺输出路径应报错")
	}
	// 阈值非法。
	o = base
	o.Threshold = "10XYZ"
	if _, err := Build(o); err == nil {
		t.Error("阈值非法应报错")
	}
	// 打包上限非法。
	o = base
	o.MaxTotal = "abc"
	if _, err := Build(o); err == nil {
		t.Error("上限非法应报错")
	}
	// 模板不存在。
	o = base
	o.Template = filepath.Join(t.TempDir(), "nope.exe")
	if _, err := Build(o); err == nil {
		t.Error("模板不存在应报错")
	}
	// 模板是目录。
	o = base
	o.Template = t.TempDir()
	if _, err := Build(o); err == nil {
		t.Error("模板为目录应报错")
	}
}

func TestBuildRefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "client.exe")
	if _, err := Build(okOptions(t, out)); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(okOptions(t, out)); err == nil {
		t.Fatal("未加 Force 时不应覆盖已存在的产物")
	}
	// 显式 Force 可以覆盖。
	o := okOptions(t, out)
	o.Force = true
	if _, err := Build(o); err != nil {
		t.Fatalf("Force 后应可覆盖: %v", err)
	}
}

func TestBuildAppliesOverrides(t *testing.T) {
	out := filepath.Join(t.TempDir(), "client.exe")
	o := okOptions(t, out)
	o.SourceDir = "D:/mysource"
	o.MaxTotal = "0"
	res, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	if res.SourceDir != "D:/mysource" {
		t.Errorf("源目录覆盖未生效: %q", res.SourceDir)
	}
	if res.MaxTotalText != "不限制" {
		t.Errorf("上限 0 应显示为不限制，实际 %q", res.MaxTotalText)
	}
	if res.Config.Gate.MaxTotalBytes != 0 {
		t.Errorf("上限 0 未生效: %d", res.Config.Gate.MaxTotalBytes)
	}
	if res.Config.PublicKeyPath != "<内嵌于客户端>" {
		t.Errorf("公钥路径应为内嵌占位，实际 %q", res.Config.PublicKeyPath)
	}
}

func TestHumanLimit(t *testing.T) {
	if got := humanLimit(0); got != "不限制" {
		t.Errorf("0 应显示不限制，实际 %q", got)
	}
	if got := humanLimit(10 * 1024 * 1024 * 1024); got == "不限制" || got == "" {
		t.Errorf("10GiB 显示异常: %q", got)
	}
}
