package keyfile

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/immml/UsbBackup/internal/config"
)

func newMatcher(t *testing.T) *Matcher {
	t.Helper()
	m, err := NewMatcher(nil, nil, 4096)
	if err != nil {
		t.Fatalf("构造检测器失败: %v", err)
	}
	return m
}

func TestMatchName(t *testing.T) {
	m := newMatcher(t)
	shouldHit := []string{
		"id_rsa", "id_ed25519", "ID_RSA", "my.pem", "server.key", "x.ppk",
		"cert.p12", "store.jks", "keystore.jks", "a.p8", "t.asc", "s.gpg",
		"wireguard_key.txt",
	}
	for _, n := range shouldHit {
		if _, ok := m.MatchName(n); !ok {
			t.Errorf("文件名 %q 应命中但未命中", n)
		}
	}
	shouldMiss := []string{"readme.md", "photo.jpg", "video.mp4", "报告.docx", "data.csv"}
	for _, n := range shouldMiss {
		if k, ok := m.MatchName(n); ok {
			t.Errorf("文件名 %q 不应命中，却命中为 %s", n, k)
		}
	}
}

func TestMatchHeader(t *testing.T) {
	m := newMatcher(t)
	cases := []struct {
		name   string
		header string
		kind   Kind
	}{
		{"PKCS#8 私钥", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n", KindPEMHeader},
		{"PKCS#1 私钥", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n", KindPEMHeader},
		{"EC 私钥", "-----BEGIN EC PRIVATE KEY-----\nMHcC\n", KindPEMHeader},
		{"加密私钥", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF\n", KindPEMHeader},
		{"OpenSSH 私钥", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n", KindPEMHeader},
		{"SSH2 私钥", "---- BEGIN SSH2 PRIVATE KEY ----\n", KindPEMHeader},
		{"PGP 私钥", "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBG\n", KindPGP},
		{"PuTTY ppk", "PuTTY-User-Key-File-3: ssh-rsa\n", KindPuTTY},
		{"OpenSSH 容器", "openssh-key-v1\x00\x00\x00\x00", KindOpenSSH},
		{"age 私钥", "AGE-SECRET-KEY-1QQQQQQQQ\n", KindAge},
		{"WireGuard", "[Interface]\nPrivateKey = abcdef=\n", KindWireGuard},
		{"Ethereum keystore", `{"address":"x","crypto":{"cipher":"aes-128-ctr","kdf":"scrypt"}}`, KindEthKS},
		{"PVK 二进制", "\xb0\xb0\xb0\xb0\x01\x00\x00\x00", KindPVK},
		{"JKS 二进制", "\xfe\xed\xfe\xed\x00\x00\x00\x02", KindJKS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, ok := m.MatchHeader([]byte(tc.header))
			if !ok {
				t.Fatalf("期望命中但未命中")
			}
			if kind != tc.kind {
				t.Fatalf("命中类型为 %s，期望 %s", kind, tc.kind)
			}
		})
	}

	notKeys := []string{
		"hello world",
		"-----BEGIN CERTIFICATE-----\nMIIB\n",
		"-----BEGIN PUBLIC KEY-----\nMIIB\n",
		"{\"name\":\"config\",\"value\":1}",
		"PK\x03\x04",
		"",
	}
	for _, s := range notKeys {
		if kind, ok := m.MatchHeader([]byte(s)); ok {
			t.Fatalf("内容 %q 不应被判定为私钥，却命中为 %s", s, kind)
		}
	}
}

func TestShouldReadHeader(t *testing.T) {
	m := newMatcher(t)
	yes := []string{"a.pem", "b.key", "noext", "c.txt", "d.json", "e.conf", "f.unknown"}
	for _, n := range yes {
		if !m.ShouldReadHeader(n) {
			t.Errorf("%q 应读取头部", n)
		}
	}
	no := []string{"movie.mp4", "photo.JPG", "archive.zip", "disk.iso", "app.exe", "big.vhdx"}
	for _, n := range no {
		if m.ShouldReadHeader(n) {
			t.Errorf("%q 不应读取头部（性能过滤失效）", n)
		}
	}
}

func TestMatchAllowMarker(t *testing.T) {
	fp := "aabb ccdd eeff 0011"
	ok := []string{
		"aabbccddeeff0011",
		"AABB CCDD EEFF 0011\n",
		"# 说明行\nfingerprint=aabbccddeeff0011\n",
		"pubkey: aabb-ccdd-eeff-0011",
	}
	for _, s := range ok {
		if !MatchAllowMarker([]byte(s), fp) {
			t.Errorf("标记内容 %q 应匹配", s)
		}
	}
	no := []string{"", "aabbccdd", "fingerprint=deadbeef", "随便写点什么"}
	for _, s := range no {
		if MatchAllowMarker([]byte(s), fp) {
			t.Errorf("标记内容 %q 不应匹配", s)
		}
	}
	if MatchAllowMarker([]byte("aabbccddeeff0011"), "") {
		t.Error("期望指纹为空时不应匹配")
	}
}

func TestScanDetectsAndIgnores(t *testing.T) {
	m := newMatcher(t)
	ctx := context.Background()
	det := config.DetectConfig{
		Mode: "both", MaxDepth: 4, MaxFiles: 1000,
		MaxHeadersBytes: 4096, TimeoutSec: 10, MarkerFile: ".usbguard-allow", ScanContents: true,
	}

	t.Run("普通目录不应判定为授权", func(t *testing.T) {
		dir := t.TempDir()
		mustWrite(t, filepath.Join(dir, "readme.md"), "# hello")
		mustWrite(t, filepath.Join(dir, "notes.txt"), "just notes")
		if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(dir, "sub", "data.json"), `{"a":1}`)

		res, err := Scan(ctx, Options{Root: dir, Matcher: m, Detect: det})
		if err != nil {
			t.Fatalf("扫描失败: %v", err)
		}
		if res.Authorized {
			t.Fatalf("普通目录被误判为持有私钥（命中类型 %v）", res.Kinds)
		}
		if res.FilesScanned == 0 {
			t.Fatal("未统计到扫描文件数")
		}
	})

	t.Run("文件名命中", func(t *testing.T) {
		dir := t.TempDir()
		mustWrite(t, filepath.Join(dir, "id_rsa"), "not really a key")
		res, err := Scan(ctx, Options{Root: dir, Matcher: m, Detect: det})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Authorized || res.HitCount == 0 {
			t.Fatalf("应判定为授权：%+v", res)
		}
	})

	t.Run("内容命中", func(t *testing.T) {
		dir := t.TempDir()
		mustWrite(t, filepath.Join(dir, "note.txt"), "-----BEGIN PRIVATE KEY-----\nMIIE\n")
		res, err := Scan(ctx, Options{Root: dir, Matcher: m, Detect: det})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Authorized {
			t.Fatalf("内容特征应命中：%+v", res)
		}
	})

	t.Run("显式授权标记需匹配指纹", func(t *testing.T) {
		dir := t.TempDir()
		mustWrite(t, filepath.Join(dir, ".usbguard-allow"), "fingerprint=aabbccddeeff0011\n")
		res, err := Scan(ctx, Options{Root: dir, Matcher: m, Detect: det, AllowedFingerprint: "aabb ccdd eeff 0011"})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Authorized {
			t.Fatalf("标记应命中：%+v", res)
		}
		// 指纹不匹配时不应仅凭标记存在就放行。
		res2, err := Scan(ctx, Options{Root: dir, Matcher: m, Detect: det, AllowedFingerprint: "0000111122223333"})
		if err != nil {
			t.Fatal(err)
		}
		if res2.Authorized {
			t.Fatal("指纹不匹配时不应判定为授权")
		}
	})

	t.Run("排除系统目录", func(t *testing.T) {
		dir := t.TempDir()
		sysDir := filepath.Join(dir, "System Volume Information")
		if err := os.MkdirAll(sysDir, 0o755); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(sysDir, "id_rsa"), "-----BEGIN PRIVATE KEY-----")
		res, err := Scan(ctx, Options{Root: dir, Matcher: m, Detect: det})
		if err != nil {
			t.Fatal(err)
		}
		if res.Authorized {
			t.Fatal("系统目录应被排除，不应据其判定授权")
		}
	})

	t.Run("深度上限", func(t *testing.T) {
		dir := t.TempDir()
		deep := dir
		for i := 0; i < 8; i++ {
			deep = filepath.Join(deep, "d")
		}
		if err := os.MkdirAll(deep, 0o755); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(deep, "id_rsa"), "x")
		shallow := det
		shallow.MaxDepth = 2
		res, err := Scan(ctx, Options{Root: dir, Matcher: m, Detect: shallow})
		if err != nil {
			t.Fatal(err)
		}
		if res.Authorized {
			t.Fatal("超出深度上限的目录不应被扫描")
		}
		if !res.Truncated {
			t.Fatal("触及深度上限时应标记 Truncated")
		}
	})

	t.Run("结果不携带文件名", func(t *testing.T) {
		dir := t.TempDir()
		mustWrite(t, filepath.Join(dir, "id_rsa"), "x")
		res, _ := Scan(ctx, Options{Root: dir, Matcher: m, Detect: det})
		// Kinds 只应包含固定的类型常量，不含任何文件名。
		for _, k := range res.Kinds {
			switch Kind(k) {
			case KindNameOnly, KindPEMHeader, KindOpenSSH, KindPuTTY, KindPGP,
				KindAge, KindWireGuard, KindPVK, KindJKS, KindPKCS12, KindEthKS, KindAllowMark:
			default:
				t.Fatalf("命中类型 %q 不是合法常量，可能泄露了文件名", k)
			}
		}
	})
}

func TestScanRejectsBadRoot(t *testing.T) {
	m := newMatcher(t)
	if _, err := Scan(context.Background(), Options{Root: "", Matcher: m}); err == nil {
		t.Fatal("空根路径应报错")
	}
	if _, err := Scan(context.Background(), Options{Root: filepath.Join(t.TempDir(), "不存在"), Matcher: m}); err == nil {
		t.Fatal("不存在的根路径应报错")
	}
	if _, err := Scan(context.Background(), Options{Root: t.TempDir()}); err == nil {
		t.Fatal("未提供 Matcher 应报错")
	}
}

func TestNewMatcherValidates(t *testing.T) {
	if _, err := NewMatcher([]string{"["}, nil, 0); err == nil {
		t.Fatal("非法模式应报错")
	}
	m, err := NewMatcher([]string{"*.mykey"}, []string{"MY-CUSTOM-MARKER"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.MatchName("a.mykey"); !ok {
		t.Fatal("自定义名称模式未生效")
	}
	if _, ok := m.MatchHeader([]byte("xx MY-CUSTOM-MARKER xx")); !ok {
		t.Fatal("自定义内容特征未生效")
	}
	if m.MaxHeaderBytes() != 4096 {
		t.Fatalf("默认头部上限应为 4096，实际 %d", m.MaxHeaderBytes())
	}
}

func TestZeroClears(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("第 %d 字节未清零", i)
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入 %s 失败: %v", path, err)
	}
}
