package keyfile

import (
	"fmt"
	"path"
	"strings"
)

// Kind 表示命中类型。它只描述"哪一类特征被命中"，
// **不携带任何文件名、路径或文件内容**（见需求 G-02）。
type Kind string

// 命中类型常量。
const (
	KindNone      Kind = ""
	KindNameOnly  Kind = "name"           // 仅文件名命中
	KindPEMHeader Kind = "pem-header"     // PEM 私钥头
	KindOpenSSH   Kind = "openssh-key-v1" // OpenSSH 新格式
	KindPuTTY     Kind = "putty"          // PuTTY .ppk
	KindPGP       Kind = "pgp-private"    // PGP 私钥块
	KindAge       Kind = "age-secret-key" // age 私钥
	KindWireGuard Kind = "wireguard"      // WireGuard 配置内私钥字段
	KindPVK       Kind = "pvk"            // Windows CryptoAPI PVK
	KindJKS       Kind = "jks"            // Java KeyStore
	KindPKCS12    Kind = "pkcs12"         // PKCS#12 / PFX
	KindEthKS     Kind = "eth-keystore"   // Ethereum keystore JSON
	KindAllowMark Kind = "allow-marker"   // 显式授权标记
	KindCustom    Kind = "custom-marker"  // 配置追加的自定义内容特征
)

// DefaultNamePatterns 是内置文件名模式表（F-201 / F-207）。
// 大小写不敏感，`*` 为通配。刻意覆盖常见密钥载体形态。
var DefaultNamePatterns = []string{
	// OpenSSH / OpenSSL 常见命名
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_xmss",
	// 通用扩展名
	"*.pem", "*.key", "*.keys", "*.priv", "*.privkey", "*.pvk", "*.skey",
	// PuTTY
	"*.ppk",
	// PKCS#12 / Java
	"*.p12", "*.pfx", "*.jks", "*.keystore", "*.bks", "*.ubr",
	// PKCS#8 其它写法
	"*.p8", "*.pkcs8", "*.der",
	// PGP / age
	"*.asc", "*.gpg", "*.pgp",
	// 文本形态
	"*_key.txt", "*_private.txt", "*private*key*",
}

// ContentMarker 把"内容特征文本"与其"命中类型"绑定。
// 显式绑定而不是靠字符串前缀猜测，避免新增特征时归类错误。
type ContentMarker struct {
	// Text 是用于子串匹配的特征文本。
	Text string
	// Kind 是命中后报告的类型。
	Kind Kind
}

// DefaultContentMarkers 是内置内容特征表（F-202 / F-207）。
// 全部为文本特征，按子串匹配，比对对象是**最多前 N 字节**的头部缓冲区。
var DefaultContentMarkers = []ContentMarker{
	{"-----BEGIN PRIVATE KEY-----", KindPEMHeader},
	{"-----BEGIN RSA PRIVATE KEY-----", KindPEMHeader},
	{"-----BEGIN DSA PRIVATE KEY-----", KindPEMHeader},
	{"-----BEGIN EC PRIVATE KEY-----", KindPEMHeader},
	{"-----BEGIN OPENSSH PRIVATE KEY-----", KindPEMHeader},
	{"-----BEGIN ENCRYPTED PRIVATE KEY-----", KindPEMHeader},
	{"-----BEGIN SSH2 PRIVATE KEY-----", KindPEMHeader},
	{"---- BEGIN SSH2 PRIVATE KEY ----", KindPEMHeader},
	{"-----BEGIN PGP PRIVATE KEY BLOCK-----", KindPGP},
	{"-----BEGIN PRIVATE KEY BLOCK-----", KindPGP},
	{"PuTTY-User-Key-File-", KindPuTTY},
	{"openssh-key-v1", KindOpenSSH},
	{"AGE-SECRET-KEY-1", KindAge},
	{"PrivateKey = ", KindWireGuard},       // WireGuard .conf
	{"PrivateKey=", KindWireGuard},         // WireGuard 无空格写法
	{`"cipher":"aes-128-ctr"`, KindEthKS},  // Ethereum keystore（json 无空格形态）
	{`"cipher": "aes-128-ctr"`, KindEthKS}, // Ethereum keystore（json 带空格形态）
}

// binarySignatures 是二进制魔数特征：offset → 期望字节序列。
type binarySignature struct {
	offset int
	magic  []byte
	kind   Kind
}

var binarySignatures = []binarySignature{
	{0x00, []byte{0xB0, 0xB0, 0xB0, 0xB0}, KindPVK}, // Windows CryptoAPI PVK
	{0x00, []byte{0xFE, 0xED, 0xFE, 0xED}, KindJKS}, // Java KeyStore
	{0x00, []byte{0xCE, 0xCE, 0xCE, 0xCE}, KindJKS}, // JCEKS
	{0x00, []byte{0x30, 0x82}, KindPKCS12},          // ASN.1 SEQUENCE（PKCS#12/PFX 常见头）
}

// textLikeExtensions 决定哪些文件在"按内容判定"阶段值得读取头部。
// 这是纯性能过滤：跳过明显不是文本/密钥载体的媒体与压缩文件，
// 避免对整盘每个文件都做 4 KiB 读取（F-202 / N-101）。
var textLikeExtensions = map[string]bool{
	"": true, ".txt": true, ".key": true, ".pem": true, ".crt": true, ".cer": true,
	".der": true, ".p8": true, ".pkcs8": true, ".ppk": true, ".p12": true,
	".pfx": true, ".jks": true, ".keystore": true, ".asc": true, ".gpg": true,
	".pgp": true, ".json": true, ".conf": true, ".config": true, ".ini": true,
	".yaml": true, ".yml": true, ".xml": true, ".env": true, ".pub": true,
	".rsa": true, ".ec": true, ".dsa": true, ".privkey": true, ".skey": true,
	".pvk": true, ".kdbx": true, ".log": false, ".zip": false, ".7z": false,
	".rar": false, ".jpg": false, ".jpeg": false, ".png": false, ".gif": false,
	".mp4": false, ".mkv": false, ".mp3": false, ".wav": false, ".iso": false,
	".vhd": false, ".exe": false, ".dll": false, ".sys": false, ".cab": false,
	".msi": false, ".bin": false, ".img": false, ".bak": true, ".old": true,
	".save": true, ".dat": true,
}

// Matcher 是无状态的私钥存在性判定器。
//
// 设计红线（G-01）：本类型只回答"像不像私钥"，绝不做以下任何事——
// 解析密钥、复制密钥、缓存密钥内容、把内容写入日志或文件、外发内容。
type Matcher struct {
	namePatterns   []string
	contentMarkers []ContentMarker
	maxHeader      int
}

// NewMatcher 基于配置构造判定器。cfg 中的额外模式会追加到内置表之后。
func NewMatcher(extraNamePatterns, extraContentMarkers []string, maxHeaderBytes int) (*Matcher, error) {
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = 4096
	}
	m := &Matcher{
		namePatterns:   make([]string, 0, len(DefaultNamePatterns)+len(extraNamePatterns)),
		contentMarkers: make([]ContentMarker, 0, len(DefaultContentMarkers)+len(extraContentMarkers)),
		maxHeader:      maxHeaderBytes,
	}
	// 校验模式合法性，避免 path.Match 在匹配期报错。
	for _, p := range append(append([]string{}, DefaultNamePatterns...), extraNamePatterns...) {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := path.Match(strings.ToLower(p), "probe"); err != nil {
			return nil, fmt.Errorf("非法文件名模式 %q: %w", p, err)
		}
		m.namePatterns = append(m.namePatterns, strings.ToLower(p))
	}
	m.contentMarkers = append(m.contentMarkers, DefaultContentMarkers...)
	for _, c := range extraContentMarkers {
		if strings.TrimSpace(c) == "" {
			continue
		}
		m.contentMarkers = append(m.contentMarkers, ContentMarker{Text: c, Kind: KindCustom})
	}
	if len(m.namePatterns) == 0 && len(m.contentMarkers) == 0 {
		return nil, fmt.Errorf("文件名模式与内容特征均为空，检测将永远无法命中")
	}
	return m, nil
}

// MaxHeaderBytes 返回头部读取上限，供扫描器在读取文件时复用。
func (m *Matcher) MaxHeaderBytes() int { return m.maxHeader }

// MatchName 按文件名模式判定（F-201）。只做字符串比对，不接触文件。
func (m *Matcher) MatchName(name string) (Kind, bool) {
	if name == "" {
		return KindNone, false
	}
	lower := strings.ToLower(name)
	for _, p := range m.namePatterns {
		if ok, err := path.Match(p, lower); err == nil && ok {
			return KindNameOnly, true
		}
	}
	return KindNone, false
}

// ShouldReadHeader 判断是否值得为按内容判定而读取该文件的头部（F-202 的性能前置过滤）。
func (m *Matcher) ShouldReadHeader(name string) bool {
	if name == "" {
		return false
	}
	lower := strings.ToLower(name)
	for _, skip := range []string{".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".tar",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic",
		".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm",
		".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg",
		".iso", ".vhd", ".vhdx", ".vmdk", ".vdi", ".exe", ".dll", ".sys",
		".msi", ".cab", ".bin", ".img", ".db", ".sqlite", ".mdf", ".ldf"} {
		if strings.HasSuffix(lower, skip) {
			return false
		}
	}
	ext := strings.ToLower(path.Ext(lower))
	if v, ok := textLikeExtensions[ext]; ok {
		return v
	}
	// 未知扩展名：保守起见读一次头部（有 4 KiB 与 maxFiles 双上限兜底）。
	return true
}

// MatchHeader 按内容特征判定（F-202）。
//
// header 是文件开头最多 maxHeader 字节的原始数据。本函数是纯函数：
// 只读入参、不落盘、不缓存，返回后由调用方负责清零缓冲区（见 Zero）。
func (m *Matcher) MatchHeader(header []byte) (Kind, bool) {
	if len(header) == 0 {
		return KindNone, false
	}
	// 二进制魔数优先（无编码歧义）。
	for _, sig := range binarySignatures {
		if len(header) >= sig.offset+len(sig.magic) {
			if string(header[sig.offset:sig.offset+len(sig.magic)]) == string(sig.magic) {
				return sig.kind, true
			}
		}
	}
	// 文本特征做子串匹配。头部很小（默认 4 KiB），朴素匹配足够快。
	// 类型由特征表直接给出，不做字符串前缀推断。
	text := string(header)
	for _, c := range m.contentMarkers {
		if strings.Contains(text, c.Text) {
			return c.Kind, true
		}
	}
	return KindNone, false
}

// MatchAllowMarker 判定显式授权标记文件内容是否匹配已配置的公钥指纹（F-203）。
//
// 标记文件内容约定：一行文本，包含期望的公钥指纹（分组长十六进制，允许含空格/冒号）。
// 这里比对的是**公钥**指纹，全程不涉及任何私钥材料（决策 D-07）。
func MatchAllowMarker(content []byte, expectedFingerprint string) bool {
	want := normalizeFingerprint(expectedFingerprint)
	if want == "" {
		return false
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 允许 "fingerprint=xxx" / "pubkey: xxx" 等写法。
		// 只有当分隔符之前确实是已知标签时才剥离前缀，避免误切指纹本身的冒号分隔。
		for _, sep := range []string{"=", ":"} {
			if i := strings.Index(line, sep); i > 0 {
				label := strings.ToLower(strings.TrimSpace(line[:i]))
				if label == "fingerprint" || label == "pubkey" || label == "key" {
					line = strings.TrimSpace(line[i+len(sep):])
					break
				}
			}
		}
		if normalizeFingerprint(line) == want {
			return true
		}
	}
	return false
}

func normalizeFingerprint(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Zero 覆盖切片内容，用于用完即弃地清除头部缓冲区（G-01）。
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
