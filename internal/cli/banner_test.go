package cli

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

// TestReorderArgs 覆盖"flag 写在位置参数之后"这一自然写法。
// 回归背景：Go 的 flag 包遇到第一个非 flag 参数就停止解析，
// 导致 `usbkeygen use <路径> --config x.json` 里的 --config 被当成位置参数。
func TestReorderArgs(t *testing.T) {
	build := func() *flag.FlagSet {
		fs := flag.NewFlagSet("probe", flag.ContinueOnError)
		fs.SetOutput(&bytes.Buffer{})
		fs.String("config", "", "")
		fs.String("out", "", "")
		fs.Int("bits", 4096, "")
		fs.Bool("force", false, "")
		fs.Bool("yes", false, "")
		return fs
	}

	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "flag 在前（原样）",
			in:   []string{"--config", "a.json", "pub.pem"},
			want: []string{"--config", "a.json", "pub.pem"},
		},
		{
			name: "flag 在后",
			in:   []string{"pub.pem", "--config", "a.json"},
			want: []string{"--config", "a.json", "pub.pem"},
		},
		{
			name: "多个 flag 混排",
			in:   []string{"dir", "--out", "x.usbk", "--force"},
			want: []string{"--out", "x.usbk", "--force", "dir"},
		},
		{
			name: "等号写法自带取值",
			in:   []string{"dir", "--out=x.usbk", "--bits=2048"},
			want: []string{"--out=x.usbk", "--bits=2048", "dir"},
		},
		{
			name: "布尔 flag 不吞下一个参数",
			in:   []string{"file", "--force", "another"},
			want: []string{"--force", "file", "another"},
		},
		{
			name: "双横线分隔符之后全部视为位置参数",
			in:   []string{"--force", "--", "--config", "x"},
			want: []string{"--force", "--", "--config", "x"},
		},
		{
			name: "分隔符后的位置参数不会被当成 flag",
			in:   []string{"file.txt", "--", "--out"},
			want: []string{"--", "file.txt", "--out"},
		},
		{
			name: "单独一个减号视为位置参数",
			in:   []string{"-", "--force"},
			want: []string{"--force", "-"},
		},
		{
			name: "纯位置参数",
			in:   []string{"a", "b"},
			want: []string{"a", "b"},
		},
		{
			name: "空输入",
			in:   nil,
			want: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ReorderArgs(build(), tc.in)
			if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Fatalf("ReorderArgs(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestReorderArgsMakesPositionalAfterFlagWork 验证端到端效果：重排后 flag 真正生效。
func TestReorderArgsMakesPositionalAfterFlagWork(t *testing.T) {
	fs := flag.NewFlagSet("use", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})
	cfg := fs.String("config", "", "")
	force := fs.Bool("force", false, "")

	args := []string{`C:\keys\usbguard.pub.pem`, "--config", `D:\cfg.json`, "--force"}
	if err := fs.Parse(ReorderArgs(fs, args)); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if *cfg != `D:\cfg.json` {
		t.Fatalf("--config 未生效，实际 %q", *cfg)
	}
	if !*force {
		t.Fatal("--force 未生效")
	}
	if fs.NArg() != 1 || fs.Arg(0) != `C:\keys\usbguard.pub.pem` {
		t.Fatalf("位置参数不正确: narg=%d arg0=%q", fs.NArg(), fs.Arg(0))
	}
}

func TestConfirmAgreement(t *testing.T) {
	cases := []struct {
		in     string
		wantOK bool
	}{
		{"I AGREE\n", true},
		{"i agree\n", true},
		{"I  AGREE\n", true},
		{"  I agree  \n", true},
		{"agree\n", false},
		{"I AGREED\n", false},
		{"no\n", false},
		{"", false},
	}
	for _, tc := range cases {
		var out bytes.Buffer
		err := ConfirmAgreement(strings.NewReader(tc.in), &out)
		if tc.wantOK && err != nil {
			t.Errorf("输入 %q 应通过，实际 %v", tc.in, err)
		}
		if !tc.wantOK && err == nil {
			t.Errorf("输入 %q 不应通过", tc.in)
		}
	}
}

func TestRenderBannerContainsRequiredNotices(t *testing.T) {
	var buf bytes.Buffer
	RenderBanner(&buf, "usbkeygen")
	// 横幅为了视觉强调在标题字之间插了空格，比较前先去掉所有空白。
	flat := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, buf.String())

	// F-901 要求包含的关键声明。
	for _, must := range []string{
		"安全警告", "免责声明", "CCBY-NC-SA", "私钥", "不删除", "网络通信",
	} {
		if !strings.Contains(flat, must) {
			t.Errorf("横幅缺少必要内容 %q", must)
		}
	}
	if !strings.Contains(buf.String(), "usbkeygen") {
		t.Error("横幅应包含程序名")
	}
}

func TestRenderNoticeIsShort(t *testing.T) {
	var buf bytes.Buffer
	RenderNotice(&buf, "usbguard")
	out := buf.String()
	if !strings.Contains(out, "DISCLAIMER.md") {
		t.Error("简短提示应指向完整免责声明文件")
	}
	if len(out) > 1200 {
		t.Errorf("简短提示过长（%d 字节），失去了自动化场景的意义", len(out))
	}
	if strings.Contains(out, "安  全  警  告") {
		t.Error("--yes 模式不应再打印整屏警告")
	}
}
