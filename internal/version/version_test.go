package version

import "testing"

func TestMultiLineForUsesGivenToolName(t *testing.T) {
	got := MultiLineFor("usbkeygen")
	if want := "usbkeygen"; !hasPrefixLine(got, want) {
		t.Fatalf("version 输出应以程序名 %q 开头，实际：%q", want, firstLine(got))
	}
	if !contains(got, "usbbackup") {
		t.Error("输出应同时展示产品名 usbbackup，便于确认属于同一产品族")
	}
}

func TestMultiLineForFallsBackToAppName(t *testing.T) {
	if got := firstLine(MultiLineFor("")); got != AppName {
		t.Fatalf("空程序名应回退到产品名 %q，实际 %q", AppName, got)
	}
	if got := firstLine(MultiLine()); got != AppName {
		t.Fatalf("MultiLine 应使用产品名 %q，实际 %q", AppName, got)
	}
}

func TestMultiLineForDistinguishesTools(t *testing.T) {
	// 四个工具必须能从 version 输出中区分开，否则排障时无法确认跑的是哪个产物。
	tools := []string{"usbbackup", "usbkeygen", "usbcomp", "usbunseal"}
	seen := make(map[string]bool, len(tools))
	for _, tool := range tools {
		line := firstLine(MultiLineFor(tool))
		if seen[line] {
			t.Fatalf("程序名 %q 与其它工具重复：%q", tool, line)
		}
		seen[line] = true
		if line != tool {
			t.Fatalf("期望首行为 %q，实际 %q", tool, line)
		}
	}
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

func hasPrefixLine(s, prefix string) bool {
	return firstLine(s) == prefix
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
