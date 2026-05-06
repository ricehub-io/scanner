package config

import (
	"os"
	"testing"
)

func writeTempTOML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "*.toml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	_ = f.Close()
	return f.Name()
}

// --- ByteSize.Bytes ---
func TestByteSizeBytes(t *testing.T) {
	tests := []struct {
		input ByteSize
		want  uint64
	}{
		{"10B", 10},
		{"100B", 100},
		{"1 KB", 1000},
		{"1 MB", 1000 * 1000},
		{"100 MB", 100 * 1000 * 1000},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			got := tt.input.Bytes()
			if got != tt.want {
				t.Errorf("ByteSize(%q).Bytes() = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// --- Init ---
func TestInit_ParsesMaxUncompressedSize(t *testing.T) {
	f := writeTempTOML(t, `max_uncompressed_size = "50 MB"`)

	var c config
	c.Init(f)

	got := c.MaxUncompressedSize.Bytes()
	want := uint64(50 * 1000 * 1000)
	if got != want {
		t.Errorf("MaxUncompressedSize = %d, want %d", got, want)
	}
}

func TestInit_ParsesShellExtensions(t *testing.T) {
	f := writeTempTOML(t, `shell_extensions = [".sh", ".bash", ".py"]`)

	var c config
	c.Init(f)

	want := []string{".sh", ".bash", ".py"}
	if len(c.ShellExtensions) != len(want) {
		t.Fatalf("ShellExtensions = %v, want %v", c.ShellExtensions, want)
	}
	for i, ext := range want {
		if c.ShellExtensions[i] != ext {
			t.Errorf("ShellExtensions[%d] = %q, want %q", i, c.ShellExtensions[i], ext)
		}
	}
}

func TestInit_CompilesHeuristicPatterns(t *testing.T) {
	toml := `
	[heuristic]
	network = ['\bwget\b', '\bcurl\b']
	execution = ['\beval\b']
	`
	f := writeTempTOML(t, toml)

	var c config
	c.Init(f)

	if len(c.Heuristic) != 2 {
		t.Fatalf("expected 2 heuristic categories, got %d", len(c.Heuristic))
	}

	networkPatterns := c.Heuristic[Network]
	if len(networkPatterns) != 2 {
		t.Fatalf("expected 2 network patterns, got %d", len(networkPatterns))
	}

	// Verify patterns are compiled and functional
	matches := []struct {
		pattern int
		input   string
		want    bool
	}{
		{0, "wget http://evil.com", true},
		{0, "echo hello", false},
		{1, "curl http://evil.com", true},
	}
	for _, m := range matches {
		got := networkPatterns[m.pattern].MatchString(m.input)
		if got != m.want {
			t.Errorf("network[%d].MatchString(%q) = %v, want %v", m.pattern, m.input, got, m.want)
		}
	}
}

func TestInit_EmptyHeuristic(t *testing.T) {
	f := writeTempTOML(t, ``)

	var c config
	c.Init(f)

	if len(c.Heuristic) != 0 {
		t.Errorf("expected empty heuristic, got %v", c.Heuristic)
	}
}
