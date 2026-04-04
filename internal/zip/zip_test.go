package zip

import (
	"archive/zip"
	"bytes"
	"os"
	"scanner/internal/config"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	config.Cfg.ShellExtensions = []string{".sh", ".bash"}
	config.Cfg.MaxUncompressedSize = "1MB"
	os.Exit(m.Run())
}

// makeZip writes a zip archive to a temp file and returns the path.
// Each key in files is the entry name, value is its content.
func makeZip(t *testing.T, files map[string]string) string {
	t.Helper()

	tmp, err := os.CreateTemp("", "*.zip")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	t.Cleanup(func() { os.Remove(tmp.Name()) })

	w := zip.NewWriter(tmp)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("failed to create zip entry %q: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write zip entry %q: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	return tmp.Name()
}

// --- IsScript ---
func TestIsScript_ByExtension(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"deploy.sh", true},
		{"run.bash", true},
		{"image.png", false},
		{"README.md", false},
		{"noextension", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := ZipFile{Name: tt.name, Content: []byte("echo hello")}
			if got := f.IsScript(); got != tt.want {
				t.Errorf("IsScript() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsScript_ByShebang(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"postinstall", "#!/bin/bash\necho hello", true},
		{"postinstall", "#!/usr/bin/env python3\nprint('hi')", true},
		{"postinstall", "echo hello", false},
		{"postinstall", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.content, func(t *testing.T) {
			f := ZipFile{Name: tt.name, Content: []byte(tt.content)}
			if got := f.IsScript(); got != tt.want {
				t.Errorf("IsScript() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsScript_ExtensionTakesPrecedenceOverShebang(t *testing.T) {
	f := ZipFile{Name: "file.png", Content: []byte("#!/bin/bash")}
	if !f.IsScript() {
		t.Error("file with shebang should be detected as script regardless of extension")
	}
}

// --- SafeUnzip ---
func TestSafeUnzip_ReadsFiles(t *testing.T) {
	path := makeZip(t, map[string]string{
		"hello.sh":  "#!/bin/bash\necho hello",
		"readme.md": "# docs",
	})

	files, err := SafeUnzip(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}

	byName := make(map[string]ZipFile)
	for _, f := range files {
		byName[f.Name] = f
	}

	if !bytes.Equal(byName["hello.sh"].Content, []byte("#!/bin/bash\necho hello")) {
		t.Errorf("unexpected content for hello.sh: %q", byName["hello.sh"].Content)
	}
}

func TestSafeUnzip_NonExistentFile(t *testing.T) {
	_, err := SafeUnzip("/tmp/does-not-exist-xyz.zip")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestSafeUnzip_PathTraversal(t *testing.T) {
	path := makeZip(t, map[string]string{
		"../evil.sh": "rm -rf /",
	})

	_, err := SafeUnzip(path)
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
	if !strings.Contains(err.Error(), "path traversal") {
		t.Errorf("expected path traversal error, got: %v", err)
	}
}

func TestSafeUnzip_TooManyFiles(t *testing.T) {
	files := make(map[string]string, 1001)
	for i := range 1001 {
		files[strings.Repeat("a", 5)+string(rune('0'+i%10))] = "x"
	}

	tmp, err := os.CreateTemp("", "*.zip")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(tmp.Name()) })

	w := zip.NewWriter(tmp)
	for i := range 1001 {
		f, _ := w.Create(strings.Repeat("a", 4) + string(rune('A'+i%26)) + string(rune('0'+i/26)) + ".txt")
		f.Write([]byte("x"))
	}
	w.Close()
	tmp.Close()

	_, err = SafeUnzip(tmp.Name())
	if err == nil {
		t.Fatal("expected error for too many files")
	}
	if !strings.Contains(err.Error(), "too many files") {
		t.Errorf("expected 'too many files' error, got: %v", err)
	}
}

func TestSafeUnzip_ArchiveTooLarge(t *testing.T) {
	org := config.Cfg
	config.Cfg.MaxUncompressedSize = "10B"
	defer func() { config.Cfg = org }()

	path := makeZip(t, map[string]string{
		"big.sh": strings.Repeat("a", 11),
	})

	_, err := SafeUnzip(path)
	if err == nil {
		t.Fatal("expected error for oversized archive")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected 'too large' error, got: %v", err)
	}
}

func TestSafeUnzip_EmptyArchive(t *testing.T) {
	path := makeZip(t, map[string]string{})

	files, err := SafeUnzip(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}
