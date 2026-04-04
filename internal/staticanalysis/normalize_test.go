package staticanalysis

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestStripComments(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "removes inline comment",
			input: "echo hello # this is a comment",
			want:  "echo hello ",
		},
		{
			name:  "removes full-line comment",
			input: "# full comment\necho hello",
			want:  "\necho hello",
		},
		{
			name:  "no comment unchanged",
			input: "echo hello",
			want:  "echo hello",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "multiple lines with mixed comments",
			input: "cmd1\n# comment\ncmd2 # inline\ncmd3",
			want:  "cmd1\n\ncmd2 \ncmd3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripComments(tt.input)
			if got != tt.want {
				t.Errorf("stripComments(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRemoveStringConcat(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "removes double quotes",
			input: `echo "hello"`,
			want:  "echo hello",
		},
		{
			name:  "removes single quotes",
			input: "echo 'hello'",
			want:  "echo hello",
		},
		{
			name:  "removes both quote types",
			input: `echo "hello" 'world'`,
			want:  "echo hello world",
		},
		{
			name:  "no quotes unchanged",
			input: "echo hello",
			want:  "echo hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := removeStringConcat(tt.input)
			if got != tt.want {
				t.Errorf("removeStringConcat(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRemoveEscapeChars(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "removes backslash",
			input: `curl\thttp://example.com`,
			want:  "curlthttp://example.com",
		},
		{
			name:  "removes multiple backslashes",
			input: `a\b\c`,
			want:  "abc",
		},
		{
			name:  "no backslash unchanged",
			input: "echo hello",
			want:  "echo hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := removeEscapeChars(tt.input)
			if got != tt.want {
				t.Errorf("removeEscapeChars(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeWhitespaces(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "collapses multiple spaces",
			input: "a  b   c",
			want:  "a b c",
		},
		{
			name:  "collapses tabs",
			input: "a\t\tb",
			want:  "a b",
		},
		{
			name:  "collapses mixed whitespace",
			input: "a \t b",
			want:  "a b",
		},
		{
			name:  "single space unchanged",
			input: "a b",
			want:  "a b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeWhitespaces(tt.input)
			if got != tt.want {
				t.Errorf("normalizeWhitespaces(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExpandVariables(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "expands double-quoted variable",
			input: `cmd="wget" $cmd http://example.com`,
			want:  `cmd="wget" wget http://example.com`,
		},
		{
			name:  "expands unquoted variable",
			input: "url=http://example.com curl $url",
			want:  "url=http://example.com curl http://example.com",
		},
		{
			name:  "no variable unchanged",
			input: "echo hello",
			want:  "echo hello",
		},
		{
			name:  "undefined variable reference unchanged",
			input: "echo $undefined",
			want:  "echo $undefined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandVariables(tt.input)
			if got != tt.want {
				t.Errorf("expandVariables(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeSeparators(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "semicolon becomes newline",
			input: "cmd1;cmd2",
			want:  "cmd1\ncmd2",
		},
		{
			name:  "double-ampersand becomes newline",
			input: "cmd1&&cmd2",
			want:  "cmd1\ncmd2",
		},
		{
			name:  "double-pipe becomes newline",
			input: "cmd1||cmd2",
			want:  "cmd1\ncmd2",
		},
		{
			name:  "no separator unchanged",
			input: "cmd1 cmd2",
			want:  "cmd1 cmd2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeSeparators(tt.input)
			if got != tt.want {
				t.Errorf("normalizeSeparators(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizePaths(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "removes dot segment",
			input: "/usr/./bin/bash",
			want:  "/usr/bin/bash",
		},
		{
			name:  "multiple dot segments",
			input: "/usr/./local/./bin",
			want:  "/usr/local/bin",
		},
		{
			name:  "no dot segment unchanged",
			input: "/usr/bin/bash",
			want:  "/usr/bin/bash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePaths(tt.input)
			if got != tt.want {
				t.Errorf("normalizePaths(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsMostlyPrintable(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "all printable ASCII",
			input: []byte("echo hello world"),
			want:  true,
		},
		{
			name:  "includes newline and tab",
			input: []byte("line1\nline2\ttab"),
			want:  true,
		},
		{
			name:  "mostly binary data",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
			want:  false,
		},
		{
			name:  "empty slice",
			input: []byte{},
			want:  false,
		},
		{
			name:  "mixed: few non-printable",
			input: append([]byte("echo hello world!!"), 0x00),
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isMostlyPrintable(tt.input)
			if got != tt.want {
				t.Errorf("isMostlyPrintable(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTryDecodeBase64(t *testing.T) {
	t.Run("valid base64 printable content", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("echo hello"))
		got, ok := tryDecodeBase64(encoded)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if got != "echo hello" {
			t.Errorf("got %q, want %q", got, "echo hello")
		}
	})

	t.Run("invalid base64 returns false", func(t *testing.T) {
		_, ok := tryDecodeBase64("not!valid!base64!")
		if ok {
			t.Error("expected ok=false for invalid base64")
		}
	})

	t.Run("binary content returns false", func(t *testing.T) {
		// encode binary-ish data (mostly non-printable)
		bin := make([]byte, 20)
		for i := range bin {
			bin[i] = byte(i)
		}
		encoded := base64.StdEncoding.EncodeToString(bin)
		_, ok := tryDecodeBase64(encoded)
		if ok {
			t.Error("expected ok=false for non-printable decoded content")
		}
	})

	t.Run("decoded content exceeding 10000 bytes returns false", func(t *testing.T) {
		large := strings.Repeat("a", 10_001)
		encoded := base64.StdEncoding.EncodeToString([]byte(large))
		_, ok := tryDecodeBase64(encoded)
		if ok {
			t.Error("expected ok=false for decoded content > 10000 bytes")
		}
	})
}

func TestDecodeBase64Recursive(t *testing.T) {
	t.Run("decodes single layer", func(t *testing.T) {
		payload := "curl http://evil.com"
		encoded := base64.StdEncoding.EncodeToString([]byte(payload))
		// pad to 20+ chars so the pattern matches
		if len(encoded) < 20 {
			t.Skip("encoded too short for pattern match")
		}
		result := decodeBase64Recursive(encoded, 3)
		if !strings.Contains(result, payload) {
			t.Errorf("expected result to contain decoded payload, got %q", result)
		}
	})

	t.Run("stops at maxDepth", func(t *testing.T) {
		// Content with no base64 patterns should be unchanged at depth 0
		result := decodeBase64Recursive("plain text no b64 here", 0)
		if result != "plain text no b64 here" {
			t.Errorf("expected unchanged content at depth 0, got %q", result)
		}
	})

	t.Run("no change when no base64 patterns", func(t *testing.T) {
		input := "echo hello world"
		result := decodeBase64Recursive(input, 3)
		if result != input {
			t.Errorf("expected unchanged content, got %q", result)
		}
	})
}

func TestNormalizeContent(t *testing.T) {
	t.Run("strips comments and normalizes whitespace", func(t *testing.T) {
		input := []byte("echo hello  # comment\ncmd   arg")
		result := normalizeContent(input)
		if strings.Contains(result, "#") {
			t.Error("result should not contain comments")
		}
		if strings.Contains(result, "  ") {
			t.Error("result should not contain consecutive spaces")
		}
	})

	t.Run("lowercases content", func(t *testing.T) {
		input := []byte("CURL HTTP://EXAMPLE.COM")
		result := normalizeContent(input)
		if strings.ToLower(result) != result {
			t.Errorf("result should be lowercase, got %q", result)
		}
	})

	t.Run("expands variables", func(t *testing.T) {
		input := []byte(`url="http://evil.com" curl $url`)
		result := normalizeContent(input)
		if !strings.Contains(result, "http://evil.com") || strings.Contains(result, "$url") {
			t.Errorf("expected variable to be expanded, got %q", result)
		}
	})

	t.Run("normalizes path separators", func(t *testing.T) {
		input := []byte("/usr/./bin/bash -c cmd1;cmd2")
		result := normalizeContent(input)
		if strings.Contains(result, "/./") {
			t.Error("result should not contain /./")
		}
	})
}
