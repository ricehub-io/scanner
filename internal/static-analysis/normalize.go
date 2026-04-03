package staticanalysis

import (
	"encoding/base64"
	"regexp"
	"strings"
)

const maxBase64Matches = 50

var (
	whitespacesPattern         = regexp.MustCompile(`\s+`)
	expandVariablesPattern     = regexp.MustCompile(`(\w+)=["']?([^"'\s]+)["']?`)
	normalizeSeparatorsPattern = regexp.MustCompile(`(;|&&|\|\|)`)
	base64Pattern              = regexp.MustCompile(`(?i)[a-z0-9+/=]{20,}`)
)

// normalizeContent strips comments, expands variables, removes string
// concatenation and escape chars to produce a form ready for pattern matching.
func normalizeContent(s []byte) string {
	content := strings.ToLower(string(s))
	content = stripComments(content)

	content = removeStringConcat(content)
	content = removeEscapeChars(content)

	content = normalizeWhitespaces(content)
	content = expandVariables(content)
	content = normalizeSeparators(content)
	content = normalizePaths(content)

	return decodeBase64Recursive(content, 3)
}

func stripComments(content string) string {
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		if idx := strings.Index(line, "#"); idx != -1 {
			lines[i] = line[:idx]
		}
	}

	return strings.Join(lines, "\n")
}

func removeStringConcat(content string) string {
	content = strings.ReplaceAll(content, `"`, "")
	content = strings.ReplaceAll(content, `'`, "")
	return content
}

func removeEscapeChars(content string) string {
	return strings.ReplaceAll(content, "\\", "")
}

func normalizeWhitespaces(content string) string {
	return whitespacesPattern.ReplaceAllString(content, " ")
}

func expandVariables(content string) string {
	vars := make(map[string]string)

	for _, match := range expandVariablesPattern.FindAllStringSubmatch(content, -1) {
		vars[match[1]] = match[2]
	}

	for k, v := range vars {
		content = strings.ReplaceAll(content, "$"+k, v)
	}

	return content
}

func normalizeSeparators(content string) string {
	return normalizeSeparatorsPattern.ReplaceAllString(content, "\n")
}

func normalizePaths(content string) string {
	return strings.ReplaceAll(content, "/./", "/")
}

func decodeBase64Recursive(content string, maxDepth uint) string {
	var i uint
	for ; i < maxDepth; i++ {
		newContent := decodeBase64(content)
		if newContent == content {
			break
		}
		content = newContent
	}
	return content
}

func decodeBase64(content string) string {
	matches := base64Pattern.FindAllString(content, -1)

	seen := make(map[string]struct{})
	for i, m := range matches {
		// TODO: increase malicious score if too many matches
		if i+1 > maxBase64Matches {
			break
		}

		if _, exists := seen[m]; exists {
			continue
		}
		seen[m] = struct{}{}

		decoded, ok := tryDecodeBase64(m)
		if !ok {
			continue
		}

		content += "\n" + decoded
	}

	return content
}

func tryDecodeBase64(content string) (string, bool) {
	decoded, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return "", false
	}

	if len(decoded) > 10_000 {
		return "", false
	}

	if !isMostlyPrintable(decoded) {
		return "", false
	}

	return string(decoded), true
}

func isMostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	printable := 0
	for _, b := range data {
		if b >= 32 && b <= 126 || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}

	return float64(printable)/float64(len(data)) > 0.8
}
