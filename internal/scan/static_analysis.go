package scan

import (
	"encoding/base64"
	"regexp"
	"scanner/internal/zip"
	"strings"
	"sync"
)

// TODO: maybe wrap rules into categories or smth so we can return
// user-friendly messages why file was detected
// or not? its gonna backfire if someone tries to bypass our system

const maxScore = 8

var (
	whitespacesPattern         = regexp.MustCompile(`\s+`)
	expandVariablesPattern     = regexp.MustCompile(`(\w+)=["']?([^"'\s]+)["']?`)
	normalizeSeparatorsPattern = regexp.MustCompile(`(;|&&|\|\|)`)
	base64Pattern              = regexp.MustCompile(`(?i)[a-z0-9+/=]{20,}`)
)

// TODO: move to config file
var (
	hardBlock = []string{
		`curl\s+.*\|\s*(bash|sh)`,
		`wget\s+.*\|\s*(bash|sh)`,
		`nc\s+.*-e\s+(bash|sh)`,
		`bash\s+-i\s+>&\s*/dev/tcp/`,
		`sh\s+-i\s+>&\s*/dev/tcp/`,
		`:\(\)\s*\{\s*:\|\:&\s*\};:`,
		`(?i)X5O!P%@AP\[4PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*`,
	}
	soft = []string{
		`source\s+`,
		`\.\s+\/`,
		`chmod\s+777`,
		`~/.bashrc`,
		`~/.profile`,
	}
	network = []string{
		`\bcurl\b`,
		`\bwget\b`,
		`\bnc\b`,
		`\bscp\b`,
		`\brsync\b`,
	}
	execution = []string{
		`\beval\b`,
		`\bexec\b`,
		`\bbash\b`,
		`\bsh\b`,
		`python\s+-c`,
		`perl\s+-e`,
	}
	obfuscation = []string{
		`base64`,
		`xxd\s+-r`,
		`openssl\s+enc`,
		`\$\(`,
		`\$\{[^}]{10,}\}`,
		`echo\s+.*\|\s*base64`,
		`printf\s+.*\|\s*base64`,
	}
	sensitive = []string{
		`/etc/passwd`,
		`/etc/shadow`,
		`dd\s+if=`,
		`mkfs`,
		`>\s*/dev/sd`,
	}
	fileSystem = []string{
		`rm\s+-rf\s+/`,
		`mount\s+`,
		`umount\s+`,
	}
	privilege = []string{
		`\bsudo\b`,
		`\bsu\b`,
		`useradd`,
		`usermod`,
		`passwd`,
	}
	persistence = []string{
		`crontab`,
		`/etc/cron`,
		`systemctl\s+enable`,
	}
	ssh = []string{
		`authorized_keys`,
		`ssh-rsa`,
	}
	exfiltration = []string{
		`\bscp\b`,
		`\brsync\b`,
		`nc\s+.*\d{2,5}`,
	}
)

// staticAnalysis scans script files within the given zip files for
// suspicious patterns (e.g. dangerous commands, base64 payloads).
func StaticAnalysis(files []zip.ZipFile) []string {
	ch := make(chan bool)
	var wg sync.WaitGroup

	for _, f := range files {
		if !f.IsScript() {
			continue
		}

		wg.Go(func() {
			content := normalizeContent(f.Content)
			ch <- scanContent(content)
		})
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for ok := range ch {
		if !ok {
			return []string{"static analysis"}
		}
	}

	return []string{}
}

func scanContent(content string) bool {
	match := func(patterns []string) bool {
		for _, pattern := range patterns {
			if matched, _ := regexp.MatchString(pattern, content); matched {
				return true
			}
		}
		return false
	}

	if match(hardBlock) {
		return false
	}

	score := 0

	// combinations
	if match(network) && match(execution) {
		score += 4
	}
	if match(obfuscation) && match(execution) {
		score += 3
	}
	if match(network) && match(obfuscation) {
		score += 3
	}
	if match(exfiltration) && match(sensitive) {
		score += 4
	}

	// individual
	// unaimeds: straight from yandere dev, its only temporary ok?
	if match(network) {
		score += 3
	}
	if match(execution) {
		score += 2
	}
	if match(obfuscation) {
		score += 2
	}
	if match(sensitive) {
		score += 4
	}
	if match(fileSystem) {
		score += 3
	}
	if match(privilege) {
		score += 1
	}
	if match(persistence) {
		score += 2
	}
	if match(exfiltration) {
		score += 3
	}
	if match(soft) {
		score += 1
	}

	// TODO: increase threshold if known file (e.g. .zshrc)
	return score <= maxScore
}

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

// TODO: limit decoded size
// TODO: limit number of decodes
func decodeBase64(content string) string {
	matches := base64Pattern.FindAllString(content, -1)

	seen := make(map[string]struct{})
	for _, m := range matches {
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
