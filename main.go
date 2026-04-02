package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	clamav "github.com/ca110us/go-clamav"
)

// TODO: load pattern list from a file or smth :p
var suspiciousPatterns = []string{
	// common
	`curl\s+.*\|\s*(bash|sh)`,
	`wget\s+.*\|\s*(bash|sh)`,
	`rm\s+-rf\s+/`,
	`chmod\s+777`,
	`/etc/passwd`,
	`/etc/shadow`,
	`base64\s+--decode`,
	`eval\s+\$\(`,
	`>\s*/dev/sd`,
	`mkfs`,
	`dd\s+if=`,
	`mount\s+`,
	`umount\s+`,

	// reverse shells & backdoors
	`nc\s+.*-e\s+(bash|sh)`,
	`bash\s+-i\s+>&\s*/dev/tcp/`,
	`sh\s+-i\s+>&\s*/dev/tcp/`,
	`python\s+-c\s+.*socket`,
	`perl\s+-e\s+.*socket`,

	// download + execute
	`curl\s+.*-o\s+\S+\s*&&\s*(bash|sh)\s+\S+`,
	`wget\s+.*-O\s+\S+\s*&&\s*(bash|sh)\s+\S+`,

	// obfuscation & encoding things
	`base64\s+-d`,
	`echo\s+.*\|\s*base64\s+-d`,
	`printf\s+.*\|\s*base64\s+-d`,
	`xxd\s+-r`,
	`openssl\s+enc`,
	`\$\{.*\}`,

	// shell features
	`eval\s+`,
	`exec\s+`,
	`source\s+`,
	`\.\s+\/`,

	// privilege escalation & tampering
	`sudo\s+`,
	`su\s+`,
	`useradd`,
	`usermod`,
	`passwd`,

	// persistence stuff
	`crontab`,
	`/etc/cron`,
	`~/.bashrc`,
	`~/.profile`,
	`systemctl\s+enable`,

	// ssh backdoor injection
	`authorized_keys`,
	`ssh-rsa`,

	// file exfiltration & data theft
	`scp\s+`,
	`rsync\s+`,
	`nc\s+.*\d{2,5}`,

	// fork bombs
	`:\(\)\s*\{\s*:\|\:&\s*\};:`,

	// for testing
	`my-test-pattern`,
}

var shellExtensions = map[string]struct{}{
	".sh": {}, ".bash": {}, ".zsh": {},
	".fish": {}, ".py": {}, ".pl": {},
}

const maxUncompressedSize = 1024 * 1024 * 100 // 100MB

type ZipFile struct {
	Name    string
	Content []byte
}

func (f ZipFile) isScript() bool {
	if _, exists := shellExtensions[filepath.Ext(f.Name)]; exists {
		return true
	}
	// fallback: check for shebang
	return bytes.HasPrefix(f.Content, []byte("#!/"))
}

// TODO(?): score system to reduce false-positives
// TODO: gzip and hex deobfuscation
func main() {
	const file = "./test_data/all.zip"
	files, err := safeUnzip(file)
	if err != nil {
		log.Fatalf("Failed to safely unzip file: %v", err)
	}

	if virusName, ret := clamavScan(file); ret != nil {
		log.Printf("ClamAV detected: %s", virusName)
	}

	if matched := staticAnalysis(files); len(matched) > 0 {
		log.Printf("Static analysis detected: %v", matched)
	}
}

func clamavScan(filePath string) (virusName string, ret error) {
	c := new(clamav.Clamav)
	err := c.Init(clamav.SCAN_OPTIONS{
		General:   0,
		Parse:     clamav.CL_SCAN_PARSE_ARCHIVE | clamav.CL_SCAN_PARSE_ELF,
		Heuristic: 0,
		Mail:      0,
		Dev:       0,
	})
	if err != nil {
		log.Fatalf("Failed to init clamav: %v", err)
	}
	defer c.Free()

	_, err = c.LoadDB("/var/lib/clamav", uint(clamav.CL_DB_DIRECTORY))
	if err != nil {
		log.Fatalf("Failed to load clamav database: %v", err)
	}

	err = c.CompileEngine()
	if err != nil {
		log.Fatalf("Failed to compile clamav engine: %v", err)
	}

	c.EngineSetNum(clamav.CL_ENGINE_MAX_SCANSIZE, maxUncompressedSize)
	c.EngineSetNum(clamav.CL_ENGINE_MAX_SCANTIME, 9000)

	_, virusName, ret = c.ScanFile(filePath)
	return
}

func safeUnzip(filePath string) ([]ZipFile, error) {
	const maxFiles = 1000

	r, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	if len(r.File) > maxFiles {
		return nil, fmt.Errorf("archive contains too many files")
	}

	var files []ZipFile
	var totalSize uint64

	for _, f := range r.File {
		if strings.Contains(f.Name, "..") {
			return nil, fmt.Errorf("path traversal detected: %s", f.Name)
		}
		totalSize += f.UncompressedSize64
		if totalSize > maxUncompressedSize {
			return nil, fmt.Errorf("uncompressed archive is too large")
		}

		fr, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open zip file: %v", err)
		}
		defer fr.Close()

		content, err := io.ReadAll(fr)
		if err != nil {
			return nil, fmt.Errorf("failed to read zip file: %v", err)
		}

		files = append(files, ZipFile{
			Name:    f.Name,
			Content: content,
		})
	}

	return files, nil
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

func expandVariables(content string) string {
	re := regexp.MustCompile(`(\w+)=["']?([^"'\s]+)["']?`)
	vars := make(map[string]string)

	for _, match := range re.FindAllStringSubmatch(content, -1) {
		vars[match[1]] = match[2]
	}

	for k, v := range vars {
		content = strings.ReplaceAll(content, "$"+k, v)
	}

	return content
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

// TODO: limit decoded size
// TODO: limit number of decodes
func decodeBase64(content string) string {
	re := regexp.MustCompile(`(?i)[a-z0-9+/=]{20,}`)
	matches := re.FindAllString(content, -1)

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

func normalizeWhitespaces(content string) string {
	re := regexp.MustCompile(`\s+`)
	return re.ReplaceAllString(content, " ")
}

func normalizeSeparators(content string) string {
	re := regexp.MustCompile(`(;|&&|\|\|)`)
	return re.ReplaceAllString(content, "\n")
}

func removeStringConcat(content string) string {
	content = strings.ReplaceAll(content, `"`, "")
	content = strings.ReplaceAll(content, `'`, "")
	return content
}

func removeEscapeChars(content string) string {
	return strings.ReplaceAll(content, "\\", "")
}

func normalizePaths(content string) string {
	return strings.ReplaceAll(content, "/./", "/")
}

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

func staticAnalysis(files []ZipFile) []string {
	ch := make(chan string)
	var wg sync.WaitGroup

	for _, f := range files {
		if !f.isScript() {
			continue
		}

		wg.Go(func() {
			for _, pattern := range suspiciousPatterns {
				content := normalizeContent(f.Content)

				matched, _ := regexp.MatchString(pattern, content)
				if matched {
					ch <- pattern
				}
			}
		})
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	var matched []string
	for pattern := range ch {
		matched = append(matched, pattern)
	}

	return matched
}
