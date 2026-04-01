package main

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
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
}

type ZipFile struct {
	Name    string
	Content []byte
}

// TODO: normalize files before scan (remove comments, collapse whitespaces, resolve simple encodings, lowercase everything)
// TODO(?): score system to reduce false-positives
func main() {
	const file = "./test_data/archived_both.zip"
	files, err := safeUnzip(file)
	if err != nil {
		log.Fatalf("Failed to safely unzip file: %v", err)
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

	c.EngineSetNum(clamav.CL_ENGINE_MAX_SCANSIZE, 1024*1024*50)
	c.EngineSetNum(clamav.CL_ENGINE_MAX_SCANTIME, 9000)

	_, virusName, ret = c.ScanFile(filePath)
	return
}

func safeUnzip(filePath string) ([]ZipFile, error) {
	const (
		maxUncompressedSize = 1024 * 1024 * 50 // 50MB
		maxFiles            = 1000
	)

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

func staticAnalysis(files []ZipFile) []string {
	ch := make(chan string)
	var wg sync.WaitGroup

	for _, f := range files {
		// TODO: check if file is a script
		wg.Go(func() {
			for _, pattern := range suspiciousPatterns {
				matched, _ := regexp.MatchString(pattern, string(f.Content))
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
