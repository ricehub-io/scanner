package main

import (
	"log"
	"os"
	"regexp"

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

// TODO: safely unzip archives
// TODO: run static analysis against all scripts in zip
// TODO: normalize files before scan (remove comments, collapse whitespaces, resolve simple encodings, lowercase everything)
// TODO(?): score system to reduce false-positives
func main() {
	const file = "./test_data/static_test.txt"
	if name, found := clamavScan(file); found != nil {
		log.Printf("clamav detected: %v", name)
	}
	if matched := staticAnalysis(file); len(matched) > 0 {
		log.Printf("static analysis found: %v", matched)
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

func staticAnalysis(filePath string) []string {
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	var findings []string
	for _, pattern := range suspiciousPatterns {
		matched, _ := regexp.MatchString(pattern, string(content))
		if matched {
			findings = append(findings, pattern)
		}
	}
	return findings
}
