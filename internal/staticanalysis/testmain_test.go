package staticanalysis

import (
	"os"
	"regexp"
	"testing"

	"github.com/ricehub-io/scanner/internal/config"
)

func TestMain(m *testing.M) {
	config.Cfg.ShellExtensions = []string{".sh"}
	config.Cfg.Heuristic = map[config.HeuristicCategory][]*regexp.Regexp{
		config.HardBlock:    {regexp.MustCompile(`rm -rf /`), regexp.MustCompile(`dangerous`)},
		config.Soft:         {regexp.MustCompile(`suspicious`)},
		config.Network:      {regexp.MustCompile(`wget`)},
		config.Execution:    {regexp.MustCompile(`eval`)},
		config.Obfuscation:  {regexp.MustCompile(`base64`)},
		config.Sensitive:    {regexp.MustCompile(`/etc/passwd`)},
		config.FileSystem:   {regexp.MustCompile(`chmod 777`)},
		config.Privilege:    {regexp.MustCompile(`sudo`)},
		config.Persistence:  {regexp.MustCompile(`crontab`)},
		config.SSH:          {regexp.MustCompile(`ssh-keygen`), regexp.MustCompile(`\bssh\b`)},
		config.Exfiltration: {regexp.MustCompile(`exfil`), regexp.MustCompile(`curl.*evil`)},
	}
	os.Exit(m.Run())
}
