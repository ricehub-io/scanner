package config

import (
	"log"
	"os"
	"regexp"

	"github.com/dustin/go-humanize"
	"github.com/pelletier/go-toml/v2"
)

var Cfg config

type config struct {
	MaxUncompressedSize ByteSize `toml:"max_uncompressed_size"`
	ShellExtensions     []string `toml:"shell_extensions"`
	Heuristic           map[HeuristicCategory][]*regexp.Regexp
}

// Init reads config file from path, parses it, and
// initializes global `Cfg` variable. Panics if anything fails.
func (c *config) Init(filePath string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	err = toml.Unmarshal(content, c)
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// TODO: check if any heuristic category is missing
}

// Wrapper used for capturing human-readable data sizes from config.
type ByteSize string

// Bytes converts the human-readable data size string to bytes.
// Panics if conversion is not possible.
func (b ByteSize) Bytes() uint64 {
	bytes, err := humanize.ParseBytes(string(b))
	if err != nil {
		log.Fatalf("Failed to convert bytes: %v", err)
	}
	return bytes
}

type HeuristicCategory string

const (
	HardBlock    HeuristicCategory = "hard_block"
	Soft         HeuristicCategory = "soft"
	Network      HeuristicCategory = "network"
	Execution    HeuristicCategory = "execution"
	Obfuscation  HeuristicCategory = "obfuscation"
	Sensitive    HeuristicCategory = "sensitive"
	FileSystem   HeuristicCategory = "file_system"
	Privilege    HeuristicCategory = "privilege"
	Persistence  HeuristicCategory = "persistence"
	SSH          HeuristicCategory = "ssh"
	Exfiltration HeuristicCategory = "exfiltration"
)
