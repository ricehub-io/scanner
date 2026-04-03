package config

import (
	"log"
	"os"
	"regexp"

	"github.com/dustin/go-humanize"
	"github.com/pelletier/go-toml/v2"
)

var Cfg rootConfig

type rootConfig struct {
	MaxUncompressedSize ByteSize `toml:"max_uncompressed_size"`
	ShellExtensions     []string `toml:"shell_extensions"`
	Heuristic           heuristicConfig
}

type heuristicConfig struct {
	HardBlock    []*regexp.Regexp `toml:"hard_block"`
	Soft         []*regexp.Regexp
	Network      []*regexp.Regexp
	Execution    []*regexp.Regexp
	Obfuscation  []*regexp.Regexp
	Sensitive    []*regexp.Regexp
	FileSystem   []*regexp.Regexp `toml:"file_system"`
	Privilege    []*regexp.Regexp
	Persistence  []*regexp.Regexp
	SSH          []*regexp.Regexp
	Exfiltration []*regexp.Regexp
}

// Init reads config file from path, parses it, and
// initializes global `cfg` variable. Panics if anything fails.
func (c *rootConfig) Init(filePath string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	err = toml.Unmarshal(content, c)
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}
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
