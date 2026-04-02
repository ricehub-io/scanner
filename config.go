package main

import (
	"log"
	"os"

	"github.com/dustin/go-humanize"
	"github.com/pelletier/go-toml/v2"
)

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

type Config struct {
	MaxUncompressedSize ByteSize `toml:"max_uncompressed_size"`
	ShellExtensions     []string `toml:"shell_extensions"`
	SuspiciousPatterns  []string `toml:"suspicious_patterns"`
}

var cfg Config

// Init reads config file from path, parses it, and
// initializes global `cfg` variable. Panics if anything fails.
func (c *Config) Init(filePath string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	err = toml.Unmarshal(content, c)
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}
}
