package config

import (
	"os"
	"regexp"

	"github.com/dustin/go-humanize"
	"github.com/pelletier/go-toml/v2"
	"go.uber.org/zap"
)

var Cfg config

type config struct {
	MaxUncompressedSize ByteSize `toml:"max_uncompressed_size"`
	ShellExtensions     []string `toml:"shell_extensions"`
	Heuristic           map[HeuristicCategory][]*regexp.Regexp
}

// Init reads config file from path, parses it, and
// initializes global `Cfg` variable. Exits if anything fails.
func (c *config) Init(filePath string) {
	l := zap.L()
	l.Info("Initializing config...", zap.String("config_path", filePath))

	content, err := os.ReadFile(filePath)
	if err != nil {
		l.Fatal("Could not read config file", zap.Error(err))
	}

	err = toml.Unmarshal(content, c)
	if err != nil {
		l.Fatal("Could not parse config file", zap.Error(err))
	}

	l.Info("Config loaded")

	// TODO: check if any heuristic category is missing
}

// Wrapper used for capturing human-readable data sizes from config.
type ByteSize string

// Bytes converts the human-readable data size string to bytes.
// Panics if conversion is not possible.
func (b ByteSize) Bytes() uint64 {
	bytes, err := humanize.ParseBytes(string(b))
	if err != nil {
		zap.L().Fatal("Could not convert human-readable bytes to uint64",
			zap.Error(err),
			zap.String("value", string(b)),
		)
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
