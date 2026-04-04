package clamav

import (
	"log"
	"scanner/internal/config"

	clamd "github.com/ca110us/go-clamav"
)

type scanner interface {
	ScanFile(string) (uint, string, error)
	Free() error
}

type ClamAV struct {
	c scanner
}

var Clam ClamAV

func (in *ClamAV) Init() {
	c := new(clamd.Clamav)

	err := c.Init(clamd.SCAN_OPTIONS{
		General:   0,
		Parse:     clamd.CL_SCAN_PARSE_ARCHIVE | clamd.CL_SCAN_PARSE_ELF,
		Heuristic: 0,
		Mail:      0,
		Dev:       0,
	})
	if err != nil {
		log.Fatalf("Failed to init clamav: %v", err)
	}

	_, err = c.LoadDB("/var/lib/clamav", uint(clamd.CL_DB_DIRECTORY))
	if err != nil {
		log.Fatalf("Failed to load clamav database: %v", err)
	}

	err = c.CompileEngine()
	if err != nil {
		log.Fatalf("Failed to compile clamav engine: %v", err)
	}

	c.EngineSetNum(
		clamd.CL_ENGINE_MAX_SCANSIZE,
		config.Cfg.MaxUncompressedSize.Bytes(),
	)
	c.EngineSetNum(clamd.CL_ENGINE_MAX_SCANTIME, 9000)

	in.c = c
}

func (in *ClamAV) Free() {
	_ = in.c.Free()
}

func (in *ClamAV) Scan(filePath string) (virusName string, ret error) {
	_, virusName, ret = in.c.ScanFile(filePath)
	return
}
