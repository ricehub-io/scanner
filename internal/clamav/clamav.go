package clamav

import (
	"fmt"

	"github.com/ricehub-io/scanner/internal/config"

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

func (in *ClamAV) Init() error {
	c := new(clamd.Clamav)

	if err := c.Init(clamd.SCAN_OPTIONS{
		General:   0,
		Parse:     clamd.CL_SCAN_PARSE_ARCHIVE | clamd.CL_SCAN_PARSE_ELF,
		Heuristic: 0,
		Mail:      0,
		Dev:       0,
	}); err != nil {
		return fmt.Errorf("clamd init: %w", err)
	}

	_, err := c.LoadDB("/var/lib/clamav", uint(clamd.CL_DB_DIRECTORY))
	if err != nil {
		return fmt.Errorf("load db: %w", err)
	}

	if err := c.CompileEngine(); err != nil {
		return fmt.Errorf("compile engine: %w", err)
	}

	if err := c.EngineSetNum(
		clamd.CL_ENGINE_MAX_SCANSIZE,
		config.Cfg.MaxUncompressedSize.Bytes(),
	); err != nil {
		return fmt.Errorf("engine set num - scan size: %w", err)
	}

	if err := c.EngineSetNum(clamd.CL_ENGINE_MAX_SCANTIME, 9000); err != nil {
		return fmt.Errorf("engine set num - scan time: %w", err)
	}

	in.c = c

	return nil
}

func (in *ClamAV) Free() {
	_ = in.c.Free()
}

func (in *ClamAV) Scan(filePath string) (virusName string, ret error) {
	_, virusName, ret = in.c.ScanFile(filePath)
	return
}
