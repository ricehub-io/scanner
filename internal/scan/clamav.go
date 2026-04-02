package scan

import (
	"log"
	"scanner/internal/config"

	clamav "github.com/ca110us/go-clamav"
	clamd "github.com/ca110us/go-clamav"
)

type ClamAV struct {
	c *clamd.Clamav
}

var Clam ClamAV

func (in *ClamAV) Init() {
	in.c = new(clamd.Clamav)

	err := in.c.Init(clamav.SCAN_OPTIONS{
		General:   0,
		Parse:     clamav.CL_SCAN_PARSE_ARCHIVE | clamav.CL_SCAN_PARSE_ELF,
		Heuristic: 0,
		Mail:      0,
		Dev:       0,
	})
	if err != nil {
		log.Fatalf("Failed to init clamav: %v", err)
	}

	_, err = in.c.LoadDB("/var/lib/clamav", uint(clamav.CL_DB_DIRECTORY))
	if err != nil {
		log.Fatalf("Failed to load clamav database: %v", err)
	}

	err = in.c.CompileEngine()
	if err != nil {
		log.Fatalf("Failed to compile clamav engine: %v", err)
	}

	in.c.EngineSetNum(clamav.CL_ENGINE_MAX_SCANSIZE, config.Cfg.MaxUncompressedSize.Bytes())
	in.c.EngineSetNum(clamav.CL_ENGINE_MAX_SCANTIME, 9000)
}

func (in *ClamAV) Free() {
	in.c.Free()
}

func (in *ClamAV) Scan(filePath string) (virusName string, ret error) {
	_, virusName, ret = in.c.ScanFile(filePath)
	return
}
