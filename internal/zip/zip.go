package zip

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ricehub-io/scanner/internal/config"
)

type ZipFile struct {
	Name    string
	Content []byte
}

func (f ZipFile) IsScript() bool {
	if slices.Contains(config.Cfg.ShellExtensions, filepath.Ext(f.Name)) {
		return true
	}
	// fallback: check for shebang
	return bytes.HasPrefix(f.Content, []byte("#!/"))
}

func SafeUnzip(filePath string) ([]ZipFile, error) {
	const maxFiles = 1000

	r, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, err
	}
	defer closeSilent(r)

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
		if totalSize > config.Cfg.MaxUncompressedSize.Bytes() {
			return nil, fmt.Errorf("uncompressed archive is too large")
		}

		fr, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open zip file: %v", err)
		}
		defer closeSilent(fr)

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

func closeSilent(c io.Closer) {
	_ = c.Close()
}
