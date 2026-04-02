package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"slices"
	"strings"
)

type ZipFile struct {
	Name    string
	Content []byte
}

func (f ZipFile) isScript() bool {
	if slices.Contains(cfg.ShellExtensions, filepath.Ext(f.Name)) {
		return true
	}
	// fallback: check for shebang
	return bytes.HasPrefix(f.Content, []byte("#!/"))
}

// TODO: score system to reduce false-positives
// TODO: gzip and hex deobfuscation
func main() {
	cfg.Init("config.toml")
	clam.Init()
	defer clam.Free()

	const file = "./test_data/all.zip"
	files, err := safeUnzip(file)
	if err != nil {
		log.Fatalf("Failed to safely unzip file: %v", err)
	}

	if virusName, ret := clam.Scan(file); ret != nil {
		log.Printf("ClamAV detected: %s", virusName)
	}

	if matched := staticAnalysis(files); len(matched) > 0 {
		log.Printf("Static analysis detected: %v", matched)
	}
}

func safeUnzip(filePath string) ([]ZipFile, error) {
	const maxFiles = 1000

	r, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, err
	}
	defer r.Close()

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
		if totalSize > cfg.MaxUncompressedSize.Bytes() {
			return nil, fmt.Errorf("uncompressed archive is too large")
		}

		fr, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open zip file: %v", err)
		}
		defer fr.Close()

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
