package staticanalysis

import (
	"scanner/internal/zip"
	"sync"
)

const maxScore = 8

// StaticAnalysis scans script files within the given zip files for
// suspicious patterns (e.g. dangerous commands, base64 payloads).
func StaticAnalysis(files []zip.ZipFile) []string {
	ch := make(chan bool)
	var wg sync.WaitGroup

	for _, f := range files {
		if !f.IsScript() {
			continue
		}

		wg.Go(func() {
			content := normalizeContent(f.Content)
			score, forceBlock := analyze(content)
			ch <- score <= maxScore && !forceBlock
		})
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for ok := range ch {
		if !ok {
			return []string{"static analysis"}
		}
	}

	return []string{}
}
