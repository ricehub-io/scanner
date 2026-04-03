package staticanalysis

import (
	"regexp"
	"scanner/internal/config"
)

// analyze scans normalized content for suspicious patterns,
// for any pattern found it increases score based on weight.
//
// Returns total score from all matched patterns
// (higher score = higher chance that file is malicious),
// and forceBlock = true, if score should be ignored and
// file marked as malicious immediately.
func analyze(content string) (score uint, forceBlock bool) {
	match := func(patterns []*regexp.Regexp) bool {
		for _, pattern := range patterns {
			if pattern.MatchString(content) {
				return true
			}
		}
		return false
	}

	patterns := config.Cfg.Heuristic

	if match(patterns.HardBlock) {
		return score, true
	}

	// combinations
	if match(patterns.Network) && match(patterns.Execution) {
		score += 4
	}
	if match(patterns.Obfuscation) && match(patterns.Execution) {
		score += 3
	}
	if match(patterns.Network) && match(patterns.Obfuscation) {
		score += 3
	}
	if match(patterns.Exfiltration) && match(patterns.Sensitive) {
		score += 4
	}

	// individual
	// unaimeds: straight from yandere dev, its only temporary ok?
	if match(patterns.Soft) {
		score += 1
	}
	if match(patterns.Network) {
		score += 3
	}
	if match(patterns.Execution) {
		score += 2
	}
	if match(patterns.Obfuscation) {
		score += 2
	}
	if match(patterns.Sensitive) {
		score += 4
	}
	if match(patterns.FileSystem) {
		score += 3
	}
	if match(patterns.Privilege) {
		score += 1
	}
	if match(patterns.Persistence) {
		score += 2
	}
	if match(patterns.Exfiltration) {
		score += 3
	}

	return
}
