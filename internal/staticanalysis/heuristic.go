package staticanalysis

import (
	"regexp"
	"scanner/internal/config"
)

var categoryWeight = map[config.HeuristicCategory]uint{
	config.Soft:         1,
	config.Network:      3,
	config.Execution:    2,
	config.Obfuscation:  2,
	config.Sensitive:    4,
	config.FileSystem:   3,
	config.Privilege:    1,
	config.Persistence:  2,
	config.SSH:          3,
	config.Exfiltration: 3,
}

// analyze analyzes normalized content for suspicious patterns,
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
	if match(patterns[config.HardBlock]) {
		return score, true
	}

	matched := make(map[config.HeuristicCategory]struct{})

	// single matches
	for cat, catPatterns := range patterns {
		if match(catPatterns) {
			score += categoryWeight[cat]
			matched[cat] = struct{}{}
		}
	}

	// combinations
	m := func(cat config.HeuristicCategory) bool {
		_, exists := matched[cat]
		return exists
	}

	if m(config.Network) && m(config.Execution) {
		score += 4
	}
	if m(config.Obfuscation) && m(config.Execution) {
		score += 3
	}
	if m(config.Network) && m(config.Obfuscation) {
		score += 3
	}
	if m(config.Exfiltration) && m(config.Sensitive) {
		score += 4
	}
	if m(config.SSH) && m(config.Network) {
		score += 5
	}
	if m(config.SSH) && m(config.Execution) {
		score += 3
	}
	if m(config.SSH) && m(config.Persistence) {
		score += 3
	}

	return
}
