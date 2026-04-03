package staticanalysis

import "regexp"

// TODO: read from config file
var (
	hardBlock = []string{
		`curl\s+.*\|\s*(bash|sh)`,
		`wget\s+.*\|\s*(bash|sh)`,
		`nc\s+.*-e\s+(bash|sh)`,
		`bash\s+-i\s+>&\s*/dev/tcp/`,
		`sh\s+-i\s+>&\s*/dev/tcp/`,
		`:\(\)\s*\{\s*:\|\:&\s*\};:`,
		`(?i)X5O!P%@AP\[4PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*`,
	}
	soft = []string{
		`source\s+`,
		`\.\s+\/`,
		`chmod\s+777`,
		`~/.bashrc`,
		`~/.profile`,
	}
	network = []string{
		`\bcurl\b`,
		`\bwget\b`,
		`\bnc\b`,
		`\bscp\b`,
		`\brsync\b`,
	}
	execution = []string{
		`\beval\b`,
		`\bexec\b`,
		`\bbash\b`,
		`\bsh\b`,
		`python\s+-c`,
		`perl\s+-e`,
	}
	obfuscation = []string{
		`base64`,
		`xxd\s+-r`,
		`openssl\s+enc`,
		`\$\(`,
		`\$\{[^}]{10,}\}`,
		`echo\s+.*\|\s*base64`,
		`printf\s+.*\|\s*base64`,
	}
	sensitive = []string{
		`/etc/passwd`,
		`/etc/shadow`,
		`dd\s+if=`,
		`mkfs`,
		`>\s*/dev/sd`,
	}
	fileSystem = []string{
		`rm\s+-rf\s+/`,
		`mount\s+`,
		`umount\s+`,
	}
	privilege = []string{
		`\bsudo\b`,
		`\bsu\b`,
		`useradd`,
		`usermod`,
		`passwd`,
	}
	persistence = []string{
		`crontab`,
		`/etc/cron`,
		`systemctl\s+enable`,
	}
	ssh = []string{
		`authorized_keys`,
		`ssh-rsa`,
	}
	exfiltration = []string{
		`\bscp\b`,
		`\brsync\b`,
		`nc\s+.*\d{2,5}`,
	}
)

// analyze expects normalized content.
func analyze(content string) (score uint, forceBlock bool) {
	match := func(patterns []string) bool {
		for _, pattern := range patterns {
			if matched, _ := regexp.MatchString(pattern, content); matched {
				return true
			}
		}
		return false
	}

	if match(hardBlock) {
		return score, true
	}

	// combinations
	if match(network) && match(execution) {
		score += 4
	}
	if match(obfuscation) && match(execution) {
		score += 3
	}
	if match(network) && match(obfuscation) {
		score += 3
	}
	if match(exfiltration) && match(sensitive) {
		score += 4
	}

	// individual
	// unaimeds: straight from yandere dev, its only temporary ok?
	if match(network) {
		score += 3
	}
	if match(execution) {
		score += 2
	}
	if match(obfuscation) {
		score += 2
	}
	if match(sensitive) {
		score += 4
	}
	if match(fileSystem) {
		score += 3
	}
	if match(privilege) {
		score += 1
	}
	if match(persistence) {
		score += 2
	}
	if match(exfiltration) {
		score += 3
	}
	if match(soft) {
		score += 1
	}

	return
}
