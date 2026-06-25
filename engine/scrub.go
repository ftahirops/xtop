package engine

import "regexp"

// scrubRules holds all compiled regexes for credential scrubbing.
// Compiled once at package init to avoid per-call overhead.
var scrubRules = []struct {
	re   *regexp.Regexp
	repl string
}{
	// -p<value>  (mysql-style short flag: single dash, p, value with no space)
	// Require a word boundary — space or start of string — before -p so we
	// don't accidentally match the -p inside --password or --port.
	{regexp.MustCompile(`((?:^|\s)-p)(\S+)`), `${1}****`},

	// --password=<value>  or  --password <value>
	{regexp.MustCompile(`(--password[= ])(\S+)`), `${1}****`},

	// --pass=<value>  or  --pass <value>
	{regexp.MustCompile(`(--pass[= ])(\S+)`), `${1}****`},

	// --token=<value>  or  --token <value>
	{regexp.MustCompile(`(--token[= ])(\S+)`), `${1}****`},

	// Env-var assignments: *_KEY=<val>, *_SECRET=<val>, *_TOKEN=<val>, *PASSWORD=<val>
	// Matches WORD_KEY=value, AWS_SECRET_KEY=value, etc.
	{regexp.MustCompile(`(\b\w*(?:_KEY|_SECRET|_TOKEN|PASSWORD)=)(\S+)`), `${1}****`},
}

// ScrubCmdline replaces credential-bearing tokens in a process command-line
// with "****". It is applied before cmdlines are shipped to the fleet hub so
// that passwords embedded in flags (e.g. mysql -pSecret) or environment
// variable assignments (AWS_SECRET_KEY=abc) are not transmitted in plaintext.
//
// Safe to call on an empty string or a plain process name — no allocations
// occur when no patterns match.
func ScrubCmdline(s string) string {
	for _, rule := range scrubRules {
		s = rule.re.ReplaceAllString(s, rule.repl)
	}
	return s
}
