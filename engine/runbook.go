package engine

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// RunbookLibrary loads operator-authored runbooks from ~/.xtop/runbooks/*.md,
// matches them against incident context, and attaches the best match to the
// current RCA result.
//
// Format — a markdown file with a small YAML-ish frontmatter block:
//
//	---
//	name: Nginx worker saturation
//	bottleneck: cpu, network
//	app: nginx
//	culprit: nginx
//	evidence: runqlat_high, conn_queue_overflow
//	signature: cpu|runqlat_high,
//	---
//
//	## Diagnosis
//	Workers are maxed out — check:
//	```bash
//	nginx -T | grep worker_processes
//	```
//
//	## Fix
//	Set `worker_processes auto;` and reload.
//
// Matching is additive: each frontmatter field adds to a score only when the
// runbook's value overlaps with the incident's. A runbook with no match fields
// acts as a generic fallback (score 0 unless it specifies otherwise).
type RunbookLibrary struct {
	mu        sync.RWMutex
	dir       string
	books     []Runbook
	lastLoad  time.Time
	reloadEvery time.Duration
}

// Runbook is a single loaded runbook document. The parsed matcher fields live
// on Match; the rendered markdown body lives on Content.
type Runbook struct {
	Path    string          `json:"path"`
	Name    string          `json:"name"`
	Match   RunbookMatcher  `json:"match"`
	Content string          `json:"content"`      // markdown body without frontmatter
	// UpdatedAt is the file's mtime — the UI can show "runbook last edited Nd ago".
	UpdatedAt time.Time `json:"updated_at"`
}

// RunbookMatcher lists the criteria (all lowercased) for choosing this runbook.
// An empty slice on a field means "don't gate on this field." All scoring is
// substring-based for apps/culprits and exact for bottlenecks/evidence IDs.
type RunbookMatcher struct {
	Bottleneck []string `json:"bottleneck,omitempty"`
	AppContains []string `json:"app_contains,omitempty"`
	CulpritContains []string `json:"culprit_contains,omitempty"`
	EvidenceAny []string `json:"evidence_any,omitempty"`
	Signature []string `json:"signature,omitempty"`
	// MinScore lets a runbook say "only fire if my score hits N" — otherwise
	// any nonzero match wins the best-of-library competition.
	MinScore int `json:"min_score,omitempty"`
}

// NewRunbookLibrary creates a library pointing at ~/.xtop/runbooks/.
func NewRunbookLibrary() *RunbookLibrary {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".xtop", "runbooks")
	lib := &RunbookLibrary{
		dir:         dir,
		reloadEvery: 60 * time.Second,
	}
	_ = lib.Reload()
	return lib
}

// Reload walks the runbook directory and reparses every *.md file. Called on
// creation and on-demand by Match() once per reloadEvery interval, so edits
// pick up without a daemon restart.
func (l *RunbookLibrary) Reload() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lastLoad = time.Now()

	info, err := os.Stat(l.dir)
	if err != nil || !info.IsDir() {
		l.books = nil
		return err
	}
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return err
	}
	var books []Runbook
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".md") && !strings.HasSuffix(name, ".markdown") {
			continue
		}
		p := filepath.Join(l.dir, e.Name())
		rb, err := loadRunbook(p)
		if err != nil {
			continue
		}
		books = append(books, rb)
	}
	l.books = books
	return nil
}

// Match returns the best-scoring runbook for the given result, or nil if no
// runbook matches (score <= 0 or below MinScore).
func (l *RunbookLibrary) Match(result *model.AnalysisResult) *model.RunbookMatch {
	if result == nil || result.Health == model.HealthOK {
		return nil
	}
	l.mu.RLock()
	stale := time.Since(l.lastLoad) > l.reloadEvery
	l.mu.RUnlock()
	if stale {
		_ = l.Reload()
	}
	l.mu.RLock()
	defer l.mu.RUnlock()

	sig := signatureFromResult(result)
	culprit := strings.ToLower(result.PrimaryProcess + " " + result.PrimaryAppName)
	app := strings.ToLower(result.PrimaryAppName)
	firingIDs := make(map[string]bool)
	for _, rca := range result.RCA {
		if rca.Bottleneck != result.PrimaryBottleneck {
			continue
		}
		for _, ev := range rca.EvidenceV2 {
			if ev.Strength > 0.35 {
				firingIDs[strings.ToLower(ev.ID)] = true
			}
		}
		break
	}

	var best *Runbook
	bestScore := 0
	for i := range l.books {
		rb := &l.books[i]
		score := rb.Match.scoreAgainst(result.PrimaryBottleneck, app, culprit, firingIDs, sig)
		if score <= 0 || score < rb.Match.MinScore {
			continue
		}
		if score > bestScore {
			best = rb
			bestScore = score
		}
	}
	if best == nil {
		return nil
	}
	return &model.RunbookMatch{
		Name:    best.Name,
		Path:    best.Path,
		Score:   bestScore,
		Preview: preview(best.Content, 240),
	}
}

// Lookup returns the full Runbook for a matched path. Used by the UI to show
// the rendered content inside a drawer / detail panel.
func (l *RunbookLibrary) Lookup(path string) *Runbook {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for i := range l.books {
		if l.books[i].Path == path {
			cp := l.books[i]
			return &cp
		}
	}
	return nil
}

// All returns a copy of the loaded runbooks (for listing in a picker).
func (l *RunbookLibrary) All() []Runbook {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Runbook, len(l.books))
	copy(out, l.books)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ── Matcher scoring ──────────────────────────────────────────────────────────

func (m RunbookMatcher) scoreAgainst(bottleneck, app, culprit string, firingIDs map[string]bool, signature string) int {
	score := 0
	// Bottleneck: exact match, high weight — this is the primary axis.
	if len(m.Bottleneck) > 0 && containsEq(m.Bottleneck, bottleneck) {
		score += 4
	} else if len(m.Bottleneck) > 0 {
		// A runbook that gated on a bottleneck but didn't match is disqualified.
		return 0
	}
	// App substring — medium weight.
	if len(m.AppContains) > 0 && anySubstring(m.AppContains, app) {
		score += 3
	} else if len(m.AppContains) > 0 {
		return 0
	}
	// Culprit substring — runs across "process+app" so either field hits.
	if len(m.CulpritContains) > 0 && anySubstring(m.CulpritContains, culprit) {
		score += 2
	} else if len(m.CulpritContains) > 0 {
		return 0
	}
	// Evidence IDs — each matching ID adds 1.
	for _, id := range m.EvidenceAny {
		if firingIDs[strings.ToLower(id)] {
			score += 1
		}
	}
	// Signature — exact equality, high weight because it's the stablest match.
	if len(m.Signature) > 0 {
		for _, s := range m.Signature {
			if strings.TrimSpace(s) == signature {
				score += 5
				break
			}
		}
	}
	return score
}

func containsEq(haystack []string, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	for _, h := range haystack {
		if strings.ToLower(strings.TrimSpace(h)) == needle {
			return true
		}
	}
	return false
}

func anySubstring(needles []string, haystack string) bool {
	for _, n := range needles {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" && strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// ── Runbook file parsing ─────────────────────────────────────────────────────

func loadRunbook(path string) (Runbook, error) {
	rb := Runbook{Path: path}
	f, err := os.Open(path)
	if err != nil {
		return rb, err
	}
	defer f.Close()
	if info, err := f.Stat(); err == nil {
		rb.UpdatedAt = info.ModTime()
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	// Detect optional frontmatter — the file must begin with "---" on its
	// own line. Anything else is parsed as a pure-markdown runbook with no
	// matchers (operator catch-all).
	lineNo := 0
	var frontmatter []string
	var bodyLines []string
	inFrontmatter := false
	frontmatterClosed := false
	for sc.Scan() {
		line := sc.Text()
		lineNo++
		if lineNo == 1 {
			if strings.TrimSpace(line) == "---" {
				inFrontmatter = true
				continue
			}
		}
		if inFrontmatter && !frontmatterClosed {
			if strings.TrimSpace(line) == "---" {
				frontmatterClosed = true
				continue
			}
			frontmatter = append(frontmatter, line)
			continue
		}
		bodyLines = append(bodyLines, line)
	}
	rb.Content = strings.TrimSpace(strings.Join(bodyLines, "\n"))
	rb.Match = parseFrontmatter(frontmatter, &rb)
	// Name defaults to filename stem when no explicit `name:` is set.
	if rb.Name == "" {
		base := filepath.Base(path)
		rb.Name = strings.TrimSuffix(base, filepath.Ext(base))
	}
	return rb, nil
}

// parseFrontmatter understands a small subset of YAML — enough for operator
// ergonomics without pulling in a YAML parser:
//
//	key: value
//	key: a, b, c
//	key:
//	  - a
//	  - b
//
// The function mutates rb for fields it consumes (currently just `name`) and
// returns the parsed RunbookMatcher.
func parseFrontmatter(lines []string, rb *Runbook) RunbookMatcher {
	var m RunbookMatcher
	var curKey string
	var pending []string

	flush := func() {
		if curKey == "" {
			return
		}
		assignMatcherField(curKey, pending, &m, rb)
		curKey = ""
		pending = nil
	}

	for _, raw := range lines {
		line := strings.TrimRight(raw, " \t")
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") && curKey != "" {
			pending = append(pending, strings.TrimSpace(trimmed[2:]))
			continue
		}
		if i := strings.Index(trimmed, ":"); i > 0 {
			flush()
			curKey = strings.TrimSpace(trimmed[:i])
			rest := strings.TrimSpace(trimmed[i+1:])
			if rest != "" {
				// Signature values carry commas by design (they are of the
				// form "bottleneck|ev1,ev2,"). Keep them whole instead of
				// CSV-splitting.
				if strings.EqualFold(curKey, "signature") {
					pending = []string{rest}
				} else {
					pending = splitCSV(rest)
				}
				flush()
			}
		}
	}
	flush()
	return m
}

func assignMatcherField(key string, vals []string, m *RunbookMatcher, rb *Runbook) {
	clean := make([]string, 0, len(vals))
	for _, v := range vals {
		v = strings.TrimSpace(strings.Trim(v, `"'`))
		if v != "" {
			clean = append(clean, v)
		}
	}
	switch strings.ToLower(key) {
	case "name":
		if len(clean) > 0 {
			rb.Name = clean[0]
		}
	case "bottleneck":
		m.Bottleneck = clean
	case "app", "app_contains":
		m.AppContains = clean
	case "culprit", "culprit_contains":
		m.CulpritContains = clean
	case "evidence", "evidence_any":
		m.EvidenceAny = clean
	case "signature":
		m.Signature = clean
	case "min_score", "minscore":
		if len(clean) > 0 {
			if n, err := atoi(clean[0]); err == nil {
				m.MinScore = n
			}
		}
	}
}

func splitCSV(s string) []string {
	// Handles "a, b, c" and "a,b,c" and plain "a".
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func preview(content string, max int) string {
	// Skip leading blank lines and pick the first paragraph for a readable snippet.
	first := ""
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" && first != "" {
			break
		}
		if line == "" {
			continue
		}
		// Strip leading markdown heading hashes.
		line = strings.TrimLeft(line, "# ")
		if first == "" {
			first = line
		} else {
			first += " " + line
		}
		if len(first) >= max {
			break
		}
	}
	if len(first) > max {
		first = first[:max] + "…"
	}
	return first
}

// atoi is a tiny strconv.Atoi replacement — the engine package is
// strconv-free elsewhere and we don't want to pull it in for one call.
func atoi(s string) (int, error) {
	n := 0
	sign := 1
	for i, c := range s {
		if i == 0 && c == '-' {
			sign = -1
			continue
		}
		if c < '0' || c > '9' {
			return 0, errAtoi
		}
		n = n*10 + int(c-'0')
	}
	return n * sign, nil
}

var errAtoi = &atoiError{}

type atoiError struct{}

func (*atoiError) Error() string { return "invalid integer" }
