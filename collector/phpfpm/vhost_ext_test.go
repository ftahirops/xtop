//go:build linux

package phpfpm

import (
	"os"
	"path/filepath"
	"testing"
)

// Debian nginx includes `sites-enabled/*` with NO extension filter, so vhost
// files named without ".conf" (e.g. "xgenstack") are live config. The old
// .conf-only filter made those sites invisible on the PHP-FPM page (2 of 6+
// shown on the reference host). conf.d keeps the .conf filter (nginx includes
// conf.d/*.conf there).
func TestParseNginxDirExtensionFilter(t *testing.T) {
	dir := t.TempDir()
	site := "server {\n  server_name example.com;\n  root /var/www/example;\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "example"), []byte(site), 0o644); err != nil {
		t.Fatal(err)
	}
	site2 := "server {\n  server_name two.com;\n  root /var/www/two;\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "two.conf"), []byte(site2), 0o644); err != nil {
		t.Fatal(err)
	}

	names := func(vs []vhostInfo) map[string]bool {
		m := map[string]bool{}
		for _, v := range vs {
			m[v.Domain] = true
		}
		return m
	}

	// sites-enabled semantics: every file is config.
	all := names(parseNginxDir(dir, false))
	if !all["example.com"] || !all["two.com"] {
		t.Fatalf("sites-enabled mode must parse extensionless files too, got %v", all)
	}

	// conf.d semantics: only *.conf.
	confOnly := names(parseNginxDir(dir, true))
	if confOnly["example.com"] || !confOnly["two.com"] {
		t.Fatalf("conf.d mode must parse only .conf files, got %v", confOnly)
	}
}
