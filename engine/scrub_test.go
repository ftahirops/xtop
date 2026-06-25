package engine

import "testing"

func TestScrubCmdline(t *testing.T) {
	cases := map[string]string{
		"mysql -uroot -pSecret123 db":      "mysql -uroot -p**** db",
		"app --password=hunter2 --port 80": "app --password=**** --port 80",
		"env AWS_SECRET_KEY=abc ./run":     "env AWS_SECRET_KEY=**** ./run",
		"normal --port 8080":               "normal --port 8080",
	}
	for in, want := range cases {
		if got := ScrubCmdline(in); got != want {
			t.Errorf("ScrubCmdline(%q)=%q want %q", in, got, want)
		}
	}
}
