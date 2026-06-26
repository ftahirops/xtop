package cmd

import (
	"testing"
)

func TestSqlIdent_ValidIdentifier(t *testing.T) {
	got, err := sqlIdent("xtop")
	if err != nil {
		t.Fatalf("sqlIdent(%q) returned unexpected error: %v", "xtop", err)
	}
	want := `"xtop"`
	if got != want {
		t.Errorf("sqlIdent(%q) = %q; want %q", "xtop", got, want)
	}
}

func TestSqlIdent_ValidIdentifierWithUnderscore(t *testing.T) {
	got, err := sqlIdent("xtop_fleet")
	if err != nil {
		t.Fatalf("sqlIdent(%q) returned unexpected error: %v", "xtop_fleet", err)
	}
	want := `"xtop_fleet"`
	if got != want {
		t.Errorf("sqlIdent(%q) = %q; want %q", "xtop_fleet", got, want)
	}
}

func TestSqlIdent_InvalidIdentifier(t *testing.T) {
	_, err := sqlIdent("foo; DROP TABLE")
	if err == nil {
		t.Fatalf("sqlIdent(%q) expected error, got nil", "foo; DROP TABLE")
	}
}

func TestSqlIdent_EmptyString(t *testing.T) {
	_, err := sqlIdent("")
	if err == nil {
		t.Fatalf("sqlIdent(%q) expected error for empty string, got nil", "")
	}
}

func TestSqlIdent_SpecialChars(t *testing.T) {
	cases := []string{
		"foo-bar",
		"foo bar",
		"foo'bar",
		`foo"bar`,
		"foo.bar",
	}
	for _, c := range cases {
		_, err := sqlIdent(c)
		if err == nil {
			t.Errorf("sqlIdent(%q) expected error, got nil", c)
		}
	}
}
