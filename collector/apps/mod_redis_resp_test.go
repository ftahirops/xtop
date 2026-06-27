//go:build linux

package apps

import (
	"bufio"
	"strings"
	"testing"
)

// TestRESPParser_BlankLines: blank/whitespace-only lines in RESP input must
// not panic (H5 fix). These functions previously did line[0] with no len guard.
func TestRESPParser_BlankLines(t *testing.T) {
	t.Run("parseSlowlogResp_empty", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseSlowlogResp panicked on blank input: %v", r)
			}
		}()
		r := bufio.NewReader(strings.NewReader("\n\n  \n"))
		parseSlowlogResp(r) // must return nil, not panic
	})

	t.Run("parseSlowlogEntry_empty", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseSlowlogEntry panicked on blank input: %v", r)
			}
		}()
		r := bufio.NewReader(strings.NewReader("\n"))
		parseSlowlogEntry(r) // must return nil, not panic
	})

	t.Run("readRespInt_empty", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("readRespInt panicked on blank input: %v", r)
			}
		}()
		r := bufio.NewReader(strings.NewReader("\n"))
		got := readRespInt(r)
		if got != 0 {
			t.Errorf("readRespInt blank line = %d, want 0", got)
		}
	})

	t.Run("readRespBulk_empty", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("readRespBulk panicked on blank input: %v", r)
			}
		}()
		r := bufio.NewReader(strings.NewReader("\n"))
		got := readRespBulk(r)
		if got != "" {
			t.Errorf("readRespBulk blank line = %q, want empty", got)
		}
	})

	t.Run("parseSlowlogEntry_blank_cmdline", func(t *testing.T) {
		// Entry header is valid (*4), but cmdLine field is blank.
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseSlowlogEntry panicked on blank cmdLine: %v", r)
			}
		}()
		// *4\r\n then valid integer fields then a blank cmdLine line
		input := "*4\n:1\n:1000\n:500\n\n"
		r := bufio.NewReader(strings.NewReader(input))
		parseSlowlogEntry(r) // must not panic
	})
}
