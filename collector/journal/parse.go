package journal

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// rawEntry mirrors the JSON field names produced by `journalctl -o json`.
// All numeric fields arrive as strings in journald JSON; use json.RawMessage
// for fields that may also be absent or have varying types.
type rawEntry struct {
	Priority            string          `json:"PRIORITY"`
	Message             string          `json:"MESSAGE"`
	PID                 json.RawMessage `json:"_PID"`
	Ident               string          `json:"SYSLOG_IDENTIFIER"`
	SystemdUnit         string          `json:"_SYSTEMD_UNIT"`
	Unit                string          `json:"UNIT"`
	RealtimeTimestamp   string          `json:"__REALTIME_TIMESTAMP"`
}

// parseJSONLines parses the newline-delimited JSON output of journalctl -o json.
// Malformed lines are silently skipped.
func parseJSONLines(data []byte) []Entry {
	lines := strings.Split(string(data), "\n")
	entries := make([]Entry, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var raw rawEntry
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue // skip malformed lines
		}

		entry := Entry{
			Message: raw.Message,
			Ident:   raw.Ident,
		}

		// PRIORITY: string → int; ignore if blank/invalid
		if p, err := strconv.Atoi(strings.TrimSpace(raw.Priority)); err == nil {
			entry.Priority = p
		}

		// _PID: can be a quoted string "1234", an integer 1234, or absent.
		// Use RawMessage and try both forms.
		if len(raw.PID) > 0 {
			// Try unquoting as string first (most common in journald JSON).
			var pidStr string
			if err := json.Unmarshal(raw.PID, &pidStr); err == nil {
				if pid, err2 := strconv.Atoi(strings.TrimSpace(pidStr)); err2 == nil {
					entry.PID = pid
				}
			} else {
				// Fall back to direct integer.
				var pidInt int
				if err2 := json.Unmarshal(raw.PID, &pidInt); err2 == nil {
					entry.PID = pidInt
				}
			}
		}

		// _SYSTEMD_UNIT preferred, fall back to UNIT.
		if raw.SystemdUnit != "" {
			entry.Unit = raw.SystemdUnit
		} else {
			entry.Unit = raw.Unit
		}

		// __REALTIME_TIMESTAMP: string of microseconds since Unix epoch.
		if raw.RealtimeTimestamp != "" {
			if us, err := strconv.ParseInt(strings.TrimSpace(raw.RealtimeTimestamp), 10, 64); err == nil {
				entry.At = time.Unix(0, us*int64(time.Microsecond)).UTC()
			}
		}

		entries = append(entries, entry)
	}

	return entries
}
