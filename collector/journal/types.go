package journal

import "time"

// Entry is a single structured journald log record decoded from JSON output.
type Entry struct {
	Priority int       // journald PRIORITY (0=emerg … 7=debug)
	Message  string    // MESSAGE field
	Unit     string    // _SYSTEMD_UNIT or UNIT
	Ident    string    // SYSLOG_IDENTIFIER
	PID      int       // _PID
	At       time.Time // __REALTIME_TIMESTAMP converted from µs-since-epoch
}
