//go:build linux

package collector

import "testing"

// TestIsClientQueryCommand pins the long-query filter: MySQL background threads
// report Time as seconds-since-thread-start (i.e. uptime), so the event
// scheduler ("Daemon") and replication threads permanently tripped the
// "Query running for Ns — consider killing" CRIT on every MySQL 8 host,
// with harmful advice. Only client work counts as a long-running query.
func TestIsClientQueryCommand(t *testing.T) {
	longRunners := []string{"Query", "Execute"}
	background := []string{
		"Sleep", "Daemon",
		"Binlog Dump", "Binlog Dump GTID",
		"Replica IO", "Replica SQL", "Slave_IO", "Slave_SQL", "Connect",
	}
	for _, c := range longRunners {
		if !isClientQueryCommand(c) {
			t.Errorf("%q is client work and must count as a long-running query", c)
		}
	}
	for _, c := range background {
		if isClientQueryCommand(c) {
			t.Errorf("%q is a background/idle thread (Time=since thread start) and must NOT trip the long-query finding", c)
		}
	}
}
