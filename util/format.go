package util

import "fmt"

// FmtBytes formats bytes to human-readable string (1024-based).
func FmtBytes(b uint64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.0f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// BenignDropReasons is the canonical set of kernel SKB_DROP_REASON strings
// that represent normal TCP/IP lifecycle events, not actual packet loss.
// Maintained in one place to prevent divergence across packages.
var BenignDropReasons = map[string]bool{
	"NOT_SPECIFIED":    true,
	"NO_SOCKET":        true,
	"SOCKET_FILTER":    true,
	"OTHERHOST":        true,
	"TCP_FLAGS":        true,
	"TCP_ZEROWINDOW":   true,
	"TCP_OLD_DATA":     true,
	"TCP_OLD_SEQUENCE": true,
	"TCP_OVERWINDOW":   true,
	"TCP_OFOMERGE":     true,
	"SKB_CONSUMED":          true,
	"TCP_OFO_QUEUE_PRUNE":   true,
}

// IsBenignDropReason returns true if the drop reason string is benign.
func IsBenignDropReason(reason string) bool {
	return BenignDropReasons[reason]
}
