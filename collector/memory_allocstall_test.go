package collector

import (
	"testing"
)

// TestSumAllocStall verifies the M-C fix: summing all allocstall_* zones
// rather than reading only allocstall_normal (which is absent on kernel >=5.14).
func TestSumAllocStall(t *testing.T) {
	tests := []struct {
		name string
		kv   map[string]string
		want uint64
	}{
		{
			name: "all four zones present (modern kernel)",
			kv: map[string]string{
				"allocstall_dma":      "1",
				"allocstall_dma32":    "2",
				"allocstall_normal":   "3",
				"allocstall_movable":  "4",
				"pgfault":             "99999", // unrelated key, must not be counted
			},
			want: 10,
		},
		{
			name: "only allocstall_normal (old kernel)",
			kv: map[string]string{
				"allocstall_normal": "42",
				"pgmajfault":        "7",
			},
			want: 42,
		},
		{
			name: "allocstall_normal and allocstall_movable (pre-5.14 split)",
			kv: map[string]string{
				"allocstall_normal":  "10",
				"allocstall_movable": "5",
			},
			want: 15,
		},
		{
			name: "no allocstall keys at all",
			kv: map[string]string{
				"pgfault":    "100",
				"pgmajfault": "1",
			},
			want: 0,
		},
		{
			name: "only allocstall_dma and allocstall_movable (missing normal)",
			kv: map[string]string{
				"allocstall_dma":     "7",
				"allocstall_movable": "3",
			},
			want: 10,
		},
		{
			name: "zero values",
			kv: map[string]string{
				"allocstall_dma":     "0",
				"allocstall_dma32":   "0",
				"allocstall_normal":  "0",
				"allocstall_movable": "0",
			},
			want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sumAllocStall(tc.kv)
			if got != tc.want {
				t.Errorf("sumAllocStall(%v) = %d; want %d", tc.kv, got, tc.want)
			}
		})
	}
}
