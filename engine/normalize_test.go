package engine

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		name              string
		value, warn, crit float64
		want              float64
	}{
		{"below warn", 3, 5, 20, 0},
		{"at warn", 5, 5, 20, 0},
		{"midpoint", 12.5, 5, 20, 0.5},
		{"at crit", 20, 5, 20, 1},
		{"above crit", 100, 5, 20, 1},
		{"zero value", 0, 5, 20, 0},
		{"negative value", -1, 5, 20, 0},
		{"equal warn crit (at threshold)", 5, 5, 5, 1},
		{"equal warn crit (below)", 3, 5, 5, 0},
		{"quarter point", 8.75, 5, 20, 0.25},
		{"three quarter", 16.25, 5, 20, 0.75},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalize(tt.value, tt.warn, tt.crit)
			if diff := got - tt.want; diff > 0.001 || diff < -0.001 {
				t.Errorf("normalize(%v, %v, %v) = %v, want %v",
					tt.value, tt.warn, tt.crit, got, tt.want)
			}
		})
	}
}
