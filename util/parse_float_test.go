package util

import (
	"math"
	"testing"
)

func TestParseFloat64_NaNInf(t *testing.T) {
	cases := []struct {
		input string
		want  float64
	}{
		{"NaN", 0},
		{"Inf", 0},
		{"+Inf", 0},
		{"-Inf", 0},
		{"abc", 0},
		{"", 0},
		{"1.5", 1.5},
		{"-3.14", -3.14},
		{"0", 0},
		{"  42.0  ", 42.0}, // whitespace trimmed
	}
	for _, tc := range cases {
		got := ParseFloat64(tc.input)
		if math.IsNaN(got) || math.IsInf(got, 0) {
			t.Errorf("ParseFloat64(%q) = %v, want finite value", tc.input, got)
		}
		if got != tc.want {
			t.Errorf("ParseFloat64(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}
