package collector

import (
	"testing"
)

func TestProbeTLS(t *testing.T) {
	if got := ProbeTLS(false); got.InsecureSkipVerify != false {
		t.Fatalf("ProbeTLS(false).InsecureSkipVerify = %v, want false", got.InsecureSkipVerify)
	}
	if got := ProbeTLS(true); got.InsecureSkipVerify != true {
		t.Fatalf("ProbeTLS(true).InsecureSkipVerify = %v, want true", got.InsecureSkipVerify)
	}
}
