package engine

import (
	"os"
	"strconv"
)

// init applies any CUSUM tuning overrides set via environment variables.
//
// Env vars (all optional):
//
//	XTOP_CUSUM_NORMAL_K       e.g. "0.5"
//	XTOP_CUSUM_NORMAL_H       e.g. "4.0"
//	XTOP_CUSUM_SKEW_K         e.g. "1.0"
//	XTOP_CUSUM_SKEW_H         e.g. "6.0"
//	XTOP_CUSUM_BIMODAL_K      e.g. "0.75"
//	XTOP_CUSUM_BIMODAL_H      e.g. "5.0"
//
// Operators tune these when xtop's change-point alarms misfire on their
// specific workload — no rebuild needed. Invalid values are silently ignored.
func init() {
	overlay := func(env string, dst *float64) {
		raw := os.Getenv(env)
		if raw == "" {
			return
		}
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil || v <= 0 {
			return
		}
		*dst = v
	}
	overlay("XTOP_CUSUM_NORMAL_K", &cusumNormal.KMul)
	overlay("XTOP_CUSUM_NORMAL_H", &cusumNormal.HMul)
	overlay("XTOP_CUSUM_SKEW_K", &cusumRightSkewed.KMul)
	overlay("XTOP_CUSUM_SKEW_H", &cusumRightSkewed.HMul)
	overlay("XTOP_CUSUM_BIMODAL_K", &cusumBimodal.KMul)
	overlay("XTOP_CUSUM_BIMODAL_H", &cusumBimodal.HMul)
}
