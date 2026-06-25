package collector

import (
	"crypto/tls"
	"os"
)

// probeInsecure controls whether outbound TLS probes skip certificate
// verification. Set XTOP_PROBE_INSECURE=1 only for self-signed / local certs
// (e.g. a dev Elasticsearch with a self-signed cert).  The default is false —
// certificates are verified.
var probeInsecure = os.Getenv("XTOP_PROBE_INSECURE") == "1"

// ProbeTLS returns a *tls.Config for outbound app/health probes.
// Pass insecure=true only when the target is known to use a self-signed cert;
// callers should normally pass probeInsecure so the env override takes effect.
func ProbeTLS(insecure bool) *tls.Config {
	return &tls.Config{InsecureSkipVerify: insecure}
}
