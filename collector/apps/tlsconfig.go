//go:build linux

package apps

import (
	"crypto/tls"
	"os"
)

// probeInsecure mirrors XTOP_PROBE_INSECURE=1 for the apps package probe sites.
// Set to "1" only for self-signed / local-cert cases; default is false so that
// app module probes (Logstash, Kibana, Elasticsearch) verify TLS by default.
var probeInsecure = os.Getenv("XTOP_PROBE_INSECURE") == "1"

// probeTLS returns a *tls.Config for outbound app-module probes.
func probeTLS(insecure bool) *tls.Config {
	return &tls.Config{InsecureSkipVerify: insecure}
}
