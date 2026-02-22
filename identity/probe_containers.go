package identity

import (
	"strings"

	"github.com/ftahirops/xtop/model"
)

// containerPurposePatterns maps image name substrings (lowercase) to a purpose label.
// Order matters: first match wins, so more specific patterns come first.
var containerPurposePatterns = []struct {
	pattern string
	purpose string
}{
	// VPN
	{"wg-easy", "vpn"},
	{"wireguard", "vpn"},
	{"openvpn", "vpn"},
	{"tailscale", "vpn"},
	{"headscale", "vpn"},
	{"netbird", "vpn"},
	{"softether", "vpn"},

	// Web servers / reverse proxies
	{"nginx-proxy", "reverse-proxy"},
	{"nginx", "web"},
	{"apache", "web"},
	{"httpd", "web"},
	{"caddy", "web"},
	{"traefik", "reverse-proxy"},
	{"haproxy", "load-balancer"},
	{"envoy", "proxy"},

	// Databases
	{"postgres", "database"},
	{"mysql", "database"},
	{"mariadb", "database"},
	{"mongo", "database"},
	{"redis", "cache"},
	{"memcached", "cache"},
	{"elasticsearch", "search"},
	{"opensearch", "search"},
	{"clickhouse", "database"},
	{"influxdb", "database"},
	{"cockroachdb", "database"},
	{"timescaledb", "database"},

	// Message queues
	{"rabbitmq", "message-queue"},
	{"kafka", "message-queue"},
	{"nats", "message-queue"},
	{"mosquitto", "message-queue"},

	// Monitoring / observability
	{"prometheus", "monitoring"},
	{"grafana", "monitoring"},
	{"alertmanager", "monitoring"},
	{"kibana", "monitoring"},
	{"loki", "logging"},
	{"fluentd", "logging"},
	{"fluentbit", "logging"},
	{"logstash", "logging"},
	{"jaeger", "tracing"},
	{"zipkin", "tracing"},
	{"datadog", "monitoring"},
	{"newrelic", "monitoring"},
	{"zabbix", "monitoring"},
	{"uptime-kuma", "monitoring"},

	// DNS
	{"pihole", "dns"},
	{"adguard", "dns"},
	{"coredns", "dns"},
	{"unbound", "dns"},

	// CI/CD
	{"gitlab-runner", "cicd"},
	{"jenkins", "cicd"},
	{"drone", "cicd"},
	{"woodpecker", "cicd"},
	{"actions-runner", "cicd"},
	{"concourse", "cicd"},

	// Container infrastructure
	{"portainer", "container-mgmt"},
	{"watchtower", "container-mgmt"},
	{"registry", "container-registry"},
	{"harbor", "container-registry"},

	// Storage / backup
	{"minio", "storage"},
	{"nextcloud", "storage"},
	{"restic", "backup"},
	{"duplicati", "backup"},
	{"borgmatic", "backup"},

	// Mail
	{"mailserver", "mail"},
	{"mailu", "mail"},
	{"postfix", "mail"},
	{"dovecot", "mail"},

	// Auth
	{"keycloak", "auth"},
	{"authentik", "auth"},
	{"authelia", "auth"},

	// General app
	{"node", "app"},
	{"python", "app"},
	{"java", "app"},
	{"golang", "app"},
	{"ruby", "app"},
	{"php", "app"},
}

// classifyContainers analyzes Docker container images to determine their purpose,
// then injects those purposes back into the identity for role classification.
func classifyContainers(id *model.ServerIdentity) {
	for i := range id.Containers {
		c := &id.Containers[i]
		if c.Purpose != "" {
			continue // already classified (e.g., by VPN probe)
		}
		imgLower := strings.ToLower(c.Image)
		for _, p := range containerPurposePatterns {
			if strings.Contains(imgLower, p.pattern) {
				c.Purpose = p.purpose
				break
			}
		}
	}
}

// containerPurposeCount returns how many running containers have the given purpose.
func containerPurposeCount(id *model.ServerIdentity, purpose string) int {
	count := 0
	for _, c := range id.Containers {
		if c.Purpose == purpose && strings.HasPrefix(c.Status, "Up") {
			count++
		}
	}
	return count
}

// hasContainerWithPurpose returns true if at least one running container has the given purpose.
func hasContainerWithPurpose(id *model.ServerIdentity, purpose string) bool {
	return containerPurposeCount(id, purpose) > 0
}
