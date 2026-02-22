package identity

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

var (
	nginxServerNameRe = regexp.MustCompile(`(?m)^\s*server_name\s+(.+?)\s*;`)
	nginxListenRe     = regexp.MustCompile(`(?m)^\s*listen\s+(\S+)`)
	nginxSSLCertRe    = regexp.MustCompile(`(?m)^\s*ssl_certificate\s+(\S+)\s*;`)
	apacheServerNameRe = regexp.MustCompile(`(?mi)^\s*ServerName\s+(\S+)`)
)

// probeWebsites discovers nginx and apache vhosts.
func probeWebsites(id *model.ServerIdentity) {
	probeNginxSites(id)
	probeApacheSites(id)
}

func probeNginxSites(id *model.ServerIdentity) {
	// Check both sites-enabled and conf.d
	dirs := []string{
		"/etc/nginx/sites-enabled",
		"/etc/nginx/conf.d",
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			content := string(data)

			// Extract server_name
			matches := nginxServerNameRe.FindAllStringSubmatch(content, -1)
			for _, m := range matches {
				names := strings.Fields(m[1])
				for _, name := range names {
					if name == "_" || name == "localhost" || name == "" {
						continue
					}
					port := 80
					// Check for SSL listen
					if strings.Contains(content, "ssl") || strings.Contains(content, "443") {
						port = 443
					}

					site := model.WebsiteInfo{
						Domain:     name,
						Port:       port,
						ConfigFile: path,
					}

					// Check SSL cert expiry
					certMatches := nginxSSLCertRe.FindStringSubmatch(content)
					if len(certMatches) > 1 {
						site.SSLExpiry = checkCertExpiry(certMatches[1])
					}

					id.Websites = append(id.Websites, site)
				}
			}
		}
	}
}

func probeApacheSites(id *model.ServerIdentity) {
	dirs := []string{
		"/etc/apache2/sites-enabled",
		"/etc/httpd/conf.d",
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			content := string(data)

			matches := apacheServerNameRe.FindAllStringSubmatch(content, -1)
			for _, m := range matches {
				name := strings.TrimSpace(m[1])
				if name == "" || name == "localhost" {
					continue
				}
				port := 80
				if strings.Contains(content, ":443") || strings.Contains(content, "SSLEngine") {
					port = 443
				}
				id.Websites = append(id.Websites, model.WebsiteInfo{
					Domain:     name,
					Port:       port,
					ConfigFile: path,
				})
			}
		}
	}
}

// checkCertExpiry returns a human-readable SSL expiry string.
func checkCertExpiry(certPath string) string {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return ""
	}

	block, _ := pem.Decode(data)
	if block == nil {
		// Try as DER
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return ""
		}
		return formatExpiry(cert)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		// Try tls.X509KeyPair approach for bundled certs
		_ = tls.Certificate{}
		return ""
	}
	return formatExpiry(cert)
}

func formatExpiry(cert *x509.Certificate) string {
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	return fmt.Sprintf("%d days (%s)", daysLeft, cert.NotAfter.Format("2006-01-02"))
}
