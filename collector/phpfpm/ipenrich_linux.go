//go:build linux

package phpfpm

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// IP enrichment without external dependencies:
//
//   1. Reverse DNS (PTR record) — usually identifies the source. AWS,
//      GCP, Azure, Hetzner, OVH, DigitalOcean all set meaningful PTRs.
//   2. Built-in cloud/ASN CIDR table for the top 20 hosting providers
//      that account for ~90% of bot/attack traffic.
//
// Lookups are cached forever in-process — same attacker IPs reappear,
// no point re-querying.
//
// rDNS lookup has a 200 ms timeout so a single misbehaving resolver
// doesn't stall the refresh cycle. If lookup fails the IP is still
// returned, just without a hostname.

type ipInfo struct {
	IP        string
	RDNS      string // best-effort PTR (may be empty)
	Provider  string // matched cloud/ASN label, e.g. "AWS", "Hetzner", "Cloudflare"
	Country   string // ISO-2 if we can guess from rDNS / cloud, else ""
}

var (
	ipCacheMu sync.RWMutex
	ipCache   = map[string]ipInfo{}
)

// enrichIPs runs lookups for every IP not already cached. Concurrent
// resolvers with a hard timeout so the whole batch finishes in well
// under 1s even on 50 IPs.
func enrichIPs(ips []string) {
	// Filter to unknowns.
	ipCacheMu.RLock()
	missing := make([]string, 0, len(ips))
	for _, ip := range ips {
		if _, ok := ipCache[ip]; !ok {
			missing = append(missing, ip)
		}
	}
	ipCacheMu.RUnlock()
	if len(missing) == 0 {
		return
	}

	const maxConcurrency = 8
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	results := make(chan ipInfo, len(missing))

	for _, ip := range missing {
		ip := ip
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results <- lookupIP(ip)
		}()
	}
	go func() { wg.Wait(); close(results) }()

	ipCacheMu.Lock()
	defer ipCacheMu.Unlock()
	for info := range results {
		ipCache[info.IP] = info
	}
}

// getCachedIP returns whatever we have for ip; empty fields if unknown.
func getCachedIP(ip string) ipInfo {
	ipCacheMu.RLock()
	defer ipCacheMu.RUnlock()
	if info, ok := ipCache[ip]; ok {
		return info
	}
	return ipInfo{IP: ip}
}

func lookupIP(ip string) ipInfo {
	info := ipInfo{IP: ip}
	// Skip private / localhost.
	if isPrivate(ip) {
		info.Provider = "private/local"
		return info
	}
	// 1. Reverse DNS with hard timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	var resolver net.Resolver
	names, _ := resolver.LookupAddr(ctx, ip)
	if len(names) > 0 {
		info.RDNS = strings.TrimSuffix(names[0], ".")
	}
	// 2. Provider from rDNS first (cheap, strong signal).
	info.Provider, info.Country = providerFromRDNS(info.RDNS)
	// 3. Fall back to CIDR table for IPs with no rDNS / generic rDNS.
	if info.Provider == "" {
		if pip := net.ParseIP(ip); pip != nil {
			info.Provider = providerFromCIDR(pip)
		}
	}
	return info
}

// providerFromRDNS classifies a PTR record by suffix. Returns
// (provider, country-guess). Country is only set when the rDNS includes
// a clear geographic indicator.
func providerFromRDNS(rdns string) (string, string) {
	if rdns == "" {
		return "", ""
	}
	r := strings.ToLower(rdns)
	type rule struct {
		needle  string
		label   string
		country string
	}
	rules := []rule{
		// Cloud providers
		{".amazonaws.com", "AWS", ""},
		{"ec2-", "AWS", ""},
		{".compute-", "AWS", ""},
		{".googleusercontent.com", "GCP", ""},
		{".bc.googleusercontent.com", "GCP", ""},
		{".cloud.google.com", "GCP", ""},
		{".azure.com", "Azure", ""},
		{".cloudapp.net", "Azure", ""},
		{".azurewebsites.net", "Azure", ""},
		{".oracle.com", "Oracle Cloud", ""},
		{".oraclecloud.com", "Oracle Cloud", ""},
		{".digitalocean.com", "DigitalOcean", ""},
		{".linode.com", "Linode", ""},
		{".linodeusercontent.com", "Linode", ""},
		{".vultr.com", "Vultr", ""},
		{".vultrusercontent.com", "Vultr", ""},
		{".hetzner.com", "Hetzner", "DE"},
		{".your-server.de", "Hetzner", "DE"},
		{".ovh.net", "OVH", "FR"},
		{".ovhcloud.com", "OVH", "FR"},
		{".ovh.ca", "OVH", "CA"},
		{".scaleway.com", "Scaleway", "FR"},
		{".online.net", "Scaleway", "FR"},
		{".contabo.com", "Contabo", "DE"},
		{".upcloud.com", "UpCloud", ""},
		{".serverel.com", "Serverel", ""},
		{".kamatera.com", "Kamatera", ""},
		// CDN / proxy
		{".cloudflare.com", "Cloudflare", ""},
		{".fastly.com", "Fastly", ""},
		{".bunnycdn.com", "BunnyCDN", ""},
		{".cdn77.com", "CDN77", ""},
		{".keycdn.com", "KeyCDN", ""},
		// Monitoring / scanners (often the IP that "scrapes" your site)
		{".uptimerobot.com", "UptimeRobot (monitor)", ""},
		{".pingdom.com", "Pingdom (monitor)", ""},
		{".statuscake.com", "StatusCake (monitor)", ""},
		{".datadoghq.com", "Datadog (monitor)", ""},
		{".datadog.com", "Datadog (monitor)", ""},
		{".censys-scanner.com", "Censys (scanner)", ""},
		{".shodan.io", "Shodan (scanner)", ""},
		{".internet-measurement.com", "Internet measurement bot", ""},
		// Generic ISPs / residential
		{".comcast.net", "Comcast ISP", "US"},
		{".verizon.net", "Verizon ISP", "US"},
		{".att.net", "AT&T ISP", "US"},
		{".rr.com", "Spectrum/RR ISP", "US"},
		{".cox.net", "Cox ISP", "US"},
		{".btcentralplus.com", "BT ISP", "GB"},
		{".sky.com", "Sky ISP", "GB"},
		{".telus.net", "TELUS ISP", "CA"},
	}
	for _, ru := range rules {
		if strings.Contains(r, ru.needle) {
			return ru.label, ru.country
		}
	}
	return "", ""
}

// providerFromCIDR is a small, hand-maintained set of CIDR ranges for
// providers whose IPs frequently have non-meaningful PTR records.
// This is intentionally compact — for serious deployments we'd ship a
// real ASN database, but a few dozen ranges cover most attack traffic.
func providerFromCIDR(ip net.IP) string {
	cidrs := []struct {
		cidr  string
		label string
	}{
		// Cloudflare (well-known)
		{"104.16.0.0/12", "Cloudflare"},
		{"172.64.0.0/13", "Cloudflare"},
		{"172.70.0.0/16", "Cloudflare"},
		{"172.71.0.0/16", "Cloudflare"},
		{"103.21.244.0/22", "Cloudflare"},
		{"103.22.200.0/22", "Cloudflare"},
		{"103.31.4.0/22", "Cloudflare"},
		{"108.162.192.0/18", "Cloudflare"},
		{"131.0.72.0/22", "Cloudflare"},
		{"141.101.64.0/18", "Cloudflare"},
		{"162.158.0.0/15", "Cloudflare"},
		{"173.245.48.0/20", "Cloudflare"},
		{"188.114.96.0/20", "Cloudflare"},
		{"190.93.240.0/20", "Cloudflare"},
		{"197.234.240.0/22", "Cloudflare"},
		{"198.41.128.0/17", "Cloudflare"},
		// AWS samples — small subset; rDNS usually wins anyway
		{"3.0.0.0/8", "AWS"},
		{"13.32.0.0/15", "AWS CloudFront"},
		{"13.224.0.0/14", "AWS CloudFront"},
		{"15.158.0.0/16", "AWS"},
		{"18.0.0.0/8", "AWS"},
		{"34.192.0.0/12", "AWS"},
		{"35.71.64.0/22", "AWS"},
		{"52.0.0.0/11", "AWS"},
		{"54.144.0.0/12", "AWS"},
		// GCP samples
		{"34.64.0.0/10", "GCP"},
		{"35.184.0.0/13", "GCP"},
		{"35.192.0.0/14", "GCP"},
		{"35.196.0.0/15", "GCP"},
		// Azure samples
		{"13.64.0.0/11", "Azure"},
		{"20.0.0.0/8", "Azure"},
		// Hetzner
		{"5.9.0.0/16", "Hetzner"},
		{"46.4.0.0/16", "Hetzner"},
		{"49.13.0.0/16", "Hetzner"},
		{"65.21.0.0/16", "Hetzner"},
		{"78.46.0.0/16", "Hetzner"},
		{"88.99.0.0/16", "Hetzner"},
		{"95.216.0.0/15", "Hetzner"},
		{"116.202.0.0/16", "Hetzner"},
		{"128.140.0.0/16", "Hetzner"},
		{"142.132.128.0/17", "Hetzner"},
		{"157.90.0.0/16", "Hetzner"},
		{"159.69.0.0/16", "Hetzner"},
		{"162.55.0.0/16", "Hetzner"},
		{"167.235.0.0/16", "Hetzner"},
		{"168.119.0.0/16", "Hetzner"},
		{"176.9.0.0/16", "Hetzner"},
		{"188.40.0.0/16", "Hetzner"},
		{"195.201.0.0/16", "Hetzner"},
		// OVH
		{"51.38.0.0/16", "OVH"},
		{"51.68.0.0/16", "OVH"},
		{"51.75.0.0/16", "OVH"},
		{"51.83.0.0/16", "OVH"},
		{"54.36.0.0/16", "OVH"},
		{"54.37.0.0/16", "OVH"},
		{"54.38.0.0/16", "OVH"},
		{"54.39.0.0/16", "OVH"},
		// DigitalOcean
		{"104.131.0.0/16", "DigitalOcean"},
		{"104.236.0.0/16", "DigitalOcean"},
		{"138.197.0.0/16", "DigitalOcean"},
		{"138.68.0.0/16", "DigitalOcean"},
		{"139.59.0.0/16", "DigitalOcean"},
		{"143.110.0.0/16", "DigitalOcean"},
		{"146.190.0.0/16", "DigitalOcean"},
		{"159.65.0.0/16", "DigitalOcean"},
		{"159.89.0.0/16", "DigitalOcean"},
		{"161.35.0.0/16", "DigitalOcean"},
		{"164.90.0.0/16", "DigitalOcean"},
		{"165.227.0.0/16", "DigitalOcean"},
		{"167.71.0.0/16", "DigitalOcean"},
		{"167.99.0.0/16", "DigitalOcean"},
		{"178.62.0.0/16", "DigitalOcean"},
		// Linode / Akamai
		{"45.33.0.0/16", "Linode"},
		{"50.116.0.0/16", "Linode"},
		{"66.175.208.0/20", "Linode"},
		{"96.126.96.0/19", "Linode"},
		{"139.162.0.0/16", "Linode"},
		{"172.104.0.0/16", "Linode"},
		{"172.105.0.0/16", "Linode"},
		{"173.255.192.0/18", "Linode"},
		{"176.58.96.0/19", "Linode"},
		{"192.46.208.0/20", "Linode"},
		{"192.81.128.0/18", "Linode"},
		// Vultr
		{"45.32.0.0/16", "Vultr"},
		{"45.63.0.0/16", "Vultr"},
		{"45.76.0.0/16", "Vultr"},
		{"45.77.0.0/16", "Vultr"},
		{"66.42.0.0/16", "Vultr"},
		{"95.179.128.0/17", "Vultr"},
		{"104.207.128.0/17", "Vultr"},
		{"108.61.0.0/16", "Vultr"},
		{"149.28.0.0/16", "Vultr"},
		{"199.247.0.0/16", "Vultr"},
		// Common scanner / abuse origins (residential reseller blocks)
		{"45.146.0.0/16", "scanner-friendly (varies)"},
		{"185.220.100.0/22", "Tor exit"},
		{"185.220.101.0/24", "Tor exit"},
		{"185.220.102.0/24", "Tor exit"},
	}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c.cidr)
		if err != nil {
			continue
		}
		if n.Contains(ip) {
			return c.label
		}
	}
	return ""
}

func isPrivate(ip string) bool {
	if ip == "" {
		return false
	}
	if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return true
	}
	pip := net.ParseIP(ip)
	if pip == nil {
		return false
	}
	for _, c := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "100.64.0.0/10",
		"fc00::/7", "fe80::/10",
	} {
		_, n, _ := net.ParseCIDR(c)
		if n != nil && n.Contains(pip) {
			return true
		}
	}
	return false
}
