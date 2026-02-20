package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// AlertConfig defines alert destinations.
type AlertConfig struct {
	Webhook string
	Command string
}

// Notifier sends alert notifications.
type Notifier struct {
	cfg    AlertConfig
	client *http.Client
}

// NewNotifier creates a notifier.
func NewNotifier(cfg AlertConfig) *Notifier {
	return &Notifier{
		cfg: cfg,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Enabled returns true if any alert destination is configured.
func (n *Notifier) Enabled() bool {
	return n.cfg.Webhook != "" || n.cfg.Command != ""
}

// Notify sends an alert event asynchronously.
func (n *Notifier) Notify(event string, payload interface{}) {
	if !n.Enabled() {
		return
	}
	go n.notify(event, payload)
}

// validateWebhookURL checks that the webhook URL uses http/https and does not
// target localhost, link-local, or cloud metadata endpoints.
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("webhook URL must use http or https scheme, got %q", scheme)
	}
	host := strings.ToLower(u.Hostname())
	blocked := []string{"169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1", "::1", "[::1]"}
	for _, b := range blocked {
		if host == b {
			return fmt.Errorf("webhook URL host %q is blocked", host)
		}
	}
	return nil
}

func (n *Notifier) notify(event string, payload interface{}) {
	body := map[string]interface{}{
		"event":   event,
		"payload": payload,
		"ts":      time.Now().Format(time.RFC3339),
	}
	data, err := json.Marshal(body)
	if err != nil {
		log.Printf("xtop: alert marshal error: %v", err)
		return
	}

	if n.cfg.Webhook != "" {
		if err := validateWebhookURL(n.cfg.Webhook); err != nil {
			log.Printf("xtop: webhook blocked: %v", err)
		} else {
			req, err := http.NewRequest("POST", n.cfg.Webhook, bytes.NewReader(data))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				resp, err := n.client.Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}
		}
	}

	if n.cfg.Command != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sh", "-c", n.cfg.Command)
		cmd.Env = append(os.Environ(), "XTOP_EVENT="+event, "XTOP_PAYLOAD="+string(data))
		_ = cmd.Run()
	}
}
