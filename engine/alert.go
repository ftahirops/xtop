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
	Webhook          string
	Command          string
	Email            string
	SlackWebhook     string
	TelegramBotToken string
	TelegramChatID   string
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
	return n.cfg.Webhook != "" || n.cfg.Command != "" ||
		n.cfg.Email != "" || n.cfg.SlackWebhook != "" ||
		(n.cfg.TelegramBotToken != "" && n.cfg.TelegramChatID != "")
}

// Notify sends an alert event asynchronously.
func (n *Notifier) Notify(event string, payload interface{}) {
	if !n.Enabled() {
		return
	}
	go n.notify(event, payload)
}

// SendFormatted dispatches a formatted alert to all configured channels.
func (n *Notifier) SendFormatted(event, subject, text string, payload interface{}) {
	if !n.Enabled() {
		return
	}
	// Webhook
	if n.cfg.Webhook != "" {
		n.sendWebhook(event, payload)
	}
	// Command
	if n.cfg.Command != "" {
		n.sendCommand(event, payload)
	}
	// Email
	if n.cfg.Email != "" {
		n.sendEmail(subject, text)
	}
	// Slack
	if n.cfg.SlackWebhook != "" {
		n.sendSlack(text)
	}
	// Telegram
	if n.cfg.TelegramBotToken != "" && n.cfg.TelegramChatID != "" {
		n.sendTelegram(text)
	}
}

// sendEmail sends an email using the system mail command.
func (n *Notifier) sendEmail(subject, body string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "mail", "-s", subject, n.cfg.Email)
	cmd.Stdin = strings.NewReader(body)
	if err := cmd.Run(); err != nil {
		log.Printf("xtop: email send error: %v", err)
	}
}

// sendSlack posts a message to a Slack incoming webhook.
func (n *Notifier) sendSlack(text string) {
	if err := validateWebhookURL(n.cfg.SlackWebhook); err != nil {
		log.Printf("xtop: slack webhook blocked: %v", err)
		return
	}
	payload := map[string]string{"text": text}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", n.cfg.SlackWebhook, bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("xtop: slack send error: %v", err)
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// sendTelegram posts a message via the Telegram Bot API.
func (n *Notifier) sendTelegram(text string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.cfg.TelegramBotToken)
	payload := map[string]string{
		"chat_id": n.cfg.TelegramChatID,
		"text":    text,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("xtop: telegram send error: %v", err)
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
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

// sendWebhook posts JSON to the configured webhook URL.
func (n *Notifier) sendWebhook(event string, payload interface{}) {
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
	if err := validateWebhookURL(n.cfg.Webhook); err != nil {
		log.Printf("xtop: webhook blocked: %v", err)
		return
	}
	req, err := http.NewRequest("POST", n.cfg.Webhook, bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// sendCommand runs the configured shell command with alert data.
func (n *Notifier) sendCommand(event string, payload interface{}) {
	data, _ := json.Marshal(map[string]interface{}{
		"event":   event,
		"payload": payload,
		"ts":      time.Now().Format(time.RFC3339),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", n.cfg.Command)
	cmd.Env = append(os.Environ(), "XTOP_EVENT="+event, "XTOP_PAYLOAD="+string(data))
	_ = cmd.Run()
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

	if n.cfg.Email != "" {
		n.sendEmail("xtop: "+event, string(data))
	}
	if n.cfg.SlackWebhook != "" {
		n.sendSlack(fmt.Sprintf("*xtop: %s*\n```\n%s\n```", event, string(data)))
	}
	if n.cfg.TelegramBotToken != "" && n.cfg.TelegramChatID != "" {
		n.sendTelegram(fmt.Sprintf("xtop: %s\n%s", event, string(data)))
	}
}
