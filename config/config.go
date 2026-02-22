package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/ftahirops/xtop/model"
)

// Config holds user-configurable defaults and integrations.
type Config struct {
	DefaultLayout int              `json:"default_layout"`
	IntervalSec   int              `json:"interval_sec"`
	HistorySize   int              `json:"history_size"`
	Section       string           `json:"default_section"`
	Prometheus     PrometheusConfig     `json:"prometheus"`
	Alerts         AlertConfig          `json:"alerts"`
	ServerIdentity *model.ServerIdentity `json:"server_identity,omitempty"`
}

type PrometheusConfig struct {
	Enabled bool   `json:"enabled"`
	Addr    string `json:"addr"`
}

type AlertConfig struct {
	Webhook          string `json:"webhook"`
	Command          string `json:"command"`
	Email            string `json:"email"`
	SlackWebhook     string `json:"slack_webhook"`
	TelegramBotToken string `json:"telegram_bot_token"`
	TelegramChatID   string `json:"telegram_chat_id"`
}

// Default returns a config with sensible defaults.
func Default() Config {
	return Config{
		DefaultLayout: 0,
		IntervalSec:   1,
		HistorySize:   300,
		Section:       "overview",
		Prometheus: PrometheusConfig{
			Enabled: false,
			Addr:    "127.0.0.1:9100",
		},
		Alerts: AlertConfig{},
	}
}

// Path returns ~/.config/xtop/config.json (or XDG_CONFIG_HOME).
// Returns empty string if home directory cannot be determined.
func Path() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "" // refuse to fall back to /tmp (security risk)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "xtop", "config.json")
}

// Load loads config from disk; returns defaults on error.
func Load() Config {
	cfg := Default()
	p := Path()
	if p == "" {
		return cfg
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("xtop: warning: config parse error: %v", err)
	}
	return cfg
}

// Save writes the config to disk.
func Save(cfg Config) error {
	path := Path()
	if path == "" {
		return fmt.Errorf("cannot determine config directory")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
