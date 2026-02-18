package ui

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// userConfig holds user preferences persisted to disk.
type userConfig struct {
	DefaultLayout int `json:"default_layout"`
}

// configPath returns ~/.config/xtop/config.json.
func configPath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "/tmp"
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "xtop", "config.json")
}

// loadConfig loads user config from disk.
func loadConfig() userConfig {
	var cfg userConfig
	data, err := os.ReadFile(configPath())
	if err != nil {
		return cfg
	}
	_ = json.Unmarshal(data, &cfg)
	return cfg
}

// saveDefaultLayout persists the default layout to disk.
func saveDefaultLayout(layout LayoutMode) error {
	cfg := loadConfig()
	cfg.DefaultLayout = int(layout)

	path := configPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
