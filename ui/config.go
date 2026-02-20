package ui

import "github.com/ftahirops/xtop/config"

// userConfig holds user preferences persisted to disk.
type userConfig struct {
	DefaultLayout int `json:"default_layout"`
}

// loadConfig loads user config from disk.
func loadConfig() userConfig {
	cfg := config.Load()
	return userConfig{DefaultLayout: cfg.DefaultLayout}
}

// saveDefaultLayout persists the default layout to disk.
func saveDefaultLayout(layout LayoutMode) error {
	cfg := config.Load()
	cfg.DefaultLayout = int(layout)
	return config.Save(cfg)
}
