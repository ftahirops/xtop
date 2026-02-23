package ui

import "github.com/ftahirops/xtop/config"

// userConfig holds user preferences persisted to disk.
type userConfig struct {
	DefaultLayout int      `json:"default_layout"`
	Roles         []string `json:"roles,omitempty"`
}

// loadConfig loads user config from disk.
func loadConfig() userConfig {
	cfg := config.Load()
	uc := userConfig{DefaultLayout: cfg.DefaultLayout}
	if cfg.ServerIdentity != nil {
		for _, r := range cfg.ServerIdentity.Roles {
			uc.Roles = append(uc.Roles, string(r))
		}
	}
	return uc
}

// saveDefaultLayout persists the default layout to disk.
func saveDefaultLayout(layout LayoutMode) error {
	cfg := config.Load()
	cfg.DefaultLayout = int(layout)
	return config.Save(cfg)
}
