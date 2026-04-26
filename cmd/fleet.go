package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// resolveFleetAgentConfig returns the merged FleetAgentConfig that a daemon
// would use. Mirrors the precedence of buildFleetClient (CLI > env > file)
// without actually constructing / starting the HTTP client — the engine's
// RunDaemon does that itself so Close() ownership stays inside the engine.
func resolveFleetAgentConfig(dataDir, cliHub, cliToken string, cliInsecure bool) model.FleetAgentConfig {
	cfg := loadFleetAgentConfig(dataDir)
	if cliHub != "" {
		cfg.HubURL = cliHub
	}
	if cliToken != "" {
		cfg.Token = cliToken
	}
	cfg.InsecureSkipVerify = cliInsecure
	if cfg.QueuePath == "" {
		cfg.QueuePath = filepath.Join(dataDir, "fleet-queue.jsonl")
	}
	return cfg
}

// buildFleetClient constructs a FleetClient from CLI flags and/or the config
// file at <dataDir>/fleet.json. Returns nil if nothing is configured (fleet
// push is opt-in).
//
// Precedence: CLI flags override config file. A CLI --fleet-hub alone with no
// token is allowed (hub may run with auth disabled).
func buildFleetClient(dataDir, cliHub, cliToken string, cliInsecure bool) *engine.FleetClient {
	cfg := loadFleetAgentConfig(dataDir)
	if cliHub != "" {
		cfg.HubURL = cliHub
	}
	if cliToken != "" {
		cfg.Token = cliToken
	}
	// The insecure flag defaults to true, so only overwrite when the caller
	// explicitly flipped it to false on the CLI — but we keep it simple here
	// and just take the CLI value.
	cfg.InsecureSkipVerify = cliInsecure

	if cfg.HubURL == "" {
		return nil
	}
	if cfg.QueuePath == "" {
		cfg.QueuePath = filepath.Join(dataDir, "fleet-queue.jsonl")
	}
	return engine.NewFleetClient(cfg)
}

// loadFleetAgentConfig reads <dataDir>/fleet.json. Missing file → empty config.
func loadFleetAgentConfig(dataDir string) model.FleetAgentConfig {
	var cfg model.FleetAgentConfig
	path := filepath.Join(dataDir, "fleet.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "xtop: warning — %s is not valid JSON: %v\n", path, err)
		return model.FleetAgentConfig{}
	}
	return cfg
}
