package apps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AppSecrets struct {
	MySQL         *DBCreds    `json:"mysql,omitempty"`
	PostgreSQL    *PGCreds    `json:"postgresql,omitempty"`
	MongoDB       *MongoCreds `json:"mongodb,omitempty"`
	Redis         *RedisCreds `json:"redis,omitempty"`
	RabbitMQ      *RabbitCreds `json:"rabbitmq,omitempty"`
	Elasticsearch *ESCreds    `json:"elasticsearch,omitempty"`
}

type DBCreds struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
}

type PGCreds struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbname"`
}

type MongoCreds struct {
	URI string `json:"uri"`
}

type RedisCreds struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
}

type RabbitCreds struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
}

type ESCreds struct {
	URL      string `json:"url"`
	User     string `json:"user"`
	Password string `json:"password"`
}

type secretsLoader struct {
	mu       sync.RWMutex
	secrets  *AppSecrets
	lastLoad time.Time
}

var globalSecrets = &secretsLoader{}

func loadSecrets() *AppSecrets {
	globalSecrets.mu.RLock()
	if globalSecrets.secrets != nil && time.Since(globalSecrets.lastLoad) < 60*time.Second {
		s := globalSecrets.secrets
		globalSecrets.mu.RUnlock()
		return s
	}
	globalSecrets.mu.RUnlock()

	globalSecrets.mu.Lock()
	defer globalSecrets.mu.Unlock()

	// Double-check after acquiring write lock
	if globalSecrets.secrets != nil && time.Since(globalSecrets.lastLoad) < 60*time.Second {
		return globalSecrets.secrets
	}

	s := &AppSecrets{}
	path := secretsPath()
	if path == "" {
		globalSecrets.secrets = s
		globalSecrets.lastLoad = time.Now()
		return s
	}

	data, err := os.ReadFile(path)
	if err != nil {
		globalSecrets.secrets = s
		globalSecrets.lastLoad = time.Now()
		return s
	}

	_ = json.Unmarshal(data, s)
	globalSecrets.secrets = s
	globalSecrets.lastLoad = time.Now()
	return s
}

func secretsPath() string {
	// Primary: /root/.xtop_secrets (simple, discoverable)
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	primary := filepath.Join(home, ".xtop_secrets")
	if _, err := os.Stat(primary); err == nil {
		return primary
	}
	// Fallback: XDG config
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		p := filepath.Join(xdg, "xtop", "secrets.json")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	legacy := filepath.Join(home, ".config", "xtop", "secrets.json")
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}
	// Return primary path (for creation instructions)
	return primary
}
