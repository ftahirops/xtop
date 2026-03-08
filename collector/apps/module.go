package apps

import "github.com/ftahirops/xtop/model"

// DetectedApp holds info about a detected app process before full collection.
type DetectedApp struct {
	PID     int
	Port    int
	Comm    string
	Cmdline string
	Index   int // instance number (0-based, for multiple instances)
}

// AppModule is the interface for application detection and monitoring modules.
type AppModule interface {
	Type() string        // "mysql", "nginx", etc.
	DisplayName() string // "MySQL", "Nginx", etc.
	Detect(processes []model.ProcessMetrics) []DetectedApp
	Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance
}
