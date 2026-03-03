package runtime

import "github.com/ftahirops/xtop/model"

// RuntimeModule is the interface for a language runtime detection module.
type RuntimeModule interface {
	Name() string                                   // "jvm", "dotnet", etc.
	DisplayName() string                            // "JVM", ".NET", etc.
	Detect(processes []model.ProcessMetrics) bool    // scan for runtime processes
	Collect() []model.RuntimeProcessMetrics         // gather metrics (only if active)
	Active() bool                                   // any processes detected?
	ProcessCount() int
}
