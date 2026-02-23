package engine

import "github.com/ftahirops/xtop/model"

// ThresholdOverride holds custom warn/crit thresholds for an evidence ID.
type ThresholdOverride struct {
	Warn float64
	Crit float64
}

// ThresholdProfile maps evidence IDs to threshold overrides.
type ThresholdProfile map[string]ThresholdOverride

// ActiveProfile is the currently loaded threshold profile.
// Set at startup from config; nil means use hardcoded defaults.
var ActiveProfile ThresholdProfile

// Profiles defines role-based threshold override sets.
var Profiles = map[string]ThresholdProfile{
	"database": {
		"io.psi":            {Warn: 3, Crit: 10},
		"io.disk.latency":   {Warn: 10, Crit: 40},
		"io.disk.util":      {Warn: 60, Crit: 85},
		"mem.available.low": {Warn: 75, Crit: 90},
		"mem.swap.activity":  {Warn: 1, Crit: 20},
	},
	"network": {
		"net.drops":       {Warn: 1, Crit: 50},
		"net.tcp.retrans": {Warn: 0.5, Crit: 3},
		"net.conntrack":   {Warn: 60, Crit: 85},
	},
	"mixed": {
		"io.psi":          {Warn: 4, Crit: 15},
		"io.disk.latency": {Warn: 15, Crit: 60},
		"io.disk.util":    {Warn: 65, Crit: 90},
		"net.drops":       {Warn: 1, Crit: 75},
		"net.tcp.retrans": {Warn: 0.8, Crit: 4},
		"net.conntrack":   {Warn: 65, Crit: 90},
	},
	"compute": {
		"cpu.psi":      {Warn: 3, Crit: 10},
		"cpu.runqueue": {Warn: 0.8, Crit: 1.5},
		"cpu.steal":    {Warn: 3, Crit: 10},
	},
	"gateway": {
		"net.conntrack": {Warn: 50, Crit: 80},
		"net.tcp.state": {Warn: 2000, Crit: 10000},
		"net.drops":     {Warn: 1, Crit: 30},
	},
}

// threshold returns the warn/crit values for an evidence ID, checking
// ActiveProfile first and falling back to the provided defaults.
func threshold(id string, defaultWarn, defaultCrit float64) (float64, float64) {
	if ActiveProfile != nil {
		if ov, ok := ActiveProfile[id]; ok {
			return ov.Warn, ov.Crit
		}
	}
	return defaultWarn, defaultCrit
}

// SelectProfile chooses the best threshold profile name for the given identity.
func SelectProfile(id *model.ServerIdentity) string {
	hasDB := id.HasRole(model.RoleDatabaseServer)
	hasWeb := id.HasRole(model.RoleWebServer) || id.HasRole(model.RoleLoadBalancer)
	hasGW := id.HasRole(model.RoleNATGateway) || id.HasRole(model.RoleRouter) || id.HasRole(model.RoleFirewall)
	hasCompute := id.HasRole(model.RoleCICDRunner) || id.HasRole(model.RoleAppServer)

	switch {
	case hasDB && hasWeb:
		return "mixed"
	case hasDB:
		return "database"
	case hasGW:
		return "gateway"
	case hasWeb:
		return "network"
	case hasCompute:
		return "compute"
	default:
		return ""
	}
}
