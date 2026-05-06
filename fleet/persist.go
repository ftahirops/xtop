package fleet

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/ftahirops/xtop/model"
)

// persistHeartbeat writes the heartbeat to Postgres (durable) and SQLite
// (hot cache). Called in a goroutine by handleHeartbeat — errors are logged
// but not returned, so a slow DB never blocks the agent.
func (h *Hub) persistHeartbeat(hb *model.FleetHeartbeat) {
	raw, err := json.Marshal(hb)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ts := hb.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	if _, err := h.pg.ExecContext(ctx, `
		INSERT INTO fleet_heartbeats
			(agent_id, hostname, ts, health, bottleneck, score, confidence,
			 cpu_busy, mem_used, io_worst, load_1, incident_id, data)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		hb.AgentID, hb.Hostname, ts,
		hb.Health.String(), hb.PrimaryBottleneck, hb.PrimaryScore, hb.Confidence,
		hb.CPUBusyPct, hb.MemUsedPct, hb.IOWorstUtil, hb.LoadAvg1,
		hb.ActiveIncidentID, raw,
	); err != nil {
		log.Printf("hub: persist heartbeat pg: %v", err)
	}

	if _, err := h.cache.ExecContext(ctx, `
		INSERT INTO heartbeats
			(agent_id, hostname, ts, health, bottleneck, score,
			 cpu_busy, mem_used, io_worst, load_1, data)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		hb.AgentID, hb.Hostname, ts.Unix(),
		hb.Health.String(), hb.PrimaryBottleneck, hb.PrimaryScore,
		hb.CPUBusyPct, hb.MemUsedPct, hb.IOWorstUtil, hb.LoadAvg1,
		string(raw),
	); err != nil {
		log.Printf("hub: persist heartbeat cache: %v", err)
	}
}

// persistIncident writes an incident update to Postgres. We store every update
// (started / updated / escalated / resolved) as a separate row so we can replay
// the incident lifecycle. `signature` lets us match similar incidents across
// hosts and time for "have we seen this before?" lookups.
func (h *Hub) persistIncident(inc *model.FleetIncident) {
	raw, err := json.Marshal(inc)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ts := inc.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	// confirmedAt: pass NULL when zero so old rows / Suspected-only updates
	// don't claim a fake confirmation time.
	var confirmedAt interface{}
	if !inc.ConfirmedAt.IsZero() {
		confirmedAt = inc.ConfirmedAt
	}
	var stateCol interface{}
	if inc.State != "" {
		stateCol = inc.State
	}

	if _, err := h.pg.ExecContext(ctx, `
		INSERT INTO fleet_incidents
			(incident_id, update_type, agent_id, hostname,
			 started_at, resolved_at, ts,
			 bottleneck, peak_score, confidence, health, culprit, signature,
			 state, confirmed_at, data)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (incident_id, update_type, ts) DO NOTHING`,
		inc.IncidentID, string(inc.UpdateType), inc.AgentID, inc.Hostname,
		inc.StartedAt, inc.ResolvedAt, ts,
		inc.Bottleneck, inc.PeakScore, inc.Confidence, inc.Health.String(),
		inc.Culprit, inc.Signature,
		stateCol, confirmedAt, raw,
	); err != nil {
		log.Printf("hub: persist incident pg: %v", err)
	}
}
