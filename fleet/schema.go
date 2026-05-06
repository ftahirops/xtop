package fleet

import (
	"context"
	"time"
)

// initPostgresSchema creates the primary tables and indices used for long-term
// fleet history. Idempotent — safe to run on every startup.
//
// Storage layout:
//   - fleet_heartbeats: one row per agent tick. `data` is the raw JSON blob so
//     we can evolve the wire type without migrations. Hot columns are promoted
//     for indexed queries (hostname, ts, health).
//   - fleet_incidents: one row per incident update (started / updated /
//     escalated / resolved). Queries typically filter by host + time window.
func (h *Hub) initPostgresSchema() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS fleet_heartbeats (
			id          BIGSERIAL PRIMARY KEY,
			agent_id    TEXT        NOT NULL,
			hostname    TEXT        NOT NULL,
			ts          TIMESTAMPTZ NOT NULL,
			health      TEXT,
			bottleneck  TEXT,
			score       INT,
			confidence  INT,
			cpu_busy    DOUBLE PRECISION,
			mem_used    DOUBLE PRECISION,
			io_worst    DOUBLE PRECISION,
			load_1      DOUBLE PRECISION,
			incident_id TEXT,
			data        JSONB       NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_hb_host_ts  ON fleet_heartbeats (hostname, ts DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_hb_agent_ts ON fleet_heartbeats (agent_id, ts DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_hb_ts       ON fleet_heartbeats (ts DESC)`,

		`CREATE TABLE IF NOT EXISTS fleet_incidents (
			incident_id  TEXT        NOT NULL,
			update_type  TEXT        NOT NULL,
			agent_id     TEXT        NOT NULL,
			hostname     TEXT        NOT NULL,
			started_at   TIMESTAMPTZ NOT NULL,
			resolved_at  TIMESTAMPTZ,
			ts           TIMESTAMPTZ NOT NULL,
			bottleneck   TEXT,
			peak_score   INT,
			confidence   INT,
			health       TEXT,
			culprit      TEXT,
			signature    TEXT,
			data         JSONB       NOT NULL,
			PRIMARY KEY (incident_id, update_type, ts)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_inc_host_start ON fleet_incidents (hostname, started_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_inc_started    ON fleet_incidents (started_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_inc_sig        ON fleet_incidents (signature)`,

		// Migration: lifecycle hot columns added with the RCA overhaul. New
		// columns are NULLable so existing rows back-populate as NULL; the
		// JSONB blob still has the values for full-fidelity queries.
		// Idempotent — ADD COLUMN IF NOT EXISTS is a Postgres 9.6+ feature.
		`ALTER TABLE fleet_incidents ADD COLUMN IF NOT EXISTS state         TEXT`,
		`ALTER TABLE fleet_incidents ADD COLUMN IF NOT EXISTS confirmed_at  TIMESTAMPTZ`,
		`CREATE INDEX IF NOT EXISTS idx_inc_state        ON fleet_incidents (state)`,
		`CREATE INDEX IF NOT EXISTS idx_inc_confirmed_at ON fleet_incidents (confirmed_at DESC)`,
	}

	for _, s := range stmts {
		if _, err := h.pg.ExecContext(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// initCacheSchema creates the SQLite hot-cache tables. The cache holds the last
// hour of heartbeats so the TUI / web can render recent sparklines without
// hitting Postgres. Janitor prunes anything older than 1h.
func (h *Hub) initCacheSchema() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS heartbeats (
			agent_id   TEXT    NOT NULL,
			hostname   TEXT    NOT NULL,
			ts         INTEGER NOT NULL,
			health     TEXT,
			bottleneck TEXT,
			score      INTEGER,
			cpu_busy   REAL,
			mem_used   REAL,
			io_worst   REAL,
			load_1     REAL,
			data       TEXT    NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cache_host_ts ON heartbeats (hostname, ts DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_cache_ts      ON heartbeats (ts DESC)`,
	}
	for _, s := range stmts {
		if _, err := h.cache.ExecContext(ctx, s); err != nil {
			return err
		}
	}
	return nil
}
