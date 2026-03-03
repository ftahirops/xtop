package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/ftahirops/xtop/model"
)

// Store provides SQLite-backed persistence for incidents and aggregates.
type Store struct {
	db *sql.DB
}

// IncidentRecord is a stored incident row.
type IncidentRecord struct {
	ID              string    `json:"id"`
	Fingerprint     string    `json:"fingerprint"`
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time,omitempty"`
	DurationSec     int       `json:"duration_sec"`
	PeakHealth      string    `json:"peak_health"`
	Bottleneck      string    `json:"bottleneck"`
	PeakScore       int       `json:"peak_score"`
	CulpritProcess  string    `json:"culprit_process,omitempty"`
	CulpritPID      int       `json:"culprit_pid,omitempty"`
	CulpritCgroup   string    `json:"culprit_cgroup,omitempty"`
	CausalChain     string    `json:"causal_chain,omitempty"`
	Narrative       string    `json:"narrative,omitempty"`
	EvidenceJSON    string    `json:"evidence_json,omitempty"`
	PeakCPU         float64   `json:"peak_cpu"`
	PeakMem         float64   `json:"peak_mem"`
	PeakIOPSI       float64   `json:"peak_io_psi"`
}

// IncidentOffender is a stored per-incident offender.
type IncidentOffender struct {
	IncidentID  string  `json:"incident_id"`
	PID         int     `json:"pid"`
	Comm        string  `json:"comm"`
	Service     string  `json:"service,omitempty"`
	ImpactScore float64 `json:"impact_score"`
	CPUPct      float64 `json:"cpu_pct"`
	MemBytes    uint64  `json:"mem_bytes"`
	IOMBps      float64 `json:"io_mbps"`
}

// Fingerprint tracks recurring incident patterns.
type Fingerprint struct {
	FP          string    `json:"fingerprint"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Count       int       `json:"count"`
	AvgDuration int       `json:"avg_duration_sec"`
	SymptomType string    `json:"symptom_type"`
	RootClass   string    `json:"root_class"`
	TopOffender string    `json:"top_offender"`
}

// AggregateSample is a 10-second aggregate row.
type AggregateSample struct {
	Health  string  `json:"health"`
	Score   int     `json:"score"`
	CPUBusy float64 `json:"cpu_busy"`
	MemPct  float64 `json:"mem_pct"`
	IOPSI   float64 `json:"io_psi"`
	TopPID  int     `json:"top_pid"`
	TopComm string  `json:"top_comm"`
}

// Open opens or creates the SQLite database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// WAL mode for concurrent reads, 5s busy timeout
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("pragma %s: %w", pragma, err)
		}
	}

	return &Store{db: db}, nil
}

// Migrate creates tables if they don't exist.
func (s *Store) Migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS incidents (
			id TEXT PRIMARY KEY,
			fingerprint TEXT NOT NULL,
			start_time DATETIME NOT NULL,
			end_time DATETIME,
			duration_sec INTEGER DEFAULT 0,
			peak_health TEXT NOT NULL,
			bottleneck TEXT NOT NULL,
			peak_score INTEGER DEFAULT 0,
			culprit_process TEXT,
			culprit_pid INTEGER,
			culprit_cgroup TEXT,
			causal_chain TEXT,
			narrative TEXT,
			evidence_json TEXT,
			peak_cpu REAL DEFAULT 0,
			peak_mem REAL DEFAULT 0,
			peak_io_psi REAL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_fp ON incidents(fingerprint)`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_start ON incidents(start_time)`,

		`CREATE TABLE IF NOT EXISTS incident_offenders (
			incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
			pid INTEGER NOT NULL,
			comm TEXT NOT NULL,
			service TEXT,
			impact_score REAL DEFAULT 0,
			cpu_pct REAL DEFAULT 0,
			mem_bytes INTEGER DEFAULT 0,
			io_mbps REAL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_offenders_incident ON incident_offenders(incident_id)`,

		`CREATE TABLE IF NOT EXISTS incident_signals (
			incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
			ts DATETIME NOT NULL,
			evidence_id TEXT NOT NULL,
			strength REAL DEFAULT 0,
			value REAL DEFAULT 0,
			unit TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_signals_incident ON incident_signals(incident_id)`,

		`CREATE TABLE IF NOT EXISTS fingerprints (
			fingerprint TEXT PRIMARY KEY,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			count INTEGER DEFAULT 1,
			avg_duration_sec INTEGER DEFAULT 0,
			symptom_type TEXT,
			root_class TEXT,
			top_offender TEXT
		)`,

		`CREATE TABLE IF NOT EXISTS aggregates_10s (
			ts DATETIME PRIMARY KEY,
			health TEXT NOT NULL,
			score INTEGER DEFAULT 0,
			cpu_busy REAL DEFAULT 0,
			mem_pct REAL DEFAULT 0,
			io_psi REAL DEFAULT 0,
			top_pid INTEGER,
			top_comm TEXT
		)`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// InsertIncident inserts a new incident with its offenders.
func (s *Store) InsertIncident(e model.Event, fp string, offenders []model.ImpactScore) error {
	evidenceJSON, _ := json.Marshal(e.Evidence)

	_, err := s.db.Exec(`INSERT INTO incidents
		(id, fingerprint, start_time, peak_health, bottleneck, peak_score,
		 culprit_process, culprit_pid, culprit_cgroup, causal_chain, evidence_json,
		 peak_cpu, peak_mem, peak_io_psi)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, fp, e.StartTime, e.PeakHealth.String(), e.Bottleneck, e.PeakScore,
		e.CulpritProcess, e.CulpritPID, e.CulpritCgroup, e.CausalChain,
		string(evidenceJSON), e.PeakCPUBusy, e.PeakMemUsedPct, e.PeakIOPSI)
	if err != nil {
		return fmt.Errorf("insert incident: %w", err)
	}

	// Insert offenders
	for _, o := range offenders {
		_, err = s.db.Exec(`INSERT INTO incident_offenders
			(incident_id, pid, comm, service, impact_score, cpu_pct, mem_bytes, io_mbps)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			e.ID, o.PID, o.Comm, o.Service, o.Composite,
			o.CPUSaturation*100, o.RSS, o.WriteMBs)
		if err != nil {
			return fmt.Errorf("insert offender: %w", err)
		}
	}

	return nil
}

// UpdateIncident updates end time and duration for a closed incident.
func (s *Store) UpdateIncident(id string, e model.Event) error {
	_, err := s.db.Exec(`UPDATE incidents SET end_time=?, duration_sec=?,
		peak_score=?, peak_cpu=?, peak_mem=?, peak_io_psi=?,
		narrative=?
		WHERE id=?`,
		e.EndTime, e.Duration, e.PeakScore,
		e.PeakCPUBusy, e.PeakMemUsedPct, e.PeakIOPSI,
		"", id)
	return err
}

// GetIncident retrieves a single incident by ID.
func (s *Store) GetIncident(id string) (*IncidentRecord, error) {
	row := s.db.QueryRow(`SELECT id, fingerprint, start_time, end_time, duration_sec,
		peak_health, bottleneck, peak_score, culprit_process, culprit_pid,
		culprit_cgroup, causal_chain, narrative, evidence_json,
		peak_cpu, peak_mem, peak_io_psi
		FROM incidents WHERE id=?`, id)

	var r IncidentRecord
	var endTime sql.NullTime
	err := row.Scan(&r.ID, &r.Fingerprint, &r.StartTime, &endTime, &r.DurationSec,
		&r.PeakHealth, &r.Bottleneck, &r.PeakScore, &r.CulpritProcess, &r.CulpritPID,
		&r.CulpritCgroup, &r.CausalChain, &r.Narrative, &r.EvidenceJSON,
		&r.PeakCPU, &r.PeakMem, &r.PeakIOPSI)
	if err != nil {
		return nil, err
	}
	if endTime.Valid {
		r.EndTime = endTime.Time
	}
	return &r, nil
}

// ListIncidents returns incidents ordered by start_time descending.
func (s *Store) ListIncidents(limit, offset int) ([]IncidentRecord, error) {
	rows, err := s.db.Query(`SELECT id, fingerprint, start_time, end_time, duration_sec,
		peak_health, bottleneck, peak_score, culprit_process, culprit_pid,
		culprit_cgroup, causal_chain, narrative, evidence_json,
		peak_cpu, peak_mem, peak_io_psi
		FROM incidents ORDER BY start_time DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanIncidents(rows)
}

// ListByFingerprint returns incidents matching a fingerprint.
func (s *Store) ListByFingerprint(fp string) ([]IncidentRecord, error) {
	rows, err := s.db.Query(`SELECT id, fingerprint, start_time, end_time, duration_sec,
		peak_health, bottleneck, peak_score, culprit_process, culprit_pid,
		culprit_cgroup, causal_chain, narrative, evidence_json,
		peak_cpu, peak_mem, peak_io_psi
		FROM incidents WHERE fingerprint=? ORDER BY start_time DESC`, fp)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanIncidents(rows)
}

// GetOffenders returns offenders for an incident.
func (s *Store) GetOffenders(incidentID string) ([]IncidentOffender, error) {
	rows, err := s.db.Query(`SELECT incident_id, pid, comm, service, impact_score,
		cpu_pct, mem_bytes, io_mbps
		FROM incident_offenders WHERE incident_id=? ORDER BY impact_score DESC`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var offenders []IncidentOffender
	for rows.Next() {
		var o IncidentOffender
		if err := rows.Scan(&o.IncidentID, &o.PID, &o.Comm, &o.Service,
			&o.ImpactScore, &o.CPUPct, &o.MemBytes, &o.IOMBps); err != nil {
			return nil, err
		}
		offenders = append(offenders, o)
	}
	return offenders, rows.Err()
}

// InsertAggregate inserts a 10-second aggregate sample.
func (s *Store) InsertAggregate(ts time.Time, summary AggregateSample) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO aggregates_10s
		(ts, health, score, cpu_busy, mem_pct, io_psi, top_pid, top_comm)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, summary.Health, summary.Score, summary.CPUBusy,
		summary.MemPct, summary.IOPSI, summary.TopPID, summary.TopComm)
	return err
}

// GetFingerprint retrieves a fingerprint record.
func (s *Store) GetFingerprint(fp string) (*Fingerprint, error) {
	row := s.db.QueryRow(`SELECT fingerprint, first_seen, last_seen, count,
		avg_duration_sec, symptom_type, root_class, top_offender
		FROM fingerprints WHERE fingerprint=?`, fp)

	var f Fingerprint
	err := row.Scan(&f.FP, &f.FirstSeen, &f.LastSeen, &f.Count,
		&f.AvgDuration, &f.SymptomType, &f.RootClass, &f.TopOffender)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// UpsertFingerprint inserts or updates a fingerprint record.
func (s *Store) UpsertFingerprint(fp Fingerprint) error {
	_, err := s.db.Exec(`INSERT INTO fingerprints
		(fingerprint, first_seen, last_seen, count, avg_duration_sec, symptom_type, root_class, top_offender)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(fingerprint) DO UPDATE SET
			last_seen=excluded.last_seen,
			count=count+1,
			avg_duration_sec=excluded.avg_duration_sec,
			top_offender=excluded.top_offender`,
		fp.FP, fp.FirstSeen, fp.LastSeen, fp.Count, fp.AvgDuration,
		fp.SymptomType, fp.RootClass, fp.TopOffender)
	return err
}

// Prune deletes incidents and aggregates older than the given time.
func (s *Store) Prune(olderThan time.Time) (int, error) {
	result, err := s.db.Exec(`DELETE FROM incidents WHERE start_time < ?`, olderThan)
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()

	s.db.Exec(`DELETE FROM aggregates_10s WHERE ts < ?`, olderThan)

	return int(n), nil
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// scanIncidents scans rows into IncidentRecord slices.
func scanIncidents(rows *sql.Rows) ([]IncidentRecord, error) {
	var records []IncidentRecord
	for rows.Next() {
		var r IncidentRecord
		var endTime sql.NullTime
		if err := rows.Scan(&r.ID, &r.Fingerprint, &r.StartTime, &endTime, &r.DurationSec,
			&r.PeakHealth, &r.Bottleneck, &r.PeakScore, &r.CulpritProcess, &r.CulpritPID,
			&r.CulpritCgroup, &r.CausalChain, &r.Narrative, &r.EvidenceJSON,
			&r.PeakCPU, &r.PeakMem, &r.PeakIOPSI); err != nil {
			return nil, err
		}
		if endTime.Valid {
			r.EndTime = endTime.Time
		}
		records = append(records, r)
	}
	return records, rows.Err()
}
