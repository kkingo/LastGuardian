package main

import (
	"database/sql"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

const schema = `
CREATE TABLE IF NOT EXISTS history (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT    NOT NULL,
    session_id       TEXT    NOT NULL,
    tool_name        TEXT    NOT NULL,
    raw_command      TEXT,
    normalized_cmd   TEXT,
    risk_level       TEXT,
    triggered_layers TEXT,
    auth_required    INTEGER NOT NULL,
    user_decision    TEXT,
    final_action     TEXT    NOT NULL,
    request_hash     TEXT,
    project_dir      TEXT,
    cache_hit        INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_history_session   ON history(session_id);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history(timestamp);
CREATE INDEX IF NOT EXISTS idx_history_action    ON history(final_action);
CREATE INDEX IF NOT EXISTS idx_history_hash      ON history(request_hash);
`

// initHistoryDB initializes the SQLite database connection and schema.
func initHistoryDB(dataDir string) error {
	dbPath := filepath.Join(dataDir, "history.db")
	var err error
	db, err = sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)")
	if err != nil {
		return err
	}

	// Create tables and indexes (IF NOT EXISTS ensures idempotency)
	_, err = db.Exec(schema)
	return err
}

// recordHistory writes a single history record to the database.
func recordHistory(r HistoryRecord) {
	if db == nil {
		return // database not enabled or init failed → silently skip
	}
	_, _ = db.Exec(`
        INSERT INTO history
        (timestamp, session_id, tool_name, raw_command, normalized_cmd,
         risk_level, triggered_layers, auth_required, user_decision,
         final_action, request_hash, project_dir, cache_hit)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Timestamp, r.SessionID, r.ToolName, r.RawCommand,
		r.NormalizedCmd, r.RiskLevel, r.TriggeredLayers,
		boolToInt(r.AuthRequired), nullIfEmpty(r.UserDecision),
		r.FinalAction, r.RequestHash, r.ProjectDir,
		boolToInt(r.CacheHit),
	)
}

// pruneHistory deletes records older than the retention period.
func pruneHistory(retentionDays int) {
	if db == nil || retentionDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format(time.RFC3339)
	_, _ = db.Exec("DELETE FROM history WHERE timestamp < ?", cutoff)
}

// closeHistoryDB closes the database connection.
func closeHistoryDB() {
	if db != nil {
		_ = db.Close()
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
