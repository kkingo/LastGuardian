package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ── Data structures ──

type HistoryRow struct {
	ID              int64
	Timestamp       string
	SessionID       string
	ToolName        string
	RawCommand      sql.NullString
	NormalizedCmd   sql.NullString
	RiskLevel       sql.NullString
	TriggeredLayers sql.NullString
	AuthRequired    int
	UserDecision    sql.NullString
	FinalAction     string
	RequestHash     sql.NullString
	ProjectDir      sql.NullString
	CacheHit        int
}

type StatsResult struct {
	TotalRecords   int            `json:"total_records"`
	AllowCount     int            `json:"allow_count"`
	BlockCount     int            `json:"block_count"`
	CacheHitCount  int            `json:"cache_hit_count"`
	AuthPrompts    int            `json:"auth_prompts"`
	ByTool         map[string]int `json:"by_tool"`
	ByAction       map[string]int `json:"by_action"`
	ByRisk         map[string]int `json:"by_risk"`
	BySessions     int            `json:"unique_sessions"`
	FirstRecord    string         `json:"first_record"`
	LastRecord     string         `json:"last_record"`
	TopBlocked     []CmdCount     `json:"top_blocked_commands"`
	TopTriggered   []LayerCount   `json:"top_triggered_layers"`
	HourlyActivity []HourBucket   `json:"hourly_activity,omitempty"`
}

type CmdCount struct {
	Command string `json:"command"`
	Count   int    `json:"count"`
}

type LayerCount struct {
	Layer string `json:"layer"`
	Count int    `json:"count"`
}

type HourBucket struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

// ── Filter flags ──

type filterFlags struct {
	dbPath  *string
	limit   *int
	since   *string
	session *string
	tool    *string
	action  *string
	risk    *string
	project *string
	query   *string
	asJSON  *bool
	verbose *bool
}

func addFilters(fs *flag.FlagSet) filterFlags {
	return filterFlags{
		dbPath:  fs.String("db", "", "Path to history.db (default: ~/.claude/hooks/data/history.db)"),
		limit:   fs.Int("n", 50, "Maximum number of records to display"),
		since:   fs.String("since", "", "Show records since duration/date (e.g. 1h, 24h, 7d, 2024-01-01)"),
		session: fs.String("session", "", "Filter by session ID (prefix match)"),
		tool:    fs.String("tool", "", "Filter by tool name (Bash, Read, Edit, Write, Glob, Grep)"),
		action:  fs.String("action", "", "Filter by final action (allow, block)"),
		risk:    fs.String("risk", "", "Filter by risk level (MEDIUM, HIGH, CRITICAL)"),
		project: fs.String("project", "", "Filter by project directory (substring match)"),
		query:   fs.String("q", "", "Search in raw_command (substring match)"),
		asJSON:  fs.Bool("json", false, "Output as JSON"),
		verbose: fs.Bool("v", false, "Show full details for each record"),
	}
}

// ── CLI entry point ──

func main() {
	// Subcommands
	listCmd := flag.NewFlagSet("list", flag.ExitOnError)
	statsCmd := flag.NewFlagSet("stats", flag.ExitOnError)
	blockedCmd := flag.NewFlagSet("blocked", flag.ExitOnError)
	sessionsCmd := flag.NewFlagSet("sessions", flag.ExitOnError)
	tailCmd := flag.NewFlagSet("tail", flag.ExitOnError)
	pruneCmd := flag.NewFlagSet("prune", flag.ExitOnError)
	promptsCmd := flag.NewFlagSet("prompts", flag.ExitOnError)

	listF := addFilters(listCmd)
	statsF := addFilters(statsCmd)
	blockedF := addFilters(blockedCmd)
	sessionsF := addFilters(sessionsCmd)
	tailF := addFilters(tailCmd)
	pruneF := addFilters(pruneCmd)
	promptsF := addFilters(promptsCmd)
	pruneDays := pruneCmd.Int("days", 90, "Delete records older than this many days")

	// Usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `guard-history — Query Claude Code guard security audit log

Usage:
  guard-history <command> [flags]

Commands:
  list       List history records (default)
  prompts    List captured user prompts
  stats      Show statistics summary
  blocked    Show only blocked records
  sessions   List unique sessions with summary
  tail       Show most recent records (like tail -f)
  prune      Delete records older than --days

Common Flags:
  -db string     Path to history.db (default: ~/.claude/hooks/data/history.db)
  -n  int        Maximum records to display (default: 50)
  -since string  Filter by time: duration (1h, 24h, 7d) or date (2024-01-01)
  -session str   Filter by session ID (prefix match)
  -tool string   Filter by tool name
  -action string Filter by final action (allow, block)
  -risk string   Filter by risk level (MEDIUM, HIGH, CRITICAL)
  -project str   Filter by project directory (substring)
  -q string      Search in raw_command (substring)
  -json          Output as JSON
  -v             Verbose: show all fields per record

Examples:
  guard-history list -n 20
  guard-history blocked -since 24h
  guard-history stats -since 7d
  guard-history list -tool Bash -action block
  guard-history list -q "git push" -json
  guard-history sessions -since 7d
  guard-history tail -n 10
  guard-history prune -days 30
`)
	}

	if len(os.Args) < 2 {
		// Default to "list"
		os.Args = append(os.Args, "list")
	}

	subcmd := os.Args[1]
	// If first arg starts with "-", treat as "list" with flags
	if strings.HasPrefix(subcmd, "-") {
		subcmd = "list"
		os.Args = append([]string{os.Args[0], "list"}, os.Args[1:]...)
	}

	var ff filterFlags
	switch subcmd {
	case "list":
		listCmd.Parse(os.Args[2:])
		ff = listF
	case "stats":
		statsCmd.Parse(os.Args[2:])
		ff = statsF
	case "blocked":
		blockedCmd.Parse(os.Args[2:])
		ff = blockedF
	case "sessions":
		sessionsCmd.Parse(os.Args[2:])
		ff = sessionsF
	case "tail":
		tailCmd.Parse(os.Args[2:])
		ff = tailF
	case "prompts":
		promptsCmd.Parse(os.Args[2:])
		ff = promptsF
	case "prune":
		pruneCmd.Parse(os.Args[2:])
		ff = pruneF
	case "help", "-h", "--help":
		flag.Usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", subcmd)
		flag.Usage()
		os.Exit(1)
	}

	// Open database
	dbPath := resolveDBPath(*ff.dbPath)
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&mode=ro")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Verify connection
	if err := db.Ping(); err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to database at %s: %v\n", dbPath, err)
		os.Exit(1)
	}

	// Dispatch
	switch subcmd {
	case "list":
		runList(db, ff, false)
	case "blocked":
		*ff.action = "block"
		runList(db, ff, false)
	case "tail":
		runList(db, ff, true)
	case "stats":
		runStats(db, ff)
	case "sessions":
		runSessions(db, ff)
	case "prompts":
		runPrompts(db, ff)
	case "prune":
		runPrune(db, *pruneDays, *ff.asJSON)
	}
}

// ── Database path resolution ──

func resolveDBPath(explicit string) string {
	if explicit != "" {
		return explicit
	}

	// Check GUARD_CONFIG_PATH for custom data_dir
	configPath := os.Getenv("GUARD_CONFIG_PATH")
	if configPath == "" {
		home, _ := os.UserHomeDir()
		configPath = filepath.Join(home, ".claude", "hooks", "guard-config.json")
	}

	if data, err := os.ReadFile(configPath); err == nil {
		var cfg struct {
			DataDir string `json:"data_dir"`
		}
		if json.Unmarshal(data, &cfg) == nil && cfg.DataDir != "" {
			dir := expandHome(cfg.DataDir)
			return filepath.Join(dir, "history.db")
		}
	}

	// Default location
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "hooks", "data", "history.db")
}

func expandHome(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}
	home, _ := os.UserHomeDir()
	if path == "~" {
		return home
	}
	if len(path) > 1 && (path[1] == '/' || path[1] == '\\') {
		return filepath.Join(home, path[2:])
	}
	return path
}

// ── Query builder ──

type whereClause struct {
	conditions []string
	args       []interface{}
}

func (w *whereClause) add(cond string, arg interface{}) {
	w.conditions = append(w.conditions, cond)
	w.args = append(w.args, arg)
}

func (w *whereClause) build() (string, []interface{}) {
	if len(w.conditions) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(w.conditions, " AND "), w.args
}

func buildFilters(ff filterFlags) whereClause {
	var w whereClause

	if *ff.since != "" {
		t := parseSince(*ff.since)
		// Convert to local timezone for consistent string comparison with DB records
		w.add("timestamp >= ?", t.Local().Format(time.RFC3339))
	}
	if *ff.session != "" {
		w.add("session_id LIKE ?", *ff.session+"%")
	}
	if *ff.tool != "" {
		w.add("tool_name = ?", *ff.tool)
	}
	if *ff.action != "" {
		w.add("final_action = ?", *ff.action)
	}
	if *ff.risk != "" {
		w.add("risk_level = ?", strings.ToUpper(*ff.risk))
	}
	if *ff.project != "" {
		w.add("project_dir LIKE ?", "%"+*ff.project+"%")
	}
	if *ff.query != "" {
		w.add("raw_command LIKE ?", "%"+*ff.query+"%")
	}

	return w
}

// parseSince interprets duration strings (1h, 24h, 7d, 30d) or ISO date strings.
func parseSince(s string) time.Time {
	// Try duration pattern: Nd, Nh, Nm
	re := regexp.MustCompile(`^(\d+)([dhm])$`)
	if m := re.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		switch m[2] {
		case "d":
			return time.Now().AddDate(0, 0, -n)
		case "h":
			return time.Now().Add(-time.Duration(n) * time.Hour)
		case "m":
			return time.Now().Add(-time.Duration(n) * time.Minute)
		}
	}

	// Try ISO datetime without timezone (treat as UTC)
	if t, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
		return t.UTC()
	}
	// Try ISO date
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}

	fmt.Fprintf(os.Stderr, "Warning: could not parse --since %q, ignoring filter\n", s)
	return time.Time{}
}

// ── Subcommand: list / blocked / tail ──

func runList(db *sql.DB, ff filterFlags, isTail bool) {
	w := buildFilters(ff)
	where, args := w.build()

	query := "SELECT id, timestamp, session_id, tool_name, raw_command, normalized_cmd, " +
		"risk_level, triggered_layers, auth_required, user_decision, final_action, " +
		"request_hash, project_dir, cache_hit FROM history" + where +
		" ORDER BY id DESC LIMIT ?"
	args = append(args, *ff.limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Query error: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	var records []HistoryRow
	for rows.Next() {
		var r HistoryRow
		if err := rows.Scan(&r.ID, &r.Timestamp, &r.SessionID, &r.ToolName,
			&r.RawCommand, &r.NormalizedCmd, &r.RiskLevel, &r.TriggeredLayers,
			&r.AuthRequired, &r.UserDecision, &r.FinalAction, &r.RequestHash,
			&r.ProjectDir, &r.CacheHit); err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
			continue
		}
		records = append(records, r)
	}

	// Reverse to chronological order for display
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}

	if *ff.asJSON {
		printRecordsJSON(records)
		return
	}

	if len(records) == 0 {
		fmt.Println("No records found.")
		return
	}

	if *ff.verbose {
		printRecordsVerbose(records)
	} else {
		printRecordsTable(records)
	}
}

func printRecordsTable(records []HistoryRow) {
	// Header
	fmt.Printf("%-4s  %-20s  %-8s  %-6s  %-8s  %-7s  %-5s  %s\n",
		"ID", "TIMESTAMP", "SESSION", "TOOL", "ACTION", "RISK", "CACHE", "COMMAND")
	fmt.Println(strings.Repeat("─", 120))

	for _, r := range records {
		ts := formatTimestamp(r.Timestamp)
		sess := truncate(r.SessionID, 8)
		tool := truncate(r.ToolName, 6)
		action := colorAction(r.FinalAction)
		risk := colorRisk(nullStr(r.RiskLevel))
		cache := boolMark(r.CacheHit == 1)
		cmd := truncate(nullStr(r.RawCommand), 55)
		if cmd == "" {
			cmd = truncate(nullStr(r.NormalizedCmd), 55)
		}

		fmt.Printf("%-4d  %-20s  %-8s  %-6s  %-8s  %-7s  %-5s  %s\n",
			r.ID, ts, sess, tool, action, risk, cache, cmd)
	}

	fmt.Printf("\nShowing %d records. Use -v for full details.\n", len(records))
}

func printRecordsVerbose(records []HistoryRow) {
	for i, r := range records {
		if i > 0 {
			fmt.Println(strings.Repeat("─", 80))
		}
		fmt.Printf("Record #%d\n", r.ID)
		fmt.Printf("  Timestamp:        %s\n", r.Timestamp)
		fmt.Printf("  Session ID:       %s\n", r.SessionID)
		fmt.Printf("  Tool:             %s\n", r.ToolName)
		fmt.Printf("  Raw Command:      %s\n", nullStr(r.RawCommand))
		fmt.Printf("  Normalized Cmd:   %s\n", nullStr(r.NormalizedCmd))
		fmt.Printf("  Risk Level:       %s\n", colorRisk(nullStr(r.RiskLevel)))
		fmt.Printf("  Triggered Layers: %s\n", nullStr(r.TriggeredLayers))
		fmt.Printf("  Auth Required:    %s\n", boolMark(r.AuthRequired == 1))
		fmt.Printf("  User Decision:    %s\n", nullStr(r.UserDecision))
		fmt.Printf("  Final Action:     %s\n", colorAction(r.FinalAction))
		fmt.Printf("  Request Hash:     %s\n", nullStr(r.RequestHash))
		fmt.Printf("  Project Dir:      %s\n", nullStr(r.ProjectDir))
		fmt.Printf("  Cache Hit:        %s\n", boolMark(r.CacheHit == 1))
	}
	fmt.Printf("\nTotal: %d records\n", len(records))
}

func printRecordsJSON(records []HistoryRow) {
	type jsonRecord struct {
		ID              int64  `json:"id"`
		Timestamp       string `json:"timestamp"`
		SessionID       string `json:"session_id"`
		ToolName        string `json:"tool_name"`
		RawCommand      string `json:"raw_command,omitempty"`
		NormalizedCmd   string `json:"normalized_cmd,omitempty"`
		RiskLevel       string `json:"risk_level,omitempty"`
		TriggeredLayers string `json:"triggered_layers,omitempty"`
		AuthRequired    bool   `json:"auth_required"`
		UserDecision    string `json:"user_decision,omitempty"`
		FinalAction     string `json:"final_action"`
		RequestHash     string `json:"request_hash,omitempty"`
		ProjectDir      string `json:"project_dir,omitempty"`
		CacheHit        bool   `json:"cache_hit"`
	}

	out := make([]jsonRecord, len(records))
	for i, r := range records {
		out[i] = jsonRecord{
			ID:              r.ID,
			Timestamp:       r.Timestamp,
			SessionID:       r.SessionID,
			ToolName:        r.ToolName,
			RawCommand:      nullStr(r.RawCommand),
			NormalizedCmd:   nullStr(r.NormalizedCmd),
			RiskLevel:       nullStr(r.RiskLevel),
			TriggeredLayers: nullStr(r.TriggeredLayers),
			AuthRequired:    r.AuthRequired == 1,
			UserDecision:    nullStr(r.UserDecision),
			FinalAction:     r.FinalAction,
			RequestHash:     nullStr(r.RequestHash),
			ProjectDir:      nullStr(r.ProjectDir),
			CacheHit:        r.CacheHit == 1,
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

// ── Subcommand: stats ──

func runStats(db *sql.DB, ff filterFlags) {
	w := buildFilters(ff)
	where, args := w.build()

	stats := StatsResult{
		ByTool:   make(map[string]int),
		ByAction: make(map[string]int),
		ByRisk:   make(map[string]int),
	}

	// Total + allow/block counts
	row := db.QueryRow("SELECT COUNT(*), "+
		"SUM(CASE WHEN final_action='allow' THEN 1 ELSE 0 END), "+
		"SUM(CASE WHEN final_action='block' THEN 1 ELSE 0 END), "+
		"SUM(CASE WHEN cache_hit=1 THEN 1 ELSE 0 END), "+
		"SUM(CASE WHEN auth_required=1 THEN 1 ELSE 0 END), "+
		"COUNT(DISTINCT session_id), "+
		"MIN(timestamp), MAX(timestamp) "+
		"FROM history"+where, args...)

	var firstTS, lastTS sql.NullString
	row.Scan(&stats.TotalRecords, &stats.AllowCount, &stats.BlockCount,
		&stats.CacheHitCount, &stats.AuthPrompts, &stats.BySessions,
		&firstTS, &lastTS)
	stats.FirstRecord = nullStr(firstTS)
	stats.LastRecord = nullStr(lastTS)

	// By tool
	rows, _ := db.Query("SELECT tool_name, COUNT(*) FROM history"+where+
		" GROUP BY tool_name ORDER BY COUNT(*) DESC", args...)
	if rows != nil {
		for rows.Next() {
			var name string
			var cnt int
			rows.Scan(&name, &cnt)
			stats.ByTool[name] = cnt
		}
		rows.Close()
	}

	// By action
	rows, _ = db.Query("SELECT final_action, COUNT(*) FROM history"+where+
		" GROUP BY final_action ORDER BY COUNT(*) DESC", args...)
	if rows != nil {
		for rows.Next() {
			var name string
			var cnt int
			rows.Scan(&name, &cnt)
			stats.ByAction[name] = cnt
		}
		rows.Close()
	}

	// By risk level
	rows, _ = db.Query("SELECT COALESCE(risk_level, 'N/A'), COUNT(*) FROM history"+where+
		" GROUP BY risk_level ORDER BY COUNT(*) DESC", args...)
	if rows != nil {
		for rows.Next() {
			var name string
			var cnt int
			rows.Scan(&name, &cnt)
			stats.ByRisk[name] = cnt
		}
		rows.Close()
	}

	// Top blocked commands
	bWhere := w
	bWhere.add("final_action = ?", "block")
	bWhereStr, bArgs := bWhere.build()
	rows, _ = db.Query("SELECT COALESCE(normalized_cmd, raw_command, '(unknown)'), COUNT(*) "+
		"FROM history"+bWhereStr+
		" GROUP BY COALESCE(normalized_cmd, raw_command) ORDER BY COUNT(*) DESC LIMIT 10", bArgs...)
	if rows != nil {
		for rows.Next() {
			var cmd string
			var cnt int
			rows.Scan(&cmd, &cnt)
			stats.TopBlocked = append(stats.TopBlocked, CmdCount{cmd, cnt})
		}
		rows.Close()
	}

	// Top triggered layers
	rows, _ = db.Query("SELECT triggered_layers, COUNT(*) FROM history"+where+
		" WHERE triggered_layers IS NOT NULL AND triggered_layers != ''"+
		" GROUP BY triggered_layers ORDER BY COUNT(*) DESC LIMIT 10", args...)
	if rows != nil {
		for rows.Next() {
			var layer string
			var cnt int
			rows.Scan(&layer, &cnt)
			stats.TopTriggered = append(stats.TopTriggered, LayerCount{layer, cnt})
		}
		rows.Close()
	}

	// Hourly activity (last 24h)
	cutoff := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	rows, _ = db.Query("SELECT substr(timestamp, 1, 13) AS hour, COUNT(*) "+
		"FROM history WHERE timestamp >= ? GROUP BY hour ORDER BY hour", cutoff)
	if rows != nil {
		for rows.Next() {
			var hour string
			var cnt int
			rows.Scan(&hour, &cnt)
			stats.HourlyActivity = append(stats.HourlyActivity, HourBucket{hour, cnt})
		}
		rows.Close()
	}

	if *ff.asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(stats)
		return
	}

	printStatsText(stats)
}

func printStatsText(s StatsResult) {
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║        Claude Guard — Security Audit Stats      ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()

	// Overview
	fmt.Println("── Overview ──")
	fmt.Printf("  Total records:     %d\n", s.TotalRecords)
	fmt.Printf("  Unique sessions:   %d\n", s.BySessions)
	fmt.Printf("  Time range:        %s → %s\n", formatTimestamp(s.FirstRecord), formatTimestamp(s.LastRecord))
	fmt.Println()

	// Action breakdown
	fmt.Println("── Actions ──")
	blockRate := 0.0
	if s.TotalRecords > 0 {
		blockRate = float64(s.BlockCount) / float64(s.TotalRecords) * 100
	}
	fmt.Printf("  ✓ Allowed:         %d\n", s.AllowCount)
	fmt.Printf("  ✗ Blocked:         %d (%.1f%%)\n", s.BlockCount, blockRate)
	fmt.Printf("  ⚡ Cache hits:      %d\n", s.CacheHitCount)
	fmt.Printf("  ? Auth prompts:    %d\n", s.AuthPrompts)
	fmt.Println()

	// By tool
	if len(s.ByTool) > 0 {
		fmt.Println("── By Tool ──")
		for tool, cnt := range s.ByTool {
			bar := strings.Repeat("█", barWidth(cnt, s.TotalRecords, 30))
			fmt.Printf("  %-8s %4d  %s\n", tool, cnt, bar)
		}
		fmt.Println()
	}

	// By risk level
	if len(s.ByRisk) > 0 {
		fmt.Println("── By Risk Level ──")
		for risk, cnt := range s.ByRisk {
			fmt.Printf("  %-10s %4d\n", risk, cnt)
		}
		fmt.Println()
	}

	// Top blocked
	if len(s.TopBlocked) > 0 {
		fmt.Println("── Top Blocked Commands ──")
		for i, c := range s.TopBlocked {
			fmt.Printf("  %2d. [%3d] %s\n", i+1, c.Count, truncate(c.Command, 70))
		}
		fmt.Println()
	}

	// Hourly activity
	if len(s.HourlyActivity) > 0 {
		fmt.Println("── Hourly Activity (last 24h) ──")
		maxCnt := 0
		for _, b := range s.HourlyActivity {
			if b.Count > maxCnt {
				maxCnt = b.Count
			}
		}
		for _, b := range s.HourlyActivity {
			hourLabel := b.Hour
			if len(hourLabel) >= 13 {
				hourLabel = hourLabel[11:13] + ":00"
			}
			bar := strings.Repeat("▓", barWidth(b.Count, maxCnt, 40))
			fmt.Printf("  %s │%s %d\n", hourLabel, bar, b.Count)
		}
		fmt.Println()
	}
}

// ── Subcommand: sessions ──

func runSessions(db *sql.DB, ff filterFlags) {
	w := buildFilters(ff)
	where, args := w.build()

	query := "SELECT session_id, COUNT(*) as cnt, " +
		"MIN(timestamp) as first_ts, MAX(timestamp) as last_ts, " +
		"SUM(CASE WHEN final_action='block' THEN 1 ELSE 0 END) as blocks, " +
		"SUM(CASE WHEN final_action='allow' THEN 1 ELSE 0 END) as allows, " +
		"SUM(CASE WHEN auth_required=1 THEN 1 ELSE 0 END) as auths " +
		"FROM history" + where +
		" GROUP BY session_id ORDER BY last_ts DESC LIMIT ?"
	args = append(args, *ff.limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Query error: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	type sessionRow struct {
		SessionID string `json:"session_id"`
		Count     int    `json:"total"`
		FirstTS   string `json:"first_seen"`
		LastTS    string `json:"last_seen"`
		Blocks    int    `json:"blocks"`
		Allows    int    `json:"allows"`
		Auths     int    `json:"auth_prompts"`
	}

	var sessions []sessionRow
	for rows.Next() {
		var s sessionRow
		rows.Scan(&s.SessionID, &s.Count, &s.FirstTS, &s.LastTS, &s.Blocks, &s.Allows, &s.Auths)
		sessions = append(sessions, s)
	}

	if *ff.asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(sessions)
		return
	}

	if len(sessions) == 0 {
		fmt.Println("No sessions found.")
		return
	}

	fmt.Printf("%-16s  %-20s  %-20s  %6s  %6s  %6s  %5s\n",
		"SESSION", "FIRST SEEN", "LAST SEEN", "TOTAL", "ALLOW", "BLOCK", "AUTH")
	fmt.Println(strings.Repeat("─", 105))

	for _, s := range sessions {
		fmt.Printf("%-16s  %-20s  %-20s  %6d  %6d  %6d  %5d\n",
			s.SessionID,
			formatTimestamp(s.FirstTS),
			formatTimestamp(s.LastTS),
			s.Count, s.Allows, s.Blocks, s.Auths)
	}

	fmt.Printf("\nTotal: %d sessions\n", len(sessions))
}

// ── Subcommand: prune ──

func runPrune(db *sql.DB, days int, asJSON bool) {
	cutoff := time.Now().AddDate(0, 0, -days).Format(time.RFC3339)

	// Count first
	var count int
	db.QueryRow("SELECT COUNT(*) FROM history WHERE timestamp < ?", cutoff).Scan(&count)

	if count == 0 {
		if asJSON {
			fmt.Println(`{"pruned": 0, "message": "no records to prune"}`)
		} else {
			fmt.Printf("No records older than %d days.\n", days)
		}
		return
	}

	result, err := db.Exec("DELETE FROM history WHERE timestamp < ?", cutoff)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Prune error: %v\n", err)
		os.Exit(1)
	}

	deleted, _ := result.RowsAffected()
	if asJSON {
		fmt.Printf(`{"pruned": %d, "cutoff": %q}`+"\n", deleted, cutoff)
	} else {
		fmt.Printf("Pruned %d records older than %d days (before %s).\n",
			deleted, days, formatTimestamp(cutoff))
	}
}

// ── Formatting helpers ──

func formatTimestamp(ts string) string {
	if ts == "" {
		return "N/A"
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		// Try RFC3339Nano
		t, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return ts // Return as-is
		}
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func nullStr(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

func colorAction(action string) string {
	switch action {
	case "allow":
		return "\033[32mallow\033[0m"  // green
	case "block":
		return "\033[31mblock\033[0m"  // red
	default:
		return action
	}
}

func colorRisk(risk string) string {
	switch risk {
	case "CRITICAL":
		return "\033[1;31mCRITICAL\033[0m"
	case "HIGH":
		return "\033[31mHIGH\033[0m"
	case "MEDIUM":
		return "\033[33mMEDIUM\033[0m"
	default:
		return risk
	}
}

func boolMark(b bool) string {
	if b {
		return "Y"
	}
	return "-"
}

func barWidth(value, maxValue, maxWidth int) int {
	if maxValue == 0 {
		return 0
	}
	w := value * maxWidth / maxValue
	if w == 0 && value > 0 {
		return 1
	}
	return w
}

// ── Subcommand: prompts ──

func runPrompts(db *sql.DB, ff filterFlags) {
	var conditions []string
	var args []interface{}

	if *ff.since != "" {
		t := parseSince(*ff.since)
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, t.Local().Format(time.RFC3339))
	}
	if *ff.session != "" {
		conditions = append(conditions, "session_id LIKE ?")
		args = append(args, *ff.session+"%")
	}
	if *ff.project != "" {
		conditions = append(conditions, "project_dir LIKE ?")
		args = append(args, "%"+*ff.project+"%")
	}
	if *ff.query != "" {
		conditions = append(conditions, "prompt LIKE ?")
		args = append(args, "%"+*ff.query+"%")
	}

	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}

	query := "SELECT id, timestamp, session_id, prompt, project_dir FROM prompts" +
		where + " ORDER BY id ASC LIMIT ?"
	args = append(args, *ff.limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Query error: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	type promptRow struct {
		ID         int64  `json:"id"`
		Timestamp  string `json:"timestamp"`
		SessionID  string `json:"session_id"`
		Prompt     string `json:"prompt"`
		ProjectDir string `json:"project_dir,omitempty"`
	}

	var prompts []promptRow
	for rows.Next() {
		var p promptRow
		var projDir sql.NullString
		if err := rows.Scan(&p.ID, &p.Timestamp, &p.SessionID, &p.Prompt, &projDir); err != nil {
			continue
		}
		p.ProjectDir = nullStr(projDir)
		prompts = append(prompts, p)
	}

	if *ff.asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(prompts)
		return
	}

	if len(prompts) == 0 {
		fmt.Println("No prompts found.")
		return
	}

	fmt.Printf("%-4s  %-20s  %-16s  %s\n", "ID", "TIMESTAMP", "SESSION", "PROMPT")
	fmt.Println(strings.Repeat("─", 100))
	for _, p := range prompts {
		ts := formatTimestamp(p.Timestamp)
		sess := truncate(p.SessionID, 16)
		prompt := truncate(p.Prompt, 55)
		fmt.Printf("%-4d  %-20s  %-16s  %s\n", p.ID, ts, sess, prompt)
	}
	fmt.Printf("\nTotal: %d prompts\n", len(prompts))
}
