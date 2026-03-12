package main

// Payload represents the JSON input from Claude Code.
type Payload struct {
	ToolName  string            `json:"tool_name"`
	ToolInput map[string]string `json:"tool_input"`
	Cwd       string            `json:"cwd"`
}

// CheckResult represents the result of a layer check.
type CheckResult struct {
	Blocked bool
	Reason  string
}

// ApprovalSummary contains structured approval information after deep analysis.
type ApprovalSummary struct {
	OperationType      string   `json:"operation_type"`
	RiskLevel          string   `json:"risk_level"`
	TriggeredLayers    []string `json:"triggered_layers"`
	CommandPreview     string   `json:"command_preview"`
	HasInterpreterWrap bool     `json:"has_interpreter_wrap"`
	HasRedirection     bool     `json:"has_redirection"`
	HasPipe            bool     `json:"has_pipe"`
	TargetPaths        []string `json:"target_paths"`
	RemoteHost         string   `json:"remote_host,omitempty"`
	IsOutOfBoundary    bool     `json:"is_out_of_boundary"`
	RequestHash        string   `json:"request_hash"`
	DetailFile         string   `json:"detail_file"`
	Timestamp          string   `json:"timestamp"`
	SessionID          string   `json:"session_id"`
	ProjectDir         string   `json:"project_dir"`
}

// CacheEntry represents a single authorization record in the session cache.
type CacheEntry struct {
	CommandPreview string `json:"command_preview"`
	RiskLevel      string `json:"risk_level"`
	Decision       string `json:"decision"`
	CachedAt       string `json:"cached_at"`
}

// SessionCache represents the session cache for a Claude Code instance.
type SessionCache struct {
	SessionID string                `json:"session_id"`
	ParentPID int                   `json:"parent_pid"`
	CreatedAt string                `json:"created_at"`
	Entries   map[string]CacheEntry `json:"entries"`
}

// HistoryRecord represents a single record in the history database.
type HistoryRecord struct {
	Timestamp       string `json:"timestamp"`
	SessionID       string `json:"session_id"`
	ToolName        string `json:"tool_name"`
	RawCommand      string `json:"raw_command"`
	NormalizedCmd   string `json:"normalized_cmd"`
	RiskLevel       string `json:"risk_level"`
	TriggeredLayers string `json:"triggered_layers"`
	AuthRequired    bool   `json:"auth_required"`
	UserDecision    string `json:"user_decision"`
	FinalAction     string `json:"final_action"`
	RequestHash     string `json:"request_hash"`
	ProjectDir      string `json:"project_dir"`
	CacheHit        bool   `json:"cache_hit"`
}

// GuardConfig represents the full guard-config.json structure.
type GuardConfig struct {
	Version      int              `json:"version"`
	DataDir      string           `json:"data_dir"`
	SessionCache SessionCacheCfg  `json:"session_cache"`
	History      HistoryCfg       `json:"history"`
	Dialog       DialogCfg        `json:"dialog"`
	RiskScoring  RiskScoringCfg   `json:"risk_scoring"`
	AllowedDirs  []string         `json:"allowed_dirs"`
	CustomRules  CustomRulesCfg   `json:"custom_rules"`
}

// SessionCacheCfg configures session cache behavior.
type SessionCacheCfg struct {
	Enabled   bool   `json:"enabled"`
	MatchMode string `json:"match_mode"`
}

// HistoryCfg configures history database behavior.
type HistoryCfg struct {
	Enabled       bool `json:"enabled"`
	RetentionDays int  `json:"retention_days"`
}

// DialogCfg configures the approval dialog.
type DialogCfg struct {
	TimeoutSeconds int    `json:"timeout_seconds"`
	Platform       string `json:"platform"`
}

// RiskScoringCfg configures risk level evaluation.
type RiskScoringCfg struct {
	CriticalThreshold int            `json:"critical_threshold"`
	HighThreshold     int            `json:"high_threshold"`
	Weights           map[string]int `json:"weights"`
}

// CustomRulesCfg allows user-defined rules without recompilation.
type CustomRulesCfg struct {
	ExtraAlwaysBlocked   []string `json:"extra_always_blocked"`
	ExtraInteractiveAuth []string `json:"extra_interactive_auth"`
	ExtraContextualRules []string `json:"extra_contextual_rules"`
}

// DialogProvider defines the platform abstraction interface for approval dialogs.
type DialogProvider interface {
	RequestApproval(summary ApprovalSummary) bool
}
