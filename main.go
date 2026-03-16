package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Global state initialized in main
var (
	cfg    GuardConfig
	dialog DialogProvider
)

func main() {
	// Top-level recover: any panic → exit 0 (fail-open, never block legitimate operations)
	defer func() {
		if r := recover(); r != nil {
			os.Exit(0)
		}
	}()

	// Load configuration
	cfg = loadConfig()

	// Initialize dialog provider
	dialog = newDialogProvider(cfg.Dialog)

	// Initialize history database (if enabled)
	if cfg.History.Enabled {
		if err := initHistoryDB(cfg.DataDir); err == nil {
			defer closeHistoryDB()
			// Prune old records on startup
			pruneHistory(cfg.History.RetentionDays)
		}
	}

	// Clean stale session cache files on startup
	if cfg.SessionCache.Enabled {
		cleanStaleSessions(cfg.DataDir)
	}

	// Read JSON payload from stdin
	payload, err := readStdinJSON()
	if err != nil {
		os.Exit(0) // malformed input → allow
	}

	toolName := payload.ToolName
	projectDir := resolveProjectDir(payload)

	switch {
	case isFileTool(toolName):
		handleFileTool(payload, projectDir)
	case toolName == "Bash" || toolName == "":
		handleBashTool(payload, projectDir)
	default:
		// Record passthrough for unknown tools
		recordPassthrough(payload, projectDir, toolName)
		os.Exit(0)
	}

	os.Exit(0)
}

// readStdinJSON reads and parses the JSON payload from stdin.
func readStdinJSON() (Payload, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return Payload{}, err
	}
	if len(data) == 0 {
		return Payload{}, fmt.Errorf("empty input")
	}
	var p Payload
	if err := json.Unmarshal(data, &p); err != nil {
		return Payload{}, err
	}
	return p, nil
}

// blockExit outputs the reason to stderr and exits with code 2.
func blockExit(reason string) {
	fmt.Fprintln(os.Stderr, reason)
	os.Exit(2)
}

// handleFileTool processes file-based tools (Read, Edit, Write, Glob, Grep).
// Only Layer 4 (PATH_BOUNDARY) applies to file tools.
func handleFileTool(p Payload, projectDir string) {
	field := pathFieldMap[p.ToolName]
	path := p.ToolInput[field]
	if path == "" {
		recordPassthrough(p, projectDir, p.ToolName)
		return // no path specified → allow
	}

	toolDesc := p.ToolInput["description"]
	absPath := toAbsNormalized(path, projectDir)

	// Layer 2: Critical path write protection (Edit/Write only)
	if isWriteTool(p.ToolName) {
		if hit, desc := checkCriticalPath(absPath, &cfg); hit {
			sid := getSessionID()
			if cfg.Mode == "silent" {
				recordHistory(HistoryRecord{
					Timestamp:       time.Now().Format(time.RFC3339),
					SessionID:       sid,
					ToolName:        p.ToolName,
					RawCommand:      absPath,
					NormalizedCmd:   p.ToolName,
					TriggeredLayers: `["Layer 2: CRITICAL_PROTECTED (path)"]`,
					AuthRequired:    true,
					UserDecision:    "auto-deny",
					FinalAction:     "block",
					ProjectDir:      projectDir,
				})
				blockExit(desc + " - auto-denied (silent mode)")
			}
			// Interactive mode: show dialog
			summary := buildApprovalSummary(desc, fmt.Sprintf("%s(%s)", p.ToolName, absPath),
				[]string{p.ToolName, absPath}, projectDir,
				[]string{"Layer 2: CRITICAL_PROTECTED (path)"}, &cfg)
			summary.SessionID = sid
			summary.ProjectDir = projectDir
			summary.ToolDescription = toolDesc
			if !dialog.RequestApproval(summary) {
				recordHistory(HistoryRecord{
					Timestamp:       time.Now().Format(time.RFC3339),
					SessionID:       sid,
					ToolName:        p.ToolName,
					RawCommand:      absPath,
					NormalizedCmd:   p.ToolName,
					TriggeredLayers: `["Layer 2: CRITICAL_PROTECTED (path)"]`,
					AuthRequired:    true,
					UserDecision:    "deny",
					FinalAction:     "block",
					ProjectDir:      projectDir,
				})
				blockExit(desc + " - denied by user")
			}
			recordHistory(HistoryRecord{
				Timestamp:       time.Now().Format(time.RFC3339),
				SessionID:       sid,
				ToolName:        p.ToolName,
				RawCommand:      absPath,
				NormalizedCmd:   p.ToolName,
				TriggeredLayers: `["Layer 2: CRITICAL_PROTECTED (path)"]`,
				AuthRequired:    true,
				UserDecision:    "allow",
				FinalAction:     "allow",
				ProjectDir:      projectDir,
			})
			return
		}
	}

	if isOutsideProject(absPath, projectDir, &cfg) {
		// Layer 4: PATH_BOUNDARY — silent mode: auto-allow
		sid := getSessionID()
		if cfg.Mode == "silent" {
			recordHistory(HistoryRecord{
				Timestamp:       time.Now().Format(time.RFC3339),
				SessionID:       sid,
				ToolName:        p.ToolName,
				RawCommand:      absPath,
				NormalizedCmd:   p.ToolName,
				TriggeredLayers: `["Layer 4: PATH_BOUNDARY"]`,
				AuthRequired:    true,
				UserDecision:    "auto-allow",
				FinalAction:     "allow",
				ProjectDir:      projectDir,
			})
			return
		}
		summary := buildApprovalSummary(
			"Path outside project",
			fmt.Sprintf("%s(%s)", p.ToolName, absPath),
			[]string{p.ToolName, absPath},
			projectDir,
			[]string{"Layer 4: PATH_BOUNDARY"},
			&cfg,
		)
		summary.SessionID = sid
		summary.ProjectDir = projectDir
		summary.ToolDescription = toolDesc

		// Check session cache
		if cfg.SessionCache.Enabled {
			cacheKey := computeCacheKey(fmt.Sprintf("%s:%s", p.ToolName, absPath), projectDir)
			cache := loadSessionCache(cfg.DataDir)
			if cached, decision := lookupCache(cache, cacheKey); cached {
				recordHistory(HistoryRecord{
					Timestamp:       time.Now().Format(time.RFC3339),
					SessionID:       sid,
					ToolName:        p.ToolName,
					RawCommand:      absPath,
					NormalizedCmd:   p.ToolName,
					RiskLevel:       summary.RiskLevel,
					TriggeredLayers: `["Layer 4: PATH_BOUNDARY"]`,
					AuthRequired:    true,
					UserDecision:    decision,
					FinalAction:     decision,
					RequestHash:     summary.RequestHash,
					ProjectDir:      projectDir,
					CacheHit:        true,
				})
				if decision == "deny" {
					blockExit("Path boundary: access to " + absPath + " denied (cached)")
				}
				return // allow (cached)
			}

			// Cache miss → show dialog
			allowed := dialog.RequestApproval(summary)
			updateCache(cache, cfg.DataDir, cacheKey, CacheEntry{
				CommandPreview: fmt.Sprintf("%s(%s)", p.ToolName, absPath),
				RiskLevel:      summary.RiskLevel,
				Decision:       decisionStr(allowed),
				CachedAt:       time.Now().Format(time.RFC3339),
			})

			finalAction := "allow"
			userDecision := "allow"
			if !allowed {
				finalAction = "block"
				userDecision = "deny"
			}
			recordHistory(HistoryRecord{
				Timestamp:       time.Now().Format(time.RFC3339),
				SessionID:       sid,
				ToolName:        p.ToolName,
				RawCommand:      absPath,
				NormalizedCmd:   p.ToolName,
				RiskLevel:       summary.RiskLevel,
				TriggeredLayers: `["Layer 4: PATH_BOUNDARY"]`,
				AuthRequired:    true,
				UserDecision:    userDecision,
				FinalAction:     finalAction,
				RequestHash:     summary.RequestHash,
				ProjectDir:      projectDir,
				CacheHit:        false,
			})
			if !allowed {
				blockExit("Path boundary: access to " + absPath + " denied by user")
			}
			return
		}

		// No cache → just show dialog
		if !dialog.RequestApproval(summary) {
			recordHistory(HistoryRecord{
				Timestamp:       time.Now().Format(time.RFC3339),
				SessionID:       sid,
				ToolName:        p.ToolName,
				RawCommand:      absPath,
				NormalizedCmd:   p.ToolName,
				RiskLevel:       summary.RiskLevel,
				TriggeredLayers: `["Layer 4: PATH_BOUNDARY"]`,
				AuthRequired:    true,
				UserDecision:    "deny",
				FinalAction:     "block",
				RequestHash:     summary.RequestHash,
				ProjectDir:      projectDir,
			})
			blockExit("Path boundary: access to " + absPath + " denied by user")
		}
		recordHistory(HistoryRecord{
			Timestamp:       time.Now().Format(time.RFC3339),
			SessionID:       sid,
			ToolName:        p.ToolName,
			RawCommand:      absPath,
			NormalizedCmd:   p.ToolName,
			RiskLevel:       summary.RiskLevel,
			TriggeredLayers: `["Layer 4: PATH_BOUNDARY"]`,
			AuthRequired:    true,
			UserDecision:    "allow",
			FinalAction:     "allow",
			RequestHash:     summary.RequestHash,
			ProjectDir:      projectDir,
		})
		return
	}

	// Path is within project → allow
	recordPassthrough(p, projectDir, p.ToolName)
}

// handleBashTool processes Bash tool commands using two-pass scanning.
func handleBashTool(p Payload, projectDir string) {
	command := p.ToolInput["command"]
	if command == "" {
		recordPassthrough(p, projectDir, "Bash")
		return
	}

	toolDesc := p.ToolInput["description"]
	sid := getSessionID()

	// Pre-split check: pipe-to-shell pattern (flagged for Layer 3 auth below)
	pipeToShell, pipeReason := checkPipeToShell(command)

	// Split command into sub-commands
	subCommands := splitCommand(command)
	parsed := make([][]string, 0, len(subCommands))
	for _, sub := range subCommands {
		parts := shellSplit(sub)
		if len(parts) > 0 {
			parsed = append(parsed, parts)
		}
	}

	// ═══ Pass 1: Hard block scan (Layer 1 only) ═══
	for _, parts := range parsed {
		if blocked, reason := checkAlwaysBlocked(parts); blocked {
			recordHistory(HistoryRecord{
				Timestamp:       time.Now().Format(time.RFC3339),
				SessionID:       sid,
				ToolName:        "Bash",
				RawCommand:      command,
				NormalizedCmd:   normalizeCmdName(parts[0]),
				TriggeredLayers: `["Layer 1: ALWAYS_BLOCKED"]`,
				AuthRequired:    false,
				FinalAction:     "block",
				ProjectDir:      projectDir,
			})
			blockExit(reason)
		}
	}

	// ═══ Pass 2: L2 Critical + L3 Interactive + L4 Path Boundary ═══
	var cache *SessionCache
	if cfg.SessionCache.Enabled {
		cache = loadSessionCache(cfg.DataDir)
	}

	for _, parts := range parsed {
		cmdStr := strings.Join(parts, " ")

		// Layer 2a: Critical commands (npx, kill, chmod — dialog/silent-deny)
		if hit, desc := checkCriticalCommands(parts); hit {
			if !handleCriticalAuth(cache, sid, command, cmdStr, parts, projectDir, desc,
				[]string{"Layer 2: CRITICAL_PROTECTED (command)"}, toolDesc) {
				blockExit(desc + " - denied")
			}
			continue
		}

		// Layer 2b: Critical operations (git push --force, npm publish, docker destroy)
		if hit, desc := checkCriticalOps(parts); hit {
			if !handleCriticalAuth(cache, sid, command, cmdStr, parts, projectDir, desc,
				[]string{"Layer 2: CRITICAL_PROTECTED (operation)"}, toolDesc) {
				blockExit(desc + " - denied")
			}
			continue
		}
	}

	// Layer 3 pre-check: pipe-to-shell pattern (raw command, before sub-command loop)
	if pipeToShell {
		if !handleInteractiveAuth(cache, sid, command, command, parsed[0], projectDir, pipeReason,
			[]string{"Layer 3: INTERACTIVE_AUTH (pipe-to-shell)"}, toolDesc) {
			blockExit(pipeReason + " - denied by user")
		}
	}

	for _, parts := range parsed {
		cmdStr := strings.Join(parts, " ")

		// Layer 3a: Git remote modification
		if hit, desc := checkGitRemoteAuth(parts); hit {
			if !handleInteractiveAuth(cache, sid, command, cmdStr, parts, projectDir, desc,
				[]string{"Layer 3: INTERACTIVE_AUTH (git-remote)"}, toolDesc) {
				blockExit(desc + " - denied by user")
			}
			continue
		}

		// Layer 3b: Network commands
		if hit, desc := checkNetworkAuth(parts); hit {
			if !handleInteractiveAuth(cache, sid, command, cmdStr, parts, projectDir, desc,
				[]string{"Layer 3: INTERACTIVE_AUTH (network)"}, toolDesc) {
				blockExit(desc + " - denied by user")
			}
			continue
		}

		// Layer 3d: Global install commands
		if hit, desc := checkGlobalInstallAuth(parts); hit {
			if !handleInteractiveAuth(cache, sid, command, cmdStr, parts, projectDir, desc,
				[]string{"Layer 3: INTERACTIVE_AUTH (global-install)"}, toolDesc) {
				blockExit(desc + " - denied by user")
			}
			continue
		}

		// Layer 3e: Dangerous operations (local-destructive, recoverable)
		if hit, desc := checkDangerousOpsAuth(parts, projectDir); hit {
			if !handleInteractiveAuth(cache, sid, command, cmdStr, parts, projectDir, desc,
				[]string{"Layer 3: INTERACTIVE_AUTH (dangerous-ops)"}, toolDesc) {
				blockExit(desc + " - denied by user")
			}
			continue
		}

		// Layer 3c: Path-sensitive commands (rm/rmdir)
		if hit, desc := checkPathSensitiveAuth(parts, projectDir); hit {
			if !handleInteractiveAuth(cache, sid, command, cmdStr, parts, projectDir, desc,
				[]string{"Layer 3: INTERACTIVE_AUTH (path-sensitive)"}, toolDesc) {
				blockExit(desc + " - denied by user")
			}
			continue
		}

		// Layer 4: Path boundary
		outsidePaths := checkPathBoundary(parts, projectDir, &cfg)
		for _, p := range outsidePaths {
			desc := "Path outside project: " + p
			if !handleInteractiveAuth(cache, sid, command, cmdStr, parts, projectDir, desc,
				[]string{"Layer 4: PATH_BOUNDARY"}, toolDesc) {
				blockExit("Path boundary: " + p + " denied by user")
			}
		}
	}

	// All passed → record and allow
	recordHistory(HistoryRecord{
		Timestamp:   time.Now().Format(time.RFC3339),
		SessionID:   sid,
		ToolName:    "Bash",
		RawCommand:  command,
		FinalAction: "allow",
		ProjectDir:  projectDir,
	})
}

// handleCriticalAuth handles L2 CRITICAL_PROTECTED authorization.
// Interactive mode: show dialog. Silent mode: auto-deny.
func handleCriticalAuth(
	cache *SessionCache,
	sessionID string,
	fullCommand string,
	cmdStr string,
	parts []string,
	projectDir string,
	desc string,
	layers []string,
	toolDescription string,
) bool {
	if cfg.Mode == "silent" {
		// Silent mode: auto-deny L2 operations
		recordHistory(HistoryRecord{
			Timestamp:       time.Now().Format(time.RFC3339),
			SessionID:       sessionID,
			ToolName:        "Bash",
			RawCommand:      fullCommand,
			NormalizedCmd:   normalizeCmdName(parts[0]),
			TriggeredLayers: toJSON(layers),
			AuthRequired:    true,
			UserDecision:    "auto-deny",
			FinalAction:     "block",
			ProjectDir:      projectDir,
		})
		return false
	}
	// Interactive mode: delegate to interactive auth (show dialog)
	return handleInteractiveAuth(cache, sessionID, fullCommand, cmdStr, parts, projectDir, desc, layers, toolDescription)
}

// handleInteractiveAuth handles L3 INTERACTIVE_AUTH authorization.
// Interactive mode: show dialog. Silent mode: auto-allow.
// Returns true if allowed, false if denied.
func handleInteractiveAuth(
	cache *SessionCache,
	sessionID string,
	fullCommand string,
	cmdStr string,
	parts []string,
	projectDir string,
	desc string,
	layers []string,
	toolDescription string,
) bool {
	// Silent mode: auto-allow L3 operations
	if cfg.Mode == "silent" {
		recordHistory(HistoryRecord{
			Timestamp:       time.Now().Format(time.RFC3339),
			SessionID:       sessionID,
			ToolName:        "Bash",
			RawCommand:      fullCommand,
			NormalizedCmd:   normalizeCmdName(parts[0]),
			TriggeredLayers: toJSON(layers),
			AuthRequired:    true,
			UserDecision:    "auto-allow",
			FinalAction:     "allow",
			ProjectDir:      projectDir,
		})
		return true
	}

	cacheKey := computeCacheKey(cmdStr, projectDir)

	// Check session cache first
	if cache != nil {
		if cached, decision := lookupCache(cache, cacheKey); cached {
			recordHistory(HistoryRecord{
				Timestamp:       time.Now().Format(time.RFC3339),
				SessionID:       sessionID,
				ToolName:        "Bash",
				RawCommand:      fullCommand,
				NormalizedCmd:   normalizeCmdName(parts[0]),
				TriggeredLayers: toJSON(layers),
				AuthRequired:    true,
				UserDecision:    decision,
				FinalAction:     decision,
				ProjectDir:      projectDir,
				CacheHit:        true,
			})
			return decision == "allow"
		}
	}

	// Cache miss → build summary and show dialog
	summary := buildApprovalSummary(desc, cmdStr, parts, projectDir, layers, &cfg)
	summary.SessionID = sessionID
	summary.ProjectDir = projectDir
	summary.ToolDescription = toolDescription
	allowed := dialog.RequestApproval(summary)

	// Write to cache
	if cache != nil {
		updateCache(cache, cfg.DataDir, cacheKey, CacheEntry{
			CommandPreview: cmdStr,
			RiskLevel:      summary.RiskLevel,
			Decision:       decisionStr(allowed),
			CachedAt:       time.Now().Format(time.RFC3339),
		})
	}

	// Record history
	finalAction := "allow"
	userDecision := "allow"
	if !allowed {
		finalAction = "block"
		userDecision = "deny"
	}
	recordHistory(HistoryRecord{
		Timestamp:       time.Now().Format(time.RFC3339),
		SessionID:       sessionID,
		ToolName:        "Bash",
		RawCommand:      fullCommand,
		NormalizedCmd:   normalizeCmdName(parts[0]),
		RiskLevel:       summary.RiskLevel,
		TriggeredLayers: toJSON(layers),
		AuthRequired:    true,
		UserDecision:    userDecision,
		FinalAction:     finalAction,
		RequestHash:     summary.RequestHash,
		ProjectDir:      projectDir,
		CacheHit:        false,
	})

	return allowed
}

// recordPassthrough records an operation that was allowed without any checks.
func recordPassthrough(p Payload, projectDir string, toolName string) {
	rawCmd := ""
	if toolName == "Bash" {
		rawCmd = p.ToolInput["command"]
	} else {
		field := pathFieldMap[toolName]
		if field != "" {
			rawCmd = p.ToolInput[field]
		}
	}
	recordHistory(HistoryRecord{
		Timestamp:   time.Now().Format(time.RFC3339),
		SessionID:   getSessionID(),
		ToolName:    toolName,
		RawCommand:  rawCmd,
		FinalAction: "allow",
		ProjectDir:  projectDir,
	})
}

// isWriteTool returns true for tools that modify file content.
func isWriteTool(toolName string) bool {
	return toolName == "Edit" || toolName == "Write"
}

// toJSON converts a string slice to a JSON array string.
func toJSON(s []string) string {
	data, err := json.Marshal(s)
	if err != nil {
		return "[]"
	}
	return string(data)
}
