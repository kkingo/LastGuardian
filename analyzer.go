package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// interpreters maps interpreter commands to the flags that indicate inline code execution.
var interpreters = map[string][]string{
	"python": {"-c"}, "python3": {"-c"},
	"bash": {"-c"}, "sh": {"-c"}, "zsh": {"-c"},
	"node": {"-e"}, "perl": {"-e"}, "ruby": {"-e"},
}

var redirectPattern = regexp.MustCompile(`(?:>>?|2>&1|2>|&>)`)

// buildApprovalSummary performs deep analysis on a command and builds an ApprovalSummary.
func buildApprovalSummary(
	operationType string,
	rawCommand string,
	parts []string,
	projectDir string,
	triggeredLayers []string,
	cfg *GuardConfig,
) ApprovalSummary {
	summary := ApprovalSummary{
		OperationType:   operationType,
		TriggeredLayers: triggeredLayers,
		CommandPreview:  rawCommand,
		Timestamp:       time.Now().Format(time.RFC3339),
	}

	// 1. Detect interpreter wrap
	if len(parts) > 0 {
		base := normalizeCmdName(parts[0])
		if flags, ok := interpreters[base]; ok {
			for _, f := range flags {
				if hasFlag(parts, f) {
					summary.HasInterpreterWrap = true
					break
				}
			}
		}
	}

	// 2. Detect redirection
	summary.HasRedirection = redirectPattern.MatchString(rawCommand)

	// 3. Detect pipe
	summary.HasPipe = strings.Contains(rawCommand, "|")

	// 4. Extract target paths (absolute form)
	if len(parts) > 1 {
		for _, arg := range parts[1:] {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if isAbsolutePath(arg) || strings.Contains(arg, "..") {
				absPath := toAbsNormalized(arg, projectDir)
				summary.TargetPaths = append(summary.TargetPaths, absPath)
				if isOutsideProject(absPath, projectDir, cfg) {
					summary.IsOutOfBoundary = true
				}
			}
		}
	}

	// 5. Extract remote host (network commands only)
	if len(parts) > 0 {
		base := normalizeCmdName(parts[0])
		if _, ok := networkAuth[base]; ok {
			for _, arg := range parts[1:] {
				if strings.HasPrefix(arg, "-") {
					continue
				}
				if strings.Contains(arg, "@") || isHostLike(arg) {
					summary.RemoteHost = arg
					break
				}
			}
		}
	}

	// 6. Evaluate risk level
	summary.RiskLevel = evaluateRiskLevel(summary, cfg)

	// 7. Compute request hash (SHA-256)
	h := sha256.Sum256([]byte(rawCommand))
	summary.RequestHash = hex.EncodeToString(h[:])

	// 8. Write detail file
	summary.DetailFile = writeDetailFile(summary)

	return summary
}

// evaluateRiskLevel computes the risk level based on weighted scoring.
func evaluateRiskLevel(s ApprovalSummary, cfg *GuardConfig) string {
	// Default weights
	weights := map[string]int{
		"interpreter_wrap": 2,
		"redirection":      1,
		"pipe":             1,
		"out_of_boundary":  2,
		"multi_path":       1,
	}
	critThreshold := 5
	highThreshold := 3

	// Override from config if available
	if cfg != nil && cfg.RiskScoring.Weights != nil {
		for k, v := range cfg.RiskScoring.Weights {
			weights[k] = v
		}
		if cfg.RiskScoring.CriticalThreshold > 0 {
			critThreshold = cfg.RiskScoring.CriticalThreshold
		}
		if cfg.RiskScoring.HighThreshold > 0 {
			highThreshold = cfg.RiskScoring.HighThreshold
		}
	}

	score := 0

	// Base score by operation type
	switch s.OperationType {
	case "File deletion", "File Deletion", "Directory deletion", "Directory Deletion":
		score += 2
	case "Network access", "Network Access", "Network transfer", "Network Transfer":
		score += 1
	case "Path Boundary", "Path outside project":
		score += 1
	default:
		if strings.Contains(strings.ToLower(s.OperationType), "delet") {
			score += 2
		} else {
			score += 1
		}
	}

	// Risk factor scores
	if s.HasInterpreterWrap {
		score += weights["interpreter_wrap"]
	}
	if s.HasRedirection {
		score += weights["redirection"]
	}
	if s.HasPipe {
		score += weights["pipe"]
	}
	if s.IsOutOfBoundary {
		score += weights["out_of_boundary"]
	}
	if len(s.TargetPaths) > 3 {
		score += weights["multi_path"]
	}

	switch {
	case score >= critThreshold:
		return "CRITICAL"
	case score >= highThreshold:
		return "HIGH"
	default:
		return "MEDIUM"
	}
}

// writeDetailFile writes the full ApprovalSummary to a JSON file in the temp directory.
func writeDetailFile(s ApprovalSummary) string {
	dir := filepath.Join(os.TempDir(), "claude-guard")
	_ = os.MkdirAll(dir, 0700)

	hashPrefix := s.RequestHash
	if len(hashPrefix) > 8 {
		hashPrefix = hashPrefix[:8]
	}

	filename := fmt.Sprintf("approval_%s_%s.json",
		time.Now().Format("20060102_150405"),
		hashPrefix)
	path := filepath.Join(dir, filename)

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return ""
	}
	_ = os.WriteFile(path, data, 0600)
	return path
}

// isHostLike checks if a string looks like a hostname or IP address.
func isHostLike(s string) bool {
	return strings.Contains(s, ".") && !strings.ContainsAny(s, `/\`)
}

// boolMark returns a human-readable risk indicator.
func boolMark(b bool) string {
	if b {
		return "YES"
	}
	return "No"
}

// psEscape escapes a string for use in a PowerShell single-quoted string.
func psEscape(s string) string {
	s = strings.ReplaceAll(s, "'", "''")
	s = strings.ReplaceAll(s, "`", "``")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
