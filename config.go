package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// defaultConfig returns the built-in default configuration.
func defaultConfig() GuardConfig {
	return GuardConfig{
		Version: 1,
		DataDir: "~/.claude/hooks/data",
		SessionCache: SessionCacheCfg{
			Enabled:   true,
			MatchMode: "exact_hash",
		},
		History: HistoryCfg{
			Enabled:       true,
			RetentionDays: 90,
		},
		Dialog: DialogCfg{
			TimeoutSeconds: 60,
			Platform:       "auto",
		},
		RiskScoring: RiskScoringCfg{
			CriticalThreshold: 5,
			HighThreshold:     3,
			Weights: map[string]int{
				"interpreter_wrap": 2,
				"redirection":      1,
				"pipe":             1,
				"out_of_boundary":  2,
				"multi_path":       1,
			},
		},
	}
}

// loadConfig loads configuration from file, falling back to defaults.
func loadConfig() GuardConfig {
	cfg := defaultConfig()

	// 1. Check environment variable for config path
	configPath := os.Getenv("GUARD_CONFIG_PATH")
	if configPath == "" {
		home, _ := os.UserHomeDir()
		configPath = filepath.Join(home, ".claude", "hooks", "guard-config.json")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		// Config file does not exist → use all defaults
		cfg.DataDir = expandHome(cfg.DataDir)
		return cfg
	}

	// 2. Unmarshal onto default config (only overrides specified fields)
	_ = json.Unmarshal(data, &cfg)

	// 3. Expand ~ in paths
	cfg.DataDir = expandHome(cfg.DataDir)
	for i, d := range cfg.AllowedDirs {
		cfg.AllowedDirs[i] = expandHome(d)
	}

	return cfg
}

// expandHome replaces a leading ~ with the user's home directory.
func expandHome(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	if len(path) > 1 && (path[1] == '/' || path[1] == '\\') {
		return filepath.Join(home, path[2:])
	}
	return path
}

// resolveProjectDir determines the project directory from available sources.
func resolveProjectDir(p Payload) string {
	if dir := os.Getenv("CLAUDE_PROJECT_DIR"); dir != "" {
		return dir
	}
	if p.Cwd != "" {
		return p.Cwd
	}
	dir, _ := os.Getwd()
	return dir
}
