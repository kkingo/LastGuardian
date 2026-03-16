// prompt-logger captures user prompts from UserPromptSubmit hook
// and stores them in history.db for session-aware reporting.
package main

import (
	"claude-guard/internal/identity"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

const maxPromptLen = 500

type promptInput struct {
	Prompt string `json:"prompt"`
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			os.Exit(0)
		}
	}()

	data, err := io.ReadAll(os.Stdin)
	if err != nil || len(data) == 0 {
		os.Exit(0)
	}

	var input promptInput
	if json.Unmarshal(data, &input) != nil || input.Prompt == "" {
		os.Exit(0)
	}

	// Skip very short prompts (greetings, confirmations)
	if utf8.RuneCountInString(input.Prompt) < 5 {
		os.Exit(0)
	}

	// Truncate long prompts
	prompt := truncateRunes(input.Prompt, maxPromptLen)

	sessionID := identity.GetSessionID()
	projectDir := identity.GetProjectDir()

	// Open database
	home, err := os.UserHomeDir()
	if err != nil {
		os.Exit(0)
	}
	dbPath := filepath.Join(home, ".claude", "hooks", "data", "history.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)")
	if err != nil {
		os.Exit(0)
	}
	defer db.Close()

	// Ensure prompts table exists
	db.Exec(`CREATE TABLE IF NOT EXISTS prompts (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp   TEXT    NOT NULL,
		session_id  TEXT    NOT NULL,
		prompt      TEXT    NOT NULL,
		project_dir TEXT
	)`)

	// Insert prompt
	db.Exec(`INSERT INTO prompts (timestamp, session_id, prompt, project_dir)
	         VALUES (?, ?, ?, ?)`,
		time.Now().Format(time.RFC3339),
		sessionID,
		prompt,
		projectDir,
	)

	os.Exit(0)
}

// truncateRunes truncates a string to maxRunes runes, appending "..." if truncated.
func truncateRunes(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes-3]) + "..."
}
