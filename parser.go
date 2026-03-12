package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// splitCommand splits a command string by &&, ||, ;, | into independent sub-commands.
var splitRe = regexp.MustCompile(`\s*(?:&&|\|\||[;|])\s*`)

func splitCommand(command string) []string {
	parts := splitRe.Split(command, -1)
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// shellSplit performs POSIX-like shell word splitting.
// Handles single quotes, double quotes, and backslash escapes.
func shellSplit(s string) []string {
	const (
		stNormal   = iota
		stSingle   // inside single quotes
		stDouble   // inside double quotes
		stEscape   // backslash escape in normal mode
		stDblEsc   // backslash escape in double quotes
	)

	var tokens []string
	var cur strings.Builder
	state := stNormal

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch state {
		case stNormal:
			switch c {
			case ' ', '\t', '\n', '\r':
				if cur.Len() > 0 {
					tokens = append(tokens, cur.String())
					cur.Reset()
				}
			case '\'':
				state = stSingle
			case '"':
				state = stDouble
			case '\\':
				if i+1 < len(s) {
					i++
					cur.WriteByte(s[i])
				}
			default:
				cur.WriteByte(c)
			}
		case stSingle:
			if c == '\'' {
				state = stNormal
			} else {
				cur.WriteByte(c)
			}
		case stDouble:
			switch c {
			case '"':
				state = stNormal
			case '\\':
				if i+1 < len(s) {
					i++
					cur.WriteByte(s[i])
				}
			default:
				cur.WriteByte(c)
			}
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// normalizeCmdName extracts the base command name, lowercases it,
// and strips known extensions (.exe, .cmd, .bat, .com, .ps1).
func normalizeCmdName(name string) string {
	base := filepath.Base(name)
	base = strings.ToLower(base)
	for _, ext := range []string{".exe", ".cmd", ".bat", ".com", ".ps1"} {
		if strings.HasSuffix(base, ext) {
			base = base[:len(base)-len(ext)]
			break
		}
	}
	return base
}

// getFirstNonFlag returns the first argument starting from index start
// that does not begin with "-".
func getFirstNonFlag(parts []string, start int) string {
	for i := start; i < len(parts); i++ {
		if !strings.HasPrefix(parts[i], "-") {
			return parts[i]
		}
	}
	return ""
}

// hasFlag checks if parts contains a specific flag.
func hasFlag(parts []string, flag string) bool {
	for _, p := range parts {
		if p == flag {
			return true
		}
	}
	return false
}

// hasAnyFlag checks if parts contains any of the given flags.
func hasAnyFlag(parts []string, flags ...string) bool {
	for _, p := range parts {
		for _, f := range flags {
			if p == f {
				return true
			}
		}
	}
	return false
}

// containsAfter checks if val appears in parts after index start.
func containsAfter(parts []string, val string, start int) bool {
	for i := start; i < len(parts); i++ {
		if parts[i] == val {
			return true
		}
	}
	return false
}

// contains checks if parts contains val.
func contains(parts []string, val string) bool {
	for _, p := range parts {
		if p == val {
			return true
		}
	}
	return false
}

// containsAll checks if parts contains all given values.
func containsAll(parts []string, vals ...string) bool {
	for _, v := range vals {
		if !contains(parts, v) {
			return false
		}
	}
	return true
}

// anyFlagContains checks if any flag-like argument (starting with "-") contains char.
func anyFlagContains(parts []string, char string) bool {
	for _, p := range parts[1:] {
		if strings.HasPrefix(p, "-") && strings.Contains(p, char) {
			return true
		}
	}
	return false
}

// isOneOf checks if val matches any of the given options.
func isOneOf(val string, options ...string) bool {
	for _, o := range options {
		if val == o {
			return true
		}
	}
	return false
}

// inVirtualEnv checks if a Python virtual environment is active.
func inVirtualEnv() bool {
	return os.Getenv("VIRTUAL_ENV") != "" || os.Getenv("CONDA_DEFAULT_ENV") != ""
}
