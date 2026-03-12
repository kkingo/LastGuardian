package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// pathFieldMap maps tool names to their path field in tool_input.
var pathFieldMap = map[string]string{
	"Read":  "file_path",
	"Edit":  "file_path",
	"Write": "file_path",
	"Glob":  "path",
	"Grep":  "path",
}

// isFileTool returns true if the tool name is a file-based tool.
func isFileTool(name string) bool {
	_, ok := pathFieldMap[name]
	return ok
}

// isAbsolutePath checks if a path is absolute (Unix or Windows style).
func isAbsolutePath(arg string) bool {
	if strings.HasPrefix(arg, "/") {
		return true
	}
	// Windows: C:\ or C:/
	if len(arg) >= 3 && arg[1] == ':' && (arg[2] == '/' || arg[2] == '\\') {
		return true
	}
	return false
}

// convertGitBashPath converts Git Bash style paths (/c/Users/...) to Windows
// native paths (C:\Users\...). On non-Windows or if the path doesn't match
// the pattern, it returns the path unchanged.
func convertGitBashPath(path string) string {
	if runtime.GOOS != "windows" {
		return path
	}
	// Match /c/... or /C/... where c is a single drive letter
	if len(path) >= 3 && path[0] == '/' &&
		((path[1] >= 'a' && path[1] <= 'z') || (path[1] >= 'A' && path[1] <= 'Z')) &&
		path[2] == '/' {
		return strings.ToUpper(string(path[1])) + ":" + filepath.FromSlash(path[2:])
	}
	// Also match /c at end (bare drive root)
	if len(path) == 2 && path[0] == '/' &&
		((path[1] >= 'a' && path[1] <= 'z') || (path[1] >= 'A' && path[1] <= 'Z')) {
		return strings.ToUpper(string(path[1])) + `:\`
	}
	return path
}

// toAbsNormalized resolves a path to an absolute, normalized form.
func toAbsNormalized(path, baseDir string) string {
	// Convert Git Bash paths (/c/Users/...) to Windows native (C:\Users\...)
	path = convertGitBashPath(path)
	baseDir = convertGitBashPath(baseDir)

	if !filepath.IsAbs(path) && !isAbsolutePath(path) {
		path = filepath.Join(baseDir, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return abs
}

// isOutsideProject checks if a path is outside the project directory
// and all allowed directories.
func isOutsideProject(path, projectDir string, cfg *GuardConfig) bool {
	absPath := toAbsNormalized(path, projectDir)
	lower := strings.ToLower(filepath.Clean(absPath))

	// Check project directory
	projLower := strings.ToLower(filepath.Clean(toAbsNormalized(projectDir, "")))
	if lower == projLower || strings.HasPrefix(lower, projLower+string(os.PathSeparator)) {
		return false
	}

	// Check built-in allowed directories
	home, _ := os.UserHomeDir()
	builtinAllowed := []string{
		filepath.Join(home, ".claude"),
	}

	for _, allowed := range builtinAllowed {
		allowedLower := strings.ToLower(filepath.Clean(allowed))
		if lower == allowedLower || strings.HasPrefix(lower, allowedLower+string(os.PathSeparator)) {
			return false
		}
	}

	// Check user-configured allowed directories
	if cfg != nil {
		for _, allowed := range cfg.AllowedDirs {
			allowedLower := strings.ToLower(filepath.Clean(allowed))
			if lower == allowedLower || strings.HasPrefix(lower, allowedLower+string(os.PathSeparator)) {
				return false
			}
		}
	}

	return true
}

// extractPaths extracts path-like arguments from command parts.
// Returns arguments that are absolute paths or contain "..".
func extractPaths(parts []string) []string {
	var paths []string
	for i, arg := range parts {
		if i == 0 {
			continue // skip command name
		}
		if strings.HasPrefix(arg, "-") {
			continue // skip flags
		}
		if isAbsolutePath(arg) || strings.Contains(arg, "..") {
			paths = append(paths, arg)
		}
	}
	return paths
}

// pathsInProject checks if all path arguments are within the project directory.
// Returns (ok, offendingPath).
func pathsInProject(parts []string, projectDir string) (bool, string) {
	proj := strings.ToLower(filepath.Clean(toAbsNormalized(projectDir, "")))
	for _, arg := range parts[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		needCheck := false
		if isAbsolutePath(arg) {
			needCheck = true
		} else if strings.Contains(arg, "..") {
			needCheck = true
		}
		if needCheck {
			p := strings.ToLower(filepath.Clean(toAbsNormalized(arg, projectDir)))
			if p != proj && !strings.HasPrefix(p, proj+string(os.PathSeparator)) {
				return false, arg
			}
		}
	}
	return true, ""
}

// checkPathBoundary checks all embedded paths in command parts
// for boundary violations. Returns paths that are outside project.
func checkPathBoundary(parts []string, projectDir string, cfg *GuardConfig) []string {
	var outside []string
	paths := extractPaths(parts)
	for _, p := range paths {
		absPath := toAbsNormalized(p, projectDir)
		if isOutsideProject(absPath, projectDir, cfg) {
			outside = append(outside, absPath)
		}
	}
	return outside
}
