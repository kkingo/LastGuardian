package main

import (
	"claude-guard/internal/identity"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const sessionsDir = "sessions"

// getSessionID delegates to the shared identity package.
func getSessionID() string {
	return identity.GetSessionID()
}

// computeCacheKey computes a SHA-256 hash of the command + project directory.
func computeCacheKey(rawCommand string, projectDir string) string {
	data := rawCommand + "\x00" + projectDir
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// newSessionCache creates an empty session cache with the given ID.
func newSessionCache(sid string) *SessionCache {
	return &SessionCache{
		SessionID: sid,
		ParentPID: os.Getppid(),
		CreatedAt: time.Now().Format(time.RFC3339),
		Entries:   make(map[string]CacheEntry),
	}
}

// loadSessionCache loads the session cache for the current session.
// Returns a new empty cache if the file doesn't exist or the session has expired.
func loadSessionCache(dataDir string) *SessionCache {
	sid := getSessionID()
	path := filepath.Join(dataDir, sessionsDir, sid+".json")

	data, err := os.ReadFile(path)
	if err != nil {
		return newSessionCache(sid)
	}

	var cache SessionCache
	if json.Unmarshal(data, &cache) != nil {
		return newSessionCache(sid)
	}

	// Verify parent process is still alive
	if !isProcessAlive(cache.ParentPID) {
		_ = os.Remove(path) // clean up stale session
		return newSessionCache(sid)
	}

	return &cache
}

// lookupCache queries the cache for a decision. Returns (hit, decision).
func lookupCache(cache *SessionCache, cacheKey string) (bool, string) {
	entry, ok := cache.Entries[cacheKey]
	if !ok {
		return false, ""
	}
	return true, entry.Decision
}

// updateCache writes a new entry to the cache and persists it.
func updateCache(cache *SessionCache, dataDir string, cacheKey string, entry CacheEntry) {
	cache.Entries[cacheKey] = entry
	saveSessionCache(cache, dataDir)
}

// saveSessionCache atomically writes the cache to disk (write-to-temp + rename).
func saveSessionCache(cache *SessionCache, dataDir string) {
	dir := filepath.Join(dataDir, sessionsDir)
	_ = os.MkdirAll(dir, 0700)

	path := filepath.Join(dir, cache.SessionID+".json")
	tmpPath := path + ".tmp"

	data, _ := json.MarshalIndent(cache, "", "  ")
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return
	}
	_ = os.Rename(tmpPath, path) // atomic replace
}

// cleanStaleSessions removes cache files for sessions whose parent process has exited.
func cleanStaleSessions(dataDir string) {
	dir := filepath.Join(dataDir, sessionsDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cache SessionCache
		if json.Unmarshal(data, &cache) != nil {
			_ = os.Remove(path) // corrupted → clean up
			continue
		}
		if !isProcessAlive(cache.ParentPID) {
			_ = os.Remove(path) // parent exited → clean up
		}
	}
}

// isProcessAlive checks if a process with the given PID is still running.
func isProcessAlive(pid int) bool {
	if runtime.GOOS == "windows" {
		return checkWindowsProcessAlive(pid)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// checkWindowsProcessAlive uses Windows API to check if a process is alive.
func checkWindowsProcessAlive(pid int) bool {
	const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	const STILL_ACTIVE = 259

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	openProcess := kernel32.NewProc("OpenProcess")
	getExitCodeProcess := kernel32.NewProc("GetExitCodeProcess")

	handle, _, _ := openProcess.Call(
		uintptr(PROCESS_QUERY_LIMITED_INFORMATION),
		0,
		uintptr(pid),
	)
	if handle == 0 {
		return false
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	var exitCode uint32
	ret, _, _ := getExitCodeProcess.Call(handle, uintptr(unsafe.Pointer(&exitCode)))
	if ret == 0 {
		return false
	}
	return exitCode == STILL_ACTIVE
}

// getProcessStartTime delegates to the shared identity package.
func getProcessStartTime(pid int) string {
	return identity.GetProcessStartTime(pid)
}

// decisionStr converts a boolean allow/deny to string.
func decisionStr(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}
