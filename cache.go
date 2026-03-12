package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const sessionsDir = "sessions"

// getSessionID creates a unique session identifier based on parent PID
// and process start time to avoid PID reuse collisions.
func getSessionID() string {
	ppid := os.Getppid()
	startTime := getProcessStartTime(ppid)
	raw := fmt.Sprintf("%d_%s", ppid, startTime)
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%d_%s", ppid, hex.EncodeToString(h[:4]))
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

// getProcessStartTime returns a string representation of the process start time.
// On Windows, uses the process creation time from the kernel.
// Falls back to empty string if unavailable.
func getProcessStartTime(pid int) string {
	if runtime.GOOS == "windows" {
		return getWindowsProcessStartTime(pid)
	}
	// Unix fallback: read /proc/<pid>/stat
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	return string(data[:min(64, len(data))])
}

// getWindowsProcessStartTime uses Windows API to get process creation time.
func getWindowsProcessStartTime(pid int) string {
	const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	openProcess := kernel32.NewProc("OpenProcess")
	getProcessTimes := kernel32.NewProc("GetProcessTimes")

	handle, _, _ := openProcess.Call(
		uintptr(PROCESS_QUERY_LIMITED_INFORMATION),
		0,
		uintptr(pid),
	)
	if handle == 0 {
		return ""
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	var creation, exit, kernel, user syscall.Filetime
	ret, _, _ := getProcessTimes.Call(
		handle,
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if ret == 0 {
		return ""
	}
	t := time.Unix(0, creation.Nanoseconds())
	return t.Format(time.RFC3339Nano)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// decisionStr converts a boolean allow/deny to string.
func decisionStr(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}
