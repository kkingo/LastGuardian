// Package identity provides shared session ID and project directory resolution
// used by both guard.exe and prompt-logger.exe.
package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// GetSessionID finds the Claude Code session ID by looking up the
// ~/.claude/sessions/ directory for a live session file whose PID
// is an ancestor of the current process.
// Falls back to the legacy PPID-based ID if no session file is found.
func GetSessionID() string {
	if sid := findClaudeSessionID(); sid != "" {
		return sid
	}
	// Fallback: legacy PPID-based ID
	ppid := os.Getppid()
	startTime := GetProcessStartTime(ppid)
	raw := fmt.Sprintf("%d_%s", ppid, startTime)
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%d_%s", ppid, hex.EncodeToString(h[:4]))
}

// findClaudeSessionID scans ~/.claude/sessions/*.json for an active session
// whose PID is an ancestor of this process, and returns its sessionId.
func findClaudeSessionID() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	sessDir := filepath.Join(home, ".claude", "sessions")
	entries, err := os.ReadDir(sessDir)
	if err != nil {
		return ""
	}

	// Collect ancestor PIDs (walk up the process tree)
	ancestors := getAncestorPIDs()

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		// Extract PID from filename (e.g., "27240.json" → 27240)
		name := strings.TrimSuffix(e.Name(), ".json")
		pid, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		// Check if this PID is an ancestor of the current process
		if _, ok := ancestors[pid]; !ok {
			continue
		}
		// Read session file to get sessionId
		data, err := os.ReadFile(filepath.Join(sessDir, e.Name()))
		if err != nil {
			continue
		}
		var sess struct {
			PID       int    `json:"pid"`
			SessionID string `json:"sessionId"`
		}
		if json.Unmarshal(data, &sess) != nil || sess.SessionID == "" {
			continue
		}
		return sess.SessionID
	}
	return ""
}

// getAncestorPIDs returns a set of PIDs that are ancestors of the current process.
func getAncestorPIDs() map[int]bool {
	ancestors := make(map[int]bool)
	pid := os.Getpid()
	for i := 0; i < 20; i++ { // max depth to avoid infinite loops
		ppid := getParentPID(pid)
		if ppid <= 1 || ppid == pid {
			break
		}
		ancestors[ppid] = true
		pid = ppid
	}
	return ancestors
}

// GetProjectDir resolves the project directory from environment or CWD.
func GetProjectDir() string {
	if dir := os.Getenv("CLAUDE_PROJECT_DIR"); dir != "" {
		return dir
	}
	dir, _ := os.Getwd()
	return dir
}

// GetProcessStartTime returns a string representation of the process start time.
func GetProcessStartTime(pid int) string {
	if runtime.GOOS == "windows" {
		return getWindowsProcessStartTime(pid)
	}
	// Unix fallback: read /proc/<pid>/stat
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	n := 64
	if len(data) < n {
		n = len(data)
	}
	return string(data[:n])
}

// getParentPID returns the parent PID of the given process.
func getParentPID(pid int) int {
	if runtime.GOOS == "windows" {
		return getWindowsParentPID(pid)
	}
	// Unix: read /proc/<pid>/stat
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	// Format: pid (comm) state ppid ...
	s := string(data)
	// Find the closing paren of comm field
	idx := strings.LastIndex(s, ")")
	if idx < 0 || idx+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[idx+2:])
	if len(fields) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}

// getWindowsParentPID uses NtQueryInformationProcess to get the parent PID.
func getWindowsParentPID(pid int) int {
	const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	openProcess := kernel32.NewProc("OpenProcess")
	ntQueryInfo := ntdll.NewProc("NtQueryInformationProcess")

	handle, _, _ := openProcess.Call(
		uintptr(PROCESS_QUERY_LIMITED_INFORMATION), 0, uintptr(pid),
	)
	if handle == 0 {
		return 0
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	// PROCESS_BASIC_INFORMATION struct (64-bit)
	type processBasicInfo struct {
		Reserved1       uintptr
		PebBaseAddress  uintptr
		Reserved2       [2]uintptr
		UniqueProcessId uintptr
		ParentProcessId uintptr
	}
	var info processBasicInfo
	var returnLen uint32
	ret, _, _ := ntQueryInfo.Call(
		handle, 0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Sizeof(info)),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if ret != 0 {
		return 0
	}
	return int(info.ParentProcessId)
}

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
