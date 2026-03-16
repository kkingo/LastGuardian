package main

import (
	"fmt"
	"regexp"
	"strings"
)

// ── Layer 1: ALWAYS_BLOCKED ──

var alwaysBlocked = map[string]string{
	// File/directory destruction
	"shred":    "File destruction blocked",
	"truncate": "File truncation blocked",

	// Permission & ownership
	"chown": "Ownership modification blocked",
	"chgrp": "Group modification blocked",

	// Privilege escalation
	"sudo":  "Privilege escalation blocked",
	"runas": "Privilege escalation blocked",
	"su":    "User switch blocked",

	// Windows system administration
	"icacls":   "ACL modification blocked",
	"reg":      "Registry modification blocked",
	"regedit":  "Registry access blocked",
	"sc":       "Service control blocked",
	"schtasks": "Scheduled task blocked",
	"wmic":     "WMI access blocked",
	"cmdkey":   "Credential management blocked",
	"bcdedit":  "Boot configuration blocked",
	"setx":     "Persistent env variable blocked",
	"takeown":  "File ownership takeover blocked",

	// Disk operations
	"dd":       "Raw disk write blocked",
	"format":   "Disk format blocked",
	"diskpart": "Disk partition blocked",
	"mkfs":     "Filesystem creation blocked",
	"fdisk":    "Disk partition blocked",
	"parted":   "Disk partition blocked",

	// Shell meta-commands
	"eval":    "Dynamic evaluation blocked",
	"exec":    "Process replacement blocked",
	"crontab": "Cron job modification blocked",
	"at":      "Scheduled task blocked",

	// Windows LOLBins
	"certutil":    "LOLBin blocked: certutil",
	"bitsadmin":   "LOLBin blocked: bitsadmin",
	"mshta":       "LOLBin blocked: mshta",
	"regsvr32":    "LOLBin blocked: regsvr32",
	"rundll32":    "LOLBin blocked: rundll32",
	"msiexec":     "LOLBin blocked: msiexec",
	"wscript":     "LOLBin blocked: wscript",
	"cscript":     "LOLBin blocked: cscript",
	"installutil": "LOLBin blocked: installutil",
	"regasm":      "LOLBin blocked: regasm",
	"regsvcs":     "LOLBin blocked: regsvcs",

	// System configuration & network management
	"netsh":    "System config blocked: netsh",
	"dism":     "System config blocked: dism",
	"sfc":      "System config blocked: sfc",
	"fsutil":   "System config blocked: fsutil",
	"cipher":   "System config blocked: cipher",
	"attrib":   "System config blocked: attrib",
	"subst":    "System config blocked: subst",
	"shutdown": "System config blocked: shutdown",
	"logoff":   "System config blocked: logoff",
	"secedit":  "System config blocked: secedit",
	"auditpol": "System config blocked: auditpol",
	"gpupdate": "System config blocked: gpupdate",

	// Linux/cross-platform system management
	"systemctl":          "System management blocked: systemctl",
	"service":            "System management blocked: service",
	"useradd":            "User management blocked: useradd",
	"userdel":            "User management blocked: userdel",
	"usermod":            "User management blocked: usermod",
	"groupadd":           "Group management blocked: groupadd",
	"groupdel":           "Group management blocked: groupdel",
	"groupmod":           "Group management blocked: groupmod",
	"passwd":             "User management blocked: passwd",
	"chpasswd":           "User management blocked: chpasswd",
	"mount":              "System management blocked: mount",
	"umount":             "System management blocked: umount",
	"iptables":           "Firewall blocked: iptables",
	"nft":                "Firewall blocked: nft",
	"visudo":             "Privilege config blocked: visudo",
	"update-alternatives": "System defaults blocked: update-alternatives",
}

// checkAlwaysBlocked checks if the command name is in the always-blocked list,
// plus subcommand checks for commands that need deeper inspection.
func checkAlwaysBlocked(parts []string) (bool, string) {
	if len(parts) == 0 {
		return false, ""
	}
	base := normalizeCmdName(parts[0])
	if reason, ok := alwaysBlocked[base]; ok {
		return true, fmt.Sprintf("%s: %s", reason, base)
	}
	// Windows user management: net user / net localgroup
	if base == "net" {
		sub := getFirstNonFlag(parts, 1)
		if isOneOf(sub, "user", "localgroup") {
			return true, fmt.Sprintf("User management blocked: net %s", sub)
		}
	}
	return false, ""
}

// ── Layer 2: CRITICAL_PROTECTED ──
// Interactive mode: WPF dialog. Silent mode: auto-deny (exit 2).

// criticalCommands: commands that moved from L1 to L2 (need human override option).
var criticalCommands = map[string]string{
	"npx":      "Remote package execution: npx",
	"kill":     "Process termination: kill",
	"pkill":    "Process termination: pkill",
	"killall":  "Process termination: killall",
	"taskkill": "Process termination: taskkill",
	"chmod":    "Permission modification: chmod",
}

// checkCriticalCommands checks if a command is in the L2 critical list.
func checkCriticalCommands(parts []string) (bool, string) {
	if len(parts) == 0 {
		return false, ""
	}
	base := normalizeCmdName(parts[0])
	if desc, ok := criticalCommands[base]; ok {
		return true, desc
	}
	return false, ""
}

// checkCriticalOps checks for dangerous operations elevated from L3 to L2.
// These are irreversible or externally visible operations.
func checkCriticalOps(parts []string) (bool, string) {
	if len(parts) == 0 {
		return false, ""
	}
	base := normalizeCmdName(parts[0])
	sub := getFirstNonFlag(parts, 1)

	switch base {
	case "git":
		if sub == "push" && hasAnyFlag(parts, "--force", "-f", "--force-with-lease") {
			return true, "Critical: git push --force"
		}
	case "npm", "pnpm", "yarn":
		if sub == "publish" {
			return true, fmt.Sprintf("Critical: %s publish", base)
		}
	case "docker":
		switch sub {
		case "volume":
			volSub := getFirstNonFlag(parts, 2)
			if volSub == "volume" {
				volSub = getFirstNonFlag(parts, 3)
			}
			if isOneOf(volSub, "rm", "remove", "prune") {
				return true, fmt.Sprintf("Critical: docker volume %s", volSub)
			}
		case "system":
			sysSub := getFirstNonFlag(parts, 2)
			if sysSub == "system" {
				sysSub = getFirstNonFlag(parts, 3)
			}
			if sysSub == "prune" {
				return true, "Critical: docker system prune"
			}
		case "compose":
			if contains(parts, "down") && hasAnyFlag(parts, "-v", "--volumes") {
				return true, "Critical: docker compose down -v (destroys volumes)"
			}
		}
	case "docker-compose":
		if contains(parts, "down") && hasAnyFlag(parts, "-v", "--volumes") {
			return true, "Critical: docker-compose down -v (destroys volumes)"
		}
	}
	return false, ""
}

// defaultCriticalPaths are built-in critical path patterns for L2 write protection.
var defaultCriticalPaths = []string{
	"/.claude/hooks/guard.exe",
	"/.claude/hooks/data/",
	"/.claude/hooks/guard-history.exe",
	"/.claude/settings.json",
	"/etc/hosts",
	"/drivers/etc/hosts",
	"/.gitconfig",
	"/.config/git/",
	"/.npmrc",
	"/.ssh/",
	"/.bashrc",
	"/.bash_profile",
	"/.profile",
	"/.zshrc",
}

// checkCriticalPath checks if a file path matches any critical path pattern.
func checkCriticalPath(filePath string, cfg *GuardConfig) (bool, string) {
	normalized := strings.ReplaceAll(strings.ToLower(filePath), "\\", "/")

	patterns := defaultCriticalPaths
	if len(cfg.CriticalPaths) > 0 {
		patterns = cfg.CriticalPaths
	}

	for _, pattern := range patterns {
		p := strings.ToLower(pattern)
		if strings.HasSuffix(p, "/") {
			// Directory pattern: match if path contains this directory
			if strings.Contains(normalized, p) {
				return true, "Critical path protected: " + filePath
			}
		} else {
			// File pattern: match if path ends with or contains this pattern
			if strings.HasSuffix(normalized, p) || strings.Contains(normalized, p) {
				return true, "Critical path protected: " + filePath
			}
		}
	}
	return false, ""
}

// ── Layer 3: INTERACTIVE_AUTH ──
// Interactive mode: WPF dialog. Silent mode: auto-allow (exit 0).

// checkDangerousOpsAuth checks for dangerous operations that require
// interactive authorization (L3). Excludes ops elevated to L2.
func checkDangerousOpsAuth(parts []string, projectDir string) (bool, string) {
	if len(parts) == 0 {
		return false, ""
	}
	base := normalizeCmdName(parts[0])
	sub := getFirstNonFlag(parts, 1)

	switch base {

	// git local-destructive operations (recoverable via reflog)
	case "git":
		switch sub {
		case "reset":
			if hasFlag(parts, "--hard") {
				return true, "Dangerous: git reset --hard"
			}
		case "checkout":
			if hasFlag(parts, "--") || containsAfter(parts, ".", 2) {
				return true, "Dangerous: git checkout discard changes"
			}
		case "restore":
			if containsAfter(parts, ".", 2) {
				return true, "Dangerous: git restore discard all changes"
			}
		case "clean":
			if anyFlagContains(parts, "f") {
				return true, "Dangerous: git clean (removes untracked files)"
			}
		case "branch":
			if hasAnyFlag(parts, "-D", "-d", "--delete") {
				return true, "Dangerous: git branch delete"
			}
		}

	// Package uninstall (reversible)
	case "pip", "pip3":
		if sub == "uninstall" {
			return true, fmt.Sprintf("Package uninstall: %s uninstall", base)
		}

	case "gem":
		if sub == "uninstall" {
			return true, "Package uninstall: gem uninstall"
		}

	// PowerShell obfuscated commands
	case "powershell", "pwsh":
		for _, arg := range parts[1:] {
			if strings.HasPrefix(strings.ToLower(arg), "-enc") {
				return true, "Obfuscated command: PowerShell -EncodedCommand"
			}
		}

	// cp/mv outside project
	case "cp", "mv":
		if ok, extPath := pathsInProject(parts, projectDir); !ok {
			return true, fmt.Sprintf("%s targets path outside project: %s", base, extPath)
		}
	}

	return false, ""
}

// ── Layer 3: INTERACTIVE_AUTH ──

// networkAuth: network commands that always require interactive authorization.
var networkAuth = map[string]string{
	"ssh":    "Network access: ssh",
	"scp":    "Network transfer: scp",
	"rsync":  "Network/file sync: rsync",
	"nc":     "Network access: nc",
	"netcat": "Network access: netcat",
	"ncat":   "Network access: ncat",
	"telnet": "Network access: telnet",
	"ftp":    "Network transfer: ftp",
	"sftp":   "Network transfer: sftp",
}

// pathSensitiveAuth: commands that require authorization based on path analysis.
var pathSensitiveAuth = map[string]string{
	"rm":    "File deletion",
	"rmdir": "Directory deletion",
}

// checkGitRemoteAuth checks if a git command modifies remote configuration.
func checkGitRemoteAuth(parts []string) (bool, string) {
	if len(parts) == 0 {
		return false, ""
	}
	base := normalizeCmdName(parts[0])

	switch base {
	case "git":
		sub := getFirstNonFlag(parts, 1)
		if sub == "remote" {
			remoteSub := getFirstNonFlag(parts, 2)
			if remoteSub == "remote" {
				remoteSub = getFirstNonFlag(parts, 3)
			}
			if isOneOf(remoteSub, "set-url", "add", "remove", "rm", "rename") {
				return true, fmt.Sprintf("Git remote modification: git remote %s", remoteSub)
			}
		}
		// git config remote.* — semantic equivalent
		if sub == "config" {
			for _, arg := range parts[2:] {
				if strings.HasPrefix(arg, "remote.") {
					return true, "Git remote modification: git config " + arg
				}
			}
		}
	}

	return false, ""
}

// checkGlobalInstallAuth checks if a command performs a global package install
// that modifies the system environment. These require interactive authorization.
func checkGlobalInstallAuth(parts []string) (bool, string) {
	if len(parts) == 0 {
		return false, ""
	}
	base := normalizeCmdName(parts[0])
	sub := getFirstNonFlag(parts, 1)

	switch base {
	case "npm", "pnpm", "yarn":
		if hasAnyFlag(parts, "-g", "--global") {
			return true, fmt.Sprintf("Global install: %s -g", base)
		}
	case "pip", "pip3":
		if sub == "install" && !inVirtualEnv() {
			if !hasAnyFlag(parts, "--target", "-t", "--user") {
				return true, fmt.Sprintf("Global install: %s install (no virtual environment)", base)
			}
		}
	case "cargo":
		if sub == "install" {
			return true, "Global install: cargo install"
		}
	case "go":
		if sub == "install" {
			return true, "Global install: go install"
		}
	case "gem":
		if sub == "install" {
			return true, "Global install: gem install"
		}
	case "dotnet":
		if containsAll(parts, "tool", "install") && hasAnyFlag(parts, "-g", "--global") {
			return true, "Global install: dotnet tool install -g"
		}
	}

	return false, ""
}

// checkNetworkAuth checks if a command is a network command requiring auth.
func checkNetworkAuth(parts []string) (bool, string) {
	if len(parts) == 0 {
		return false, ""
	}
	base := normalizeCmdName(parts[0])
	if desc, ok := networkAuth[base]; ok {
		return true, desc
	}
	return false, ""
}

// checkPathSensitiveAuth checks if a path-sensitive command needs authorization
// based on whether its target paths are inside the project directory.
func checkPathSensitiveAuth(parts []string, projectDir string) (bool, string) {
	if len(parts) == 0 {
		return false, ""
	}
	base := normalizeCmdName(parts[0])
	desc, ok := pathSensitiveAuth[base]
	if !ok {
		return false, ""
	}

	// Extract all non-flag arguments (skip command name)
	var pathArgs []string
	for _, arg := range parts[1:] {
		if !strings.HasPrefix(arg, "-") {
			pathArgs = append(pathArgs, arg)
		}
	}

	// No path arguments → can't determine safety → require auth
	if len(pathArgs) == 0 {
		return true, desc + " (no path specified)"
	}

	// Check each path argument
	for _, arg := range pathArgs {
		if isAbsolutePath(arg) || strings.Contains(arg, "..") {
			absPath := toAbsNormalized(arg, projectDir)
			if isOutsideProject(absPath, projectDir, nil) {
				return true, fmt.Sprintf("%s: %s (outside project)", desc, arg)
			}
		}
		// Plain relative paths (no "..") → inside project → safe
	}

	return false, "" // All paths within project → allow
}

// ── Pre-split check: pipe-to-shell ──

var pipeToShellRe = regexp.MustCompile(
	`(?i)(curl|wget)\s+.*\|\s*(bash|sh|zsh|dash|powershell|pwsh|python|perl|ruby|node)`)

// checkPipeToShell detects curl/wget piped to shell interpreters.
// Must be called on the raw command BEFORE splitting by pipe.
func checkPipeToShell(rawCommand string) (bool, string) {
	if pipeToShellRe.MatchString(rawCommand) {
		return true, "Dangerous: pipe-to-shell execution pattern detected"
	}
	return false, ""
}
