# LastGuardian

A multi-layered security guard system for Claude Code's `--dangerously-skip-permissions` mode on Windows. It intercepts every tool invocation (Bash, Read, Edit, Write, Glob, Grep) via Claude Code's **PreToolUse hook** protocol, applies a four-layer defense model, and either blocks, prompts the user via a native WPF dialog, or allows the operation — all before the command executes.

## Design Philosophy

### Why This Exists

Claude Code's `--dangerously-skip-permissions` mode removes all built-in confirmation prompts, allowing the AI to execute any command without user approval. This is powerful for productivity but dangerous in practice — a single hallucinated `rm -rf /` or `git push --force` could cause irreversible damage.

**LastGuardian** acts as a transparent security layer that restores safety guarantees without sacrificing the speed benefits of skip-permissions mode. It follows a **fail-open** design: if the guard itself crashes or encounters an error, it allows the operation to proceed (exit code 0), ensuring it never blocks legitimate work.

### Architecture Overview

```
Claude Code (skip-permissions)
        │
        ▼
   PreToolUse Hook
        │
        ▼
  ┌─────────────┐
  │  guard.exe   │ ← Receives JSON payload on stdin
  │              │
  │  Layer 1     │ → ALWAYS_BLOCKED   (hard block, no bypass)
  │  Layer 2     │ → CONTEXTUAL_BLOCKED (context-dependent hard block)
  │  Layer 3     │ → INTERACTIVE_AUTH  (WPF dialog prompt)
  │  Layer 4     │ → PATH_BOUNDARY    (project directory fence)
  │              │
  │  Exit 0      │ → Allow
  │  Exit 2      │ → Block (reason on stderr)
  └─────────────┘
        │
        ▼
  ┌─────────────┐
  │ Session Cache│ ← Per-session SHA256-keyed JSON files
  │ History DB   │ ← SQLite audit log (modernc.org/sqlite, pure Go)
  └─────────────┘
```

### Four-Layer Defense Model

#### Layer 1: ALWAYS_BLOCKED (Hard Block)

Commands that are **never** allowed regardless of context:

| Category | Commands |
|----------|----------|
| File destruction | `shred`, `truncate` |
| Process management | `kill`, `pkill`, `killall`, `taskkill` |
| Permission/ownership | `chmod`, `chown`, `chgrp` |
| Privilege escalation | `sudo`, `runas`, `su` |
| Windows system admin | `reg`, `regedit`, `sc`, `schtasks`, `wmic`, `icacls`, `bcdedit`, `setx`, `takeown`, `cmdkey` |
| Disk operations | `dd`, `format`, `diskpart`, `mkfs`, `fdisk`, `parted` |
| Shell meta-commands | `eval`, `exec`, `crontab`, `at` |
| Remote execution | `npx` |

#### Layer 2: CONTEXTUAL_BLOCKED (Context-Dependent Hard Block)

Commands blocked only when used with specific dangerous flags or patterns:

- **Git destructive operations**: `git push --force`, `git reset --hard`, `git checkout -- .`, `git clean -f`, `git branch -D`, `git remote set-url/add/remove`
- **Package managers (global)**: `npm/pnpm/yarn -g`, `npm publish`
- **Package install outside venv**: `pip install` (when no `VIRTUAL_ENV` or `CONDA_DEFAULT_ENV`)
- **System-level package installs**: `cargo install`, `go install`, `gem install`
- **Cross-boundary file operations**: `cp`/`mv` with paths outside the project directory
- **Obfuscated commands**: `powershell -EncodedCommand`
- **Docker destructive ops**: `docker volume rm/prune`, `docker system prune`, `docker compose down -v`
- **Pipe-to-shell patterns**: `curl ... | bash`, `wget ... | sh` (pre-split detection)

#### Layer 3: INTERACTIVE_AUTH (User Approval via WPF Dialog)

Commands that require explicit user approval through a native Windows dialog:

- **Network commands**: `ssh`, `scp`, `rsync`, `nc`, `netcat`, `telnet`, `ftp`, `sftp`
- **Path-sensitive deletions**: `rm`/`rmdir` with absolute paths or `..` traversal outside the project

The WPF dialog displays:
- Operation type and risk level badge (MEDIUM / HIGH / CRITICAL)
- Triggered security layers
- Session info (operation, session ID, project dir, timestamp, hash)
- Full command preview
- Allow / Deny buttons with 60-second auto-deny timeout

#### Layer 4: PATH_BOUNDARY (Project Directory Fence)

All file tool operations (Read, Edit, Write, Glob, Grep) and embedded absolute paths in Bash commands are checked against the project directory boundary. Paths outside the project (and configured `allowed_dirs`) trigger an interactive approval dialog.

Special handling for **Git Bash path convention**: `/c/Users/...` is automatically converted to `C:\Users\...` on Windows, preventing false positives from MSYS2 path translation.

### Risk Scoring Engine

Each intercepted operation receives a weighted risk score:

| Factor | Weight |
|--------|--------|
| Base: file deletion | +2 |
| Base: network/other | +1 |
| Interpreter wrap (`python -c`, `bash -c`) | +2 |
| Output redirection (`>`, `2>&1`) | +1 |
| Pipe (`\|`) | +1 |
| Path outside project boundary | +2 |
| Multiple target paths (>3) | +1 |

Risk levels: **MEDIUM** (score < 3), **HIGH** (score 3-4), **CRITICAL** (score >= 5). Thresholds and weights are configurable.

### Session Cache

Approved/denied decisions are cached per Claude Code session using SHA256-keyed JSON files. This avoids repeatedly prompting for the same command within a session. The cache is keyed to the parent process PID + creation time, and stale sessions are automatically cleaned up on startup.

### Audit History

All operations (allowed, blocked, and prompted) are recorded in a SQLite database (`history.db`) using [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) — a pure-Go SQLite implementation requiring **no CGO**. Records include timestamp, session ID, tool name, raw command, risk level, triggered layers, user decision, and cache hit status. A companion CLI tool (`guard-history`) provides querying capabilities.

## Quick Start (Windows)

### Prerequisites

- **Go 1.23+** (for building from source)
- **Windows 10/11** (WPF dialogs require Windows desktop)
- **Claude Code** installed and configured

### Step 1: Build the Binaries

```bash
# Clone the repository
git clone https://github.com/kkingo/LastGuardian.git
cd LastGuardian

# Build the main guard binary
go build -ldflags="-s -w" -o guard.exe .

# Build the history viewer (optional)
go build -ldflags="-s -w" -o guard-history.exe ./cmd/guard-history/
```

### Step 2: Deploy to Claude Code Hooks Directory

```bash
# Create the hooks directory if it doesn't exist
mkdir -p "$HOME/.claude/hooks"

# Copy binaries
cp guard.exe "$HOME/.claude/hooks/"
cp guard-history.exe "$HOME/.claude/hooks/"  # optional

# Create the data directory for history and session cache
mkdir -p "$HOME/.claude/hooks/data"
```

### Step 3: Configure Claude Code Hooks

Edit `%USERPROFILE%\.claude\settings.json` (or `~/.claude/settings.json`). Add the following `hooks` section (merge with existing settings if the file already exists):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "$HOME/.claude/hooks/guard.exe",
            "timeout": 30
          }
        ]
      },
      {
        "matcher": "Glob|Grep",
        "hooks": [
          {
            "type": "command",
            "command": "$HOME/.claude/hooks/guard.exe",
            "timeout": 30
          }
        ]
      },
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$HOME/.claude/hooks/guard.exe",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

A complete example is provided in [`examples/settings-hooks.json`](examples/settings-hooks.json).

### Step 4: (Optional) Custom Configuration

Create `~/.claude/hooks/guard-config.json` to customize behavior:

```json
{
  "version": 1,
  "data_dir": "~/.claude/hooks/data",
  "dialog": {
    "timeout_seconds": 60,
    "platform": "auto"
  },
  "allowed_dirs": [
    "D:\\shared-libs",
    "C:\\tools"
  ],
  "custom_rules": {
    "extra_always_blocked": ["dangerous-tool"],
    "extra_interactive_auth": [],
    "extra_contextual_rules": []
  }
}
```

See [`examples/guard-config.json`](examples/guard-config.json) for the full default configuration.

### Step 5: Verify Installation

Launch Claude Code with `--dangerously-skip-permissions` and try a command that should trigger the guard:

```bash
claude --dangerously-skip-permissions
```

Then ask Claude to run `ssh user@example.com` — a WPF approval dialog should appear.

## History Viewer CLI

The `guard-history` tool queries the audit database:

```bash
# List recent operations
guard-history list -n 20

# Show only blocked operations
guard-history blocked

# Statistics summary
guard-history stats

# Show sessions
guard-history sessions

# Follow new entries in real-time
guard-history tail

# Filter by tool, action, risk level
guard-history list -tool Bash -action block -risk HIGH

# JSON output for scripting
guard-history list -json

# Prune old records
guard-history prune -days 30
```

## How the Hook Protocol Works

Claude Code's PreToolUse hooks receive a JSON payload on **stdin**:

```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "ssh user@remote-server.com"
  },
  "cwd": "D:/AI-workspace"
}
```

The hook process must exit with:
- **Exit 0** → Allow the operation
- **Exit 2** → Block the operation (reason printed to stderr is shown to Claude)

LastGuardian reads this payload, runs it through all four security layers, and exits accordingly. The entire process completes in milliseconds for allowed operations; only Layer 3/4 prompts introduce user-visible delay (the WPF dialog).

## Project Structure

```
LastGuardian/
├── main.go            # Entry point, hook protocol handler, tool routing
├── types.go           # Data structures (Payload, ApprovalSummary, configs)
├── config.go          # Configuration loading with defaults and JSON override
├── parser.go          # Shell command splitting, normalization, flag parsing
├── layers.go          # Layer 1-3 security rules (blocked/contextual/auth)
├── pathcheck.go       # Layer 4 path boundary, Git Bash path conversion
├── analyzer.go        # Deep command analysis, risk scoring, hash computation
├── dialog.go          # WPF dialog generation (PowerShell), platform detection
├── cache.go           # Session cache (SHA256-keyed, per-PID JSON files)
├── store.go           # SQLite history database (pure Go, no CGO)
├── guard_test.go      # Unit tests for all layers
├── go.mod / go.sum    # Go module definition
├── cmd/
│   └── guard-history/
│       └── main.go    # History viewer CLI tool
└── examples/
    ├── guard-config.json    # Full default configuration example
    └── settings-hooks.json  # Claude Code hooks configuration example
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Pure Go, static binary** | Single `guard.exe` with zero runtime dependencies. No Python, no Node, no DLL hell. Deploys by copying one file. |
| **Fail-open (exit 0 on panic)** | A crashed guard must never block legitimate work. The `defer recover()` in `main()` ensures any panic exits with code 0. |
| **Pure-Go SQLite (modernc.org/sqlite)** | Eliminates CGO and GCC dependency on Windows. Cross-compiles cleanly. |
| **WPF over MessageBox** | Rich UI with risk badges, session info, command preview, and auto-deny timeout. MessageBox is too limited for security-critical decisions. |
| **Session cache per PID** | Avoids re-prompting within the same Claude Code session. Cache invalidates automatically when the parent process exits. |
| **Git Bash path conversion** | Claude Code on Windows runs hooks via Git Bash, which translates `C:\` to `/c/`. Without conversion, all paths appear "outside project". |
| **Two-pass command scanning** | Pass 1 (hard blocks) runs before Pass 2 (interactive prompts), ensuring dangerous commands never reach the dialog. |

## License

MIT
