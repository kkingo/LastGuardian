#!/usr/bin/env python3
"""Switch LastGuardian guard.exe between interactive and silent modes."""

import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

CONFIG_PATH = Path.home() / ".claude" / "hooks" / "data" / "guard-config.json"
HISTORY_EXE = Path.home() / ".claude" / "hooks" / "guard-history.exe"
VALID_MODES = ("interactive", "silent")


def read_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def write_config(config: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


def _query_history_exe(subcmd: str, since: str, limit: int = 500) -> list:
    """Query guard-history.exe with given subcommand and filters."""
    if not HISTORY_EXE.exists():
        return []
    try:
        result = subprocess.run(
            [str(HISTORY_EXE), subcmd, "-since", since, "-json", "-n", str(limit)],
            capture_output=True, text=True, timeout=10, encoding="utf-8"
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            return data if isinstance(data, list) else []
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        pass
    return []


def get_silent_history(since: str) -> list:
    """Query guard-history.exe for commands executed since the given timestamp."""
    return _query_history_exe("list", since)


def get_silent_prompts(since: str) -> list:
    """Query guard-history.exe for user prompts since the given timestamp."""
    return _query_history_exe("prompts", since)


def build_session_report(prompts: list, history: list) -> list:
    """Group history records by session_id and prompt timestamp ranges."""
    # Group by session
    session_prompts = defaultdict(list)
    for p in prompts:
        session_prompts[p["session_id"]].append(p)

    session_history = defaultdict(list)
    for h in history:
        session_history[h["session_id"]].append(h)

    all_sids = sorted(set(session_prompts.keys()) | set(session_history.keys()))
    sessions = []

    for sid in all_sids:
        s_prompts = sorted(session_prompts.get(sid, []), key=lambda x: x["timestamp"])
        s_history = sorted(session_history.get(sid, []), key=lambda x: x["timestamp"])

        prompt_groups = []

        # Assign each history record to the nearest preceding prompt
        for i, prompt in enumerate(s_prompts):
            start_ts = prompt["timestamp"]
            end_ts = s_prompts[i + 1]["timestamp"] if i + 1 < len(s_prompts) else "9999-12-31T23:59:59Z"
            ops = [h for h in s_history if start_ts <= h["timestamp"] < end_ts]
            prompt_groups.append({
                "prompt": prompt["prompt"],
                "timestamp": prompt["timestamp"],
                "operations": _summarize_ops(ops),
            })

        # Orphaned operations (before the first prompt)
        if s_prompts:
            first_ts = s_prompts[0]["timestamp"]
            orphaned = [h for h in s_history if h["timestamp"] < first_ts]
        else:
            orphaned = s_history

        if orphaned:
            prompt_groups.insert(0, {
                "prompt": "(session startup / pre-prompt operations)",
                "timestamp": orphaned[0]["timestamp"] if orphaned else "",
                "operations": _summarize_ops(orphaned),
            })

        # Determine project_dir from first available record
        project_dir = ""
        if s_history:
            project_dir = s_history[0].get("project_dir", "")
        elif s_prompts:
            project_dir = s_prompts[0].get("project_dir", "")

        sessions.append({
            "session_id": sid,
            "project_dir": project_dir,
            "prompts": prompt_groups,
        })

    return sessions


def _summarize_ops(ops: list) -> list:
    """Create a compact summary of operations."""
    return [
        {
            "tool": op.get("tool_name", ""),
            "command": (op.get("raw_command") or "")[:120],
            "action": op.get("final_action", ""),
            "layer": op.get("triggered_layers") or "",
        }
        for op in ops
    ]


def main():
    config = read_config()
    old_mode = config.get("mode", "interactive")
    output = {}

    if len(sys.argv) >= 2:
        new_mode = sys.argv[1].lower().strip()
        if new_mode not in VALID_MODES:
            print(f"Error: invalid mode '{new_mode}'. Use 'interactive' or 'silent'.")
            sys.exit(1)

        # Entering silent mode: record start timestamp
        if new_mode == "silent" and old_mode != "silent":
            config["silent_since"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Leaving silent mode: collect session-grouped report
        if new_mode == "interactive" and old_mode == "silent":
            silent_since = config.get("silent_since", "")
            if silent_since:
                history = get_silent_history(silent_since) or []
                prompts = get_silent_prompts(silent_since) or []
                output["sessions"] = build_session_report(prompts, history)
                output["silent_since"] = silent_since
            config.pop("silent_since", None)

        config["mode"] = new_mode
        write_config(config)

    output["mode"] = config.get("mode", "interactive")
    print(json.dumps(output, ensure_ascii=False))


if __name__ == "__main__":
    main()
