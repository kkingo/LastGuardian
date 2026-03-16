---
name: lastguardian
description: Switch LastGuardian guard.exe between interactive and silent modes. Use when user says "/lastguardian interactive", "/lastguardian silent", "/lastguardian", or asks to change guard mode, switch guard mode, toggle LastGuardian mode, or any request involving LastGuardian mode switching.
---

# LastGuardian Mode Switcher

Switch guard.exe between `interactive` and `silent` modes.

## Usage

```
/lastguardian interactive   — Enable WPF dialog prompts for L2/L3/L4
/lastguardian silent        — L2 auto-deny, L3/L4 auto-allow, no dialogs
/lastguardian               — Show current mode
```

## Implementation

Run the bundled script:

```bash
python ~/.claude/skills/lastguardian/scripts/switch_mode.py [interactive|silent]
```

The script outputs JSON. Handle two scenarios:

### Normal switch or query

Output: `{"mode": "interactive"}` or `{"mode": "silent"}`

Report the current mode to the user.

### Silent → Interactive switch (with session report)

When switching from silent to interactive, the output includes `sessions`:

```json
{
  "mode": "interactive",
  "silent_since": "2026-03-17T02:00:00",
  "sessions": [
    {
      "session_id": "27240_cb786c5d",
      "project_dir": "D:/AI-workspace",
      "prompts": [
        {
          "prompt": "帮我测试双模式钩子",
          "timestamp": "2026-03-17T02:01:00+08:00",
          "operations": [
            {"tool": "Bash", "command": "ls ...", "action": "allow", "layer": ""},
            {"tool": "Bash", "command": "npx cowsay", "action": "block", "layer": "[\"Layer 2: CRITICAL_PROTECTED\"]"}
          ]
        }
      ]
    }
  ]
}
```

When `sessions` is present and non-empty, generate a **Silent Mode Execution Review**:

1. Group by session — use `project_dir` to identify the project context
2. Within each session, list user prompts chronologically as section headers
3. For each prompt, summarize the operations concisely (do NOT list every command)
4. Highlight any operations that triggered L2 CRITICAL_PROTECTED (auto-denied)
5. Highlight any operations that triggered L3 INTERACTIVE_AUTH (auto-allowed)
6. Keep concise — focus on what was accomplished per prompt, not raw commands

Format example:

```
## Silent Mode Execution Review
Period: 2026-03-17 02:00 — 03:30 (1.5h)

### Session 1: D:/AI-workspace (LastGuardian)

**Q: "帮我测试双模式钩子是否正常工作"**
- Explored project: listed files, read 3 source files
- Tested L1/L2/L3 commands: sudo(blocked), npx(L2 denied), curl(L3 allowed)

**Q: "切换回交互模式看看报告"**
- Ran switch_mode.py to return to interactive

### Session 2: D:/pyworks/ServerlessAllocation

**Q: "分析训练结果"**
- Read 5 CSV result files, ran 2 plotting scripts
- Auto-Allowed (L3): 1x pip install matplotlib

### Auto-Denied Summary (L2 Critical)
- 1x npx cowsay (Session 1)

### Auto-Allowed Summary (L3)
- 1x pip install matplotlib (Session 2)
```

If `sessions` is empty or absent, skip the review.

## Mode Reference

| Mode | L1 | L2 CRITICAL | L3 INTERACTIVE | L4 PATH |
|------|-----|-------------|----------------|---------|
| interactive | block | dialog | dialog | dialog |
| silent | block | auto-deny | auto-allow | auto-allow |
