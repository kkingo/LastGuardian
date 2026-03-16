# LastGuardian 双模式 + 三层架构重设计

> 日期：2026-03-16
> 状态：已确认，待实施

---

## 1. 设计背景

LastGuardian 当前采用三层防御架构（L1 硬拦截 → L3 交互授权 → L4 路径边界），所有非 L1 的拦截都依赖 WPF 弹窗交互。这带来两个问题：

1. **无法适应无人值守场景**：自动化流水线或长时间无人看管时，弹窗会阻塞执行流程。
2. **缺少中间安全层级**：某些操作（如 `npm publish`、`git push --force`）过于危险，即使无人值守也不应自动放行，但当前 L3 在静默模式下会全部放行。

## 2. 双模式设计

### 2.1 模式定义

| 模式 | 名称 | 行为 |
|------|------|------|
| `interactive` | 交互模式 | L2/L3/L4 触发时弹出 WPF 对话框，由用户实时决策 |
| `silent` | 静默模式 | L2 自动拒绝，L3/L4 自动放行，无弹窗 |

### 2.2 模式切换

通过 `guard-config.json` 配置文件中的 `mode` 字段切换：

```json
{
  "mode": "interactive"
}
```

guard.exe 每次调用都读取配置，切换即时生效，无需重启 Claude Code。

### 2.3 各层在不同模式下的行为矩阵

| 层 | 交互模式 | 静默模式 | 设计意图 |
|----|---------|---------|---------|
| L1 ALWAYS_BLOCKED | exit 2 硬拦截 | exit 2 硬拦截 | 无论如何都不允许的高危操作 |
| L2 CRITICAL_PROTECTED | WPF 弹窗 | exit 2 自动拒绝 | 需要人类判断的危险操作，不信任 AI 自主决策 |
| L3 INTERACTIVE_AUTH | WPF 弹窗 | exit 0 自动放行 | 有一定风险但可接受的操作，信任 AI 在合理范围内使用 |
| L4 PATH_BOUNDARY | WPF 弹窗 | exit 0 自动放行 | 路径越界检测，与 L3 同级 |

---

## 3. 三层规则完整清单

### 3.1 Layer 1: ALWAYS_BLOCKED（共约 68 条）

双模式下均硬拦截，exit 2，无绕过可能。

#### 3.1.1 原有规则（27 条命令 + 1 条子命令检查）

**文件破坏**

| 命令 | 说明 |
|------|------|
| `shred` | 安全删除文件 |
| `truncate` | 截断文件内容 |

**权限与属主（部分）**

| 命令 | 说明 |
|------|------|
| `chown` | 修改文件属主 |
| `chgrp` | 修改文件属组 |

**提权**

| 命令 | 说明 |
|------|------|
| `sudo` | 提权执行 |
| `runas` | Windows 提权执行 |
| `su` | 切换用户 |

**Windows 系统管理**

| 命令 | 说明 |
|------|------|
| `icacls` | ACL 修改 |
| `reg` | 注册表修改 |
| `regedit` | 注册表编辑器 |
| `sc` | 服务控制 |
| `schtasks` | 计划任务 |
| `wmic` | WMI 访问 |
| `cmdkey` | 凭据管理 |
| `bcdedit` | 启动配置 |
| `setx` | 持久环境变量 |
| `takeown` | 文件所有权接管 |

**磁盘操作**

| 命令 | 说明 |
|------|------|
| `dd` | 原始磁盘写入 |
| `format` | 磁盘格式化 |
| `diskpart` | 磁盘分区 |
| `mkfs` | 文件系统创建 |
| `fdisk` | 磁盘分区 |
| `parted` | 磁盘分区 |

**Shell 元命令**

| 命令 | 说明 |
|------|------|
| `eval` | 动态代码执行 |
| `exec` | 进程替换 |
| `crontab` | 定时任务修改 |
| `at` | 计划任务 |

**子命令检查**

| 命令 | 子命令 | 说明 |
|------|--------|------|
| `net` | `user`, `localgroup` | Windows 用户管理 |

#### 3.1.2 新增：Windows LOLBins（11 条）

这些是 Windows 自带的合法程序，但常被滥用于下载文件、执行代码或绕过安全策略。在 Claude Code 开发场景中没有合法使用理由。

| 命令 | 威胁说明 |
|------|---------|
| `certutil` | 下载文件 / 编解码数据，常见安全绕过手段 |
| `bitsadmin` | 后台下载文件，可创建持久化任务 |
| `mshta` | 执行 HTA 文件，远程代码执行 |
| `regsvr32` | 注册/执行 DLL，可从远程 URL 加载 |
| `rundll32` | 执行任意 DLL 导出函数 |
| `msiexec` | 安装 MSI 包，可从远程 URL 安装 |
| `wscript` | Windows Script Host (GUI) |
| `cscript` | Windows Script Host (CLI) |
| `installutil` | .NET 安装工具，可绕过白名单执行代码 |
| `regasm` | .NET 程序集注册 |
| `regsvcs` | .NET COM+ 注册 |

#### 3.1.3 新增：系统配置与网络管理（12 条）

| 命令 | 威胁说明 |
|------|---------|
| `netsh` | 防火墙规则 / 网络配置 / 代理设置修改 |
| `dism` | 系统映像管理，启用/禁用 Windows 功能 |
| `sfc` | 系统文件检查/修复 |
| `fsutil` | 文件系统底层操作（硬链接、配额） |
| `cipher` | NTFS 加密/擦除 |
| `attrib` | 文件属性修改（隐藏/系统/只读） |
| `subst` | 虚拟驱动器映射 |
| `shutdown` | 关机/重启 |
| `logoff` | 注销用户会话 |
| `secedit` | 安全策略配置 |
| `auditpol` | 审计策略配置 |
| `gpupdate` | 组策略强制刷新 |

#### 3.1.4 新增：Linux/跨平台系统管理（16 条）

为 WSL 环境和未来 Linux 部署预留覆盖。

| 命令 | 威胁说明 |
|------|---------|
| `systemctl` | 系统服务管理 |
| `service` | 系统服务管理（SysV） |
| `useradd` | 创建系统用户 |
| `userdel` | 删除系统用户 |
| `usermod` | 修改用户属性 |
| `groupadd` | 创建系统组 |
| `groupdel` | 删除系统组 |
| `groupmod` | 修改组属性 |
| `passwd` | 修改用户密码 |
| `chpasswd` | 批量修改密码 |
| `mount` | 挂载文件系统 |
| `umount` | 卸载文件系统 |
| `iptables` | 防火墙规则管理 |
| `nft` | nftables 防火墙 |
| `visudo` | sudoers 文件编辑 |
| `update-alternatives` | 系统默认程序修改 |

---

### 3.2 Layer 2: CRITICAL_PROTECTED

交互模式弹窗，静默模式自动拒绝。覆盖两类操作：

#### 3.2.1 从 L1 降级的命令（6 条）

开发场景存在合理使用需求，但不应无人值守时自动执行。

| 命令 | 降级理由 |
|------|---------|
| `npx` | `npx create-next-app` 等是标准开发操作 |
| `kill` | 常需杀掉卡住的 dev server |
| `pkill` | 按进程名终止 |
| `killall` | 同上 |
| `taskkill` | Windows 下的进程终止 |
| `chmod` | `chmod +x` 是 Linux 常见操作 |

#### 3.2.2 从 L3 升级的危险操作（5 条规则）

这些操作不可逆或对外可见，静默模式下不应自动放行。

| 操作 | 检查条件 | 升级理由 |
|------|---------|---------|
| `git push --force` | `git push` + `--force`/`-f`/`--force-with-lease` | 可永久覆盖远程提交历史 |
| 包发布 | `npm/pnpm/yarn publish` | 发布到公共仓库，对外可见 |
| Docker 卷删除 | `docker volume rm/remove/prune` | 数据不可恢复 |
| Docker 系统清理 | `docker system prune` | 批量销毁镜像/容器/卷 |
| Docker Compose 销毁 | `docker compose down -v` | 销毁数据卷 |

#### 3.2.3 关键路径写保护（新增）

拦截所有工具（Bash + Read/Edit/Write）对以下路径的**写操作**。交互模式弹窗确认，静默模式直接拒绝。

| 保护目标 | 路径模式 |
|----------|---------|
| Guard 二进制 | `*/.claude/hooks/guard.exe` |
| Guard 数据 | `*/.claude/hooks/data/*` |
| 钩子脚本 | `*/.claude/hooks/*.sh` |
| Claude Code 全局设置 | `*/.claude/settings.json` |
| 系统 hosts | `*/etc/hosts`, `*/drivers/etc/hosts` |
| Git 全局配置 | `*/.gitconfig`, `*/.config/git/*` |
| npm 全局配置 | `*/.npmrc` |
| SSH 密钥与配置 | `*/.ssh/*` |
| Shell 配置文件 | `*/.bashrc`, `*/.bash_profile`, `*/.profile`, `*/.zshrc` |

---

### 3.3 Layer 3: INTERACTIVE_AUTH

交互模式弹窗，静默模式自动放行。这些操作有一定风险但在自动化场景中可接受。

#### 3.3.1 子检查器执行顺序

| 序号 | 检查器 | 覆盖操作 |
|------|--------|---------|
| 3a | `checkGitRemoteAuth` | `git remote add/set-url/remove/rm/rename`、`git config remote.*` |
| 3b | `checkNetworkAuth` | `ssh`、`scp`、`rsync`、`nc`、`netcat`、`ncat`、`telnet`、`ftp`、`sftp` |
| 3d | `checkGlobalInstallAuth` | `npm/pnpm/yarn -g`、`pip install`（无 venv）、`cargo install`、`go install`、`gem install`、`dotnet tool install -g` |
| 3e | `checkDangerousOpsAuth` | 见下表 |
| 3c | `checkPathSensitiveAuth` | `rm`/`rmdir` 跨目录路径 |
| pre | `checkPipeToShell` | `curl/wget \| bash/sh/python/...` |

#### 3.3.2 checkDangerousOpsAuth 保留规则

| 操作 | 检查条件 |
|------|---------|
| git reset --hard | `git reset` + `--hard` |
| git checkout 丢弃 | `git checkout` + `--` 或 `.` |
| git restore 丢弃 | `git restore` + `.` |
| git clean | `git clean` + `-f` |
| git branch 删除 | `git branch` + `-D`/`-d`/`--delete` |
| pip/pip3 uninstall | `pip/pip3 uninstall` |
| gem uninstall | `gem uninstall` |
| PowerShell 混淆 | `powershell/pwsh -EncodedCommand` |
| cp/mv 跨项目 | `cp`/`mv` 目标路径在项目外 |

---

### 3.4 Layer 4: PATH_BOUNDARY

不变。扫描所有命令参数中的绝对路径，越界触发授权（交互弹窗/静默放行）。可通过 `allowedPaths` 配置白名单。

---

## 4. 实施计划

### 4.1 文件改动清单

| 文件 | 改动内容 |
|------|---------|
| `config.go` | 新增 `Mode` 字段（`"interactive"` / `"silent"`），默认 `"interactive"` |
| `layers.go` | (1) L1 新增 39 条命令 (2) L1 移除 npx、kill 系列、chmod (3) 新增 `checkCriticalCommands()` 和 `checkCriticalPaths()` 函数 (4) 从 `checkDangerousOpsAuth` 中移除升级到 L2 的 5 条规则 |
| `main.go` | (1) `handleBashTool` Pass 2 新增 L2 检查 (2) `handleFileTool` 新增关键路径写保护检查 (3) `handleInteractiveAuth` 新增 mode 参数，根据模式决定弹窗/自动放行 (4) 新增 `handleCriticalAuth` 函数，根据模式决定弹窗/自动拒绝 |
| `guard_test.go` | 新增 `TestCriticalCommands`、`TestCriticalPaths`，更新 `TestAlwaysBlocked`、`TestDangerousOpsAuth` |

### 4.2 实施步骤

1. `config.go`：添加 Mode 字段和解析逻辑
2. `layers.go`：更新 L1 规则表 + 新增 L2 检查函数
3. `main.go`：实现双模式分发逻辑
4. `guard_test.go`：全面更新测试用例
5. 编译、部署、验证
6. 提交并推送

---

## 5. Skill 模式切换

通过 Claude Code Skill `/lastguardian` 切换模式，无需手动编辑配置文件。

### 5.1 使用方式

```
/lastguardian interactive   — 切换为交互模式（弹窗审批）
/lastguardian silent        — 切换为静默模式（L2 自动拒绝，L3/L4 自动放行）
/lastguardian               — 查看当前模式
```

### 5.2 技能文件结构

```
~/.claude/skills/lastguardian/lastguardian/
├── SKILL.md                     — 技能描述与触发条件
└── scripts/
    └── switch_mode.py           — 模式切换脚本
```

### 5.3 实现原理

`switch_mode.py` 读写 `~/.claude/hooks/data/guard-config.json` 的 `mode` 字段。guard.exe 每次调用时读取该配置，切换即时生效。

脚本输出统一为 JSON 格式，无参数时查询当前模式，有参数时更新后返回新模式。

### 5.4 静默模式执行回顾

当从 silent 切换回 interactive 时，脚本自动完成以下流程：

1. 读取配置中的 `silent_since` 时间戳（进入静默模式时自动记录）
2. 调用 `guard-history.exe list -since <timestamp> -json` 获取静默期间所有操作记录
3. 将操作列表作为 `silent_history` 字段输出
4. SKILL.md 指导 Claude 基于该列表生成语义级回顾报告

#### 输出格式

普通切换或查询：
```json
{"mode": "interactive"}
```

静默 → 交互切换（含历史回顾）：
```json
{
  "mode": "interactive",
  "silent_since": "2026-03-16T14:49:14",
  "silent_history": [
    {"tool_name": "Bash", "raw_command": "...", "triggered_layers": "...", "final_action": "allow", ...},
    ...
  ]
}
```

#### 回顾报告生成规则

由 Claude 根据 SKILL.md 中的指引生成，要求：

- 不逐条列举命令，而是按语义目的分组（如"项目探索"、"代码修改"、"构建测试"）
- 高亮显示 L2 CRITICAL_PROTECTED 触发的操作（静默模式下被自动拒绝的）
- 高亮显示 L3 INTERACTIVE_AUTH 触发的操作（静默模式下被自动放行的）
- 报告包含时间段、操作总数、分类摘要

#### 数据流

```
用户: /lastguardian interactive
  ↓
switch_mode.py:
  1. 读取 guard-config.json 中的 silent_since
  2. 调用 guard-history.exe list -since <timestamp> -json
  3. 输出 {mode, silent_since, silent_history}
  4. 清除 silent_since，写回 config
  ↓
SKILL.md 指导 Claude:
  解析 silent_history → 语义分组 → 生成回顾报告
  ↓
用户看到：模式切换确认 + 执行回顾报告
```

---

## 6. 配置文件示例

```json
{
  "mode": "interactive",
  "session_cache": {
    "enabled": true,
    "ttl_hours": 4
  },
  "timeout_seconds": 60,
  "allowed_paths": [
    "C:\\Users\\king\\.claude\\hooks\\data\\sessions"
  ],
  "critical_paths": [
    "*/.claude/hooks/guard.exe",
    "*/.claude/hooks/data/*",
    "*/.claude/hooks/*.sh",
    "*/.claude/settings.json",
    "*/etc/hosts",
    "*/drivers/etc/hosts",
    "*/.gitconfig",
    "*/.config/git/*",
    "*/.npmrc",
    "*/.ssh/*",
    "*/.bashrc",
    "*/.bash_profile",
    "*/.profile",
    "*/.zshrc"
  ]
}
```
