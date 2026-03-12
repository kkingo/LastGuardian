package main

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ── Platform detection ──

func detectPlatform() string {
	switch runtime.GOOS {
	case "windows":
		return "windows-wpf"
	default:
		return "headless"
	}
}

// newDialogProvider creates the appropriate DialogProvider based on config and platform.
func newDialogProvider(cfg DialogCfg) DialogProvider {
	platform := cfg.Platform
	if platform == "auto" || platform == "" {
		platform = detectPlatform()
	}

	timeout := cfg.TimeoutSeconds
	if timeout <= 0 {
		timeout = 60
	}

	switch platform {
	case "windows-wpf":
		return &WindowsWPFDialog{Timeout: timeout}
	default:
		return &FallbackDialog{}
	}
}

// ── Windows WPF Dialog ──

// WindowsWPFDialog implements DialogProvider using PowerShell WPF windows.
type WindowsWPFDialog struct {
	Timeout int
}

func (d *WindowsWPFDialog) RequestApproval(summary ApprovalSummary) bool {
	script := buildWPFScript(summary, d.Timeout)

	timeout := time.Duration(d.Timeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Sta", "-Command", script)
	err := cmd.Run()
	if err != nil {
		return false // timeout, PowerShell unavailable, or user closed window
	}
	return cmd.ProcessState.ExitCode() == 0
}

func buildWPFScript(s ApprovalSummary, timeout int) string {
	// Determine visual properties based on risk level
	var title, badgeColor, bgColor string
	switch s.RiskLevel {
	case "CRITICAL":
		title = "GUARD: CRITICAL - Authorization Required"
		badgeColor = "#8B0000"
		bgColor = "#FFF5F5"
	case "HIGH":
		title = "GUARD: High Risk - Authorization Required"
		badgeColor = "#DC143C"
		bgColor = "#FFFFFF"
	default: // MEDIUM
		title = "GUARD: Authorization Required"
		badgeColor = "#FF8C00"
		bgColor = "#FFFFFF"
	}

	// Triggered layers
	layersText := psEscape(strings.Join(s.TriggeredLayers, ", "))

	// Session info
	sessionID := psEscape(s.SessionID)
	projectDir := psEscape(s.ProjectDir)
	timestamp := psEscape(s.Timestamp)

	// Tool description (Claude's intent for this operation)
	toolDescription := psEscape(s.ToolDescription)
	if toolDescription == "" {
		toolDescription = "(N/A)"
	}
	if len(toolDescription) > 500 {
		toolDescription = toolDescription[:500] + "..."
	}

	// Command preview (escape for PS)
	cmdPreview := psEscape(s.CommandPreview)
	if len(cmdPreview) > 2000 {
		cmdPreview = cmdPreview[:2000] + "..."
	}

	// Hash prefix
	hashPrefix := s.RequestHash
	if len(hashPrefix) > 8 {
		hashPrefix = hashPrefix[:8]
	}

	// Auto-close timeout for the dialog (slightly less than process timeout)
	dialogTimeout := timeout - 2
	if dialogTimeout < 5 {
		dialogTimeout = 5
	}

	return fmt.Sprintf(`
Add-Type -AssemblyName PresentationFramework

$result = $false
$window = New-Object System.Windows.Window
$window.Title = '%s'
$window.Width = 680
$window.Height = 800
$window.WindowStartupLocation = 'CenterScreen'
$window.ResizeMode = 'NoResize'
$window.Topmost = $true
$window.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString('%s')

$root = New-Object System.Windows.Controls.DockPanel
$root.Margin = '18,14,18,14'
$root.LastChildFill = $true

# === TOP: Header (Dock=Top) ===
$headerPanel = New-Object System.Windows.Controls.StackPanel
$headerPanel.Margin = '0,0,0,20'
[System.Windows.Controls.DockPanel]::SetDock($headerPanel, 'Top')

$titleRow = New-Object System.Windows.Controls.WrapPanel
$titleRow.Margin = '0,0,0,3'

$opText = New-Object System.Windows.Controls.TextBlock
$opText.Text = '%s'
$opText.FontSize = 22
$opText.FontWeight = 'Bold'
$opText.VerticalAlignment = 'Center'
$opText.Margin = '0,0,14,0'
$titleRow.Children.Add($opText)

$badge = New-Object System.Windows.Controls.Border
$badge.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString('%s')
$badge.CornerRadius = '4'
$badge.Padding = '12,4,12,4'
$badge.VerticalAlignment = 'Center'
$badgeText = New-Object System.Windows.Controls.TextBlock
$badgeText.Text = '%s'
$badgeText.FontSize = 19
$badgeText.FontWeight = 'Bold'
$badgeText.Foreground = 'White'
$badge.Child = $badgeText
$titleRow.Children.Add($badge)

$headerPanel.Children.Add($titleRow)

$layerText = New-Object System.Windows.Controls.TextBlock
$layerText.Text = 'Triggered: %s'
$layerText.FontSize = 17
$layerText.Foreground = '#555555'
$headerPanel.Children.Add($layerText)

$root.Children.Add($headerPanel)

# === TOP: Session Info (Dock=Top, fixed height 200px) ===
$infoOuter = New-Object System.Windows.Controls.DockPanel
$infoOuter.LastChildFill = $true
$infoOuter.Height = 240
$infoOuter.Margin = '0,0,0,20'
[System.Windows.Controls.DockPanel]::SetDock($infoOuter, 'Top')

$infoTitle = New-Object System.Windows.Controls.TextBlock
$infoTitle.Text = 'Session Info'
$infoTitle.FontSize = 19
$infoTitle.FontWeight = 'Bold'
$infoTitle.Margin = '0,0,0,5'
[System.Windows.Controls.DockPanel]::SetDock($infoTitle, 'Top')
$infoOuter.Children.Add($infoTitle)

$infoBorder = New-Object System.Windows.Controls.Border
$infoBorder.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#DDDDDD')
$infoBorder.BorderThickness = '1'
$infoBorder.CornerRadius = '4'
$infoBorder.Padding = '14,10,14,10'
$infoBorder.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#FAFAFA')

$infoScroll = New-Object System.Windows.Controls.ScrollViewer
$infoScroll.VerticalScrollBarVisibility = 'Auto'

$infoPanel = New-Object System.Windows.Controls.StackPanel

$opLine = New-Object System.Windows.Controls.TextBlock
$opLine.FontSize = 17
$opLine.FontFamily = 'Consolas'
$opLine.Margin = '0,0,0,5'
$opRun = New-Object System.Windows.Documents.Run
$opRun.Text = 'Operation: '
$opRun.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#888888')
$opLine.Inlines.Add($opRun)
$opVal = New-Object System.Windows.Documents.Run
$opVal.Text = '%s'
$opVal.FontWeight = 'SemiBold'
$opLine.Inlines.Add($opVal)
$infoPanel.Children.Add($opLine)

$intentLine = New-Object System.Windows.Controls.TextBlock
$intentLine.FontSize = 17
$intentLine.FontFamily = 'Consolas'
$intentLine.Margin = '0,0,0,5'
$intentLine.TextWrapping = 'Wrap'
$intentRun = New-Object System.Windows.Documents.Run
$intentRun.Text = 'Intent:    '
$intentRun.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#888888')
$intentLine.Inlines.Add($intentRun)
$intentVal = New-Object System.Windows.Documents.Run
$intentVal.Text = '%s'
$intentVal.FontWeight = 'SemiBold'
$intentLine.Inlines.Add($intentVal)
$infoPanel.Children.Add($intentLine)

$sessLine = New-Object System.Windows.Controls.TextBlock
$sessLine.FontSize = 17
$sessLine.FontFamily = 'Consolas'
$sessLine.Margin = '0,0,0,5'
$sessRun = New-Object System.Windows.Documents.Run
$sessRun.Text = 'Session:   '
$sessRun.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#888888')
$sessLine.Inlines.Add($sessRun)
$sessVal = New-Object System.Windows.Documents.Run
$sessVal.Text = '%s'
$sessLine.Inlines.Add($sessVal)
$infoPanel.Children.Add($sessLine)

$projLine = New-Object System.Windows.Controls.TextBlock
$projLine.FontSize = 17
$projLine.FontFamily = 'Consolas'
$projLine.Margin = '0,0,0,5'
$projRun = New-Object System.Windows.Documents.Run
$projRun.Text = 'Project:   '
$projRun.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#888888')
$projLine.Inlines.Add($projRun)
$projVal = New-Object System.Windows.Documents.Run
$projVal.Text = '%s'
$projLine.Inlines.Add($projVal)
$infoPanel.Children.Add($projLine)

$tsLine = New-Object System.Windows.Controls.TextBlock
$tsLine.FontSize = 17
$tsLine.FontFamily = 'Consolas'
$tsLine.Margin = '0,0,0,5'
$tsRun = New-Object System.Windows.Documents.Run
$tsRun.Text = 'Time:      '
$tsRun.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#888888')
$tsLine.Inlines.Add($tsRun)
$tsVal = New-Object System.Windows.Documents.Run
$tsVal.Text = '%s'
$tsLine.Inlines.Add($tsVal)
$infoPanel.Children.Add($tsLine)

$hashLine = New-Object System.Windows.Controls.TextBlock
$hashLine.FontSize = 17
$hashLine.FontFamily = 'Consolas'
$hashRun = New-Object System.Windows.Documents.Run
$hashRun.Text = 'Hash:      '
$hashRun.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#888888')
$hashLine.Inlines.Add($hashRun)
$hashVal = New-Object System.Windows.Documents.Run
$hashVal.Text = '%s'
$hashLine.Inlines.Add($hashVal)
$infoPanel.Children.Add($hashLine)

$infoScroll.Content = $infoPanel
$infoBorder.Child = $infoScroll
$infoOuter.Children.Add($infoBorder)
$root.Children.Add($infoOuter)

# === BOTTOM: Buttons (Dock=Bottom) ===
$btnPanel = New-Object System.Windows.Controls.StackPanel
$btnPanel.Orientation = 'Horizontal'
$btnPanel.HorizontalAlignment = 'Center'
$btnPanel.Margin = '0,20,0,0'
[System.Windows.Controls.DockPanel]::SetDock($btnPanel, 'Bottom')

$allowBtn = New-Object System.Windows.Controls.Button
$allowBtn.Content = '    Allow    '
$allowBtn.FontSize = 24
$allowBtn.Padding = '36,8,36,8'
$allowBtn.Margin = '0,0,30,0'
$allowBtn.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#4CAF50')
$allowBtn.Foreground = 'White'
$allowBtn.Add_Click({ $script:result = $true; $window.Close() })

$denyBtn = New-Object System.Windows.Controls.Button
$denyBtn.Content = '    Deny    '
$denyBtn.FontSize = 24
$denyBtn.Padding = '36,8,36,8'
$denyBtn.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#F44336')
$denyBtn.Foreground = 'White'
$denyBtn.Add_Click({ $script:result = $false; $window.Close() })

$btnPanel.Children.Add($allowBtn)
$btnPanel.Children.Add($denyBtn)
$root.Children.Add($btnPanel)

# === CENTER: Command area (LastChildFill — expands to fill) ===
$cmdWrapper = New-Object System.Windows.Controls.DockPanel
$cmdWrapper.LastChildFill = $true

$cmdLabel = New-Object System.Windows.Controls.TextBlock
$cmdLabel.Text = 'Command to execute:'
$cmdLabel.FontSize = 19
$cmdLabel.FontWeight = 'SemiBold'
$cmdLabel.Margin = '0,0,0,4'
[System.Windows.Controls.DockPanel]::SetDock($cmdLabel, 'Top')
$cmdWrapper.Children.Add($cmdLabel)

$cmdBorder = New-Object System.Windows.Controls.Border
$cmdBorder.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#CCCCCC')
$cmdBorder.BorderThickness = '1'
$cmdBorder.CornerRadius = '4'

$cmdScroll = New-Object System.Windows.Controls.ScrollViewer
$cmdScroll.VerticalScrollBarVisibility = 'Auto'

$cmdBox = New-Object System.Windows.Controls.TextBox
$cmdBox.Text = '%s'
$cmdBox.IsReadOnly = $true
$cmdBox.TextWrapping = 'Wrap'
$cmdBox.BorderThickness = '0'
$cmdBox.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#F5F5F5')
$cmdBox.Padding = '10'
$cmdBox.FontFamily = 'Consolas'
$cmdBox.FontSize = 17

$cmdScroll.Content = $cmdBox
$cmdBorder.Child = $cmdScroll
$cmdWrapper.Children.Add($cmdBorder)
$root.Children.Add($cmdWrapper)

$window.Content = $root

# Auto-close timer (deny on timeout)
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(%d)
$timer.Add_Tick({ $script:result = $false; $window.Close() })
$timer.Start()

$window.ShowDialog() | Out-Null
$timer.Stop()

if ($result) { exit 0 } else { exit 1 }
`,
		psEscape(title), bgColor,
		psEscape(s.OperationType),
		badgeColor,
		psEscape(s.RiskLevel),
		layersText,
		psEscape(s.OperationType),
		toolDescription,
		sessionID,
		projectDir,
		timestamp,
		hashPrefix,
		cmdPreview,
		dialogTimeout,
	)
}

// ── Fallback Dialog (headless) ──

// FallbackDialog always denies requests (for headless environments).
type FallbackDialog struct{}

func (d *FallbackDialog) RequestApproval(summary ApprovalSummary) bool {
	return false
}
