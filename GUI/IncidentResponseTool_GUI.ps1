# Incident Response Tool GUI (Fixed New-SecurePassword, no ternary, balanced braces)

# 1) Import shared module (password generator, utilities)
$ModulePath = Join-Path $PSScriptRoot '..\Modules\IncidentResponseCore\IncidentResponseCore.psm1'
Import-Module $ModulePath -Force

# 2) Load WPF assemblies
Add-Type -AssemblyName PresentationFramework

# 3) Load XAML UI
$xamlPath = Join-Path $PSScriptRoot 'IncidentResponseTool.xaml'
$xaml     = Get-Content -Path $xamlPath -Raw
$reader   = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader $xaml))
$window   = [Windows.Markup.XamlReader]::Load($reader)

# 4) Find controls
$UpnInput             = $window.FindName('UpnInput')
$ValidateUpnButton    = $window.FindName('ValidateUpnButton')
$TestModeOn           = $window.FindName('TestModeOn')
$TestModeOff          = $window.FindName('TestModeOff')
$StatusUserInfo       = $window.FindName('StatusUserInfo')
$MainMenuPanel        = $window.FindName('MainMenuPanel')
$ContainmentPanel     = $window.FindName('ContainmentPanel')
$ExportLogsPanel      = $window.FindName('ExportLogsPanel')
$RemediationPanel     = $window.FindName('RemediationPanel')
$ContainmentButton    = $window.FindName('ContainmentButton')
$ExportLogsButton     = $window.FindName('ExportLogsButton')
$RemediationButton    = $window.FindName('RemediationButton')
$ExitButton           = $window.FindName('ExitButton')
$RevokeButton         = $window.FindName('RevokeButton')
$BlockButton          = $window.FindName('BlockButton')
$ResetPassButton      = $window.FindName('ResetPassButton')
$ContainmentBack      = $window.FindName('ContainmentBackButton')
$SigninLogsButton     = $window.FindName('SigninLogsButton')
$UnifiedLogsButton    = $window.FindName('UnifiedLogsButton')
$InboxRulesButton     = $window.FindName('InboxRulesButton')
$LogsBackButton       = $window.FindName('LogsBackButton')
$ReenableButton       = $window.FindName('ReenableButton')
$SummarizeButton      = $window.FindName('SummarizeButton')
$RemediationBack      = $window.FindName('RemediationBackButton')
$OutputBox            = $window.FindName('OutputBox')

# 5) Authenticate
Connect-MgGraph -Scopes 'User.Read.All','Directory.Read.All','AuditLog.Read.All'
Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue
Connect-ExchangeOnline -ShowBanner:$false

# 6) Helpers
function Write-GuiOutput { param($t) $OutputBox.AppendText($t + "`r`n"); $OutputBox.ScrollToEnd() }
function Confirm-Action   { param($m) $r=[System.Windows.MessageBox]::Show($m,'Confirm',[System.Windows.MessageBoxButton]::YesNo,[System.Windows.MessageBoxImage]::Question); return $r -eq 'Yes' }
function Log-Action       { param($a) Add-Content -Path $ActionLogPath -Value ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $a) }

function Initialize-Folders {
    $base = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Incident Response'
    if (-not (Test-Path $base)) { New-Item -Path $base -ItemType Directory | Out-Null }
    $ts = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $script:IncidentFolderPath = Join-Path $base "Session_$ts"
    New-Item -Path $IncidentFolderPath -ItemType Directory | Out-Null
    $script:ActionLogPath = Join-Path $IncidentFolderPath 'ActionLog.txt'
    "[{0}] Session started for {1} ({2})" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $UserPrincipalName, $UserDisplayName |
        Out-File -FilePath $ActionLogPath -Encoding UTF8
    $script:LogsFolder = Join-Path $IncidentFolderPath "Logs_$ts"
    New-Item -Path $LogsFolder -ItemType Directory | Out-Null
}

# 7) Task functions
function Do-Revoke     { Write-GuiOutput "-- Revoking sessions"; if ($TestModeOn.IsChecked) { Write-GuiOutput "[Test] simulated"; Log-Action '[Test] revoke skipped' } elseif (Confirm-Action "Revoke sessions?") { Revoke-MgUserSignInSession -UserId $User.Id; Write-GuiOutput "Done"; Log-Action 'Sessions revoked' } }
function Do-Block      { Write-GuiOutput "-- Blocking sign-in"; if ($TestModeOn.IsChecked) { Write-GuiOutput "[Test] simulated"; Log-Action '[Test] block skipped' } elseif (Confirm-Action "Block sign-in?") { Update-MgUser -UserId $User.Id -AccountEnabled $false; Write-GuiOutput "Done"; Log-Action 'Sign-in blocked' } }
function Do-Reset      {
    $pw = New-SecurePassword
    Write-GuiOutput "-- Resetting password to $pw"
    if ($TestModeOn.IsChecked) {
        Write-GuiOutput "[Test] simulated"; Log-Action '[Test] reset skipped'
    } elseif (Confirm-Action "Reset password?") {
        Update-MgUser -UserId $User.Id -PasswordProfile @{ ForceChangePasswordNextSignIn = $true; Password = $pw }
        Write-GuiOutput "Done"; Log-Action 'Password reset'
    }
}
function Do-SigninLogs { Write-GuiOutput "-- Exporting sign-in logs"; Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$UserPrincipalName'" | Export-Csv (Join-Path $LogsFolder 'SigninLogs.csv') -NoTypeInformation; Write-GuiOutput "Done"; Log-Action 'Signin logs exported' }
function Do-Unified    { Write-GuiOutput "-- Exporting unified audit logs"; Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -UserIds $UserPrincipalName | Export-Csv (Join-Path $LogsFolder 'UnifiedAuditLog.csv') -NoTypeInformation; Write-GuiOutput "Done"; Log-Action 'Unified logs exported' }
function Do-InboxRules { Write-GuiOutput "-- Exporting inbox rules"; Get-InboxRule -Mailbox $UserPrincipalName | Select Name,Enabled,Priority,Description,From,SubjectContainsWords,RedirectTo,MoveToFolder,StopProcessingRules | Export-Csv (Join-Path $LogsFolder 'InboxRules.csv') -NoTypeInformation; Write-GuiOutput "Done"; Log-Action 'Inbox rules exported' }
function Do-Reenable   { Write-GuiOutput "-- Re-enabling account"; if ($TestModeOn.IsChecked) { Write-GuiOutput "[Test] simulated"; Log-Action '[Test] reenable skipped' } elseif (Confirm-Action "Re-enable account?") { Update-MgUser -UserId $User.Id -AccountEnabled $true; Write-GuiOutput "Done"; Log-Action 'Account re-enabled' } }
function Do-Summarize  { Write-GuiOutput "-- Finalize & summarize"; Write-GuiOutput "Session folder: $IncidentFolderPath"; Write-GuiOutput "Logs folder:    $LogsFolder"; Log-Action 'Session summarized' }

# 8) Navigation
function Show-Panel { param($panel)
    $MainMenuPanel.Visibility    = 'Collapsed'
    $ContainmentPanel.Visibility = 'Collapsed'
    $ExportLogsPanel.Visibility  = 'Collapsed'
    $RemediationPanel.Visibility = 'Collapsed'
    $panel.Visibility            = 'Visible'
}
function Show-Main  { Show-Panel $MainMenuPanel }

# 9) Button events

$ValidateUpnButton.Add_Click({
    $upn = $UpnInput.Text.Trim()
    if (-not $upn) {
        [System.Windows.MessageBox]::Show('Please enter a UPN','Error',[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Warning)
        return
    }
    try {
        $usr = Get-MgUser -UserId $upn -Property DisplayName -ErrorAction Stop
        $global:UserPrincipalName = $upn
        $global:UserDisplayName  = $usr.DisplayName
        # determine mode text
        if ($TestModeOn.IsChecked) { $modeText = 'Test' } else { $modeText = 'Live' }
        $StatusUserInfo.Text = "User: $upn ($($usr.DisplayName)) - Mode: $modeText"

        Initialize-Folders
        Show-Main
    } catch {
        [System.Windows.MessageBox]::Show('UPN not found','Error',[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error)
    }
})

$TestModeOn.Add_Checked({
    $StatusUserInfo.Text = "User: $UserPrincipalName ($UserDisplayName) - Mode: Test"
})
$TestModeOff.Add_Checked({
    $StatusUserInfo.Text = "User: $UserPrincipalName ($UserDisplayName) - Mode: Live"
})

$ContainmentButton.Add_Click({ Show-Panel $ContainmentPanel })
$ExportLogsButton.Add_Click({ Show-Panel $ExportLogsPanel })
$RemediationButton.Add_Click({ Show-Panel $RemediationPanel })

$ExitButton.Add_Click({
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    $window.Close()
})

$ContainmentBack.Add_Click({ Show-Main })
$LogsBackButton.Add_Click({ Show-Main })
$RemediationBack.Add_Click({ Show-Main })

$RevokeButton.Add_Click({ Do-Revoke })
$BlockButton.Add_Click({ Do-Block })
$ResetPassButton.Add_Click({ Do-Reset })
$SigninLogsButton.Add_Click({ Do-SigninLogs })
$UnifiedLogsButton.Add_Click({ Do-Unified })
$InboxRulesButton.Add_Click({ Do-InboxRules })
$ReenableButton.Add_Click({ Do-Reenable })
$SummarizeButton.Add_Click({ Do-Summarize })

# 10) Show the window
$window.ShowDialog() | Out-Null
