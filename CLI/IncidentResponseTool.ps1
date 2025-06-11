# Incident Response CLI Tool
# Author: Edward Byrd

#---------------------------
# Show-TestBanner Helper
#---------------------------
function Show-TestBanner {
    param([string]$Title)
    if ($Global:TestMode) {
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Yellow
        Write-Host ("    TEST MODE: {0}" -f $Title) -ForegroundColor Yellow
        Write-Host ("=" * 60) -ForegroundColor Yellow
        Write-Host ""
    }
}

#---------------------------
# Initialization & Imports
#---------------------------
Clear-Host
$Global:TestMode = $false

# Import shared module (password generator, utilities)
$ModulePath = "$PSScriptRoot\..\Modules\IncidentResponseCore\IncidentResponseCore.psm1"
Import-Module $ModulePath -Force

# Connect to Microsoft Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
$null = Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All","Device.Read.All","AuditLog.Read.All" -NoWelcome

# Retrieve admin identity from current Graph context
$ctx = Get-MgContext -ErrorAction Stop
$Global:AdminUPN = $ctx.Account

# Prompt for compromised user UPN
do {
    $Global:CompromisedUserUPN = Read-Host "Enter compromised user UPN"
} while ([string]::IsNullOrWhiteSpace($Global:CompromisedUserUPN))

# Get target details
$target = Get-MgUser -UserId $Global:CompromisedUserUPN -Property DisplayName,Mail
$Global:CompromisedDisplayName = $target.DisplayName
if ([string]::IsNullOrEmpty($target.Mail)) {
    $Global:CompromisedEmail = $Global:CompromisedUserUPN
} else {
    $Global:CompromisedEmail = $target.Mail
}

Write-Host "Target: $Global:CompromisedDisplayName <$Global:CompromisedEmail>" -ForegroundColor Green
Start-Sleep -Seconds 1

# Ensure Exchange Online module
if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
}
Import-Module ExchangeOnlineManagement
if (-not (Get-ConnectionInformation)) { Connect-ExchangeOnline }

# Create session folder and log file path
$desktop              = [Environment]::GetFolderPath('Desktop')
$baseFolder           = Join-Path $desktop 'Incident Response'
if (-not (Test-Path $baseFolder)) {
    New-Item -Path $baseFolder -ItemType Directory | Out-Null
}
$sessionTs                 = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$Global:IncidentFolderPath = Join-Path $baseFolder "Session_$sessionTs"
New-Item -Path $Global:IncidentFolderPath -ItemType Directory | Out-Null
$Global:ActionLogPath      = Join-Path $Global:IncidentFolderPath 'ActionLog.txt'

#---------------------------
# Action Logger
#---------------------------
function Log-Action {
    param([string]$Action)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    if ($Global:TestMode) { $mode = 'TEST MODE' } else { $mode = 'LIVE' }
    $entry = "[$timestamp][$mode] Admin: $Global:AdminUPN; Action: $Action; Target: $Global:CompromisedDisplayName <$Global:CompromisedEmail>"
    Add-Content -Path $Global:ActionLogPath -Value $entry
}

#---------------------------
# Task State Trackers
#---------------------------
$Global:ContainmentTasksCompleted    = @{ Revoke=$false; BlockSignIn=$false; ResetPass=$false }
$Global:MailboxTasksCompleted        = @{ ExportRules=$false; RemoveRules=$false; SearchSuspicious=$false }
$Global:LogTasksCompleted            = @{ SigninLogs=$false; AuditLogs=$false }
$Global:DeviceTasksCompleted         = @{ Devices=$false; Roles=$false }
$Global:FinalizeTasksCompleted       = @{ Summary=$false }
$Global:RemediationTasksCompleted    = @{ Reenable=$false }

#---------------------------
# Utility Functions
#---------------------------
function Mark-TaskComplete {
    param($taskName)
    foreach ($dict in @(
        $Global:ContainmentTasksCompleted,
        $Global:MailboxTasksCompleted,
        $Global:LogTasksCompleted,
        $Global:DeviceTasksCompleted,
        $Global:FinalizeTasksCompleted,
        $Global:RemediationTasksCompleted
    )) {
        if ($dict.ContainsKey($taskName)) {
            $dict[$taskName] = $true
        }
    }
}

function Get-TaskMarker {
    param($taskName)
    foreach ($dict in @(
        $Global:ContainmentTasksCompleted,
        $Global:MailboxTasksCompleted,
        $Global:LogTasksCompleted,
        $Global:DeviceTasksCompleted,
        $Global:FinalizeTasksCompleted,
        $Global:RemediationTasksCompleted
    )) {
        if ($dict.ContainsKey($taskName)) {
            if ($dict[$taskName]) { return '*' }
            else { return ' ' }
        }
    }
    return ' '
}

function Write-CliOutput {
    param($text)
    Write-Host $text -ForegroundColor Cyan
}

function Pause-And-Wait {
    Read-Host "Press Enter to continue"
}

function Check-RequiredTasks {
    if ($Global:ContainmentTasksCompleted.Values -contains $false) {
        Write-CliOutput "Complete all Containment tasks first."
        Pause-And-Wait
        return $false
    }
    if ($Global:LogTasksCompleted.Values -contains $false) {
        Write-CliOutput "Complete all Log Collection tasks first."
        Pause-And-Wait
        return $false
    }
    return $true
}

#---------------------------
# Export Logs
#---------------------------
function Export-IncidentLogs {
    Clear-Host
    Show-TestBanner -Title 'Export Incident Logs'
    Write-Host "=== Export Incident Logs ===" -ForegroundColor Yellow

    $ts   = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $path = Join-Path $Global:IncidentFolderPath "Logs_$ts"
    New-Item -Path $path -ItemType Directory | Out-Null

    Write-Host "Collecting sign-in logs..."
    Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$Global:CompromisedUserUPN'" |
        Export-Csv (Join-Path $path 'SigninLogs.csv') -NoTypeInformation
    Mark-TaskComplete 'SigninLogs'

    Write-Host "Collecting unified audit logs..."
    Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -UserIds $Global:CompromisedUserUPN |
        Export-Csv (Join-Path $path 'UnifiedAuditLog.csv') -NoTypeInformation
    Mark-TaskComplete 'AuditLogs'

    Write-Host "Exporting detailed inbox rules..."
    Get-InboxRule -Mailbox $Global:CompromisedUserUPN |
        Select-Object Name,Enabled,Priority,Description,From,SubjectContainsWords,RedirectTo,MoveToFolder,StopProcessingRules |
        Export-Csv (Join-Path $path 'InboxRules.csv') -NoTypeInformation
    Mark-TaskComplete 'ExportRules'

    Log-Action -Action 'Export incident logs'
    Write-CliOutput "Logs saved to $path"
    Pause-And-Wait
}

#---------------------------
# Containment Menu
#---------------------------
function Show-ContainmentMenu {
    do {
        Clear-Host
        Show-TestBanner -Title 'Containment & Account Lockdown'
        Write-Host "Target: $Global:CompromisedDisplayName <$Global:CompromisedEmail>" -ForegroundColor Cyan
        Write-Host "=== Containment & Account Lockdown ===" -ForegroundColor Yellow
        Write-Host "1. Revoke user sessions $(Get-TaskMarker 'Revoke')"
        Write-Host "2. Block user sign-in $(Get-TaskMarker 'BlockSignIn')"
        Write-Host "3. Reset user password $(Get-TaskMarker 'ResetPass')"
        Write-Host "4. Return to main menu"
        $choice = Read-Host "Choose an option"

        switch ($choice) {
            '1' {
                if ($Global:TestMode) {
                    Write-Host "[TEST MODE] Simulating revoke" -ForegroundColor Yellow
                } else {
                    Revoke-MgUserSignInSession -UserId $Global:CompromisedUserUPN | Out-Null
                    Mark-TaskComplete 'Revoke'
                    Write-CliOutput "Sessions revoked"
                }
                Log-Action -Action 'Revoke user sessions'
                Pause-And-Wait
            }
            '2' {
                if ($Global:TestMode) {
                    Write-Host "[TEST MODE] Simulating block" -ForegroundColor Yellow
                } else {
                    Update-MgUser -UserId $Global:CompromisedUserUPN -AccountEnabled:$false
                    Mark-TaskComplete 'BlockSignIn'
                    Write-CliOutput "Sign-in blocked"
                }
                Log-Action -Action 'Block user sign-in'
                Pause-And-Wait
            }
            '3' {
                if ($Global:TestMode) {
                    Write-Host "[TEST MODE] Simulating password reset" -ForegroundColor Yellow
                } else {
                    $newPass = New-SecurePassword
                    Update-MgUser -UserId $Global:CompromisedUserUPN -PasswordProfile @{
                        Password                        = $newPass
                        ForceChangePasswordNextSignIn = $true
                    }
                    Mark-TaskComplete 'ResetPass'
                    Write-CliOutput "Password reset to $newPass"
                }
                Log-Action -Action 'Reset user password'
                Pause-And-Wait
            }
            '4' { return }
            default {
                Write-CliOutput "Invalid selection."
                Pause-And-Wait
            }
        }
    } while ($true)
}

#---------------------------
# Remediation Menu
#---------------------------
function Show-RemediationMenu {
    if (-not (Check-RequiredTasks)) {
        Write-CliOutput "Warning: Some required tasks are incomplete. Proceed anyway? (Y/N)"
        $override = Read-Host
        if ($override -ne 'Y') { return }
    }
    do {
        Clear-Host
        Show-TestBanner -Title 'Remediation & Recovery'
        Write-Host "Target: $Global:CompromisedDisplayName <$Global:CompromisedEmail>" -ForegroundColor Cyan
        Write-Host "=== Remediation & Recovery ===" -ForegroundColor Yellow
        Write-Host "1. Re-enable user account $(Get-TaskMarker 'Reenable')"
        Write-Host "2. Finalize & Summarize $(Get-TaskMarker 'Summary')"
        Write-Host "3. Return to main menu"
        $choice = Read-Host "Choose an option"

        switch ($choice) {
            '1' {
                if ($Global:TestMode) {
                    Write-Host "[TEST MODE] Simulating re-enable" -ForegroundColor Yellow
                } else {
                    Update-MgUser -UserId $Global:CompromisedUserUPN -AccountEnabled:$true
                    Mark-TaskComplete 'Reenable'
                    Write-CliOutput "Account re-enabled"
                }
                Log-Action -Action 'Re-enable user account'
                Pause-And-Wait
            }
            '2' {
                if ($Global:TestMode) {
                    Write-Host "[TEST MODE] Skipping final summary" -ForegroundColor Yellow
                } else {
                    $ts = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
                    "Incident $($Global:CompromisedUserUPN) done at $ts" |
                        Out-File (Join-Path $Global:IncidentFolderPath "Summary_$ts.txt")
                    Mark-TaskComplete 'Summary'
                    Write-CliOutput "Summary created"
                }
                Log-Action -Action 'Finalize & Summarize'
                Pause-And-Wait
            }
            '3' { return }
            default {
                Write-CliOutput "Invalid selection."
                Pause-And-Wait
            }
        }
    } while ($true)
}

#---------------------------
# Main Menu
#---------------------------
function Show-MainMenu {
    do {
        Clear-Host
        Write-Host "=== Incident Response Tool ===" -ForegroundColor Cyan
        Write-Host "Target: $Global:CompromisedDisplayName <$Global:CompromisedEmail>" -ForegroundColor Cyan
        if ($Global:TestMode) { Write-Host "[TEST MODE: ON]" -ForegroundColor DarkYellow }
        else { Write-Host "[TEST MODE: OFF]" -ForegroundColor DarkYellow }

        Write-Host "1. Containment & Account Lockdown"
        Write-Host "2. Export Incident Logs"
        Write-Host "3. Remediation & Recovery"
        Write-Host "4. Set/Change Compromised User UPN"
        Write-Host "5. Exit"
        Write-Host "T. Toggle Test Mode"

        $choice = Read-Host "Choose an option"
        switch ($choice) {
            '1' { Show-ContainmentMenu; continue }
            '2' { Export-IncidentLogs; continue }
            '3' { Show-RemediationMenu; continue }
            '4' {
                do {
                    $Global:CompromisedUserUPN = Read-Host "Enter new UPN"
                } while ([string]::IsNullOrWhiteSpace($Global:CompromisedUserUPN))

                $target = Get-MgUser -UserId $Global:CompromisedUserUPN -Property DisplayName,Mail
                $Global:CompromisedDisplayName = $target.DisplayName
                if ([string]::IsNullOrEmpty($target.Mail)) {
                    $Global:CompromisedEmail = $Global:CompromisedUserUPN
                } else {
                    $Global:CompromisedEmail = $target.Mail
                }

                Write-CliOutput "Target set to $Global:CompromisedDisplayName <$Global:CompromisedEmail>"
                Pause-And-Wait
                continue
            }
            '5' {
                Disconnect-MgGraph | Out-Null
                Clear-Host
                Write-Host "Exiting..." -ForegroundColor Yellow
                exit
            }
            'T' { $Global:TestMode = -not $Global:TestMode; continue }
            default {
                Write-CliOutput "Invalid choice."
                Pause-And-Wait
                continue
            }
        }
    } while ($true)
}

# Launch tool
Show-MainMenu
