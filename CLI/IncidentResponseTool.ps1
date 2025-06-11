# Incident Response CLI Tool
# Author: Edward Byrd

#---------------------------
# Show-TestBanner Helper
#---------------------------
function Show-TestBanner {
    param(
        [string]$Title
    )
    if ($Global:TestMode) {
        Write-Host ""
        Write-Host (("=" * 60)) -ForegroundColor Yellow
        Write-Host ("    TEST MODE: {0}" -f $Title) -ForegroundColor Yellow
        Write-Host (("=" * 60)) -ForegroundColor Yellow
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

# Prompt for compromised user UPN
do {
    $Global:CompromisedUserUPN = Read-Host "Enter compromised user UPN"
} while ([string]::IsNullOrWhiteSpace($Global:CompromisedUserUPN))
Write-Host "Target: $Global:CompromisedUserUPN" -ForegroundColor Green
Start-Sleep -Seconds 1

# Ensure Exchange Online module
if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
}
Import-Module ExchangeOnlineManagement
if (-not (Get-ConnectionInformation)) { Connect-ExchangeOnline }

#---------------------------
# Task State Trackers
#---------------------------
$Global:ContainmentTasksCompleted = @{ Revoke=$false; BlockSignIn=$false; ResetPass=$false }
$Global:MailboxTasksCompleted   = @{ ExportRules=$false; RemoveRules=$false; SearchSuspicious=$false }
$Global:LogTasksCompleted       = @{ SigninLogs=$false; AuditLogs=$false }
$Global:DeviceTasksCompleted    = @{ Devices=$false; Roles=$false }
$Global:FinalizeTasksCompleted  = @{ Summary=$false }
$Global:RemediationTasksCompleted = @{ Reenable=$false }

#---------------------------
# Utility Functions
#---------------------------
function Mark-TaskComplete {
    param($taskName)
    foreach($dict in @(
        $Global:ContainmentTasksCompleted,
        $Global:MailboxTasksCompleted,
        $Global:LogTasksCompleted,
        $Global:DeviceTasksCompleted,
        $Global:FinalizeTasksCompleted,
        $Global:RemediationTasksCompleted
    )) {
        if($dict.ContainsKey($taskName)) {
            $dict[$taskName] = $true
        }
    }
}

function Get-TaskMarker {
    param($taskName)
    foreach($dict in @(
        $Global:ContainmentTasksCompleted,
        $Global:MailboxTasksCompleted,
        $Global:LogTasksCompleted,
        $Global:DeviceTasksCompleted,
        $Global:FinalizeTasksCompleted,
        $Global:RemediationTasksCompleted
    )) {
        if($dict.ContainsKey($taskName)) {
            if($dict[$taskName]) { return "*" } else { return " " }
        }
    }
    return " "
}

function Write-CliOutput {
    param($text)
    Write-Host $text -ForegroundColor Cyan
}

function Pause-And-Wait {
    Read-Host "Press Enter to continue"
}

function Check-RequiredTasks {
    if($Global:ContainmentTasksCompleted.Values -contains $false) {
        Write-CliOutput "Complete all Containment tasks first."
        Pause-And-Wait; return $false
    }
    if($Global:LogTasksCompleted.Values -contains $false) {
        Write-CliOutput "Complete all Log Collection tasks first."
        Pause-And-Wait; return $false
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

    $desktop    = [Environment]::GetFolderPath('Desktop')
    $baseFolder = Join-Path $desktop 'Incident Response'
    if (-not (Test-Path $baseFolder)) {
        New-Item -Path $baseFolder -ItemType Directory | Out-Null
    }

    $ts   = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $path = Join-Path $baseFolder ("Incident_$ts")
    New-Item -Path $path -ItemType Directory | Out-Null

    Write-Host "Collecting sign-in logs..."
    Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$Global:CompromisedUserUPN'" |
        Export-Csv (Join-Path $path 'SigninLogs.csv') -NoTypeInformation
    Mark-TaskComplete "SigninLogs"

    Write-Host "Collecting unified audit logs..."
    Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -UserIds $Global:CompromisedUserUPN |
        Export-Csv (Join-Path $path 'UnifiedAuditLog.csv') -NoTypeInformation
    Mark-TaskComplete "AuditLogs"

    Write-Host "Exporting detailed inbox rules..."
    $rules = Get-InboxRule -Mailbox $Global:CompromisedUserUPN
    $props = @(
        'Name','Enabled','Priority','Description',
        'From','SubjectContainsWords','RedirectTo','MoveToFolder','StopProcessingRules'
    )
    $rules | Select-Object $props |
        Export-Csv (Join-Path $path 'InboxRules_Detailed.csv') -NoTypeInformation
    Mark-TaskComplete "ExportRules"

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
        Write-Host "=== Containment & Account Lockdown ===" -ForegroundColor Yellow
        Write-Host ("1. Revoke user sessions " + (Get-TaskMarker "Revoke"))
        Write-Host ("2. Block user sign-in " + (Get-TaskMarker "BlockSignIn"))
        Write-Host ("3. Reset user password " + (Get-TaskMarker "ResetPass"))
        Write-Host "4. Return to main menu"
        $choice = Read-Host "Choose an option"

        switch($choice) {
            '1' {
                if($Global:TestMode) { Write-Host "[TEST MODE] Simulating revoke" -ForegroundColor Yellow } else {
                    Revoke-MgUserSignInSession -UserId $Global:CompromisedUserUPN | Out-Null; Mark-TaskComplete "Revoke"; Write-CliOutput "Sessions revoked"
                }
                Pause-And-Wait
            }
            '2' {
                if($Global:TestMode) { Write-Host "[TEST MODE] Simulating block" -ForegroundColor Yellow } else {
                    Update-MgUser -UserId $Global:CompromisedUserUPN -AccountEnabled:$false; Mark-TaskComplete "BlockSignIn"; Write-CliOutput "Sign-in blocked"
                }
                Pause-And-Wait
            }
            '3' {
                if($Global:TestMode) { Write-Host "[TEST MODE] Simulating password reset" -ForegroundColor Yellow } else {
                    $newPass = New-SecurePassword; Update-MgUser -UserId $Global:CompromisedUserUPN -PasswordProfile @{ Password=$newPass; ForceChangePasswordNextSignIn=$true }
                    Mark-TaskComplete "ResetPass"; Write-CliOutput "Password reset to $newPass"
                }
                Pause-And-Wait
            }
            '4' { return }
            default { Write-CliOutput "Invalid selection."; Pause-And-Wait }
        }
    } while($true)
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
        Write-Host "=== Remediation & Recovery ===" -ForegroundColor Yellow
        Write-Host ("1. Re-enable user account " + (Get-TaskMarker "Reenable"))
        Write-Host "2. Notify end user"
        Write-Host ("3. Finalize & Summarize " + (Get-TaskMarker "Summary"))
        Write-Host "4. Return to main menu"
        $choice = Read-Host "Choose an option"

        switch($choice) {
            '1' {
                if($Global:TestMode) { Write-Host "[TEST MODE] Simulating re-enable" -ForegroundColor Yellow } else {
                    Update-MgUser -UserId $Global:CompromisedUserUPN -AccountEnabled:$true; Mark-TaskComplete "Reenable"; Write-CliOutput "Account re-enabled"
                }
                Pause-And-Wait
            }
            '2' { Write-CliOutput "Reminder sent to user."; Pause-And-Wait }
            '3' {
                if($Global:TestMode) { Write-Host "[TEST MODE] Skipping final summary" -ForegroundColor Yellow } else {
                    $ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"; "Incident $($Global:CompromisedUserUPN) done at $ts" | Out-File "${path}\Summary-$ts.txt"; Mark-TaskComplete "Summary"; Write-CliOutput "Summary created"
                }
                Pause-And-Wait
            }
            '4' { return }
            default { Write-CliOutput "Invalid selection."; Pause-And-Wait }
        }
    } while($true)
}

#---------------------------
# Main Menu
#---------------------------
function Show-MainMenu {
    do {
        Clear-Host
        Write-Host "=== Incident Response Tool ===" -ForegroundColor Cyan
        if($Global:CompromisedUserUPN) { Write-Host "Target: $Global:CompromisedUserUPN" -ForegroundColor Cyan }
        if($Global:TestMode) { Write-Host "[TEST MODE: ON] Simulation mode." -ForegroundColor DarkYellow } else { Write-Host "[TEST MODE: OFF]" -ForegroundColor DarkYellow }

        Write-Host "1. Containment & Account Lockdown"
        Write-Host "2. Export Incident Logs"
        Write-Host "3. Remediation & Recovery"
        Write-Host "4. Set/Change Compromised User UPN"
        Write-Host "5. Exit"
        Write-Host "T. Toggle Test Mode"

        $choice = Read-Host "Choose an option"
        switch($choice) {
            '1' { Show-ContainmentMenu; continue }
            '2' { Export-IncidentLogs; continue }
            '3' { Show-RemediationMenu; continue }
            '4' { $Global:CompromisedUserUPN = Read-Host "Enter new UPN"; Write-CliOutput "UPN set to $Global:CompromisedUserUPN"; Pause-And-Wait; continue }
            '5' { Disconnect-MgGraph | Out-Null; Clear-Host; Write-Host "Exiting..." -ForegroundColor Yellow; exit }
            'T' { $Global:TestMode = -not $Global:TestMode; continue }
            default { Write-CliOutput "Invalid choice."; Pause-And-Wait; continue }
        }
    } while($true)
}

# Launch tool
Show-MainMenu
