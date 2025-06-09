# Incident Response CLI Tool
# Author: Edward Byrd

Clear-Host
$TestMode = $false

$ModulePath = "$PSScriptRoot\..\Modules\IncidentResponseCore\IncidentResponseCore.psm1"
Import-Module $ModulePath -Force

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
$null = Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "Device.Read.All", "AuditLog.Read.All" -NoWelcome

Write-Host "`nWelcome to the Incident Response CLI Tool" -ForegroundColor Cyan
do {
    $Global:CompromisedUserUPN = Read-Host "Please enter the UPN of the compromised user"
} while ([string]::IsNullOrWhiteSpace($Global:CompromisedUserUPN))
Write-Host "`nTarget set to: $Global:CompromisedUserUPN" -ForegroundColor Green
Start-Sleep -Seconds 1

if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
}
Import-Module ExchangeOnlineManagement
if (-not (Get-ConnectionInformation)) { Connect-ExchangeOnline }

$Global:ContainmentTasksCompleted = @{
    Revoke = $false
    BlockSignIn = $false
    ResetPass = $false
}

function Mark-TaskComplete {
    param ($taskName)
    if ($Global:ContainmentTasksCompleted.ContainsKey($taskName)) {
        $Global:ContainmentTasksCompleted[$taskName] = $true
    }
}

function Get-TaskMarker {
    param ($taskName)
    if ($Global:ContainmentTasksCompleted[$taskName]) { return "*" }
    else { return " " }
}

function Write-CliOutput {
    param ($text)
    Write-Host $text -ForegroundColor Cyan
}

function Pause-And-Wait {
    Write-Host ""
    Read-Host "Press Enter to return to the previous menu"
}

function Export-IncidentLogs {
    Clear-Host
    Write-Host "=== Exporting Incident Logs ===" -ForegroundColor Yellow
    if ($Global:CompromisedUserUPN) { Write-Host "Target: $Global:CompromisedUserUPN" -ForegroundColor Cyan }

    $confirm = Read-Host "Do you want to proceed with exporting logs for $Global:CompromisedUserUPN? (Y/N)"
    if ($confirm -ne "Y") {
        Write-Host "Export cancelled." -ForegroundColor Red
        Pause-And-Wait
        Show-MainMenu
        return
    }

    if ($TestMode) {
        Write-Host "[TEST MODE ENABLED] Simulating log export for $Global:CompromisedUserUPN" -ForegroundColor DarkYellow
        Write-Host "Command: Export sign-in logs, directory audit, mailbox rules, device registration, and IOC summary." -ForegroundColor DarkGray
    } else {
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $exportPath = "C:\\Optimal\\Incident_Response\\Incident_$timestamp"
        New-Item -Path $exportPath -ItemType Directory -Force | Out-Null

        Write-Host "Exporting logs to: $exportPath" -ForegroundColor Cyan
        Write-Progress -Activity "Exporting Incident Logs" -Status "Initializing..." -PercentComplete 0

        Write-Progress -Activity "Exporting Incident Logs" -Status "Collecting sign-in logs..." -PercentComplete 20
        Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$Global:CompromisedUserUPN'" | Export-Csv "$exportPath\SignInLogs.csv" -NoTypeInformation
        Write-Progress -Activity "Exporting Incident Logs" -Status "Collecting directory audit logs..." -PercentComplete 40
        Get-MgAuditLogDirectoryAudit -Filter "initiatedBy/user/userPrincipalName eq '$Global:CompromisedUserUPN'" | Export-Csv "$exportPath\DirectoryAudit.csv" -NoTypeInformation

        $rules = Get-InboxRule -Mailbox $Global:CompromisedUserUPN
        Write-Progress -Activity "Exporting Incident Logs" -Status "Collecting mailbox rules..." -PercentComplete 60
        $rules | Export-Csv "$exportPath\MailboxRules.csv" -NoTypeInformation

        Write-Progress -Activity "Exporting Incident Logs" -Status "Collecting device registration info..." -PercentComplete 80
        Get-MgDevice -Filter "registeredOwners/any(o:o/userPrincipalName eq '$Global:CompromisedUserUPN')" | Export-Csv "$exportPath\DeviceInfo.csv" -NoTypeInformation

        $ioc = @{
            UserUPN = $Global:CompromisedUserUPN
            ExportPath = $exportPath
            Timestamp = (Get-Date).ToString("s")
        }
        $iocSummary = "IOC Summary Report"
        $iocSummary += "`n-------------------"
        $iocSummary += "`nUserUPN: $($ioc.UserUPN)"
        $iocSummary += "`nExportPath: $($ioc.ExportPath)"
        $iocSummary += "`nTimestamp: $($ioc.Timestamp)"
        Write-Progress -Activity "Exporting Incident Logs" -Status "Finalizing IOC summary..." -PercentComplete 95
        $iocSummary | Out-File "$exportPath\IOC_Summary.txt" -Encoding utf8
        Write-Progress -Activity "Exporting Incident Logs" -Completed -Status "Done"
    }

    Pause-And-Wait
    Export-IncidentLogs
}

function Show-MainMenu {
    Clear-Host
    Write-Host "=== Incident Response Tool ===" -ForegroundColor Cyan

    if ($Global:CompromisedUserUPN) {
        Write-Host "Target: $Global:CompromisedUserUPN" -ForegroundColor Cyan
        try {
            $user = Get-MgUser -UserId $Global:CompromisedUserUPN
            Write-Host "Display Name    : $($user.DisplayName)" -ForegroundColor DarkGray
            Write-Host "Job Title       : $($user.JobTitle)" -ForegroundColor DarkGray
            $enabledStatus = if ($user.AccountEnabled) { 'ENABLED' } else { 'DISABLED' }
            
        } catch {
            Write-Host "Warning: Unable to retrieve user details." -ForegroundColor Red
        }
    }

    if ($TestMode) {
        Write-Host "[TEST MODE ENABLED] No live changes will be made." -ForegroundColor DarkYellow
    }

    Write-Host "1. Containment and Account Lockdown"
    Write-Host "2. Export Incident Logs"
    Write-Host "3. Set/Change Compromised User UPN"
    Write-Host "4. Exit"
    Write-Host "T. Toggle Test Mode (enable/disable)"

    $mainChoice = Read-Host "Choose an option"

    switch ($mainChoice) {
        '1' { 
    Clear-Host
    Write-Host "=== Containment & Account Lockdown ===" -ForegroundColor Yellow
    if ($Global:CompromisedUserUPN) { Write-Host "Target: $Global:CompromisedUserUPN" -ForegroundColor Cyan }
    if ($TestMode) { Write-Host "[TEST MODE ENABLED] Actions are simulated only." -ForegroundColor DarkYellow }

    Write-Host ("1. Revoke user sessions " + (Get-TaskMarker "Revoke"))
    Write-Host ("2. Block user sign-in " + (Get-TaskMarker "BlockSignIn"))
    Write-Host ("3. Reset user password " + (Get-TaskMarker "ResetPass"))
    Write-Host "4. Return to main menu"
    $choice = Read-Host "Choose an option"

    switch ($choice) {
        '1' {
            $confirm = Read-Host "Revoke sessions for $Global:CompromisedUserUPN? (Y/N)"
            if ($confirm -eq 'Y') {
                if ($TestMode) {
                    Write-Host "[TEST MODE] Simulating: Revoke-MgUserSignInSession -UserId $Global:CompromisedUserUPN" -ForegroundColor Yellow
                } else {
                    Write-Host "[LIVE MODE] Running: Revoke-MgUserSignInSession -UserId $Global:CompromisedUserUPN" -ForegroundColor Red
                    Revoke-MgUserSignInSession -UserId $Global:CompromisedUserUPN | Out-Null
                    Mark-TaskComplete "Revoke"
                        Write-CliOutput "Sessions revoked at $(Get-Date)"
                }
            }
            Pause-And-Wait; Show-MainMenu
        }
        '2' {
            $confirm = Read-Host "Block sign-in for $Global:CompromisedUserUPN? (Y/N)"
            if ($confirm -eq 'Y') {
                if ($TestMode) {
                    Write-Host "[TEST MODE] Simulating: Update-MgUser -UserId $Global:CompromisedUserUPN -AccountEnabled \$false" -ForegroundColor Yellow
                } else {
                    Write-Host "[LIVE MODE] Running: Update-MgUser -UserId $Global:CompromisedUserUPN -AccountEnabled \$false" -ForegroundColor Red
                    Update-MgUser -UserId $Global:CompromisedUserUPN -AccountEnabled:$false
                    Mark-TaskComplete "BlockSignIn"
                    Write-CliOutput "Account sign-in blocked at $(Get-Date)"
                }
            }
            Pause-And-Wait; Show-MainMenu
        }
        '3' {
            $confirm = Read-Host "Generate and set new password for $Global:CompromisedUserUPN? (Y/N)"
            if ($confirm -eq 'Y') {
                $newPass = New-SecurePassphrase
                Write-Host "New temporary password: $newPass" -ForegroundColor Magenta
                Read-Host "Press Enter once you've saved the password"
                if (-not $TestMode) {
                    Update-MgUser -UserId $Global:CompromisedUserUPN -PasswordProfile @{
                        ForceChangePasswordNextSignIn = $true
                        Password = $newPass
                    }
                    Mark-TaskComplete "ResetPass"
                    Write-CliOutput "Password reset at $(Get-Date)"
                } else {
                    Write-Host "[TEST MODE] Simulating password reset for $Global:CompromisedUserUPN" -ForegroundColor Yellow
                }
            }
            Pause-And-Wait; Show-MainMenu
        }
        default {
            Show-MainMenu
        }
    }
 }
        '2' { Export-IncidentLogs }
        '3' {
            $Global:CompromisedUserUPN = Read-Host "Enter the UPN of the compromised account"
            Write-Host "Compromised user set to: $Global:CompromisedUserUPN" -ForegroundColor Cyan
    $Global:ContainmentTasksCompleted.Revoke = $false
    $Global:ContainmentTasksCompleted.BlockSignIn = $false
    $Global:ContainmentTasksCompleted.ResetPass = $false
            Pause-And-Wait
            Show-MainMenu
        }
        '4' {
            Disconnect-MgGraph | Out-Null
            Write-Host "`nExiting Incident Response CLI..." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            Clear-Host
            $Global:ContainmentTasksCompleted.Revoke = $false
            $Global:ContainmentTasksCompleted.BlockSignIn = $false
            $Global:ContainmentTasksCompleted.ResetPass = $false
            exit
        }
        'T' {
            $TestMode = -not $TestMode
            if ($TestMode) {
                Write-Host "Test Mode is now: ON" -ForegroundColor Yellow
            } else {
                Write-Host "Test Mode is now: OFF" -ForegroundColor Yellow
            }
            Pause-And-Wait
            Show-MainMenu
        }
        default {
            Write-CliOutput "Invalid choice."
            Pause-And-Wait
            Show-MainMenu
        }
    }
}

Show-MainMenu