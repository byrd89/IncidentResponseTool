# Incident Response CLI Tool
# Author: Edward Byrd
# Purpose: Unified Incident Response CLI with menu-driven workflow

Clear-Host

# === CONFIGURATION ===
$TestMode = $false  # Default to OFF

$ModulePath = "$PSScriptRoot\..\Modules\IncidentResponseCore\IncidentResponseCore.psm1"
Import-Module $ModulePath -Force

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "Device.Read.All", "AuditLog.Read.All"

# Load Exchange Online
if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
}
Import-Module ExchangeOnlineManagement
if (-not (Get-ConnectionInformation)) { Connect-ExchangeOnline }

function New-SecurePassphrase {
    $words = @("Falcon", "River", "Jungle", "Orange", "Cyber", "Matrix", "Castle", "Photon", "Spark", "Neon")
    $symbols = "!@#$%^&*"
    $numbers = "0123456789"

    $word1 = Get-Random -InputObject $words
    $word2 = Get-Random -InputObject $words
    $symbol = Get-Random -InputObject $symbols.ToCharArray()
    $number = Get-Random -InputObject $numbers.ToCharArray()

    $passphrase = "$word1$symbol$word2$number" -split '' | Sort-Object {Get-Random}
    return ($passphrase -join '')
}

function Write-CliOutput {
    param ($text)
    Write-Host $text -ForegroundColor Cyan
}

function Pause-And-Wait {
    Write-Host ""
    Read-Host "Press Enter to return to the previous menu"
}

function Show-ContainmentMenu {
    Clear-Host
    Write-Host "=== Containment & Account Lockdown ===" -ForegroundColor Yellow
    if ($TestMode) { Write-Host "[TEST MODE ENABLED] Actions are simulated only." -ForegroundColor DarkYellow }
    Write-Host "1. Revoke user sessions"
    Write-Host "2. Block user sign-in"
    Write-Host "3. Reset user password"
    Write-Host "4. Return to main menu"

    $choice = Read-Host "Choose an option"

    switch ($choice) {
        '1' {
            $upn = Read-Host "Enter the compromised user's UPN"
            if ($upn) {
                $confirm = Read-Host "Revoke sessions for $upn? (Y/N)"
                if ($confirm -eq 'Y') {
                    if ($TestMode) {
                        Write-Host "[INFO] Test Mode is enabled. This action is being simulated and will not impact the actual account." -ForegroundColor DarkCyan
                        Write-Host "[TEST MODE] Simulating: Revoke sign-in sessions for $upn" -ForegroundColor Yellow
                        Write-Host "Command: Revoke-MgUserSignInSession -UserId $upn" -ForegroundColor DarkGray
                    } else {
                        $confirm2 = Read-Host "WARNING: You are about to revoke all sessions. Type Y to continue"
                        if ($confirm2 -ne "Y") { Write-Host "Action cancelled." -ForegroundColor Red; Pause-And-Wait; Show-ContainmentMenu }
                        Write-Host "[LIVE MODE] Proceeding with permanent account change..." -ForegroundColor Red
                        Write-Host "Running: Revoke-MgUserSignInSession -UserId $upn" -ForegroundColor Gray
                        Revoke-MgUserSignInSession -UserId $upn | Out-Null
                        Write-CliOutput "Sessions revoked for $upn at $(Get-Date)"
                    }
                    Pause-And-Wait
                    Show-ContainmentMenu
                }
            }
        }

        '2' {
            $upn = Read-Host "Enter the compromised user's UPN"
            if ($upn) {
                $confirm = Read-Host "Block sign-in for $upn? (Y/N)"
                if ($confirm -eq 'Y') {
                    if ($TestMode) {
                        Write-Host "[INFO] Test Mode is enabled. This action is being simulated and will not impact the actual account." -ForegroundColor DarkCyan
                        Write-Host "[TEST MODE] Simulating: Blocking sign-in for $upn" -ForegroundColor Yellow
                        Write-Host "Command: Update-MgUser -UserId $upn -AccountEnabled \$false" -ForegroundColor DarkGray
                    } else {
                        $confirm2 = Read-Host "WARNING: You are about to block this user. Type Y to continue"
                        if ($confirm2 -ne "Y") { Write-Host "Action cancelled." -ForegroundColor Red; Pause-And-Wait; Show-ContainmentMenu }
                        Write-Host "[LIVE MODE] Proceeding with permanent account change..." -ForegroundColor Red
                        Write-Host "Running: Update-MgUser -UserId $upn -AccountEnabled \$false" -ForegroundColor Gray
                        Update-MgUser -UserId $upn -AccountEnabled:$false
                        Write-CliOutput "Sign-in blocked for $upn at $(Get-Date)"
                    }
                    Pause-And-Wait
                    Show-ContainmentMenu
                }
            }
        }

        '3' {
            $upn = Read-Host "Enter the compromised user's UPN"
            if ($upn) {
                $confirm = Read-Host "Generate and set new passphrase for $upn? (Y/N)"
                if ($confirm -eq 'Y') {
                    $newPass = New-SecurePassphrase
                    Write-Host "New temporary passphrase: $newPass" -ForegroundColor Magenta
                    Read-Host "Press Enter once you've saved the passphrase"
                    Update-MgUser -UserId $upn -PasswordProfile @{
                    ForceChangePasswordNextSignIn = $true
                    Password = $newPass
                    }
                    Write-CliOutput "Password reset for $upn at $(Get-Date)"
                    Pause-And-Wait
                    Show-ContainmentMenu
                }
            }
        }

        '4' { Show-MainMenu }

        default {
            Write-CliOutput "Invalid choice."
            Pause-And-Wait
            Show-ContainmentMenu
        }
    }
}

function Show-MainMenu {
    Clear-Host
    Write-Host "=== Incident Response Tool ===" -ForegroundColor Cyan
    if ($TestMode) { Write-Host "[TEST MODE ENABLED] No live changes will be made." -ForegroundColor DarkYellow }
    Write-Host "1. Containment and Account Lockdown"
    Write-Host "2. Exit"
    Write-Host "T. Toggle Test Mode (enable/disable)"

    $mainChoice = Read-Host "Choose an option"

    switch ($mainChoice) {
        '1' { Show-ContainmentMenu }

        '2' {
            Disconnect-MgGraph | Out-Null
            Write-Host "`nExiting Incident Response CLI..." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            Clear-Host
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