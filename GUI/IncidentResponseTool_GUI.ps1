# Incident Response CLI Menu
Import-Module "$PSScriptRoot\..\Modules\SecurePassphrase\SecurePassphrase.psm1"

# Generate Secure Passphrase
$Passphrase = New-SecurePassphrase
Write-GuiOutput "Generated Passphrase: $Passphrase"

function Show-MainMenu {
    Clear-Host
    Write-Host "Select an incident response action:" -ForegroundColor Cyan
    Write-Host "1. Containment and Account Lockdown"
    Write-Host "2. Mailbox Protection"
    Write-Host "3. Audit and Cleanup"
    Write-Host "4. Post-Remediation Tasks"
    Write-Host "0. Exit"
    return Read-Host "Enter your choice"
}

function Show-ContainmentMenu {
    Clear-Host
    Write-Host "Containment and Account Lockdown:" -ForegroundColor Yellow
    Write-Host "1. Revoke user's active sessions"
    Write-Host "2. Block user sign-in in Entra ID"
    Write-Host "3. Reset user password and force sign-out"
    Write-Host "4. Back to Main Menu"
    return Read-Host "Enter your choice"
}

function Confirm-Action {
    param ($Message)
    $response = Read-Host "$Message [Y/N]"
    return $response -match '^y'
}

function Log-IOCAction {
    param ($Action)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp`t$Action" | Out-File -FilePath "$OutputFolder\IOC_Summary_$FileDateStamp.txt" -Append -Encoding UTF8
}

function Revoke-Sessions {
    Write-Host "\nThis will revoke all active sessions for the user. This signs them out across all apps."
    if (Confirm-Action "Proceed with revoking sessions?") {
        Revoke-MgUserSignInSession -UserId $User.Id
        $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "Sessions revoked at $now" -ForegroundColor Green
        Log-IOCAction "Sessions revoked at $now"
    }
}

function Block-SignIn {
    Write-Host "\nThis will block sign-in for the user in Entra ID."
    if (Confirm-Action "Proceed with blocking sign-in?") {
        Update-MgUser -UserId $User.Id -AccountEnabled:$false
        $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "Sign-in blocked at $now" -ForegroundColor Green
        Log-IOCAction "Sign-in blocked at $now"
    }
}

function Generate-Passphrase {
    $words = @("alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo", "lima", "mango", "ninja", "omega", "panda", "quantum", "rocket", "sunny", "tango", "uniform", "vortex", "whiskey", "xray", "yankee", "zebra")
    -join (1..3 | ForEach-Object { Get-Random -InputObject $words }) -join "-"
}

function Reset-Password {
    Write-Host "\nThis will reset the user's password using a secure, easy-to-share format."
    $passphrase = Generate-Passphrase
    Write-Host "\nGenerated Password: $passphrase" -ForegroundColor Yellow
    if (Confirm-Action "Proceed with password reset?") {
        $SecurePassword = ConvertTo-SecureString -String $passphrase -AsPlainText -Force
        Set-MgUserPassword -UserId $User.Id -PasswordProfile @{ ForceChangePasswordNextSignIn = $true; Password = $passphrase }
        $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "Password reset successful at $now" -ForegroundColor Green
        Log-IOCAction "Password reset at $now"
        Remove-Variable passphrase
    }
}

# START MAIN FLOW

$UserPrincipalName = Read-Host "Enter the compromised user's UPN"
$User = Get-MgUser -UserId $UserPrincipalName -ErrorAction Stop
$RunTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$FileDateStamp = Get-Date -Format "MM-dd-yyyy"
$BasePath = "C:\\Optimal\\Incident_Response"
$OutputFolder = Join-Path $BasePath "Incident_Response_$RunTimestamp"
if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder | Out-Null }

while ($true) {
    switch (Show-MainMenu) {
        '1' {
            while ($true) {
                switch (Show-ContainmentMenu) {
                    '1' { Revoke-Sessions }
                    '2' { Block-SignIn }
                    '3' { Reset-Password }
                    '4' { break }
                    default { Write-Host "Invalid selection. Try again." -ForegroundColor Red }
                }
            }
        }
        '2' { Write-Host "Mailbox Protection not yet implemented." -ForegroundColor DarkYellow }
        '3' { Write-Host "Audit and Cleanup not yet implemented." -ForegroundColor DarkYellow }
        '4' { Write-Host "Post-Remediation Tasks not yet implemented." -ForegroundColor DarkYellow }
        '0' { break }
        default { Write-Host "Invalid selection. Try again." -ForegroundColor Red }
    }
}

Write-Host "\nExiting Incident Response Tool..." -ForegroundColor Cyan
