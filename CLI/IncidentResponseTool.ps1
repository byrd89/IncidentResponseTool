$ModulePath = "$PSScriptRoot\..\Modules\IncidentResponseCore\IncidentResponseCore.psm1"
Import-Module $ModulePath -Force

# Import required Graph modules
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Identity.SignIns
Import-Module Microsoft.Graph.Identity.DirectoryManagement

# Connect with the correct permissions
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "Device.Read.All", "AuditLog.Read.All"

# Prompt for the user and timestamp
$UserPrincipalName = Read-Host "`nEnter the compromised user's UPN (email address)"
# Retrieve user object using Microsoft Graph
try {
    $User = Get-MgUser -UserId $UserPrincipalName -ErrorAction Stop
    Write-Host "`nTarget User:" -ForegroundColor Cyan
    Write-Host "Display Name     : $($User.DisplayName)"
    Write-Host "User Principal   : $($User.UserPrincipalName)"
    Write-Host "ID               : $($User.Id)`n"
} catch {
    Write-Warning "Unable to find user '$UserPrincipalName'. Please check the UPN and try again."
    exit
}
$RunTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$FileDateStamp = Get-Date -Format "MM-dd-yyyy"
$BasePath = "C:\Optimal\Incident_Response"
$OutputFolder = Join-Path $BasePath "Incident_Response_$RunTimestamp"


# Create output folder
if (-not (Test-Path -Path $BasePath)) {
    New-Item -ItemType Directory -Path $BasePath | Out-Null
}

if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

Write-Host "[$(Get-Date -Format T)] Starting incident response for $UserPrincipalName..." -ForegroundColor Cyan

# Ensure ExchangeOnline is available
if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
}
Import-Module ExchangeOnlineManagement

# Exchange Online Connection Check
if (-not (Get-ConnectionInformation)) {
    Connect-ExchangeOnline
}

# Initialize progress tracker
$progress = 0
function Show-Progress {
    param ($Activity)
    $script:progress++
    Write-Progress -Activity $Activity -Status "$progress/6 steps complete" -PercentComplete ($progress * 100 / 6)
}

# Step 1: Retrieve Audit logs
Show-Progress -Activity "Retrieving Unified Audit Logs..."

try {
    $AuditLogs = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-2) -EndDate (Get-Date) -UserIds $UserPrincipalName -ResultSize 100 -ErrorAction Stop

    if ($AuditLogs) {
        # Save audit logs silently
        if ($AuditLogs) {
            $AuditLogs | Export-Csv "$OutputFolder\AuditLogs_$FileDateStamp.csv" -NoTypeInformation
    } else {
    "No audit logs found for this user." | Out-File "$OutputFolder\AuditLogs_$FileDateStamp.txt"
}

    } else {
        Write-Warning "No audit logs found for this user."
    }
} catch {
    Write-Warning "Error retrieving audit logs: $_"
}


# Step 2: Export Sign-In Logs (Microsoft Graph)
Show-Progress -Activity "Exporting Sign-In Logs..."

try {
    $SignInLogs = Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$UserPrincipalName'" -Top 100
    if ($SignInLogs) {
        $SignInLogs | Export-Csv "$OutputFolder\SignInLogs_$FileDateStamp.csv" -NoTypeInformation
    } else {
        "No sign-in log results found" | Out-File "$OutputFolder\SignInLogs_$FileDateStamp.txt"
    }
} catch {
    Write-Warning "Error retrieving sign-in logs: $_"
}


# Step 3: Export Mailbox Rules
Show-Progress -Activity "Exporting Mailbox Rules..."
$MailboxRules = Get-InboxRule -Mailbox $UserPrincipalName
if ($MailboxRules) {
    $MailboxRules | Select Name, Description, Enabled, From, RedirectTo | Export-Csv "$OutputFolder\MailboxRules_$FileDateStamp.csv" -NoTypeInformation
} else {
    "No mailbox rules found" | Out-File "$OutputFolder\MailboxRules_$FileDateStamp.txt"
}

# Step 4: Export Device Registration Info (Microsoft Graph)
Show-Progress -Activity "Gathering Device Registration Info..."

try {
    $User = Get-MgUser -UserId $UserPrincipalName
    $Devices = Get-MgUserRegisteredDevice -UserId $User.Id
    if ($Devices) {
        $Devices | Export-Csv "$OutputFolder\RegisteredDevices_$FileDateStamp.csv" -NoTypeInformation
    } else {
        "No registered devices found" | Out-File "$OutputFolder\RegisteredDevices_$FileDateStamp.txt"
    }
} catch {
    Write-Warning "Error retrieving registered devices: $_"
}


# Step 5: Export Summary JSON
Show-Progress -Activity "Writing Summary File..."
$Summary = @{
    User = $UserPrincipalName
    Timestamp = $DateStamp
    AuditLogsFound = ($AuditLogs -ne $null -and $AuditLogs.Count -gt 0)
    SignInLogsFound = ($SignInLogs -ne $null -and $SignInLogs.Count -gt 0)
    MailboxRulesFound = ($MailboxRules -ne $null -and $MailboxRules.Count -gt 0)
    DevicesFound = ($Devices -ne $null -and $Devices.Count -gt 0)
}

$Summary | ConvertTo-Json -Depth 5 | Out-File "$OutputFolder\Summary.json"

# Step 6: Final message
Show-Progress -Activity "Finalizing..."
Write-Host "[$(Get-Date -Format T)] Incident data saved to $OutputFolder" -ForegroundColor Green

function Get-IOCAnalysis {
    param (
        $SignInLogs,
        $MailboxRules,
        $AuditLogs,
        $OutputFolder,
        $FileDateStamp
    )

    # Initialize an array to hold the summary findings
    $SuspiciousFindings = @()

    Write-Host "`n=== Running IOC Analysis ===" -ForegroundColor Cyan

    # ---------- SIGN-IN LOG ANALYSIS ----------
    if ($SignInLogs) {
        # Check for sign-ins from countries outside the US and Canada
        $ForeignLogins = $SignInLogs | Where-Object {
            $_.Location.Country -and $_.Location.Country -notin @("United States", "Canada")
        }

        if ($ForeignLogins.Count -gt 0) {
            $SuspiciousFindings += "Foreign sign-ins detected: $($ForeignLogins.Count)"
        } else {
            $SuspiciousFindings += "No foreign sign-ins found"
        }

        # Check for legacy authentication protocol usage (IMAP, POP, SMTP, etc.)
        $LegacyApps = $SignInLogs | Where-Object {
            $_.ClientAppUsed -in @("IMAP", "POP", "SMTP", "Other clients")
        }

        if ($LegacyApps.Count -gt 0) {
            $SuspiciousFindings += "Legacy authentication protocols used: $($LegacyApps.ClientAppUsed | Sort-Object -Unique -join ', ')"
        } else {
            $SuspiciousFindings += "No legacy protocol usage detected"
        }
    } else {
        $SuspiciousFindings += "Sign-in logs not available"
    }

    # ---------- MAILBOX RULE ANALYSIS ----------
    if ($MailboxRules) {
        # Look for inbox rules that redirect mail to external addresses
        $ExternalForwards = $MailboxRules | Where-Object {
            $_.RedirectTo -match "@"
        }

        if ($ExternalForwards.Count -gt 0) {
            $SuspiciousFindings += "Mailbox rule forwards to external address found"
        } else {
            $SuspiciousFindings += "No external forwarding rules found"
        }

        # Look for rules that might be deleting or hiding messages
        $AutoDeletes = $MailboxRules | Where-Object {
            $_.Description -match "delete" -or $_.From -eq $null
        }

        if ($AutoDeletes.Count -gt 0) {
            $SuspiciousFindings += "Potential auto-delete or hidden inbox rule detected"
        }
    } else {
        $SuspiciousFindings += "No mailbox rules available for evaluation"
    }

    # ---------- AUDIT LOG ANALYSIS ----------
    if ($AuditLogs) {
        # Check for operations that may indicate mailbox tampering or privilege abuse
        $SuspiciousOps = $AuditLogs | Where-Object {
            $_.Operation -in @("Set-Mailbox", "Add-MailboxPermission", "UpdateInboxRules", "New-InboxRule")
        }

        if ($SuspiciousOps.Count -gt 0) {
            $SuspiciousFindings += "Suspicious mailbox operations detected: $($SuspiciousOps.Operation | Sort-Object -Unique -join ', ')"
        } else {
            $SuspiciousFindings += "No suspicious mailbox operations detected"
        }
    } else {
        $SuspiciousFindings += "Audit logs not available"
    }

    # ---------- OUTPUT RESULTS ----------
    # Save the IOC summary to a timestamped text file
    $IOCReportPath = "$OutputFolder\IOC_Summary_$FileDateStamp.txt"
    $SuspiciousFindings | Out-File -FilePath $IOCReportPath -Encoding UTF8

    # Display the summary in the terminal
    Write-Host "`n=== IOC Summary ===" -ForegroundColor Cyan
    $SuspiciousFindings | ForEach-Object { Write-Host $_ }

    Write-Host "`nIOC findings saved to $IOCReportPath" -ForegroundColor Green
}

# Step 6: Run IOC analysis
Get-IOCAnalysis -SignInLogs $SignInLogs -MailboxRules $MailboxRules -AuditLogs $AuditLogs -OutputFolder $OutputFolder -FileDateStamp $FileDateStamp
