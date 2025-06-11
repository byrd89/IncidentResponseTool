function Get-UserInformation {
    param (
        [string]$UserPrincipalName,
        [ScriptBlock]$Logger
    )
    try {
        if ($Logger) { & $Logger "Retrieving user information for $UserPrincipalName..." }
        $User = Get-MgUser -UserId $UserPrincipalName -ErrorAction Stop
        return $User
    } catch {
        if ($Logger) { & $Logger "Unable to find user '$UserPrincipalName'. Please check the UPN and try again." }
        return $null
    }
}

function Get-AuditLogs {
    param (
        [string]$UserPrincipalName,
        [string]$OutputFolder,
        [string]$FileDateStamp,
        [ScriptBlock]$Logger
    )
    if ($Logger) { & $Logger "Retrieving audit logs..." }
    try {
        $AuditLogs = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-2) -EndDate (Get-Date) -UserIds $UserPrincipalName -ResultSize 100 -ErrorAction Stop
        if ($AuditLogs) {
            $AuditLogs | Export-Csv "$OutputFolder\AuditLogs_$FileDateStamp.csv" -NoTypeInformation
            if ($Logger) { & $Logger "Audit logs saved to AuditLogs_$FileDateStamp.csv" }
        } else {
            "No audit logs found for this user." | Out-File "$OutputFolder\AuditLogs_$FileDateStamp.txt"
            if ($Logger) { & $Logger "No audit logs found. Text summary saved." }
        }
        return $AuditLogs
    } catch {
        if ($Logger) { & $Logger "Error retrieving audit logs: $_" }
        return $null
    }
}

function Get-IOCAnalysis {
    param (
        $SignInLogs,
        $MailboxRules,
        $AuditLogs,
        $OutputFolder,
        $FileDateStamp,
        [ScriptBlock]$Logger
    )

    $SuspiciousFindings = @()

    if ($Logger) { & $Logger "Running IOC Analysis..." }

    if ($SignInLogs) {
        $ForeignLogins = $SignInLogs | Where-Object {
            $_.Location.Country -and $_.Location.Country -notin @("United States", "Canada")
        }

        if ($ForeignLogins.Count -gt 0) {
            $SuspiciousFindings += "Foreign sign-ins detected: $($ForeignLogins.Count)"
        } else {
            $SuspiciousFindings += "No foreign sign-ins found"
        }

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

    if ($MailboxRules) {
        $ExternalForwards = $MailboxRules | Where-Object {
            $_.RedirectTo -match "@"
        }

        if ($ExternalForwards.Count -gt 0) {
            $SuspiciousFindings += "Mailbox rule forwards to external address found"
        } else {
            $SuspiciousFindings += "No external forwarding rules found"
        }

        $AutoDeletes = $MailboxRules | Where-Object {
            $_.Description -match "delete" -or $_.From -eq $null
        }

        if ($AutoDeletes.Count -gt 0) {
            $SuspiciousFindings += "Potential auto-delete or hidden inbox rule detected"
        }
    } else {
        $SuspiciousFindings += "No mailbox rules available for evaluation"
    }

    if ($AuditLogs) {
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

    $IOCReportPath = "$OutputFolder\IOC_Summary_$FileDateStamp.txt"
    $SuspiciousFindings | Out-File -FilePath $IOCReportPath -Encoding UTF8

    if ($Logger) {
        & $Logger "IOC Summary:"
        $SuspiciousFindings | ForEach-Object { & $Logger $_ }
        & $Logger "IOC findings saved to $IOCReportPath"
    }

    return $SuspiciousFindings
}

# Generates a secure random password that meets Microsoft cloud policy recommendations
function New-SecurePassword {
    param (
        [int]$length = 14
    )

    $upper = [char[]]"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lower = [char[]]"abcdefghijklmnopqrstuvwxyz"
    $digit = [char[]]"0123456789"
    $symbol = [char[]]"!@#$%^&*()-_=+[]{}|;:,.<>?/~"

    # Ensure at least one character from each category
    $mandatory = @(
        Get-Random -InputObject $upper
        Get-Random -InputObject $lower
        Get-Random -InputObject $digit
        Get-Random -InputObject $symbol
    )

    # Fill the rest of the password
    $allChars = $upper + $lower + $digit + $symbol
    $remaining = -join (1..($length - $mandatory.Count) | ForEach-Object { Get-Random -InputObject $allChars })

    # Shuffle full password
    $passwordChars = ($mandatory + $remaining.ToCharArray()) | Sort-Object { Get-Random }
    return -join $passwordChars
}