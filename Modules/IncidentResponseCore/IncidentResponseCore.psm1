function Get-UserInformation {
    param (
        [string]$UserPrincipalName
    )
    try {
        $User = Get-MgUser -UserId $UserPrincipalName -ErrorAction Stop
        return $User
    } catch {
        Write-Warning "Unable to find user '$UserPrincipalName'. Please check the UPN and try again."
        return $null
    }
}

function Get-AuditLogs {
    param (
        [string]$UserPrincipalName,
        [string]$OutputFolder,
        [string]$FileDateStamp
    )
    try {
        $AuditLogs = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-2) -EndDate (Get-Date) -UserIds $UserPrincipalName -ResultSize 100 -ErrorAction Stop
        if ($AuditLogs) {
            $AuditLogs | Export-Csv "$OutputFolder\AuditLogs_$FileDateStamp.csv" -NoTypeInformation
        } else {
            "No audit logs found for this user." | Out-File "$OutputFolder\AuditLogs_$FileDateStamp.txt"
        }
        return $AuditLogs
    } catch {
        Write-Warning "Error retrieving audit logs: $_"
        return $null
    }
}

function Get-IOCAnalysis {
    param (
        $SignInLogs,
        $MailboxRules,
        $AuditLogs,
        $OutputFolder,
        $FileDateStamp
    )

    $SuspiciousFindings = @()

    Write-Host "`n=== Running IOC Analysis ===" -ForegroundColor Cyan

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

    Write-Host "`n=== IOC Summary ===" -ForegroundColor Cyan
    $SuspiciousFindings | ForEach-Object { Write-Host $_ }

    Write-Host "`nIOC findings saved to $IOCReportPath" -ForegroundColor Green
}
