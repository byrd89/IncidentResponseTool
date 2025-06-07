# Prompt for the user and timestamp
$UserPrincipalName = Read-Host "Enter the compromised user's UPN (email address):"
$DateStamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$OutputFolder = "C:\IR_Reports\$UserPrincipalName\$DateStamp"

# Create output folder
if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

Write-Host "[$(Get-Date -Format T)] Starting incident response for $UserPrincipalName..." -ForegroundColor Cyan

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

# Step 1: Export Audit Logs
Show-Progress -Activity "Exporting Unified Audit Logs..."
$AuditLogs = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -UserIds $UserPrincipalName -ResultSize 5000
if ($AuditLogs) {
    $AuditLogs | Export-Csv "$OutputFolder\AuditLogs.csv" -NoTypeInformation
} else {
    "No audit log results found" | Out-File "$OutputFolder\AuditLogs.txt"
}

# Step 2: Export Sign-In Logs (AzureAD)
Show-Progress -Activity "Exporting Sign-In Logs..."
$SignInLogs = Get-AzureADAuditSignInLogs -Filter "userPrincipalName eq '$UserPrincipalName'"
if ($SignInLogs) {
    $SignInLogs | Export-Csv "$OutputFolder\SignInLogs.csv" -NoTypeInformation
} else {
    "No sign-in log results found" | Out-File "$OutputFolder\SignInLogs.txt"
}

# Step 3: Export Mailbox Rules
Show-Progress -Activity "Exporting Mailbox Rules..."
$MailboxRules = Get-InboxRule -Mailbox $UserPrincipalName
if ($MailboxRules) {
    $MailboxRules | Select Name, Description, Enabled, From, RedirectTo | Export-Csv "$OutputFolder\MailboxRules.csv" -NoTypeInformation
} else {
    "No mailbox rules found" | Out-File "$OutputFolder\MailboxRules.txt"
}

# Step 4: Export Device Registration Info (if applicable)
Show-Progress -Activity "Gathering Device Registration Info..."
$Devices = Get-AzureADUserRegisteredDevice -ObjectId $UserPrincipalName
if ($Devices) {
    $Devices | Export-Csv "$OutputFolder\RegisteredDevices.csv" -NoTypeInformation
} else {
    "No registered devices found" | Out-File "$OutputFolder\RegisteredDevices.txt"
}

# Step 5: Export Summary JSON
Show-Progress -Activity "Writing Summary File..."
$Summary = @{
    User = $UserPrincipalName
    Timestamp = $DateStamp
    AuditLogsFound = ($AuditLogs.Count -gt 0)
    SignInLogsFound = ($SignInLogs.Count -gt 0)
    MailboxRulesFound = ($MailboxRules.Count -gt 0)
    DevicesFound = ($Devices.Count -gt 0)
}
$Summary | ConvertTo-Json | Out-File "$OutputFolder\Summary.json"

# Step 6: Final message
Show-Progress -Activity "Finalizing..."
Write-Host "[$(Get-Date -Format T)] Incident data saved to $OutputFolder" -ForegroundColor Green
