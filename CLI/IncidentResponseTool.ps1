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
$User = Get-UserInformation -UserPrincipalName $UserPrincipalName
if (-not $User) { exit }

Write-Host "`nTarget User:" -ForegroundColor Cyan
Write-Host "Display Name     : $($User.DisplayName)"
Write-Host "User Principal   : $($User.UserPrincipalName)"
Write-Host "ID               : $($User.Id)`n"

$RunTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$FileDateStamp = Get-Date -Format "MM-dd-yyyy"
$BasePath = "C:\Optimal\Incident_Response"
$OutputFolder = Join-Path $BasePath "Incident_Response_$RunTimestamp"

if (-not (Test-Path -Path $BasePath)) {
    New-Item -ItemType Directory -Path $BasePath | Out-Null
}
if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

Write-Host "[$(Get-Date -Format T)] Starting incident response for $UserPrincipalName..." -ForegroundColor Cyan

if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
}
Import-Module ExchangeOnlineManagement
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
$AuditLogs = Get-AuditLogs -UserPrincipalName $UserPrincipalName -OutputFolder $OutputFolder -FileDateStamp $FileDateStamp

# Step 2: Export Sign-In Logs (Microsoft Graph)
Show-Progress -Activity "Exporting Sign-In Logs..."
$SignInLogs = Get-SignInLogs -UserPrincipalName $UserPrincipalName
if ($SignInLogs) {
    $SignInLogs | Export-Csv "$OutputFolder\SignInLogs_$FileDateStamp.csv" -NoTypeInformation
} else {
    "No sign-in log results found" | Out-File "$OutputFolder\SignInLogs_$FileDateStamp.txt"
}

# Step 3: Export Mailbox Rules
Show-Progress -Activity "Exporting Mailbox Rules..."
$MailboxRules = Get-MailboxRules -UserPrincipalName $UserPrincipalName
if ($MailboxRules) {
    $MailboxRules | Select Name, Description, Enabled, From, RedirectTo | Export-Csv "$OutputFolder\MailboxRules_$FileDateStamp.csv" -NoTypeInformation
} else {
    "No mailbox rules found" | Out-File "$OutputFolder\MailboxRules_$FileDateStamp.txt"
}

# Step 4: Export Device Registration Info (Microsoft Graph)
Show-Progress -Activity "Gathering Device Registration Info..."
$Devices = Get-RegisteredDevices -User $User
if ($Devices) {
    $Devices | Export-Csv "$OutputFolder\RegisteredDevices_$FileDateStamp.csv" -NoTypeInformation
} else {
    "No registered devices found" | Out-File "$OutputFolder\RegisteredDevices_$FileDateStamp.txt"
}

# Step 5: Export Summary JSON
Show-Progress -Activity "Writing Summary File..."
$Summary = @{
    User = $UserPrincipalName
    Timestamp = $RunTimestamp
    AuditLogsFound = ($AuditLogs -ne $null -and $AuditLogs.Count -gt 0)
    SignInLogsFound = ($SignInLogs -ne $null -and $SignInLogs.Count -gt 0)
    MailboxRulesFound = ($MailboxRules -ne $null -and $MailboxRules.Count -gt 0)
    DevicesFound = ($Devices -ne $null -and $Devices.Count -gt 0)
}
$Summary | ConvertTo-Json -Depth 5 | Out-File "$OutputFolder\Summary.json"

# Step 6: Run IOC analysis
Get-IOCAnalysis -SignInLogs $SignInLogs -MailboxRules $MailboxRules -AuditLogs $AuditLogs -OutputFolder $OutputFolder -FileDateStamp $FileDateStamp

# Step 7: Final message
Show-Progress -Activity "Finalizing..."
Write-Host "[$(Get-Date -Format T)] Incident data saved to $OutputFolder" -ForegroundColor Green
Disconnect-MgGraph -ErrorAction SilentlyContinue
