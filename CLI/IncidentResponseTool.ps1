$ModulePath = "$PSScriptRoot\..\Modules\IncidentResponseCore\IncidentResponseCore.psm1"
Import-Module $ModulePath -Force

# Define CLI Logger
function Write-CliOutput {
    param ($text)
    Write-Host $text -ForegroundColor Cyan
}

# Import required Graph modules
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Identity.SignIns
Import-Module Microsoft.Graph.Identity.DirectoryManagement

# Connect to Graph
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "Device.Read.All", "AuditLog.Read.All"

# Prompt for user
$UserPrincipalName = Read-Host "`nEnter the compromised user's UPN (email address)"
$User = Get-UserInformation -UserPrincipalName $UserPrincipalName -Logger $function:Write-CliOutput
if (-not $User) {
    exit
}

Write-CliOutput "`nTarget User:"
Write-CliOutput "Display Name     : $($User.DisplayName)"
Write-CliOutput "User Principal   : $($User.UserPrincipalName)"
Write-CliOutput "ID               : $($User.Id)`n"

# Setup paths
$RunTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$FileDateStamp = Get-Date -Format "MM-dd-yyyy"
$BasePath = "C:\Optimal\Incident_Response"
$OutputFolder = Join-Path $BasePath "Incident_Response_$RunTimestamp"

if (-not (Test-Path $BasePath)) { New-Item -ItemType Directory -Path $BasePath | Out-Null }
if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder | Out-Null }

Write-CliOutput "[$(Get-Date -Format T)] Starting incident response for $UserPrincipalName..."

# Exchange Online setup
if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
}
Import-Module ExchangeOnlineManagement
if (-not (Get-ConnectionInformation)) { Connect-ExchangeOnline }

# Progress simulation
$progress = 0
function Show-Progress {
    param ($Activity)
    $script:progress++
    $percent = [Math]::Min(($progress * 100 / 6), 100)
    Write-Progress -Activity $Activity -Status "$progress/6 steps complete" -PercentComplete $percent
}

# Step 1: Audit Logs
Show-Progress -Activity "Retrieving Unified Audit Logs..."
$AuditLogs = Get-AuditLogs -UserPrincipalName $UserPrincipalName -OutputFolder $OutputFolder -FileDateStamp $FileDateStamp -Logger $function:Write-CliOutput

# Step 2: Sign-In Logs
Show-Progress -Activity "Exporting Sign-In Logs..."
$SignInLogs = Get-SignInLogs -UserPrincipalName $UserPrincipalName -Logger $function:Write-CliOutput

# Step 3: Mailbox Rules
Show-Progress -Activity "Exporting Mailbox Rules..."
$MailboxRules = Get-MailboxRules -UserPrincipalName $UserPrincipalName -Logger $function:Write-CliOutput

# Step 4: Devices
Show-Progress -Activity "Gathering Device Registration Info..."
$Devices = Get-RegisteredDevices -User $User -Logger $function:Write-CliOutput

# Step 5: Summary JSON
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

# Step 6: IOC Analysis
Show-Progress -Activity "Running IOC Analysis..."
$IOCFindings = Get-IOCAnalysis -SignInLogs $SignInLogs -MailboxRules $MailboxRules -AuditLogs $AuditLogs -OutputFolder $OutputFolder -FileDateStamp $FileDateStamp -Logger $function:Write-CliOutput

# Completion
Show-Progress -Activity "Finalizing..."
Write-CliOutput "[$(Get-Date -Format T)] Incident data saved to $OutputFolder"
Write-CliOutput "=== IOC Summary ==="
$IOCFindings | ForEach-Object { Write-CliOutput $_ }
