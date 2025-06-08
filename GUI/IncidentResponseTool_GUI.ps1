$ModulePath = "$PSScriptRoot\..\Modules\IncidentResponseCore\IncidentResponseCore.psm1"
Import-Module $ModulePath -Force

Add-Type -AssemblyName PresentationFramework

# Ensure ExchangeOnline is loaded
if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
}
Import-Module ExchangeOnlineManagement
if (-not (Get-ConnectionInformation)) {
    Connect-ExchangeOnline
}

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "Device.Read.All", "AuditLog.Read.All"

# Load XAML
[xml]$XAML = Get-Content "$PSScriptRoot\IncidentResponseTool.xaml"
$Reader = (New-Object System.Xml.XmlNodeReader $XAML)
$Window = [Windows.Markup.XamlReader]::Load($Reader)

# Bind UI elements
$UpnInput    = $Window.FindName("UpnInput")
$StartButton = $Window.FindName("StartButton")
$ProgressBar = $Window.FindName("ProgressBar")
$OutputBox   = $Window.FindName("OutputBox")
$ExitButton  = $Window.FindName("ExitButton")

# Function: Append to output window
function Write-GuiOutput {
    param ($text)
    $OutputBox.AppendText("$text`n")
    $OutputBox.ScrollToEnd()
}

# Clean up on exit
$Window.Add_Closed({
    Write-GuiOutput "Logging out of Microsoft Graph..."
    Disconnect-MgGraph -ErrorAction SilentlyContinue
})

# Exit Button logic
$ExitButton.Add_Click({
    Disconnect-MgGraph | Out-Null
    $Window.Close()
})

# Wire button click to shared core logic
$StartButton.Add_Click({
    $UserPrincipalName = $UpnInput.Text
    if (-not $UserPrincipalName) {
        Write-GuiOutput "Please enter a UPN."
        return
    }

    Write-GuiOutput "Starting incident response for: $UserPrincipalName"
    $ProgressBar.Value = 0

    $RunTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
    $FileDateStamp = Get-Date -Format "MM-dd-yyyy"
    $BasePath = "C:\Optimal\Incident_Response"
    $OutputFolder = Join-Path $BasePath "Incident_Response_$RunTimestamp"

    if (-not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder | Out-Null
    }

    Write-GuiOutput "Retrieving user information..."
    $User = Get-UserInformation -UserPrincipalName $UserPrincipalName
    if (-not $User) {
        Write-GuiOutput "Unable to find user '$UserPrincipalName'. Please check the UPN and try again."
        return
    }
    Write-GuiOutput "Display Name     : $($User.DisplayName)"
    Write-GuiOutput "User Principal   : $($User.UserPrincipalName)"
    Write-GuiOutput "ID               : $($User.Id)"
    $ProgressBar.Value = 1

    Write-GuiOutput "Retrieving audit logs..."
    $AuditLogs = Get-AuditLogs -UserPrincipalName $UserPrincipalName -OutputFolder $OutputFolder -FileDateStamp $FileDateStamp
    $ProgressBar.Value = 2

    Write-GuiOutput "Retrieving sign-in logs..."
    $SignInLogs = Get-SignInLogs -UserPrincipalName $UserPrincipalName
    $ProgressBar.Value = 3

    Write-GuiOutput "Retrieving mailbox rules..."
    $MailboxRules = Get-MailboxRules -UserPrincipalName $UserPrincipalName
    $ProgressBar.Value = 4

    Write-GuiOutput "Retrieving registered devices..."
    $Devices = Get-RegisteredDevices -User $User

    Write-GuiOutput "Writing summary file..."
    $Summary = @{
        User = $UserPrincipalName
        Timestamp = $RunTimestamp
        AuditLogsFound = ($AuditLogs -ne $null -and $AuditLogs.Count -gt 0)
        SignInLogsFound = ($SignInLogs -ne $null -and $SignInLogs.Count -gt 0)
        MailboxRulesFound = ($MailboxRules -ne $null -and $MailboxRules.Count -gt 0)
        DevicesFound = ($Devices -ne $null -and $Devices.Count -gt 0)
    }
    $Summary | ConvertTo-Json -Depth 5 | Out-File "$OutputFolder\Summary.json"
    $ProgressBar.Value = 5

    Write-GuiOutput "Running IOC analysis..."
    $IOCFindings = Get-IOCAnalysis -SignInLogs $SignInLogs -MailboxRules $MailboxRules -AuditLogs $AuditLogs -OutputFolder $OutputFolder -FileDateStamp $FileDateStamp
    $ProgressBar.Value = 6

    Write-GuiOutput "Incident response completed for $UserPrincipalName`n"
    Write-GuiOutput "=== IOC Summary ==="
    $IOCFindings | ForEach-Object { Write-GuiOutput $_ }
})

# Show GUI
$Window.ShowDialog() | Out-Null
