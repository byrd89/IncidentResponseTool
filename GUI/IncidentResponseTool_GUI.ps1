$ModulePath = "$PSScriptRoot\..\Modules\IncidentResponseCore\IncidentResponseCore.psm1"
Import-Module $ModulePath -Force

Add-Type -AssemblyName PresentationFramework

# Load XAML
[xml]$XAML = Get-Content "$PSScriptRoot\IncidentResponseTool.xaml"
$Reader = (New-Object System.Xml.XmlNodeReader $XAML)
$Window = [Windows.Markup.XamlReader]::Load($Reader)

# Bind UI elements
$UpnInput    = $Window.FindName("UpnInput")
$StartButton = $Window.FindName("StartButton")
$ProgressBar = $Window.FindName("ProgressBar")
$OutputBox   = $Window.FindName("OutputBox")

# Function: Append to output window
function Write-GuiOutput {
    param ($text)
    $OutputBox.AppendText("$text`n")
    $OutputBox.ScrollToEnd()
}

# Wire button click to your CLI logic
$StartButton.Add_Click({
    $User = $UpnInput.Text
    if (-not $User) {
        Write-GuiOutput "Please enter a UPN."
        return
    }

    Write-GuiOutput "Starting incident response for: $User"
    $ProgressBar.Value = 1

    # ⬇ Place your existing CLI logic here ⬇
    # You’ll just need to replace all Write-Host calls with Write-GuiOutput

    # Example:
    Start-Sleep -Seconds 1
    Write-GuiOutput "Step 1 complete (fake audit log call)"
    $ProgressBar.Value = 2

    # Finish other steps...

    $ProgressBar.Value = 6
    Write-GuiOutput "✔ Incident response completed for $User"
})

# Show GUI
$Window.ShowDialog() | Out-Null
