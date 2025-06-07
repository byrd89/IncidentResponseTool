# Incident Response Tool (PowerShell)

This PowerShell script automates the process of collecting investigation data related to a compromised Microsoft 365 user. It is designed for use by IT administrators and security teams, especially in MSP and enterprise environments.

## Features

- Prompt for compromised user's email address
- Export:
  - Unified Audit Logs (Exchange Online)
  - Azure AD Sign-In Logs
  - Mailbox Rules
  - Device Registration Info
- Generate a JSON summary for fast triage
- Save results to a date-stamped folder
- Handle "no results found" conditions gracefully
- Progress bar to show execution steps

## Output Structure
C:\IR_Reports\user@domain.com\2025-06-07_14-45
├── AuditLogs.csv
├── SignInLogs.csv
├── MailboxRules.csv
├── RegisteredDevices.csv
├── Summary.json
├── *.txt (for empty/no-result warnings)

## Requirements

- PowerShell 7 (preferred)
- Modules:
  - ExchangeOnlineManagement
  - AzureAD or Microsoft.Graph (for device info)
- Microsoft 365 Audit Logging must be enabled
- Sufficient admin permissions to pull logs

## How to Use

1. Connect to Microsoft 365 as an admin (you will be prompted).
2. Run the script in VS Code or PowerShell 7.
3. Enter the compromised user's UPN when prompted.
4. Results are saved locally to `C:\IR_Reports`.

```powershell
.\IncidentResponseTool.ps1



Roadmap / To-Do
 Add session revocation / disable account

 Add Defender alert pull via Graph

 ZIP output folder for sharing

 Build GUI version using WPF

Notes
If Search-UnifiedAuditLog isn’t recognized, ensure you are authenticated with Connect-ExchangeOnline.

Device logging requires AzureAD or Microsoft Graph SDK.

You can fork this repo and build on new features using branches.

License
MIT License (or update this to fit your usage).