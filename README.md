# Incident Response CLI Tool

Author: Edward Byrd  
Purpose: Unified PowerShell-based Incident Response Toolkit for Microsoft 365 Environments

## Overview

This CLI tool supports incident response efforts by providing a guided, menu-driven PowerShell interface for investigating and mitigating account compromises in Microsoft 365 environments. It integrates with Microsoft Graph and Exchange Online to automate key actions and exports relevant logs for forensic review.

## Features

- Menu-driven interface for consistent containment workflows
- Integration with Microsoft Graph and Exchange Online PowerShell modules
- Test Mode to simulate actions without making changes
- Displays compromised user information throughout the session
- Collects and exports:
  - Audit logs
  - Sign-in logs
  - Mailbox rules
  - Device registration details
  - IOC summary report
- Tracks completed actions using a persistent marker (*)
- Progress bar during log export
- Ability to change the compromised account mid-session
- Log output saved to: `C:\Optimal\Incident_Response\<timestamp>`

## Workflow

1. Launch the script
2. Sign in with Microsoft 365 admin credentials
3. Enter the UPN of the compromised user
4. Select from the main menu options:
   - Containment and Account Lockdown
     - Revoke sessions
     - Block sign-in
     - Reset password
   - Export logs
   - Change compromised UPN
   - Exit
5. Actions completed during the session are marked for easy tracking

## Prerequisites

- PowerShell 7.x (recommended)
- Microsoft 365 admin credentials
- Required PowerShell modules:
  - Microsoft.Graph
  - ExchangeOnlineManagement

## Installation

1. Clone or download the script files
2. Open PowerShell as Administrator
3. Run the script using:
   ```powershell
   .\IncidentResponseTool.ps1
   ```
4. (Optional) Temporarily allow script execution if blocked:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope Process
   ```

## License

MIT License (adjust as needed)