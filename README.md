# Incident Response CLI Tool

Author: Edward Byrd  
Purpose: Unified PowerShell-based Incident Response toolkit for Microsoft 365 environments

## Overview

This CLI tool supports incident-response efforts by providing a guided, menu-driven PowerShell interface for investigating and mitigating account compromises in Microsoft 365. It integrates with Microsoft Graph and Exchange Online to automate key containment actions, export relevant evidence, and log every step for auditability.

**Version 1.0** introduces a complete end-to-end workflow, optional Test Mode, and per-incident session folders.

## Features

| Category | Details |
|----------|---------|
| **Menu-Driven Workflow** | Main menu → Containment → Evidence Collection → Remediation |
| **Test Mode** | Toggle at any time. All destructive actions become no-ops and every submenu shows a yellow TEST MODE banner. |
| **Action Logging** | Each core action appends to `ActionLog.txt` with timestamp, admin UPN, action name, and target user. |
| **Target Awareness** | Display name & primary address shown in headers of the main menu and every submenu. |
| **Containment** | Revoke sessions • Block sign-in • Force password reset |
| **Evidence Collection** | Exports sign-in logs, unified audit logs (last 7 days), and inbox rules. All artifacts land in `Logs_<timestamp>` under a unique Session folder on the Desktop. |
| **Remediation** | Re-enable the account (prereqs enforced) and generate a plain-text summary file. |
| **Progress Tracking** | Asterisk (*) markers show which steps are complete in each submenu. |
| **Session Folder** | Every run creates `Desktop\Incident Response\Session_<timestamp>` to keep logs and summaries cleanly separated. |

## Workflow

1. Launch the script  
2. Authenticate to Microsoft Graph (interactive prompt if not pre-connected)  
3. Enter the compromised user’s UPN  
4. Work through the numbered menus:  
   - Containment & Account Lockdown  
   - Export Incident Logs  
   - Remediation & Recovery  
5. Toggle **T** to enable/disable Test Mode at any time.

Completed items are marked with `*` so you always know what’s left.

## Prerequisites

* PowerShell 7.x (or Windows PowerShell 5.1)  
* Microsoft 365 admin credentials with Audit Log + User Admin rights  
* Modules:  
  * Microsoft.Graph  
  * ExchangeOnlineManagement (auto-installs if missing)

## Installation & Usage

```powershell
git clone <your-repo>
cd IncidentResponseCLI
# (optional) allow local scripts in this session only
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

# Run
pwsh -ExecutionPolicy Bypass -File .\IncidentResponseTool.ps1
```

## File & Folder Layout

```
Desktop/
└─ Incident Response/
   └─ Session_YYYY-MM-DD_hh-mm-ss/
      ├─ ActionLog.txt
      ├─ Logs_YYYY-MM-DD_hh-mm-ss/
      │  ├─ SigninLogs.csv
      │  ├─ UnifiedAuditLog.csv
      │  └─ InboxRules.csv
      └─ Summary_YYYY-MM-DD_hh-mm-ss.txt
```

## Changelog

### 1.0 – 2025-06-11
* Initial full release  
* Added Test Mode with safety banners  
* Added per-incident Session folders & Action-logging  
* Added target display name/email in all menus  
* Fixed admin UPN detection using `Get-MgContext`  
* Stabilized menu flow and parser errors

## License

MIT License (update if needed)
