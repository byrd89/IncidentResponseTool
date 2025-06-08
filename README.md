# Incident Response Tool

This project is a PowerShell-based Incident Response Tool designed to help IT and security teams investigate suspected user compromises in Microsoft 365 environments. It supports both **CLI** and **GUI (WPF)** versions and integrates with **Microsoft Graph** and **Exchange Online PowerShell** for complete investigation workflows.

---

##  Features

- Prompt for user UPN and timestamped folder structure
- Retrieves:
  - Unified Audit Logs
  - Azure AD Sign-In Logs
  - Mailbox Inbox Rules
  - Registered Devices
- IOC (Indicator of Compromise) Analysis with summary
- Microsoft Graph authentication and auto-logout
- Modern WPF GUI with:
  - UPN input
  - Progress bar
  - Output window
  - Button to trigger log retrieval and display IOC summary

---

##  Project Structure

```
Incident Response/
│
├── CLI/
│   └── IncidentResponseTool.ps1         # CLI version of the tool
│
├── GUI/
│   ├── IncidentResponseTool.xaml        # XAML layout for GUI
│   └── IncidentResponseTool_GUI.ps1     # GUI logic for PowerShell WPF app
│
├── Modules/
│   └── IncidentResponseCore.psm1        # Shared functions for CLI & GUI
│
└── README.md
```

---

##  Requirements

- PowerShell 7.x or Windows PowerShell 5.1+
- Microsoft.Graph PowerShell SDK modules:
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Identity.SignIns`
  - `Microsoft.Graph.Identity.DirectoryManagement`
- ExchangeOnlineManagement module
- Visual Studio (for GUI editing)

---

##  How to Run

### CLI:
```powershell
cd .\CLI
Set-ExecutionPolicy Bypass -Scope Process -Force
.\IncidentResponseTool.ps1
```

### GUI:
```powershell
cd .\GUI
Set-ExecutionPolicy Bypass -Scope Process -Force
.\IncidentResponseTool_GUI.ps1
```

---

##  IOC Summary

The tool analyzes logs for:
- Foreign sign-ins
- Legacy protocol use (IMAP/POP/SMTP)
- External forwarding inbox rules
- Suspicious audit log activity (rule changes, mailbox changes)

---

##  Auto-Logout

The app logs out of Microsoft Graph automatically on:
- GUI window close
- CLI script exit

---

_Last updated: June 08, 2025_