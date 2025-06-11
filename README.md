# Incident Response CLI & GUI Tool

Author: Edward Byrd  
Purpose: Unified PowerShell-based Incident-Response toolkit (CLI **and** WPF GUI) for Microsoft 365 environments

---

## Overview
The project now ships in **two flavors**:

| Variant | Entry Point | Audience | Notes |
|---------|-------------|----------|-------|
| **CLI** | `IncidentResponseTool.ps1` | Terminal-savvy responders | Original menu-driven console interface |
| **GUI** | `IncidentResponseTool_GUI.ps1` + `IncidentResponseTool.xaml` | Help-desk & Tier-1 techs | Mouse-first WPF app with dedicated buttons |

Both versions share a core module **`IncidentResponseCore.psm1`** for reusable functions such as `New-SecurePassword`, logging helpers, and other utilities.

---

## Features (superset of CLI + GUI)

| Category | Details |
|----------|---------|
| **Dual Interface** | Choose between CLI or WPF GUI at launch time. |
| **Menu-Driven Workflow** | Main menu → Containment → Export Logs → Remediation (same flow in both variants). |
| **Dedicated Buttons (GUI)** | Each action (Revoke, Block, Reset, etc.) has its own button; sub-menus mirror the CLI lists. |
| **Test Mode** | Radio-button in GUI, `T` toggle in CLI. Status bar shows “Mode: Test” or “Mode: Live”. |
| **Action Logging** | `ActionLog.txt` in every Session folder. |
| **Secure Passwords** | Password resets now call **`New-SecurePassword`** from `IncidentResponseCore.psm1` (14-char strong mix). |
| **Target Awareness** | UPN & display name always visible. |
| **Progress & Status** | GUI status bar + output pane; CLI asterisks. |
| **Session Folder** | `Desktop\Incident Response\Session_<timestamp>` keeps logs & summaries tidy. |

---

## GUI Workflow

1. Launch **`IncidentResponseTool_GUI.ps1`**  
2. Authenticate to Graph and Exchange when prompted (standard MSAL pop-ups).  
3. Enter compromised user’s UPN → **Validate UPN**  
4. Use the Main Menu buttons:  
   - **Containment & Account Lockdown**  
   - **Export Incident Logs**  
   - **Remediation & Recovery**  
5. Click **Exit** when done (module sessions auto-disconnect).

---

## Prerequisites

* PowerShell 7.x (or Windows PowerShell 5.1)  
* Microsoft 365 admin creds with Audit-Log & User-Admin rights  
* Installed modules:  
  * `Microsoft.Graph`  
  * `ExchangeOnlineManagement`  
* Execution policy allowing local unsigned modules (`RemoteSigned` or unblock the `.psm1`).

---

## Installation & Usage

```powershell
git clone <your-repo>
cd IncidentResponse

# Allow local scripts this session only (optional)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

# --- CLI ---
pwsh -ExecutionPolicy Bypass -File .\CLI\IncidentResponseTool.ps1

# --- GUI ---
pwsh -ExecutionPolicy Bypass -File .\GUI\IncidentResponseTool_GUI.ps1
```

---

## File & Folder Layout

```
IncidentResponse/
├─ CLI/
│  └─ IncidentResponseTool.ps1
├─ GUI/
│  ├─ IncidentResponseTool_GUI.ps1
│  └─ IncidentResponseTool.xaml
└─ Modules/
   └─ IncidentResponseCore/
      └─ IncidentResponseCore.psm1
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

---

## Changelog

### **1.1.0 – 2025-06-11**
* **Added WPF GUI** with Main-Menu & sub-menus (Containment, Logs, Remediation).  
* Integrated **`IncidentResponseCore.psm1`** shared module; switched to **`New-SecurePassword`** for resets.  
* Escaped `&amp;` entities in XAML to fix parsing errors.  
* Removed unsupported `-Confirm` on `Disconnect-MgGraph`; wrapped disconnects in `try/catch`.  
* Status bar now shows **User + Mode (Test/Live)** in GUI.  
* Refactored code: isolated task functions, centralized folder initialization.

### **1.0.0 – 2025-06-11**
* Initial CLI release with Test Mode, session folders, action logging, and full workflow.

---

## License
MIT License
