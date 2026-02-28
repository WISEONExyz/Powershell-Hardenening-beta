# PowerShell Hardening Dashboard

This project provides a Windows Forms GUI for:
- auditing risky PowerShell activity,
- reviewing and blocking listening TCP ports,
- generating prioritized hardening recommendations,
- applying/rolling back selected hardening fixes,
- exporting findings and recommendations to CSV.

The main script is:
- `hardening-dashboard.ps1`

## What The Script Does

### 1) PowerShell Audit tab
- Scans:
  - PSReadLine history (`Get-PSReadLineOption` history path),
  - legacy history file (`ConsoleHost_history.txt`),
  - transcript files in `Documents` (up to 15),
  - event logs:
    - `Microsoft-Windows-PowerShell/Operational`
    - `Windows PowerShell`
    - event IDs `4103`, `4104`, `400`, `403`
- Matches risky patterns such as:
  - `Invoke-Expression` / `iex`
  - `-ExecutionPolicy Bypass`
  - `-EncodedCommand`
  - `DownloadString`
  - `Invoke-WebRequest` / `Invoke-RestMethod`
  - `Net.WebClient`
  - Defender tamper/exclusion commands
  - credential and LOLBin-style patterns
- Displays results in a grid with:
  - manual column resize,
  - zoom slider (`70%` to `140%`),
  - virtual vertical/horizontal scroll bars.
- Exports audit findings to CSV via **Export CSV**.

### 2) Port Lockdown tab
- Loads listening TCP ports from `Get-NetTCPConnection -State Listen`.
- Also loads a curated high-risk external port catalog (commonly targeted service ports).
- Shows combined ports in a checklist with status tags:
  - `HighRisk` or `Observed`
  - `Listening` or `NotListening`
  - `Blocked` or `Unblocked`
- Includes always-visible scrolling support on the port list:
  - vertical scrollbar for long lists
  - horizontal scrollbar for long row text
- Lets you:
  - block selected ports,
  - unblock selected ports,
  - block a custom port (`1..65535`).
  - unblock a custom port (`1..65535`).
- Creates firewall rules named:
  - `HardeningBlock_In_<port>`
- Removes the same rule name when unblocking.
- Writes action logs to the output textbox.

#### Port Blocking Impact On The Local Machine
- Blocking a port in this tool creates an **inbound Windows Firewall block rule** for that TCP port (`Profile Any`).
- This blocks remote network traffic coming into that port on the laptop/PC.
- If a local service depends on inbound access on that port, remote clients will no longer connect.
- Typical examples:
  - `3389` blocked: Remote Desktop access fails.
  - `445/139/135` blocked: file sharing and some Windows network-management operations can fail.
  - `5985/5986` blocked: WinRM/remote PowerShell management fails.
  - DB ports (`1433`, `3306`, `5432`, `27017`) blocked: remote DB connections fail.
- You can reverse this from the UI using **Unblock Selected** or **Unblock Port**.

### 3) Recommendations tab
- Generates recommendations from:
  - latest audit findings,
  - listening ports,
  - port binding context (public vs non-public),
  - environment context (domain joined, public firewall default inbound action).
- Computes:
  - **Security Posture Score** (`0..100`),
  - **Risk Level** (`Low`, `Guarded`, `Elevated`, `High`),
  - **Top 3 Risk Drivers**.
- Correlates findings into behavior alerts (example: bypass + encoded + web pull).
- Provides fix workflow:
  - **Preview Fix**
  - **Apply Fix**
  - **Rollback**
- Available fix IDs:
  - `restrict_smb_private`
  - `enforce_allsigned`
  - `reenable_defender`
- Exports recommendation report bundle via **Export CSV Report**:
  - `<name>-summary.csv`
  - `<name>-alerts.csv`
  - `<name>-checklist.csv`
  - `<name>-recommendations.csv`

## Current UI State

- `Export PDF Report` was intentionally removed.
- CSV exports are the supported reporting format.
- Threat analysis is available from the **PowerShell Audit** tab via the **Threat Analysis** button after a scan is run.

## Requirements

- Windows PowerShell 5.1+ or PowerShell 7 on Windows.
- Windows desktop session (WinForms GUI).
- Recommended: run as Administrator for firewall/Defender changes.
- Defender cmdlets (`Get-MpPreference`, `Set-MpPreference`) must be available for Defender-related fixes/checks.

## How To Run

From the project folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\hardening-dashboard.ps1
```

Or absolute path:

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Users\USER\OneDrive\Documents\hardening\hardening-dashboard.ps1"
```

## Typical Workflow

1. Open **PowerShell Audit** and click **Run Audit Scan**.
2. (Optional) Export raw findings with **Export CSV**.
3. Open **Port Lockdown** and click **Refresh Ports**.
4. Block unnecessary ports if needed.
5. Open **Recommendations** and click **Generate Recommendations**.
6. Review score/drivers/alerts.
7. Use **Preview Fix** -> **Apply Fix** -> **Rollback** if needed.
8. Export recommendation report bundle with **Export CSV Report**.

## Troubleshooting

### Script file not found
If PowerShell says `-File parameter does not exist`, verify path and run from correct directory.

### Permission-related failures
Firewall, Defender, and execution policy changes can fail without elevation. Start PowerShell as Administrator.

### Empty/no findings
No findings may be valid if there are no matching risky patterns in available history/logs.

### CSV export message appears but files are missing
Check the folder chosen in the save dialog and verify write permissions.

## Notes For Future Improvements

- Baseline compare and trend history are partially prepared (`baselineSummary` exists) and can be expanded.
- Threat analysis flow can be expanded with richer automated actions and safer approval gates.
- Additional hardening templates/modes can be added on top of current fix engine.
