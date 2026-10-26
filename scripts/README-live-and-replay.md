# Live Windows telemetry and public dataset replay

These are two distinct data paths:

- `collect_windows_telemetry.ps1` sends current Windows Sysmon, Defender, and selected Security log events to the app. They are live host telemetry and are stored under the tenant from the user's JWT.
- `POST /api/v1/events/replay` imports a public log file as simulated replay data. It is visibly labeled `is_simulated=true` and cannot be confused with live laptop events.

## 1. Start the app and get a token

From the repository root:

```powershell
docker compose up --build -d
```

Log in using your app account. Keep the token in the current PowerShell process; do not commit it to a file:

```powershell
$login = Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8000/api/v1/auth/login" `
  -ContentType "application/json" `
  -Body (@{ email = "YOUR_EMAIL"; password = "YOUR_PASSWORD" } | ConvertTo-Json)
$env:SOC_ACCESS_TOKEN = $login.access_token
```

The JWT expires according to `ACCESS_TOKEN_EXPIRE_MINUTES` (60 minutes by default). Log in again after it expires.

## 2. Collect live Windows events

Install Microsoft Sysmon on the Windows laptop using Microsoft's Sysinternals instructions. Open PowerShell as Administrator and verify the Sysmon channel exists:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3
```

From the repository root, run the collector in that same PowerShell process (after setting `SOC_ACCESS_TOKEN` above):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\collect_windows_telemetry.ps1
```

It polls every 15 seconds and stores its timestamp checkpoint under `%LOCALAPPDATA%\AISocCopilot`. Stop it with Ctrl+C. It reads Sysmon process, network, process-access, file-create, and DNS events; Defender detection/remediation/configuration events; PowerShell module/script-block events; and selected Windows Security logon/process events. A real benign event may create no alert; the detection rules only alert on matched evidence.

## 3. Replay varied Splunk Attack Data samples

The public [Splunk Attack Data repository](https://github.com/splunk/attack_data) has datasets organized by ATT&CK technique. The samples cover LSASS access, NTDS database access, PowerShell script-block activity, Defender exclusion changes, and NTLM authentication telemetry. Some datasets are generated in lab/Attack Range environments; they are recorded test logs, not live telemetry from your laptop or live attacks. The script downloads only these selected log files, then uploads them to the replay endpoint:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\replay_splunk_attack_data.ps1
```

After updating the backend parser, rebuild the API and retry just one sample to avoid replaying the successful datasets again:

```powershell
docker compose up --build -d
.\scripts\replay_splunk_attack_data.ps1 -Technique T1110.003
```

To add more distinct alert examples, replay the NTDS or Defender-exclusion sample individually:

```powershell
.\scripts\replay_splunk_attack_data.ps1 -Technique T1003.003
.\scripts\replay_splunk_attack_data.ps1 -Technique T1562.001
```

The API applies the normal detection and correlation rules and marks all imported events and resulting alerts as simulated. The available rules may create alerts for matching evidence; a dataset does not guarantee a specific alert if its records do not match a rule or parser. The NTLM sample is treated as authentication telemetry and is not automatically called a brute-force attack. These logs are useful to exercise and evaluate the pipeline; they do not train an ML model or make detections learned from real traffic. This workflow only downloads and imports recorded logs; it does not execute any payloads.

To replay only one sample, use `curl.exe` to download its individual `.log` file from the repository's `media.githubusercontent.com` URL and upload it to `POST /api/v1/events/replay` with the same bearer token. Files must be under the endpoint's 25 MiB limit.
