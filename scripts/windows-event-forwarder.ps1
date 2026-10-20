<#
    Real Windows Event Log -> AI SOC Copilot ingestion connector.

    Reads genuine security telemetry from the local Windows event logs and forwards it to the
    authenticated ingest webhook. This is a REAL data source (your own host), not simulated data.

    Logs read (best-effort; access errors are reported, not hidden):
      - Microsoft-Windows-Windows Defender/Operational  (real malware/AV events)
      - Microsoft-Windows-PowerShell/Operational         (script block logging, 4103/4104)

    The Security log (4624/4625/4688...) requires an ELEVATED shell. Run this from an
    Administrator PowerShell to include it.

    Usage:
      powershell -ExecutionPolicy Bypass -File .\scripts\windows-event-forwarder.ps1 `
        -BaseUrl http://127.0.0.1:8000/api/v1 -SourceId webhook-default -Token dev-ingest-token

    Scheduling: wrap it in a Windows Scheduled Task to run every N minutes for near-real-time intake.
#>
param(
  [string]$BaseUrl = "http://127.0.0.1:8000/api/v1",
  [string]$SourceId = "webhook-default",
  [string]$Token = "dev-ingest-token",
  [string]$TenantId = "tenant_default",
  [int]$MaxEvents = 200
)

$hostName = $env:COMPUTERNAME
$records = New-Object System.Collections.ArrayList

function New-Rec($evt, $type, $source, $sev, $proc, $cmd, $user) {
  [pscustomobject]@{
    event_id     = "$source-$($evt.RecordId)-$($evt.Id)"
    timestamp    = $evt.TimeCreated.ToUniversalTime().ToString("o")
    hostname     = $hostName
    user         = $user
    event_type   = $type
    source       = $source
    severity     = $sev
    process_name = $proc
    command_line = $cmd
  }
}

try {
  $def = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents $MaxEvents -ErrorAction Stop
  foreach ($e in $def) {
    $type = switch ($e.Id) { 1006 {'malware_detection'} 1007 {'malware_action'} 1015 {'malware_detection'} 1116 {'malware_detection'} 1117 {'malware_action'} default {'defender_status'} }
    $sev  = switch ($e.Id) { 1006 {'critical'} 1116 {'critical'} 1007 {'high'} 1117 {'high'} default {'low'} }
    $msg = "$($e.Message -replace '\s+',' ')"
    if ($msg.Length -gt 900) { $msg = $msg.Substring(0,900) }
    [void]$records.Add((New-Rec $e $type 'windows-defender' $sev 'MsMpEng.exe' $msg $null))
  }
  Write-Output "Defender: $($def.Count) real events"
} catch { Write-Output "Defender skipped: $($_.Exception.Message)" }

try {
  $ps = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4103,4104} -MaxEvents $MaxEvents -ErrorAction Stop
  foreach ($e in $ps) {
    $msg = "$($e.Message -replace '\s+',' ')"
    if ($msg.Length -gt 900) { $msg = $msg.Substring(0,900) }
    [void]$records.Add((New-Rec $e 'script_block' 'windows-powershell' 'low' 'powershell.exe' $msg $null))
  }
  Write-Output "PowerShell: $($ps.Count) real events"
} catch { Write-Output "PowerShell skipped: $($_.Exception.Message)" }

try {
  $sec = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4688} -MaxEvents $MaxEvents -ErrorAction Stop
  foreach ($e in $sec) {
    $type = if ($e.Id -eq 4625) { 'failed_logon' } else { 'process_creation' }
    $sev  = if ($e.Id -eq 4625) { 'medium' } else { 'low' }
    $msg = "$($e.Message -replace '\s+',' ')"
    if ($msg.Length -gt 900) { $msg = $msg.Substring(0,900) }
    [void]$records.Add((New-Rec $e $type 'windows-security' $sev $null $msg $null))
  }
  Write-Output "Security: $($sec.Count) real events"
} catch { Write-Output "Security skipped (needs elevated shell): $($_.Exception.Message)" }

if ($records.Count -eq 0) { Write-Output "No real events collected."; exit 0 }

Write-Output "Total real events: $($records.Count)"
$payload = @{ events = @($records) } | ConvertTo-Json -Depth 6 -Compress
$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
$resp = Invoke-RestMethod -Method Post -Uri "$BaseUrl/ingest/webhook/$SourceId" `
  -Headers @{ "X-Ingest-Token" = $Token; "X-Tenant-Id" = $TenantId } `
  -ContentType "application/json; charset=utf-8" -Body $bodyBytes
$resp | ConvertTo-Json -Depth 5
