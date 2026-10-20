param(
    [string]$ApiBaseUrl = "http://localhost:8000/api/v1",
    [int]$PollSeconds = 15,
    [int]$BatchSize = 200
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($env:SOC_ACCESS_TOKEN)) {
    throw "Set SOC_ACCESS_TOKEN to a valid SOC API access token first."
}

$stateDirectory = Join-Path $env:LOCALAPPDATA "AISocCopilot"
$statePath = Join-Path $stateDirectory "windows-event-checkpoint.txt"
New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
if (Test-Path $statePath) {
    try { $cursor = [datetime]::Parse((Get-Content -LiteralPath $statePath -Raw).Trim()).ToLocalTime() }
    catch { $cursor = (Get-Date).AddMinutes(-5) }
}
else {
    # Start with a small lookback instead of uploading the entire Windows event history.
    $cursor = (Get-Date).AddMinutes(-5)
}

$channels = @(
    @{ LogName = "Microsoft-Windows-Sysmon/Operational"; Kind = "sysmon"; Ids = @(1, 3, 10, 11, 22) },
    @{ LogName = "Microsoft-Windows-Windows Defender/Operational"; Kind = "defender"; Ids = @(1116, 1117, 5001, 5007) },
    @{ LogName = "Microsoft-Windows-PowerShell/Operational"; Kind = "powershell"; Ids = @(4103, 4104) },
    @{ LogName = "Security"; Kind = "security"; Ids = @(4625, 4688) }
)

function Get-EventFields($EventRecord) {
    $fields = @{}
    try {
        [xml]$xml = $EventRecord.ToXml()
        foreach ($item in @($xml.Event.EventData.Data)) {
            if ($null -ne $item) {
                $name = [string]$item.Name
                if ([string]::IsNullOrWhiteSpace($name)) { $name = "Data$($fields.Count)" }
                $fields[$name] = [string]$item.InnerText
            }
        }
    }
    catch { }
    return $fields
}

function Convert-ToSocEvent($EventRecord, $Kind) {
    $fields = Get-EventFields $EventRecord
    $message = ""
    try { $message = [string]$EventRecord.Message } catch { }
    $eventType = $null
    $source = $null
    $processName = $null
    $commandLine = $null
    $userName = $null
    $domain = $null
    $fileHash = $null

    switch ($Kind) {
        "sysmon" {
            $source = "edr"
            switch ([int]$EventRecord.Id) {
                1  { $eventType = "process_creation"; $processName = $fields.Image; $commandLine = $fields.CommandLine; $userName = $fields.User }
                3  { $eventType = "network_connection"; $processName = $fields.Image; $userName = $fields.User }
                10 { $eventType = "process_access"; $processName = $fields.SourceImage; $userName = $fields.User }
                11 { $eventType = "file_create"; $processName = $fields.Image; $userName = $fields.User }
                22 { $eventType = "dns_query"; $processName = $fields.Image; $domain = $fields.QueryName; $userName = $fields.User }
            }
            $fileHash = $fields.Hashes
        }
        "defender" {
            $source = "endpoint_av"
            switch ([int]$EventRecord.Id) {
                1116 { $eventType = "malware_detection" }
                1117 { $eventType = "malware_action" }
                5001 { $eventType = "defender_status" }
                5007 { $eventType = "defender_config_change" }
            }
            $processName = $fields.Path
            $userName = $fields.User
        }
        "powershell" {
            $source = "edr"
            switch ([int]$EventRecord.Id) {
                4103 { $eventType = "powershell_module" }
                4104 { $eventType = "powershell_script_block" }
            }
            $processName = "powershell.exe"
            $commandLine = $fields.ScriptBlockText
            if (-not $commandLine) { $commandLine = $fields.Payload }
            $userName = $fields.UserId
        }
        "security" {
            $source = "identity"
            switch ([int]$EventRecord.Id) {
                4625 { $eventType = "failed_logon"; $userName = $fields.TargetUserName }
                4688 { $eventType = "process_creation"; $processName = $fields.NewProcessName; $commandLine = $fields.CommandLine; $userName = $fields.SubjectUserName }
            }
        }
    }
    if (-not $eventType) { return $null }
    $srcIp = $fields.SourceIp
    if (-not $srcIp) { $srcIp = $fields.IpAddress }

    $raw = @{
        channel = $EventRecord.LogName
        provider = $EventRecord.ProviderName
        windows_event_id = [int]$EventRecord.Id
        record_id = $EventRecord.RecordId
        message = $message
        event_data = $fields
    }
    return @{
        event_id = "$($env:COMPUTERNAME):$($EventRecord.LogName):$($EventRecord.RecordId)"
        timestamp = $EventRecord.TimeCreated.ToUniversalTime().ToString("o")
        source = $source
        event_type = $eventType
        severity = "low"
        hostname = $env:COMPUTERNAME
        user = $userName
        process_name = $processName
        command_line = $commandLine
        domain = $domain
        file_hash = $fileHash
        src_ip = $srcIp
        dst_ip = $fields.DestinationIp
        src_port = $fields.SourcePort
        dst_port = $fields.DestinationPort
        raw_data = ($raw | ConvertTo-Json -Depth 6 -Compress)
    }
}

$endpoint = "$ApiBaseUrl/events/telemetry/windows"
Write-Host "Windows telemetry collector started. Endpoint: $endpoint"
Write-Host "Reads Sysmon, Defender, PowerShell, and selected Windows Security events. Press Ctrl+C to stop."

while ($true) {
    $nextCursor = Get-Date
    $events = [System.Collections.Generic.List[object]]::new()
    $readFailed = $false

    foreach ($channel in $channels) {
        try {
            $records = Get-WinEvent -FilterHashtable @{
                LogName = $channel.LogName
                StartTime = $cursor
                Id = $channel.Ids
            } -ErrorAction Stop | Sort-Object TimeCreated
            foreach ($record in $records) {
                $converted = Convert-ToSocEvent $record $channel.Kind
                if ($null -ne $converted) { $events.Add($converted) }
            }
        }
        catch {
            if ($_.FullyQualifiedErrorId -notlike "*NoMatchingEventsFound*" -and
                $_.Exception.Message -notmatch "No events were found|channel.*could not be found|could not find.*channel") {
                $readFailed = $true
                Write-Warning "Could not read '$($channel.LogName)'; run PowerShell as Administrator and check Sysmon is installed. $($_.Exception.Message)"
            }
        }
    }

    $uploadSucceeded = $true
    for ($offset = 0; $offset -lt $events.Count; $offset += $BatchSize) {
        $end = [Math]::Min($offset + $BatchSize - 1, $events.Count - 1)
        $batch = @($events.GetRange($offset, $end - $offset + 1))
        $body = @{ events = $batch } | ConvertTo-Json -Depth 8 -Compress
        try {
            $response = Invoke-RestMethod `
                -Method Post `
                -Uri $endpoint `
                -Headers @{ Authorization = "Bearer $env:SOC_ACCESS_TOKEN" } `
                -ContentType "application/json" `
                -Body $body
            Write-Host "Uploaded $($response.accepted_count) events; alerts created: $($response.alerts_created)."
        }
        catch {
            $uploadSucceeded = $false
            Write-Warning "Upload failed; checkpoint will not advance. Check API availability and whether SOC_ACCESS_TOKEN has expired. $($_.Exception.Message)"
            break
        }
    }

    if ($uploadSucceeded -and -not $readFailed) {
        $nextCursor.ToString("o") | Set-Content -LiteralPath $statePath -Encoding utf8
        $cursor = $nextCursor
    }
    Start-Sleep -Seconds $PollSeconds
}
