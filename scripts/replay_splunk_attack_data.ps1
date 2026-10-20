param(
    [string]$ApiBaseUrl = "http://localhost:8000/api/v1",
    [ValidateSet("all", "T1003.001", "T1003.003", "T1059.001", "T1110.003", "T1562.001")]
    [string]$Technique = "all"
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($env:SOC_ACCESS_TOKEN)) {
    throw "Set SOC_ACCESS_TOKEN to a valid SOC API access token first."
}

# Curated, small samples from Splunk's public Attack Data repository. This downloads
# only the listed logs, never the full repository. The files are recorded test data.
$datasets = @(
    @{
        Technique = "T1003.001 - LSASS credential access"
        RelativePath = "datasets/attack_techniques/T1003.001/snapattack/snapattack.log"
        FileName = "splunk-T1003.001-snapattack.log"
    },
    @{
        Technique = "T1059.001 - PowerShell FromBase64String"
        RelativePath = "datasets/attack_techniques/T1059.001/powershell_script_block_logging/frombase64string.log"
        FileName = "splunk-T1059.001-frombase64string.log"
    },
    @{
        Technique = "T1110.003 - NTLM authentication telemetry"
        RelativePath = "datasets/attack_techniques/T1110.003/ntlm_bruteforce/ntlm_bruteforce.log"
        FileName = "splunk-T1110.003-ntlm.log"
    },
    @{
        Technique = "T1003.003 - NTDS credential access"
        RelativePath = "datasets/attack_techniques/T1003.003/atomic_red_team/4688_windows-security.log"
        FileName = "splunk-T1003.003-ntds.log"
    },
    @{
        Technique = "T1562.001 - PowerShell Defender exclusion"
        RelativePath = "datasets/attack_techniques/T1562.001/powershell_windows_defender_exclusion_commands/windows-xml.log"
        FileName = "splunk-T1562.001-defender-exclusion.log"
    }
)

if ($Technique -ne "all") {
    $datasets = @($datasets | Where-Object { $_.Technique.StartsWith($Technique) })
}

$dataDirectory = Join-Path $env:TEMP "AISocCopilot-Splunk-Attack-Data"
New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null
$headers = @("Authorization: Bearer $env:SOC_ACCESS_TOKEN")

foreach ($dataset in $datasets) {
    $url = "https://media.githubusercontent.com/media/splunk/attack_data/master/$($dataset.RelativePath)"
    $filePath = Join-Path $dataDirectory $dataset.FileName

    Write-Host "`nDownloading and replaying $($dataset.Technique)..."
    & curl.exe --fail --location --silent --show-error --output $filePath $url
    if ($LASTEXITCODE -ne 0) {
        throw "Download failed for $($dataset.RelativePath). Check the repository path and network access."
    }

    $fileInfo = Get-Item -LiteralPath $filePath
    if ($fileInfo.Length -eq 0 -or $fileInfo.Length -gt 25MB) {
        throw "Downloaded file '$($dataset.FileName)' is empty or larger than the API's 25 MiB upload limit."
    }
    $prefix = Get-Content -LiteralPath $filePath -TotalCount 1 -ErrorAction Stop
    if ($prefix -match "^version https://git-lfs.github.com/spec/v1") {
        throw "Git LFS returned a pointer instead of log data for '$($dataset.FileName)'."
    }

    $response = & curl.exe --fail-with-body --silent --show-error -X POST `
        "$ApiBaseUrl/events/replay" `
        -H $headers[0] `
        -F "file=@$filePath"
    if ($LASTEXITCODE -ne 0) {
        throw "Replay upload failed for '$($dataset.FileName)'. API response: $($response -join ' ')"
    }
    Write-Host $response
}

Write-Host "`nReplay complete. Imported records and any alerts are labeled simulated; this does not generate live attacks or train an ML model."
Write-Host "Downloaded sample logs are in: $dataDirectory"
