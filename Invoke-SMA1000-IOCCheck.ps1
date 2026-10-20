[CmdletBinding()]
param(
    [string]$SmaHost,
    [string]$SshUser = "root"
)

$logDirectory = "C:\temp"
$logPath = Join-Path $logDirectory "SMA_Log.log"
$sessionLogPath = Join-Path $logDirectory "SMA_Collection_Session.log"

function Write-LogLine {
    param([Parameter(Mandatory = $true)][string]$Message)
    $Message | Tee-Object -FilePath $logPath -Append
}

if (-not $SmaHost) {
    $SmaHost = Read-Host "SMA hostname or IP"
}
if (-not $SmaHost) {
    throw "An SMA hostname or IP is required."
}
if (-not $SshUser) {
    $SshUser = Read-Host "SSH username"
}

$plinkPath = (Get-Command plink.exe -ErrorAction SilentlyContinue).Source
$puttyDirectories = @()
if ($env:ProgramFiles) { $puttyDirectories += (Join-Path $env:ProgramFiles "PuTTY") }
if (${env:ProgramFiles(x86)}) { $puttyDirectories += (Join-Path ${env:ProgramFiles(x86)} "PuTTY") }
foreach ($directory in $puttyDirectories) {
    if (-not $plinkPath) {
        $candidate = Join-Path $directory "plink.exe"
        if (Test-Path -LiteralPath $candidate) { $plinkPath = $candidate }
    }
}
if (-not $plinkPath) {
    Write-Host "PuTTY Plink is required for this collector."
    $installChoice = Read-Host "Install PuTTY using winget now? (Y/N)"
    if ($installChoice.Trim().ToUpperInvariant() -ne "Y") {
        throw "Collector cancelled. Install PuTTY with Plink, then rerun the collector."
    }
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) { throw "winget was not found. Install PuTTY including Plink, then rerun the collector." }
    & $winget.Source install --id PuTTY.PuTTY --exact --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) { throw "winget could not install PuTTY (exit $LASTEXITCODE). Install PuTTY, then rerun the collector." }
    $plinkPath = (Get-Command plink.exe -ErrorAction SilentlyContinue).Source
    foreach ($directory in $puttyDirectories) {
        if (-not $plinkPath) {
            $candidate = Join-Path $directory "plink.exe"
            if (Test-Path -LiteralPath $candidate) { $plinkPath = $candidate }
        }
    }
    if (-not $plinkPath) {
        throw "PuTTY installation completed, but Plink is not available. Restart PowerShell and rerun the collector."
    }
}

New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
Set-Content -Path $logPath -Value "SMA 1000 IOC collection started: $(Get-Date -Format o)"
Set-Content -Path $sessionLogPath -Value "SSH collection session for $SshUser@$SmaHost"

$target = "$SshUser@$SmaHost"
$remoteCommand = 'BASE_URL="https://raw.githubusercontent.com/garrettoh/Vuln_Mgmt_Scripts/main"; FETCH=/tmp/IOC_CVE-2026-102255-8.sh; OUT=/tmp/SMA1000-IOC-run.$$.out; if ! curl -kfsSL "$BASE_URL/IOC_CVE-2026-102255-8.sh" -o "$FETCH"; then echo "__SMAIOC_FETCH_FAILED__"; exit 0; fi; sh "$FETCH" > "$OUT" 2>&1; check_rc=$?; cat "$OUT"; result_dir=$(sed -n "s/^Results directory:[[:space:]]*//p" "$OUT" | tail -n 1); if [ -n "$result_dir" ] && [ -f "$result_dir/results.txt" ]; then echo "__SMAIOC_REPORT_BEGIN__"; cat "$result_dir/results.txt"; echo "__SMAIOC_REPORT_END__"; fi; rm -f "$FETCH" "$OUT"; echo "__SMAIOC_EXIT=$check_rc"; exit 0'

Write-LogLine "Connecting to $target over SSH. Authenticate when prompted."
Write-LogLine "The SMA will run the aggregate check; curl -k is used as requested."
Start-Transcript -Path $sessionLogPath -Append | Out-Null
Write-LogLine "Using PuTTY Plink."
& $plinkPath -ssh -T -l $SshUser $SmaHost $remoteCommand
$sshExitCode = $LASTEXITCODE
Stop-Transcript | Out-Null

$sessionText = Get-Content -Path $sessionLogPath -Raw
if ($sessionText -match "__SMAIOC_FETCH_FAILED__") {
    Write-LogLine "ERROR: The SMA could not download the aggregate script."
    Write-LogLine "Session transcript: $sessionLogPath"
    throw "Remote script download failed. See $logPath."
}

$resultMatch = [regex]::Match($sessionText, "(?m)^Results directory:\s*(/tmp/\S+)\s*$")
if (-not $resultMatch.Success) {
    Write-LogLine "ERROR: The aggregate check did not report a results directory (SSH exit $sshExitCode)."
    Write-LogLine "Session transcript: $sessionLogPath"
    throw "Could not locate the remote report. See $logPath."
}
$remoteResultsDirectory = $resultMatch.Groups[1].Value
$localReport = Join-Path $logDirectory "SMA_Remote_Report.tmp"
$reportMatch = [regex]::Match($sessionText, "(?s)__SMAIOC_REPORT_BEGIN__\r?\n(.*?)\r?\n__SMAIOC_REPORT_END__")
if (-not $reportMatch.Success) {
    Write-LogLine "ERROR: The aggregate report was not returned over SSH."
    Write-LogLine "Session transcript: $sessionLogPath"
    throw "Could not retrieve the remote report. See $logPath."
}
Set-Content -Path $localReport -Value $reportMatch.Groups[1].Value.TrimEnd("`r", "`n") -Encoding UTF8
$checkExitCode = "unknown"
if ($sessionText -match "__SMAIOC_EXIT=(\d+)") {
    $checkExitCode = $Matches[1]
}

Write-LogLine "Retrieved aggregate report over the Plink SSH session."

Write-LogLine ""
Write-LogLine "========== SMA aggregate report =========="
Get-Content -Path $localReport | Tee-Object -FilePath $logPath -Append
Write-LogLine "========== End of SMA aggregate report =========="
Write-LogLine "Remote results directory: $remoteResultsDirectory"
Write-LogLine "Remote check exit: $checkExitCode"
Write-LogLine "Saved local log: $logPath"
Write-LogLine "SSH session transcript: $sessionLogPath"
Remove-Item -LiteralPath $localReport -Force

Write-Host ""
Write-Host "Full check collection finished. Upload this file here:"
Write-Host $logPath
Write-Host "SSH transcript: $sessionLogPath"
