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

$sshPath = (Get-Command ssh.exe -ErrorAction SilentlyContinue).Source
$scpPath = (Get-Command scp.exe -ErrorAction SilentlyContinue).Source

if (-not $sshPath -and $env:WINDIR) {
    $candidate = Join-Path $env:WINDIR "System32\OpenSSH\ssh.exe"
    if (Test-Path -LiteralPath $candidate) { $sshPath = $candidate }
}
if (-not $scpPath -and $env:WINDIR) {
    $candidate = Join-Path $env:WINDIR "System32\OpenSSH\scp.exe"
    if (Test-Path -LiteralPath $candidate) { $scpPath = $candidate }
}

if (-not ($sshPath -and $scpPath)) {
    Write-Host "Windows OpenSSH Client (ssh.exe and scp.exe) is required for this collector."
    $installChoice = Read-Host "Install Windows OpenSSH Client now? (Y/N)"
    if ($installChoice.Trim().ToUpperInvariant() -ne "Y") {
        throw "Collector cancelled. Install Windows OpenSSH Client, then rerun the collector."
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "OpenSSH installation needs administrator rights. Reopen PowerShell as Administrator and rerun this collector."
    }
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 -ErrorAction Stop | Out-Host

    $sshPath = (Get-Command ssh.exe -ErrorAction SilentlyContinue).Source
    $scpPath = (Get-Command scp.exe -ErrorAction SilentlyContinue).Source
    if (-not $sshPath -and $env:WINDIR) {
        $candidate = Join-Path $env:WINDIR "System32\OpenSSH\ssh.exe"
        if (Test-Path -LiteralPath $candidate) { $sshPath = $candidate }
    }
    if (-not $scpPath -and $env:WINDIR) {
        $candidate = Join-Path $env:WINDIR "System32\OpenSSH\scp.exe"
        if (Test-Path -LiteralPath $candidate) { $scpPath = $candidate }
    }
    if (-not ($sshPath -and $scpPath)) {
        throw "OpenSSH installation completed, but ssh.exe/scp.exe are not available. Restart PowerShell and rerun the collector."
    }
}

New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
Set-Content -Path $logPath -Value "SMA 1000 IOC collection started: $(Get-Date -Format o)"
Set-Content -Path $sessionLogPath -Value "SSH collection session for $SshUser@$SmaHost"

$target = "$SshUser@$SmaHost"
$remoteCommand = 'BASE_URL="https://raw.githubusercontent.com/garrettoh/Vuln_Mgmt_Scripts/main"; FETCH=/tmp/IOC_CVE-2026-102255-8.sh; if ! curl -kfsSL "$BASE_URL/IOC_CVE-2026-102255-8.sh" -o "$FETCH"; then echo "__SMAIOC_FETCH_FAILED__"; exit 0; fi; sh "$FETCH"; check_rc=$?; rm -f "$FETCH"; echo "__SMAIOC_EXIT=$check_rc"; exit 0'

Write-LogLine "Connecting to $target over SSH. Authenticate when prompted."
Write-LogLine "The SMA will run the aggregate check; curl -k is used as requested."
Start-Transcript -Path $sessionLogPath -Append | Out-Null
Write-LogLine "Using Windows OpenSSH."
& $sshPath -T $target $remoteCommand
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
$remoteReport = "$remoteResultsDirectory/results.txt"
$localReport = Join-Path $logDirectory "SMA_Remote_Report.tmp"
$checkExitCode = "unknown"
if ($sessionText -match "__SMAIOC_EXIT=(\d+)") {
    $checkExitCode = $Matches[1]
}

Write-LogLine "Copying $remoteReport to $localReport over SCP."
Start-Transcript -Path $sessionLogPath -Append | Out-Null
& $scpPath -q "${target}:$remoteReport" $localReport
$scpExitCode = $LASTEXITCODE
Stop-Transcript | Out-Null
if ($scpExitCode -ne 0 -or -not (Test-Path -LiteralPath $localReport)) {
    Write-LogLine "ERROR: SCP could not copy the remote report (exit $scpExitCode)."
    Write-LogLine "Session transcript: $sessionLogPath"
    throw "Report copy failed. See $logPath."
}

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
