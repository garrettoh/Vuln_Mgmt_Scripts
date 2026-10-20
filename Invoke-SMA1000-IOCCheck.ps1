[CmdletBinding()]
param(
    [string]$SmaHost,
    [string]$SshUser = "root"
)

$logDirectory = "C:\temp"
$logPath = Join-Path $logDirectory "SMA_Log.log"
$sessionLogPath = Join-Path $logDirectory "SMA_Collection_Session.log"

function Write-LogLine {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message)
    $Message | Tee-Object -FilePath $logPath -Append
}

if (-not ("SmaInteractiveProcessRunner" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;

public static class SmaInteractiveProcessRunner {
    private static string Quote(string value) {
        var result = new StringBuilder("\"");
        int slashes = 0;
        foreach (char ch in value) {
            if (ch == '\\') { slashes++; continue; }
            if (ch == '"') {
                result.Append('\\', slashes * 2 + 1).Append('"');
                slashes = 0;
                continue;
            }
            result.Append('\\', slashes).Append(ch);
            slashes = 0;
        }
        result.Append('\\', slashes * 2).Append('"');
        return result.ToString();
    }

    private static void Pump(Stream input, string path, Stream console) {
        using (var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read)) {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.Read(buffer, 0, buffer.Length)) > 0) {
                file.Write(buffer, 0, count);
                file.Flush();
                console.Write(buffer, 0, count);
                console.Flush();
            }
        }
    }

    public static int Run(string executable, string[] arguments, string stdoutPath, string stderrPath) {
        var info = new ProcessStartInfo();
        info.FileName = executable;
        info.Arguments = String.Join(" ", Array.ConvertAll(arguments, Quote));
        info.UseShellExecute = false;
        info.CreateNoWindow = false;
        info.RedirectStandardOutput = true;
        info.RedirectStandardError = true;
        info.RedirectStandardInput = false;
        using (var process = new Process()) {
            process.StartInfo = info;
            process.Start();
            var stdout = Task.Factory.StartNew(() => Pump(process.StandardOutput.BaseStream, stdoutPath, Console.OpenStandardOutput()));
            var stderr = Task.Factory.StartNew(() => Pump(process.StandardError.BaseStream, stderrPath, Console.OpenStandardError()));
            process.WaitForExit();
            Task.WaitAll(stdout, stderr);
            return process.ExitCode;
        }
    }
}
'@
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
$remoteCommand = 'BASE_URL="https://raw.githubusercontent.com/garrettoh/Vuln_Mgmt_Scripts/main"; FETCH=/tmp/IOC_CVE-2026-102255-8.sh; OUT=/tmp/SMA1000-IOC-run.$$.out; if ! curl -kfsSL "$BASE_URL/IOC_CVE-2026-102255-8.sh" -o "$FETCH"; then echo "__SMAIOC_FETCH_FAILED__"; exit 0; fi; sh "$FETCH" > "$OUT" 2>&1; check_rc=$?; echo "__SMAIOC_REPORT_BEGIN__"; cat "$OUT"; echo "__SMAIOC_REPORT_END__"; rm -f "$FETCH" "$OUT"; echo "__SMAIOC_EXIT=$check_rc"; exit 0'

Write-LogLine "Connecting to $target over SSH. Authenticate when prompted."
Write-LogLine "The SMA will run the aggregate check; curl -k is used as requested."
Write-LogLine "Using PuTTY Plink."
$plinkStdoutPath = Join-Path $env:TEMP ("SMA_Plink_" + [guid]::NewGuid().ToString("N") + ".stdout")
$plinkStderrPath = Join-Path $env:TEMP ("SMA_Plink_" + [guid]::NewGuid().ToString("N") + ".stderr")
$plinkArguments = @("-ssh", "-T", "-l", $SshUser, $SmaHost, $remoteCommand)
$sshExitCode = [SmaInteractiveProcessRunner]::Run($plinkPath, $plinkArguments, $plinkStdoutPath, $plinkStderrPath)
$stdoutText = [System.IO.File]::ReadAllText($plinkStdoutPath)
$stderrText = [System.IO.File]::ReadAllText($plinkStderrPath)
$sessionText = $stdoutText + $stderrText
[System.IO.File]::AppendAllText($sessionLogPath, $sessionText, (New-Object System.Text.UTF8Encoding($false)))
Remove-Item -LiteralPath $plinkStdoutPath, $plinkStderrPath -Force -ErrorAction SilentlyContinue
if ($sessionText -match "__SMAIOC_FETCH_FAILED__") {
    Write-LogLine "ERROR: The SMA could not download the aggregate script."
    Write-LogLine "Session transcript: $sessionLogPath"
    throw "Remote script download failed. See $logPath."
}

$resultMatch = [regex]::Match($sessionText, "Results directory:\s*(/tmp/\S+)")
if ($resultMatch.Success) { $remoteResultsDirectory = $resultMatch.Groups[1].Value }
else { $remoteResultsDirectory = "See $sessionLogPath" }
$localReport = Join-Path $logDirectory "SMA_Remote_Report.tmp"
$reportMatch = [regex]::Match($sessionText, "(?s)__SMAIOC_REPORT_BEGIN__[\r\n ]*(.*?)\s*__SMAIOC_REPORT_END__")
if ($reportMatch.Success) {
    $reportContent = $reportMatch.Groups[1].Value.TrimEnd("`r", "`n")
}
else {
    # PowerShell transcription can alter or omit boundary lines for native output.
    # Preserve the captured SSH session instead of discarding a completed scan.
    Write-LogLine "WARNING: Report boundary markers were incomplete; saving the full SSH transcript as the report."
    $reportContent = $sessionText
}
Set-Content -Path $localReport -Value $reportContent -Encoding UTF8
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
