# Vuln_Mgmt_Scripts

Read-only IOC triage scripts for SonicWall SMA 1000. Individual scripts use the repository convention `CVE-<CVE-ID>.sh`. Each CVE has its own standalone script; an optional aggregate runner is also provided.

## CVE-2026-102255 through 102258

- `CVE-2026-102255.sh` - SSRF/internal-destination leads in WorkPlace and service logs.
- `CVE-2026-102256.sh` - shell command/downloader leads in access, management, and system logs.
- `CVE-2026-102257.sh` - path traversal/archive leads in AMC and service logs.
- `CVE-2026-102258.sh` - script-like content leads in AMC and access logs.
- `IOC_CVE-2026-102255-8.sh` - optional aggregate runner; downloads and runs the four individual scripts and prints a per-CVE summary.

SonicWall advisory [SNWLID-2026-0017](https://www.sonicwall.com/support/notices/kA1VN000002QP3G0AW) identifies these as SSRF, OS command injection/RCE, Zip Slip path traversal, and stored XSS. The advisory said there was no evidence of exploitation when published. It lists fixed builds 12.4.3-03670 and 12.5.0-03082 or later; recheck the current vendor advisory for updates.

The advisory does not publish specific log signatures for these CVEs. These scripts therefore search broad behavioral leads in common SMA1000 log locations, including rotated/compressed logs. Matches can be benign and require investigation. No match does not prove the appliance is clean. They do not modify appliance logs or settings. Run as root, following the existing script convention.

Each individual script prints its findings to the SSH terminal and saves the same output in a unique file under `/tmp`, such as `/tmp/CVE-2026-102255.xxxxxx.log`. It prints the result file path at the end. The aggregate runner also saves its combined transcript under a unique `/tmp/SMA1000-IOC-results.*` directory; these result files are retained after the script exits.

## Run an individual check

Use the repository raw URL below after these changes have been pushed. For a pinned script, replace `main` with the published commit hash:

```sh
curl -kfsSL "https://raw.githubusercontent.com/garrettoh/Vuln_Mgmt_Scripts/main/CVE-2026-102255.sh" -o /tmp/CVE-2026-102255.sh && sh /tmp/CVE-2026-102255.sh; rc=$?; rm -f /tmp/CVE-2026-102255.sh; exit $rc
```

Change the filename to the desired CVE. The temporary-file method avoids piping a failed or incomplete download into the shell. The script writes findings to the SSH terminal and to its own uniquely named output file under `/tmp`.

## Optional aggregate run

Set `BASE_URL` to the pinned raw repository directory, then download and run the aggregate script:

```sh
export BASE_URL="https://raw.githubusercontent.com/garrettoh/Vuln_Mgmt_Scripts/main"; curl -kfsSL "$BASE_URL/IOC_CVE-2026-102255-8.sh" -o /tmp/IOC_CVE-2026-102255-8.sh && sh /tmp/IOC_CVE-2026-102255-8.sh; rc=$?; rm -f /tmp/IOC_CVE-2026-102255-8.sh; exit $rc
```

The aggregate runner downloads each individual script from `BASE_URL` with `curl -k`, prints each output and a summary to the SSH terminal, and saves the combined transcript under `/tmp/SMA1000-IOC-results.*/results.txt`. The individual result files are also retained. It exits 0 (no heuristic leads), 1 (at least one CVE had leads), or 2 (one or more checks failed). Set `BASE_URL` to a trusted pinned URL for repeatable operational use. `-k` disables TLS certificate verification to work around the SMA CA error; use it only on a trusted connection.

Exit status for an individual script: 0 means no heuristic match, 1 means review leads found, and 2 means not run as root. Output clarifies that no matches does not establish the appliance is clean.

## Collect the full check from Windows PowerShell

`Invoke-SMA1000-IOCCheck.ps1` uses PuTTY's Plink command-line tool to connect to the SMA and run the aggregate check. It returns the report over the same SSH session, avoiding a second SCP connection. The collector writes the combined report and SSH session output to `C:\temp\SMA_Log.log` and `C:\temp\SMA_Collection_Session.log`. Plink output is forwarded live to the console and captured to files, keeping host-key and password prompts interactive. It does not store an SSH password. PuTTY key authentication avoids repeated prompts.

From the repository folder, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SMA1000-IOCCheck.ps1 -SmaHost 192.0.2.10 -SshUser root
```

Replace the example host with the SMA's address. The script leaves the PowerShell session open and prints the local report path when collection finishes. The remote aggregate script uses `curl -k` for the SMA's reported CA verification error.

To download and run the collector in one PowerShell command, let it prompt for the SMA host. It uses `curl.exe -k` when available; otherwise it falls back to PowerShell web requests with TLS 1.2 enabled:

```powershell
$f = Join-Path $env:TEMP 'Invoke-SMA1000-IOCCheck.ps1'; $u = 'https://raw.githubusercontent.com/garrettoh/Vuln_Mgmt_Scripts/6832719f91e6bc81fc13439d96d3100ca09b3c99/Invoke-SMA1000-IOCCheck.ps1'; try { if (Get-Command curl.exe -ErrorAction SilentlyContinue) { curl.exe -kfsSL $u -o $f; if ($LASTEXITCODE -ne 0) { throw 'Collector download failed' } } else { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $f }; if (-not (Select-String -Path $f -SimpleMatch 'PuTTY Plink is required for this collector' -Quiet)) { throw 'Wrong or stale script downloaded; it was not run.' }; & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $f } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
```
The command checks for the expected PuTTY requirement before running the collector, so a stale cached copy is not executed. The downloaded script prompts for the SMA hostname/IP and SSH authentication, runs all four checks, and writes the collected report to `C:\temp\SMA_Log.log`. The PowerShell session stays open after collection. When `curl.exe` is present, `-k` bypasses workstation certificate validation; use that path only over a trusted connection. The fallback keeps certificate validation enabled and can still fail if the machine trust store is missing the required CA.

If Plink is missing, the collector asks whether to install PuTTY through `winget`. If `winget` is unavailable or installation is blocked by policy, install PuTTY with Plink through your normal workstation process, then rerun the one-line command.
