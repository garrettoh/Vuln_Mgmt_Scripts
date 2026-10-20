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
curl -fsSL "https://raw.githubusercontent.com/garrettoh/Vuln_Mgmt_Scripts/main/CVE-2026-102255.sh" -o /tmp/CVE-2026-102255.sh && sh /tmp/CVE-2026-102255.sh; rc=$?; rm -f /tmp/CVE-2026-102255.sh; exit $rc
```

Change the filename to the desired CVE. The temporary-file method avoids piping a failed or incomplete download into the shell. The script writes findings to the SSH terminal and to its own uniquely named output file under `/tmp`.

## Optional aggregate run

Set `BASE_URL` to the pinned raw repository directory, then download and run the aggregate script:

```sh
export BASE_URL="https://raw.githubusercontent.com/garrettoh/Vuln_Mgmt_Scripts/main"; curl -fsSL "$BASE_URL/IOC_CVE-2026-102255-8.sh" -o /tmp/IOC_CVE-2026-102255-8.sh && sh /tmp/IOC_CVE-2026-102255-8.sh; rc=$?; rm -f /tmp/IOC_CVE-2026-102255-8.sh; exit $rc
```

The aggregate runner downloads each individual script from `BASE_URL`, prints each output and a summary to the SSH terminal, and saves the combined transcript under `/tmp/SMA1000-IOC-results.*/results.txt`. The individual result files are also retained. It exits 0 (no heuristic leads), 1 (at least one CVE had leads), or 2 (one or more checks failed). Set `BASE_URL` to a trusted pinned URL for repeatable operational use. The raw `main` URL will work after these changes are pushed.

Exit status for an individual script: 0 means no heuristic match, 1 means review leads found, and 2 means not run as root. Output clarifies that no matches does not establish the appliance is clean.
