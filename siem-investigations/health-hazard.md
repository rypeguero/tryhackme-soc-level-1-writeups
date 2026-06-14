# Health Hazard SIEM Investigation

## Objective

The objective of this investigation was to validate or disprove the hypothesis that a compromised third-party software package was used to gain initial access, execute malicious commands, stage a payload, and establish persistence on a Windows endpoint.

This writeup focuses on the investigation process, evidence review, timeline building, IOC identification, and MITRE ATT&CK mapping. It does not include TryHackMe flags or direct room answers.

## Scenario Summary

The simulated environment involved a user building a website and installing JavaScript packages. After the package installation, suspicious endpoint activity appeared in Splunk Enterprise. The investigation focused on determining whether the package installation was benign developer activity or part of a malicious supply chain compromise.

The key suspicious behavior involved an npm package installation followed by command execution, hidden encoded PowerShell, a DNS query to a suspicious update-themed domain, and creation of a Windows Registry Run key for persistence.

## Tools Used

- TryHackMe Threat Hunting Simulator
- Splunk Enterprise
- Sysmon event logs
- Windows process creation telemetry
- Windows registry event telemetry
- DNS query telemetry
- MITRE ATT&CK

## Hypothesis

An attacker may have leveraged a compromised third-party software package to gain initial access to the system and silently stage a payload for later execution. The attacker likely established persistence to maintain access without immediate detection.

## Investigation Approach

The investigation started broadly by searching for JavaScript package manager activity, then narrowed into process lineage, encoded PowerShell behavior, network indicators, and registry modification events.

The main hunt questions were:

1. Was a suspicious third-party package installed?
2. Did the package trigger command execution after installation?
3. Did the command attempt to download or stage a payload?
4. Was persistence established?
5. Was there evidence that the staged payload executed?

## Key Splunk Searches

### Package Installation Search

```spl
"healthchk-lib@1.0.1"
| table _time EventCode Image ParentImage CommandLine ParentCommandLine User host
| sort _time
```

### Process Chain Search

```spl
"healthchk-lib@1.0.1" OR "EncodedCommand"
| table _time EventCode Image ParentImage CommandLine ParentCommandLine User host
| sort _time
```

### Persistence and Payload Search

```spl
"Windows Update Monitor" OR "SystemHealthUpdater.exe" OR "global-update.wlndows.thm"
| table _time EventCode TaskCategory Image TargetObject Details QueryName User host
| sort _time
```

### Full Timeline Search

```spl
"healthchk-lib@1.0.1" OR "EncodedCommand" OR "global-update.wlndows.thm" OR "Windows Update Monitor"
| table _time EventCode TaskCategory Image ParentImage CommandLine ParentCommandLine QueryName TargetObject Details User
| sort _time
```

## Timeline of Events

| Time | Stage | Evidence | Interpretation |
|---|---|---|---|
| 2025-06-21 10:58:24 | Package Installation | `node.exe` executed `npm-cli.js install healthchk-lib@1.0.1` | A third-party npm package was installed on the endpoint. |
| 2025-06-21 10:58:27 | Post-Install Command Execution | `node.exe` spawned `cmd.exe` | The package installation triggered command execution. |
| 2025-06-21 10:58:27 | Hidden Encoded PowerShell | `cmd.exe` launched `powershell.exe -NoP -W Hidden -EncodedCommand` | PowerShell was executed in a stealthy and obfuscated manner. |
| 2025-06-21 10:58:29 | DNS Query | PowerShell queried `global-update.wlndows.thm` | The host attempted to contact a suspicious update-themed domain. |
| 2025-06-21 10:58:29 | Registry Persistence | PowerShell created `Windows Update Monitor` under the user Run key | Persistence was established through a Windows Registry Run key. |

## Key Evidence

### 1. Suspicious npm Package Installation

The first key event showed Node.js executing an npm install command for the package `healthchk-lib@1.0.1`.

| Field | Evidence |
|---|---|
| Event Type | Process Create |
| EventCode | 1 |
| Image | `C:\Program Files\nodejs\node.exe` |
| ParentImage | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| CommandLine | `npm-cli.js install healthchk-lib@1.0.1` |
| Host | `PAW-TOM` |
| User | `PAW-TOM\itadmin-tom` |

This event was important because the later suspicious command execution was directly tied back to the npm package installation.

### 2. Malicious Post-Install Command Execution

Shortly after installation, `node.exe` spawned `cmd.exe`, which then launched PowerShell with hidden and encoded command-line options.

| Field | Evidence |
|---|---|
| Event Type | Process Create |
| EventCode | 1 |
| Image | `C:\Windows\System32\cmd.exe` |
| ParentImage | `C:\Program Files\nodejs\node.exe` |
| ParentCommandLine | `npm-cli.js install healthchk-lib@1.0.1` |
| CommandLine | `cmd.exe /d /s /c powershell.exe -NoP -W Hidden -EncodedCommand ...` |

This behavior is suspicious because normal package installation activity should not launch hidden encoded PowerShell. The parent-child relationship showed that the suspicious command execution originated from the Node.js/npm process.

### 3. Suspicious PowerShell Download Activity

The encoded PowerShell command referenced a download operation using `Invoke-WebRequest`. The command attempted to retrieve a payload from a suspicious domain and write it to the user's AppData Roaming directory.

| Indicator | Value |
|---|---|
| Download URL | `http://global-update.wlndows.thm/SystemHealthUpdater.exe` |
| Domain | `global-update.wlndows.thm` |
| Payload Name | `SystemHealthUpdater.exe` |
| Intended Payload Path | `%APPDATA%\SystemHealthUpdater.exe` |

The domain `wlndows.thm` appeared suspicious because it resembled `windows` but used a missing `i`, suggesting typo-style masquerading.

### 4. DNS Query to Suspicious Domain

Sysmon DNS telemetry showed PowerShell querying the suspicious domain.

| Field | Evidence |
|---|---|
| Event Type | DNS Query |
| EventCode | 22 |
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| QueryName | `global-update.wlndows.thm` |
| Host | `PAW-TOM` |
| User | `PAW-TOM\itadmin-tom` |

This helped confirm that the hidden PowerShell process attempted outbound network activity consistent with the decoded download command.

### 5. Registry Run Key Persistence

The strongest persistence evidence was a Sysmon registry value set event showing creation of a Run key value named `Windows Update Monitor`.

| Field | Evidence |
|---|---|
| Event Type | Registry Value Set |
| EventCode | 13 |
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| TargetObject | `HKU\S-1-5-21-1966530601-3185510712-10604624-500\Software\Microsoft\Windows\CurrentVersion\Run\Windows Update Monitor` |
| Details | `powershell.exe -NoP -W Hidden -EncodedCommand ...` |

The encoded registry value launched:

```powershell
Start-Process 'C:\Users\Administrator\AppData\Roaming\SystemHealthUpdater.exe'
```

This showed that the attacker established persistence by configuring the payload to run at user logon.

## Indicators of Compromise

### Host-Based IOCs

| Type | Indicator |
|---|---|
| NPM Package | `healthchk-lib@1.0.1` |
| Process | `C:\Program Files\nodejs\node.exe` |
| Process | `C:\Windows\System32\cmd.exe` |
| Process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| PowerShell Flags | `-NoP -W Hidden -EncodedCommand` |
| Registry Path | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| Registry Value Name | `Windows Update Monitor` |
| Payload Name | `SystemHealthUpdater.exe` |
| Payload Path | `C:\Users\Administrator\AppData\Roaming\SystemHealthUpdater.exe` |

### Network-Based IOCs

| Type | Indicator |
|---|---|
| Domain | `global-update.wlndows.thm` |
| URL | `http://global-update.wlndows.thm/SystemHealthUpdater.exe` |
| Protocol | HTTP |
| Port | 80 |

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1195 - Supply Chain Compromise | Suspicious package `healthchk-lib@1.0.1` installed through npm. |
| Execution | T1059 - Command and Scripting Interpreter | `cmd.exe` launched hidden encoded PowerShell. |
| Defense Evasion | T1027 - Obfuscated Files or Information | PowerShell used `-EncodedCommand` to obscure the command content. |
| Command and Control / Transfer | T1105 - Ingress Tool Transfer | PowerShell attempted to download `SystemHealthUpdater.exe` from `global-update.wlndows.thm`. |
| Persistence | T1547.001 - Registry Run Keys / Startup Folder | Registry Run key value `Windows Update Monitor` was created. |

## Findings

The hypothesis was proven. The evidence showed that the package `healthchk-lib@1.0.1` was installed and then led to suspicious command execution. The resulting process chain launched hidden encoded PowerShell, contacted a suspicious domain, and created registry-based persistence.

The investigation confirmed persistence through a Windows Registry Run key. The Run key was configured to execute `SystemHealthUpdater.exe` from the user's AppData Roaming directory during user logon.

No process execution evidence was observed for `SystemHealthUpdater.exe` during the reviewed logs. Based on the available telemetry, the payload appeared to be staged for later execution rather than executed immediately.

## Recommended Remediation

- Remove the malicious npm package from the affected project.
- Delete the Registry Run key value named `Windows Update Monitor`.
- Locate and remove `SystemHealthUpdater.exe` from the affected user's AppData Roaming directory if present.
- Isolate the affected host until persistence and payload artifacts are removed.
- Search across the environment for `healthchk-lib@1.0.1`, `SystemHealthUpdater.exe`, `global-update.wlndows.thm`, and `Windows Update Monitor`.
- Review developer package installation activity for other suspicious post-install scripts.
- Add detections for package manager processes spawning `cmd.exe` or `powershell.exe`.
- Add detections for hidden encoded PowerShell and suspicious Registry Run key modifications.

## Lessons Learned

This investigation reinforced the importance of process lineage in SIEM investigations. The npm package itself was suspicious, but the case became much stronger when the parent-child process chain showed `node.exe` spawning `cmd.exe`, followed by hidden encoded PowerShell.

The most important lesson was to follow the full hypothesis. It was not enough to identify the suspicious package or the download attempt. The investigation needed to confirm whether persistence was established. The Registry Run key event provided the final proof that the attacker intended to maintain access and execute the staged payload later.

## Portfolio Note

This writeup is part of my SOC analyst learning portfolio. It focuses on practical SIEM investigation skills, including Splunk searching, Sysmon event interpretation, attack timeline development, IOC extraction, and MITRE ATT&CK mapping.
