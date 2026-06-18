# EDR Alert Investigation

## Objective

The objective of this lab was to review EDR detections and understand what endpoint visibility can show during alert triage.

The focus was on process chains, file paths, command lines, network activity, indicators of compromise, and threat intelligence labels.

## Scenario Summary

I reviewed three endpoint detections:

- A malicious Office document that downloaded a payload
- A suspicious executable that accessed LSASS and attempted exfiltration
- An unsigned internal utility that was flagged by the EDR

## Tools Used

- TryHackMe SOC Level 1 lab environment
- EDR dashboard
- Process chain review
- Indicator review
- Threat intelligence results
- MITRE ATT&CK mapping

## Detection Overview

| Host | Detection | Severity | Decision |
|---|---|---:|---|
| DESKTOP-HR01 | Malicious Office document downloaded payload | High | True Positive |
| WIN-ENG-LAPTOP03 | Credential dumping and exfiltration attempt | High | True Positive |
| DESKTOP-DEV01 | Internal utility flagged as suspicious | Medium | Benign True Positive |

---

## Detection 1: Malicious Office Document Downloaded Payload

### Summary

A macro-enabled Office document named `invoice.docm` was opened by user `alice.thomas` on `DESKTOP-HR01`. The document launched `CMD.EXE`, which then launched `cURL.EXE` to download a payload.

### Key Evidence

| Field | Details |
|---|---|
| User | `alice.thomas` |
| Host | `DESKTOP-HR01` |
| Initial File | `C:\User\alice\Downloads\invoice.docm` |
| Office Process | `WINWORD.EXE` |
| Download Tool | `cURL.EXE` |
| Downloaded File | `C:\Users\Public\install.exe` |
| External Domain | `ayebd.thm` |
| External IP | `1.161.138.92` |
| MITRE Technique | `T1566.001 - Spearphishing Attachment` |
| Confidence Score | `95` |

### Process Chain

```text
invoice.docm
    ↓
WINWORD.EXE
    ↓
CMD.EXE
    ↓
cURL.EXE
    ↓
install.exe saved to disk
```

### Analysis

This detection is suspicious because a Word document launched command prompt and used cURL to download an executable payload. Normal Office document activity should not spawn CMD and download files from an external domain.

The payload was saved to `C:\Users\Public\install.exe`, which is a suspicious location for a downloaded executable.

### Decision

This detection was assessed as a **True Positive**.

### Recommended Actions

- Quarantine `install.exe`.
- Check whether the payload was executed.
- Search for the same hash across other endpoints.
- Block the related domain and IP if confirmed malicious.
- Review how `invoice.docm` was delivered to the user.

---

## Detection 2: Credential Dumping and Exfiltration Attempt

### Summary

An unsigned executable named `syncsvc.exe` ran from the user's Temp folder on `WIN-ENG-LAPTOP03`. It accessed `lsass.exe`, wrote a dump file, created persistence-related registry keys, and attempted to exfiltrate the dump file.

### Key Evidence

| Field | Details |
|---|---|
| User | `haris.khan` |
| Host | `WIN-ENG-LAPTOP03` |
| Suspicious File | `C:\Users\haris.khan\AppData\Local\Temp\syncsvc.exe` |
| Target Process | `C:\Windows\System32\lsass.exe` |
| Command Line | `syncsvc.exe -ma lsass.exe C:\Users\Public\dump_2025.dmp` |
| Dump File | `C:\Users\Public\dump_2025.dmp` |
| Exfiltration URL | `https://files-wetransfer.com/upload/session/ab12cd34ef56/dump_2025.dmp` |
| Domain | `files-wetransfer.com` |
| IP Address | `100.42.28.64` |
| EDR Status | Blocked |
| Threat Intel | Matches known credential dumping tool |

### Process Chain

```text
explorer.exe
    ↓
syncsvc.exe
    ↓
lsass.exe
```

### Analysis

This was the strongest detection in the lab. The executable ran from a Temp directory, was unsigned, accessed LSASS memory, and wrote a dump file to disk.

The process also attempted to upload the dump file to an external URL. The EDR blocked the outbound attempt, but the activity still showed clear signs of credential dumping and attempted exfiltration.

### Decision

This detection was assessed as a **True Positive**.

### Recommended Actions

- Isolate `WIN-ENG-LAPTOP03`.
- Quarantine `syncsvc.exe`.
- Preserve logs and the dump file for investigation.
- Remove persistence registry keys related to `syncsvc`.
- Reset credentials for the affected user if compromise is confirmed.
- Search for the same hash across the environment.
- Review other endpoints for similar LSASS access.

### MITRE ATT&CK Mapping

| Tactic | Technique | Reason |
|---|---|---|
| Credential Access | OS Credential Dumping | `syncsvc.exe` accessed `lsass.exe` memory. |
| Persistence | Registry Run Keys | Registry keys were created for `syncsvc`. |
| Exfiltration | Exfiltration Over Web Service | The dump file was sent to an external upload URL. |

---

## Detection 3: Internal Utility Flagged as Suspicious

### Summary

An unsigned binary named `UpdateAgent.exe` ran from the user's AppData folder on `DESKTOP-DEV01`. The EDR flagged the behavior because the file executed from a non-standard location and initiated an outbound HTTP connection.

### Key Evidence

| Field | Details |
|---|---|
| User | `daniel.richards` |
| Host | `DESKTOP-DEV01` |
| File | `C:\Users\daniel.richards\AppData\Roaming\UpdateAgent.exe` |
| Parent Process | `explorer.exe` |
| Signed | No |
| Network Connection | `10.10.20.5:8080` |
| Protocol | HTTP |
| Threat Intel Label | Known internal IT utility tool |
| IP Status | Internal Safe |
| Hash Status | Marked Safe |
| Confidence Score | `35` |

### Process Chain

```text
explorer.exe
    ↓
UpdateAgent.exe
```

### Analysis

This detection had suspicious behavior because an unsigned executable ran from AppData and made an HTTP connection. However, threat intelligence identified the file as a known internal IT utility, and the destination IP was marked as internal and safe.

The EDR correctly detected unusual behavior, but the additional context reduced the risk.

### Decision

This detection was assessed as a **Benign True Positive**.

### Recommended Actions

- Confirm the file is approved by IT.
- Add the known internal utility to an approved software list if appropriate.
- Continue monitoring for abnormal behavior from the executable.
- Do not mark similar AppData executions as safe without validation.

---

## Overall Findings

| Finding | Details |
|---|---|
| Process chains matter | Parent-child process relationships helped explain each detection. |
| Office spawning CMD is suspicious | `WINWORD.EXE` launching CMD and cURL supported a true positive decision. |
| LSASS access is high risk | Unauthorized LSASS memory access strongly indicated credential dumping. |
| Threat intelligence adds context | `UpdateAgent.exe` looked suspicious, but threat intel identified it as an internal tool. |

## Lessons Learned

This lab showed how EDR visibility helps analysts understand endpoint activity. Process chains, file paths, command lines, network connections, and threat intelligence results all helped support the triage decisions.

The main takeaway was that suspicious behavior should be reviewed in context. Some detections require immediate escalation, while others may be benign when validated against trusted internal information.
