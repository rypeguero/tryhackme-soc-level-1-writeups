# SOC Level 1 Alert Triage

## Objective

The objective of this lab was to practice Security Operations Center (SOC) Level 1 alert triage by reviewing security alerts, analyzing the available evidence, and determining whether each alert represented benign activity, a false positive, or a true positive requiring further investigation.

## Scenario Summary

This exercise involved reviewing multiple alerts from an alert management queue. Each alert included details such as severity, affected user or host, source network, destination, file information, and activity context.

The purpose of the triage process was to avoid relying only on alert severity and instead make decisions based on evidence, environment context, and suspicious indicators.

![SOC alert triage dashboard screenshot](https://github.com/rypeguero/tryhackme-soc-level-1/blob/main/writeups/alert-triage/images/alert-triage-summary.png?raw=true)

## Tools Used

- TryHackMe SOC Level 1 lab environment
- Alert queue review
- Alert metadata analysis
- Basic indicator review
- MITRE ATT&CK: Adversarial Tactics, Techniques, and Common Knowledge

## Alerts Reviewed

| Alert | Severity | Decision | Summary |
|---|---:|---|---|
| Download from GitHub Repository | Low | False Positive | Activity was consistent with developer access to an official GitHub repository. |
| Potential Data Exfiltration | Critical | False Positive | High-volume traffic was identified, but the destination and source network were consistent with legitimate Zoom meeting activity. |
| Double-Extension File Creation | High | True Positive | A suspicious `.mp4.exe` file was downloaded from an external website, consistent with file extension deception. |

## Key Evidence

### Alert 1: Download from GitHub Repository

| Field | Evidence |
|---|---|
| Accessed URL | `https://github.com/facebook/react` |
| Source User | `G.Chandler` |
| Source Host | `LPT-IT-063` |
| Source Network | `VPN/DEVELOPERS` |
| Triage Decision | False Positive |

The alert triggered because GitHub access can be risky in an enterprise environment. Public repositories may contain unauthorized tools, malicious scripts, or exploit code. However, the accessed repository was the official React repository, and the activity came from a developer Virtual Private Network (VPN) segment.

Based on the available evidence, this activity was consistent with expected developer behavior.

### Alert 2: Potential Data Exfiltration

| Field | Evidence |
|---|---|
| Destination | `*.zoom.us` |
| Source IP | `192.168.45.66` |
| Source Network | `UK04/MEETINGROOM` |
| Sent Data | `5.8 GB` |
| Received Data | `5.2 GB` |
| Triage Decision | False Positive |

This alert triggered because more than 5 gigabytes of data was sent from a single device to a single destination within one day. While this can indicate possible data exfiltration, the context did not support a malicious conclusion.

The destination was a Zoom domain, and the source network was a meeting room network. The traffic was also bidirectional, with a similar amount of data sent and received. This pattern is more consistent with video conferencing, screen sharing, or meeting-related activity than confirmed data exfiltration.

### Alert 3: Double-Extension File Creation

| Field | Evidence |
|---|---|
| Host | `LPT-HR-009` |
| Process Name | `chrome.exe` |
| Process User | `S.Conway` |
| Target File | `C:\Users\S.Conway\Downloads\cats2025.mp4.exe` |
| File Mark of the Web (MotW) | `https://freecatvideoshd.monster/cats2025.mp4.exe` |
| File Message-Digest Algorithm 5 (MD5) | `14d8486f3f63875ef93cfd240c5dc10b` |
| Triage Decision | True Positive |

This alert was categorized as a true positive. The downloaded file used a double extension: `.mp4.exe`. Although the filename appeared to reference a video file, the final extension was `.exe`, meaning the file was actually an executable.

The file was downloaded through Chrome into the user's Downloads folder, and the Mark of the Web (MotW) showed that it came from an external website. This behavior is consistent with file extension deception, a common technique used in phishing and malware delivery.

## Analysis

The three alerts showed why SOC analysts must review context before making a decision.

The GitHub alert was low severity and did not show suspicious behavior based on the provided details. The repository was official, and the source network was associated with developers. While GitHub access should still follow company policy, the activity did not indicate malicious behavior.

The data exfiltration alert was marked critical, but severity alone was not enough to determine risk. After reviewing the destination, source network, and traffic pattern, the activity appeared consistent with legitimate Zoom usage from a meeting room device.

The double-extension file alert was the most suspicious. The filename attempted to appear as a media file, but the final extension showed it was an executable. The external download source, browser process, user Downloads folder, and file naming pattern made this alert valid and worthy of escalation.

## Findings

| Finding | Details |
|---|---|
| Alert severity does not always equal actual risk | The critical Zoom alert was likely benign after reviewing context. |
| Business context matters during triage | Developer activity and meeting room activity helped explain two alerts. |
| File extension deception is a strong suspicious indicator | The `.mp4.exe` file was consistent with phishing or malware delivery behavior. |
| True positives should be escalated for deeper investigation | The suspicious executable required endpoint review and possible containment. |

## MITRE ATT&CK Mapping

| Tactic | Technique | Reason |
|---|---|---|
| Initial Access | Phishing | The suspicious executable may have been delivered through deceptive user-facing content. |
| Execution | User Execution | The file would likely require the user to open or run it. |
| Defense Evasion | Masquerading | The file name attempted to appear as an MP4 video while actually being an executable. |

## Recommended Remediation

For the confirmed suspicious file download, recommended actions include:

- Escalate the alert for endpoint investigation.
- Check whether `cats2025.mp4.exe` was executed.
- Quarantine or remove the suspicious file if still present.
- Review endpoint logs for child processes, persistence, or additional downloads.
- Search for the same file hash across the environment.
- Review whether the same user or host accessed related suspicious domains.
- Provide user awareness training on suspicious downloads and double-extension files.
- Continue monitoring for related alerts involving the same host, user, domain, or hash.

## Lessons Learned

This lab reinforced that alert triage requires more than reading the alert title or severity level. A critical alert may be benign when business context supports the activity, while a lower-volume file event may represent a real security risk.

The most important takeaway was that SOC analysts need to review the full alert context, including user role, source network, destination, file path, process name, and suspicious indicators, before deciding whether to close, escalate, or continue investigating an alert.
