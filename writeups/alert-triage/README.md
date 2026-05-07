# SOC Level 1 Alert Triage

## Objective

The objective of this lab was to practice Security Operations Center (SOC) Level 1 alert triage by reviewing security alerts, analyzing available evidence, and determining whether each alert represented benign activity, a false positive, or a true positive requiring further investigation.

## Scenario Summary

This exercise involved reviewing multiple alerts from an alert management queue. Each alert included details such as severity, affected user or host, source network, destination, file information, and activity context.

The purpose of the triage process was to avoid relying only on alert severity and instead make decisions based on evidence, business context, and suspicious indicators.

![SOC alert triage dashboard screenshot](images/alert-triage-summary.png)

*Figure 1: Alert triage queue reviewed during the investigation.*

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
| Potential Data Exfiltration | Critical | False Positive | High-volume traffic was identified, but the destination and source network were consistent with legitimate meeting activity. |
| Double-Extension File Creation | High | True Positive | A suspicious double-extension executable was downloaded from an external website, consistent with file extension deception. |

## Key Evidence

### Alert 1: Download from GitHub Repository

| Field | Evidence |
|---|---|
| Accessed Resource | Official public software repository |
| Source User | Developer-associated user |
| Source Host | Corporate laptop |
| Source Network | Developer Virtual Private Network (VPN) segment |
| Triage Decision | False Positive |

This alert triggered because GitHub access can be risky in an enterprise environment. Public repositories may contain unauthorized tools, malicious scripts, or exploit code.

However, the accessed repository appeared legitimate, and the activity came from a developer VPN segment. Based on the available evidence, this activity was consistent with expected developer behavior.

### Alert 2: Potential Data Exfiltration

| Field | Evidence |
|---|---|
| Destination | Video conferencing service |
| Source Network | Meeting room network |
| Traffic Pattern | High-volume bidirectional traffic |
| Triage Decision | False Positive |

This alert triggered because a large amount of data was sent from a single device to a single destination within one day. While this can indicate possible data exfiltration, the context did not support a malicious conclusion.

The destination was associated with video conferencing, and the source network was tied to a meeting room device. The traffic was also bidirectional, with a similar amount of data sent and received. This pattern is more consistent with video conferencing, screen sharing, or meeting-related activity than confirmed data exfiltration.

### Alert 3: Double-Extension File Creation

| Field | Evidence |
|---|---|
| Host | User workstation |
| Process Name | Web browser process |
| Process User | Standard user account |
| Target File | Suspicious double-extension executable in the Downloads folder |
| File Source | External website |
| File Hash | Recorded for investigation and environment-wide search |
| Triage Decision | True Positive |

This alert was categorized as a true positive.

The downloaded file used a double extension. Although the filename appeared to reference a media file, the final extension showed that the file was actually an executable. The file was downloaded through a browser into the user's Downloads folder, and the source showed that it came from an external website.

This behavior is consistent with file extension deception, a common technique used in phishing and malware delivery.

## Analysis

The three alerts showed why SOC analysts must review context before making a decision.

The GitHub alert was low severity and did not show suspicious behavior based on the provided details. The accessed repository appeared legitimate, and the source network was associated with developers. While GitHub access should still follow company policy, the activity did not indicate malicious behavior.

The data exfiltration alert was marked critical, but severity alone was not enough to determine risk. After reviewing the destination, source network, and traffic pattern, the activity appeared consistent with legitimate meeting or video conferencing usage from a meeting room device.

The double-extension file alert was the most suspicious. The filename attempted to appear as a media file, but the final extension showed it was an executable. The external download source, browser process, user Downloads folder, and file naming pattern made this alert valid and worthy of escalation.

## Findings

| Finding | Details |
|---|---|
| Alert severity does not always equal actual risk | A critical alert may be benign when business context supports the activity. |
| Business context matters during triage | Developer activity and meeting room activity helped explain two alerts. |
| File extension deception is a strong suspicious indicator | A file pretending to be media while actually being executable is consistent with phishing or malware delivery behavior. |
| True positives should be escalated for deeper investigation | The suspicious executable required endpoint review and possible containment. |

## MITRE ATT&CK Mapping

| Tactic | Technique | Reason |
|---|---|---|
| Initial Access | Phishing | The suspicious executable may have been delivered through deceptive user-facing content. |
| Execution | User Execution | The file would likely require the user to open or run it. |
| Defense Evasion | Masquerading | The file name attempted to appear as a media file while actually being an executable. |

## Recommended Remediation

For the confirmed suspicious file download, recommended actions include:

- Escalate the alert for endpoint investigation.
- Check whether the suspicious executable was opened or executed.
- Quarantine or remove the suspicious file if still present.
- Review endpoint logs for child processes, persistence, or additional downloads.
- Search for the same file hash across the environment.
- Review whether the same user or host accessed related suspicious domains.
- Provide user awareness training on suspicious downloads and double-extension files.
- Continue monitoring for related alerts involving the same host, user, domain, or hash.

## Lessons Learned

This lab reinforced that alert triage requires more than reading the alert title or severity level.

A critical alert may be benign when business context supports the activity, while a lower-volume file event may represent a real security risk. The most important takeaway was that SOC analysts need to review the full alert context, including user role, source network, destination, file path, process name, and suspicious indicators, before deciding whether to close, escalate, or continue investigating an alert.
