---
layout: post
title: "ClickFix Detection: Comparing the Public Approaches"
date: 2026-10-10 15:00:00 -0600
tags: [BSidesEdmonton2026, detection, ClickFix, FileFix, Microsoft Defender for Endpoint, KQL]
excerpt: "A study note on the public ways to detect ClickFix: where each one looks, which variants it covers, and when to use it."
series: research
---

## 0. Introduction

In a Sophos talk at BSides Edmonton 2026, ClickFix was listed as one of the most common ways attackers get initial access. There are already many public detections for it, and they look at different things. This post is my study note: I put the public approaches side by side and compare where each one fits.

> **Disclaimer**
>
> - The views in this post are my own and do not represent my employer.
> - The KQL queries are examples. Adjust and validate them for your own environment before using them in production.

---

## 1. What ClickFix is

A lure page pretends to be a CAPTCHA or an error message. It quietly copies a command to the clipboard, then tells the user to paste it somewhere and press Enter.

**ATT&CK:** [T1204.004](https://attack.mitre.org/techniques/T1204/004/) Malicious Copy and Paste. The execution step usually also involves [T1059.001](https://attack.mitre.org/techniques/T1059/001/) PowerShell.

Where the user pastes the command decides what traces it leaves:

| Variant | Where the command is pasted | Traces |
|---|---|---|
| ClickFix | Win+R Run dialog | `RunMRU` registry key; parent process `explorer.exe` |
| FileFix | Address bar of the browser's file upload dialog | `TypedPaths` registry key; parent process is the browser |
| TerminalFix | A PowerShell window the user opens | Almost none |

---

## 2. Five ways to detect it

**① Registry.** Whatever the user types into the Run dialog is saved as-is in RunMRU. What they type into the file dialog's address bar is saved in TypedPaths. Query these two keys and you see the full command the user pasted ([kqlquery.com](https://kqlquery.com/posts/investigate-clickfix/), [Elastic](https://github.com/elastic/detection-rules/pull/6914)).

**② Process chain.** `explorer.exe` or a browser directly starts PowerShell, cmd, mshta, or a similar program ([Huntress](https://www.huntress.com/blog/dont-sweat-clickfix-techniques)).

**③ Keywords.** Lure commands often end with a `#` comment and words like "captcha", "robot", or "verification" ([SigmaHQ](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_potential_clickfix_execution.yml)). This is accurate, but it stops working as soon as the attacker changes the wording ([Prophet Security](https://www.prophetsecurity.ai/blog/clickfix-attack)).

**④ Built-in alerts.** Microsoft Defender for Endpoint (MDE) already has ClickFix alerts. But the gap between PowerShell starting and the alert firing is often more than a minute ([glueckkanja](https://www.glueckkanja.com/en/posts/2026-09-21-clickfix-prevent-detect)).

**⑤ Browser layer.** Catch the command at the moment the page writes it to the clipboard. At that point nothing has run yet, so it doesn't matter which program the attacker uses or how the command is obfuscated. Push Security works this way, and Opera's Paste Protect, released in July 2026, follows the same idea ([Push Security](https://pushsecurity.com/blog/the-state-of-clickfix-by-detection-data), [Opera](https://blogs.opera.com/news/2026/07/opera-introduces-paste-protect-to-keep-you-safe-from-clipboard-attacks/)). The downside is that you need to deploy a browser extension or a different browser.

### KQL

The queries below map to methods ① to ④ above. Method ⑤ runs in the browser, so there is no KQL for it.

For ①, I think the most useful version ignores keywords and looks only at the "shape" of the command: longer than 50 characters ([detect.fyi](https://detect.fyi/hunting-clickfix-initial-access-techniques-8c1b38d5ef9b) found the average sample was about 179), and containing a URL, an IP address, or a base64 block.

```kql
// ① Registry + command shape: RunMRU (Win+R) and TypedPaths (FileFix)
// No filter on the writing process: for FileFix, the browser writes TypedPaths, not explorer.exe
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any ("RunMRU", "TypedPaths")
| where RegistryValueName != "MRUList"
| where strlen(RegistryValueData) > 50
| where RegistryValueData matches regex @"(?i)(https?://|\b\d{1,3}(\.\d{1,3}){3}\b|[A-Za-z0-9+/]{40,})"
| project Timestamp, ReportId, DeviceId, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueData
```

```kql
// ② Process chain: explorer.exe or a browser starts a script interpreter or LOLBin
// OriginalFileName also catches renamed binaries (CrashFix renames finger.exe to ct.exe)
let lolbins = dynamic(["powershell.exe","pwsh.exe","cmd.exe","mshta.exe","rundll32.exe",
    "regsvr32.exe","msiexec.exe","curl.exe","finger.exe","wscript.exe","cscript.exe"]);
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("explorer.exe","chrome.exe","msedge.exe","firefox.exe","brave.exe")
| where FileName in~ (lolbins) or ProcessVersionInfoOriginalFileName in~ (lolbins)
// Command-line filter: without it, every PowerShell opened from the Start menu matches
| where ProcessCommandLine matches regex @"(?i)(https?://|\\\\[\w.\-@]+\\|-enc|iex|iwr)"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

```kql
// ③ Keywords: a "#" comment plus typical lure words
DeviceRegistryEvents
| where RegistryKey has_any ("RunMRU", "TypedPaths")
| where RegistryValueData contains "#"
| where RegistryValueData has_any ("captcha", "robot", "verification", "verify", "human")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueData
```

```kql
// ④ Built-in alerts: see what MDE has already raised for ClickFix
AlertInfo
| where Title has_any ("ClickFix", "RunMRU", "Run dialog")
| project Timestamp, Title, Severity, DetectionSource
```

Two things to keep in mind:

- Don't limit the writing process to `explorer.exe` in query ①. For FileFix, the browser writes TypedPaths.
- Query ① can also be bypassed. In October 2026, Microsoft described a "browser cache smuggling" variant: the payload is hidden in the browser cache ahead of time, and the pasted command only finds it on disk and runs it. The command contains no URL, IP address, or base64 ([The Hacker News](https://thehackernews.com/2026/10/clickfix-smuggles-payloads-through.html)). RunMRU still records the command, so you would filter on something else, such as a browser profile path or `wscript` in the command.

---

## 3. Comparison

| Method | Covers | Strength | Weakness |
|---|---|---|---|
| ① Registry | ClickFix, FileFix | Shows the full command; simple rule | Can't see TerminalFix |
| ② Process chain | ClickFix, FileFix | Doesn't depend on the command text | Noisy; needs command-line filters |
| ③ Keywords | Depends on the wording | High accuracy | Easiest to bypass |
| ④ Built-in alerts | Depends on the vendor | Nothing to write yourself | Delayed |
| ⑤ Browser layer | All variants | Stops it before anything runs | Extra deployment |

TerminalFix is a blind spot for all the endpoint methods (① to ④). The browser layer is the only one that covers it.

---

## 4. Which to use

- **Few custom rules so far:** rely on the built-in alerts, and add query ① as an MDE custom detection rule.
- **Threat hunting:** run ② and ③ on a schedule. When one hits, check whether that process made outbound connections.
- **If budget allows:** add browser-layer protection. It is the only method that stops the command before it runs.
- **Prevention:** most users don't need the Run dialog, so you can disable Win+R with Group Policy. This helps less than it sounds: attack kits are moving to Win+X, and there is no built-in Group Policy to disable Win+X ([Push Security](https://pushsecurity.com/blog/the-state-of-clickfix-by-detection-data)).

---

## References

- Prophet Security: [ClickFix Attacks: How to Detect and Investigate Fake CAPTCHA Lures](https://www.prophetsecurity.ai/blog/clickfix-attack)
- Huntress: [ClickFix Attack: Variants, Detection & How It Works](https://www.huntress.com/blog/dont-sweat-clickfix-techniques)
- glueckkanja: [ClickFix. When the user is the exploit, and how to stop it](https://www.glueckkanja.com/en/posts/2026-09-21-clickfix-prevent-detect)
- kqlquery.com: [Investigating ClickFix Incidents](https://kqlquery.com/posts/investigate-clickfix/)
- detect.fyi: [Hunting ClickFix Initial Access Techniques](https://detect.fyi/hunting-clickfix-initial-access-techniques-8c1b38d5ef9b)
- Elastic: [detection-rules PR #6914](https://github.com/elastic/detection-rules/pull/6914)
- SigmaHQ: [Potential ClickFix Execution Pattern - Registry](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_potential_clickfix_execution.yml)
- Push Security: [The numbers behind ClickFix attacks in H2 2026](https://pushsecurity.com/blog/the-state-of-clickfix-by-detection-data)
- Opera: [Opera introduces Paste Protect](https://blogs.opera.com/news/2026/07/opera-introduces-paste-protect-to-keep-you-safe-from-clipboard-attacks/)
- The Hacker News: [ClickFix Smuggles Payloads Through Browser Cache to Bypass Windows Run Limits](https://thehackernews.com/2026/10/clickfix-smuggles-payloads-through.html)
- MITRE ATT&CK: technique IDs in this post are mapped to [ATT&CK v19](https://attack.mitre.org/resources/versions/).
