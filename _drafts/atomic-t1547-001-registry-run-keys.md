---
layout: post
title: "Atomic T1547.001: Registry Run Keys"
date: 2026-10-23 12:00:00 -0600
tags: [atomic red team, detection, Persistence, Microsoft Defender for Endpoint, KQL]
excerpt: "A Run key is the simplest persistence there is, and MDE won't alert on it by default. Here is what the telemetry looks like and a detection that separates the malicious writes from the noise."

atomic:
  technique_id: "T1547.001"
  technique_name: "Registry Run Keys / Startup Folder"
  parent_technique: "T1547"
  tactics: [Persistence, Privilege Escalation]
  platform: Windows
  data_source: DeviceRegistryEvents
  mde_default_alert: false
  custom_detection: true
---

## What this technique is

A Registry Run key makes a program start automatically when a user logs in. Legitimate software uses these keys all the time, which is exactly why they are a convenient place to hide persistence. An attacker writes a value under one of the Run keys pointing at their payload, and it runs on every logon from then on. If the key is under `HKLM`, the payload runs for every user and can run with higher privileges, which is why ATT&CK maps this to both persistence and privilege escalation.

**ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/) Registry Run Keys / Startup Folder (Persistence, Privilege Escalation). Parent: [T1547](https://attack.mitre.org/techniques/T1547/) Boot or Logon Autostart Execution.

> **Disclaimer**
>
> - The views in this post are my own and do not represent my employer.
> - This is a detection-engineering exercise. Every step runs against my own lab machine with a payload that does nothing harmful. None of it is for offensive use.
> - The KQL is an example. Validate and tune it for your own environment before using it in production.

---

## The test

I ran two variants on my lab VM, both harmless. The point of the second one is to validate that the detection fires on an attacker-shaped value, not just on any Run key write.

**Variant A, a clean-looking value.** A Run key under the current user that points at Notepad. The only thing it would ever do is open Notepad at the next logon.

```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
  /v "AtomicTestA" /t REG_SZ /d "notepad.exe" /f
```

**Variant B, an attacker-shaped but still harmless value.** A Run key that points at PowerShell with a command that immediately exits. It launches PowerShell and does nothing else, but the value looks like what an attacker would leave: a script interpreter with a hidden window.

```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
  /v "AtomicTestB" /t REG_SZ /d "powershell.exe -WindowStyle Hidden -Command exit" /f
```

I used the `HKCU` hive on purpose: it needs no admin rights and only affects my own test account. Both values are removed in the cleanup step at the end.

---

## What shows up in the logs

Both writes land in `DeviceRegistryEvents` with `ActionType == "RegistryValueSet"`. The fields that matter for detection:

| Field | Variant B value |
|---|---|
| `ActionType` | `RegistryValueSet` |
| `RegistryKey` | `HKEY_CURRENT_USER\...\CurrentVersion\Run` |
| `RegistryValueName` | `AtomicTestB` |
| `RegistryValueData` | `powershell.exe -WindowStyle Hidden -Command exit` |
| `InitiatingProcessFileName` | `reg.exe` |
| `InitiatingProcessParentFileName` | `cmd.exe` (or `powershell.exe`) |
| `InitiatingProcessAccountName` | my test user |

The two fields that carry the signal are `RegistryKey` (which autostart location) and `RegistryValueData` (what actually runs). `InitiatingProcessParentFileName` is useful context: a Run key written by `reg.exe` whose parent is a browser or Office app is very different from one written by an installer.

---

## Did MDE alert?

No. Neither variant raised an alert on its own. That is the expected result, and it is the main reason this technique is worth writing up. Legitimate installers and updaters write Run keys constantly, so an alert on every Run key write would drown an analyst in noise. Microsoft Defender for Endpoint will raise something only when the payload itself is independently suspicious, for example a known-bad file or a script it already flags.

The takeaway for a SOC: Run key persistence is a hunting and custom-detection target. You cannot rely on the built-in alerts to surface it, so you need a query of your own.

---

## Detection

Two layers. The first is a broad hunting query that surfaces every Run key write for review. It catches Variant A, but it is too noisy to run as a scheduled rule. The second is a higher-confidence detection that only fires when the value points at something an attacker would use. It catches Variant B and is quiet enough to alert on.

**Layer 1, hunt (review by hand):**

```kql
DeviceRegistryEvents
| where Timestamp > ago(1d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce")
| where RegistryValueName != "MRUList"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

**Layer 2, detection (quiet enough to alert):**

```kql
let RunKeys = dynamic([
    @"\CurrentVersion\Run",
    @"\CurrentVersion\RunOnce",
    @"\CurrentVersion\RunServices",
    @"\CurrentVersion\Policies\Explorer\Run"]);
let SuspiciousValue = dynamic([
    @"\Temp\", @"\AppData\", @"\Users\Public\", @"\ProgramData\",
    "powershell", "pwsh", "cmd.exe", "mshta", "wscript", "cscript",
    "rundll32", "regsvr32", "-enc", "-w hidden", "-windowstyle hidden",
    "iex", "downloadstring", ".vbs", ".js", ".bat", ".ps1", ".hta", "http"]);
DeviceRegistryEvents
| where Timestamp > ago(1d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (RunKeys)
| where RegistryValueName != "MRUList"
| where RegistryValueData has_any (SuspiciousValue)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    InitiatingProcessFileName, InitiatingProcessParentFileName,
    RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
| order by Timestamp desc
```

What each part does:

- `RunKeys` covers the common autostart keys, not just the single `Run` key. `RunOnce` and the `Policies\Explorer\Run` key are abused the same way and are easy to forget.
- `RegistryValueName != "MRUList"` drops a built-in value that changes on its own and is never a payload.
- `SuspiciousValue` is where the confidence comes from. A Run key pointing at a script interpreter, a user-writable folder like `AppData` or `Temp`, or a URL is far more likely to be an attacker than a vendor. Variant A (`notepad.exe` in `System32`) does not match, which is correct: on its own it is not suspicious. Variant B matches on `powershell` and `-windowstyle hidden`.

This is written against the MDE advanced hunting schema, where the time column is `Timestamp`. In Sentinel the same table streamed through the Defender connector also has `TimeGenerated`; swap the column if you run it there.

---

## Tuning

The value list drives both the hits and the false positives, so tune it to your fleet:

- **Known installers and updaters** write Run keys legitimately. If a specific signed updater keeps firing, allowlist it by `InitiatingProcessFileName` or, better, by its signer, rather than removing the value pattern.
- **`RunOnce`** is used by installers in the middle of a reboot, so it is noisier than `Run`. If it is too noisy for you, split it into its own lower-severity rule.
- **Baseline per device.** The strongest version of this detection compares today's Run key writes against what each device has written in the last 30 days and only surfaces new value data. That removes the steady-state vendor noise and leaves the genuinely new entries.
- Pair this with the parent process. A Run key written by `reg.exe` whose parent is `explorer.exe`, a browser, or an Office application is worth a look regardless of the value.

---

## Cleanup

Always remove a persistence entry after testing, or it runs at your next logon.

```powershell
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AtomicTestA" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AtomicTestB" /f
```

---

## References

- [Atomic Red Team T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md)
- [MITRE ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [Microsoft Learn: DeviceRegistryEvents table](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceregistryevents-table)
