---
layout: post
title: "Atomic T1548.002: Bypass User Account Control"
date: 2026-10-28 10:00:00 -0600
tags: [atomic red team, detection, Privilege Escalation, Microsoft Defender for Endpoint, KQL]
excerpt: "Atomic test 3 for T1548.002: Defender blocked the Fodhelper UAC bypass at its first command, and a detection I couldn't test on this VM."
series: atomic-red-team
label: "T1548.002 · Privilege Escalation"
---

**ATT&CK:** [T1548.002](https://attack.mitre.org/techniques/T1548/002/) Bypass User Account Control (Privilege Escalation, Defense Evasion). Parent: [T1548](https://attack.mitre.org/techniques/T1548/) Abuse Elevation Control Mechanism.

> **Disclaimer**
>
> - The views in this post are my own and do not represent my employer.
> - This is a detection-engineering exercise. Every step runs against my own lab machine with a payload that does nothing harmful. None of it is for offensive use.
> - The KQL is an example. Validate and tune it for your own environment before using it in production.

---

## The test

Atomic test 3, "Bypass UAC using Fodhelper". `fodhelper.exe` auto-elevates without a User Account Control (UAC) prompt and reads `HKCU\Software\Classes\ms-settings\Shell\Open\command` when it starts. The test writes `cmd.exe` into that key with an empty `DelegateExecute` value, then starts fodhelper, which runs `cmd.exe` at High integrity.

I ran it from a Medium-integrity shell. From an elevated shell the child would be High anyway.

**Reproduce:**

```powershell
Invoke-AtomicTest T1548.002 -TestNumbers 3 -CheckPrereqs
Invoke-AtomicTest T1548.002 -TestNumbers 3
```

**Clean up:**

```powershell
Invoke-AtomicTest T1548.002 -TestNumbers 3 -Cleanup
```

---

## Did MDE alert?

Microsoft Defender for Endpoint (MDE) blocked the test before it started. Windows Security showed "Threats found" on every attempt.

---

## What shows up in the logs

### The first run

Both runs failed with:

```
Exception calling "Start" with "0" argument(s): "Access is denied"
```

![Two runs of test 3 from a Medium-integrity shell, both Access is denied, with the Threats found notification](/assets/images/atomic-t1548-002/atomic-run-access-denied.png)

A confirmation query, not a detection:

```kql
DeviceEvents
| where TimeGenerated > ago(1h)
| where DeviceName startswith "winlab-vm"
| where ActionType has_any ("AsrUacBypassBlocked","ProcessBlocked","SmartScreen","ExploitGuard","SenseUnblock","AntivirusDetection","AntivirusScanCompleted")
| project TimeGenerated, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| sort by TimeGenerated desc
```

![Eight AntivirusDetection rows on Atomic files flagged as Trojan, HackTool and VirTool](/assets/images/atomic-t1548-002/antivirus-detections.png)

All eight rows are `AntivirusDetection` on Atomic files (`T1548.002.yaml`, `SharpHound.ps1`, `SOAPHound.exe` and others), flagged as Trojan, HackTool and VirTool. Excluding `C:\AtomicRedTeam` and the Temp folder didn't help, because the quarantine wasn't the cause. The exception comes from `$process.Start()`: Windows refused to start the process that runs the test commands.

### Running it by hand

```powershell
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /ve /d "cmd.exe" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v "DelegateExecute" /t REG_SZ /d "" /f
Start-Process "C:\Windows\System32\fodhelper.exe"
```

The first line was blocked:

![reg add on the ms-settings key: Program 'reg.exe' failed to run: Access is denied, from a High-integrity shell](/assets/images/atomic-t1548-002/reg-add-blocked.png)

reg.exe never started. Defender blocked it at process creation based on the command line, even from a High-integrity admin shell.

### Did fodhelper run?

```kql
search in (DeviceProcessEvents, DeviceEvents, DeviceRegistryEvents) "fodhelper"
| where TimeGenerated > ago(1h)
| where DeviceName startswith "winlab-vm"
| project TimeGenerated, $table, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated desc
```

![Two OtherAlertRelatedActivity rows from powershell.exe, no fodhelper process](/assets/images/atomic-t1548-002/fodhelper-search.png)

Two `OtherAlertRelatedActivity` rows from `powershell.exe`. No fodhelper process.

### Procmon and Sysmon

![Procmon filter: Path contains ms-settings\shell\open](/assets/images/atomic-t1548-002/procmon-filter.png)

Procmon's filter on the key matched nothing across both runs, and Sysmon logged no write under `shell\open\command`. The block came before any write, so there was nothing to record.

### Verdict

One host, one account, one interactive PowerShell session. No registry change, no fodhelper, nothing at High integrity. True positive for an attempted UAC bypass, prevented, no impact.

In a client queue I'd still check what started that PowerShell session. Someone had code running as the user and wanted admin rights.

---

## Turning Defender off

`Set-MpPreference -DisableRealtimeMonitoring $true` returned no error, but real-time protection stayed on. Tamper Protection is managed from the MDE tenant.

![Tamper Protection greyed out: This setting is managed by your administrator](/assets/images/atomic-t1548-002/tamper-protection-managed.png)

The supported workaround is troubleshooting mode in the Defender portal, for up to four hours. I left protection on, since that's how managed endpoints run.

---

## Detection

These aren't validated on this VM. The technique was blocked before it produced the events they need. The logic follows Sigma (Shell Open Registry Keys Manipulation, Bypass UAC Using DelegateExecute, Bypass UAC via Fodhelper.exe) and Splunk's FodHelper UAC Bypass. I'll test them on a machine where the chain completes.

The registry write:

```kql
DeviceRegistryEvents
| where TimeGenerated > ago(1d)
| where ActionType == "RegistryValueSet"
| where RegistryKey contains @"\Classes\ms-settings\Shell\Open\command"
    or RegistryKey contains @"\Classes\mscfile\shell\open\command"
    or RegistryKey contains @"\Classes\Folder\shell\open\command"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessIntegrityLevel, RegistryKey, RegistryValueName, RegistryValueData
| sort by TimeGenerated desc
```

Legitimate writes to these per-user keys are rare. `ms-settings` covers fodhelper and computerdefaults, `mscfile` covers eventvwr, `Folder` covers sdclt.

This is the step Defender blocked. Microsoft treats the HKCU `shell\open\command` write as the point to act on, and so does this query.

Defender's block was on reg.exe's command line. PowerShell's registry provider or a direct API call can write the same key without reg.exe. I haven't tested those. The query looks at the write itself, whatever made it.

The elevated child:

```kql
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where InitiatingProcessFileName in~ ("fodhelper.exe","computerdefaults.exe","eventvwr.exe","sdclt.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","rundll32.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, ProcessIntegrityLevel, ProcessTokenElevation
| sort by TimeGenerated desc
```

These binaries have no reason to start a shell. A shell child at High integrity is the bypass working. Nothing returned on this VM.

---

## Tuning

- Benign writes come mostly from software registering file handlers. Allowlist by signer or initiating process.
- Don't alert on fodhelper or eventvwr running alone. The child process is the signal.
- With prevention on, the write may never happen and the first query stays quiet. Check Defender's block events in `DeviceEvents`.

---

## Takeaways

The fodhelper, eventvwr and sdclt bypasses all depend on one step, the per-user `shell\open\command` write, so that's where the detection sits. Defender blocked the same step.

In the PowerShell and scheduled task posts, MDE alerted after the activity ran. This time it stopped the first command. On managed endpoints, a UAC bypass is more likely to show up as an attempt and a block than as an elevation.

---

## References

- [Atomic Red Team T1548.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md)
- [MITRE ATT&CK T1548.002](https://attack.mitre.org/techniques/T1548/002/)
- [Sigma: Shell Open Registry Keys Manipulation](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_event/registry_event_shell_open_keys_manipulation.yml)
- [Sigma: Bypass UAC Using DelegateExecute](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_bypass_uac_using_delegateexecute.yml)
- [Sigma: Bypass UAC via Fodhelper.exe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_uac_bypass_fodhelper.yml)
- [Splunk: FodHelper UAC Bypass](https://research.splunk.com/endpoint/909f8fd8-7ac8-11eb-a1f3-acde48001122/)
- [Microsoft Learn: Troubleshooting mode in Microsoft Defender for Endpoint](https://learn.microsoft.com/defender-endpoint/troubleshooting-mode-enable)
- [Microsoft Learn: DeviceRegistryEvents table](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceregistryevents-table)
