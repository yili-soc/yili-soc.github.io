---
layout: post
title: "Atomic T1218: Regsvr32 and Mshta"
date: 2026-10-28 13:00:00 -0600
tags: [atomic red team, detection, Defense Evasion, Microsoft Defender for Endpoint, KQL]
excerpt: "Two LOLBin tests, both prevented, but at different points: mshta was stopped before it started, regsvr32 ran far enough to leave telemetry."
series: atomic-red-team
label: "T1218 · Defense Evasion"
---

**ATT&CK:** [T1218](https://attack.mitre.org/techniques/T1218/) System Binary Proxy Execution (Defense Evasion). Sub-techniques: [T1218.010](https://attack.mitre.org/techniques/T1218/010/) Regsvr32, [T1218.005](https://attack.mitre.org/techniques/T1218/005/) Mshta.

> **Disclaimer**
>
> - The views in this post are my own and do not represent my employer.
> - This is a detection-engineering exercise. Every step runs against my own lab machine with a payload that does nothing harmful. None of it is for offensive use.
> - The KQL is an example. Validate and tune it for your own environment before using it in production.

---

This one covers living-off-the-land binaries (LOLBins): regsvr32 and mshta. Both are signed, built-in Windows programs with a legitimate job, and both can be driven to run an attacker's script instead of doing that job. The point of T1218 is that the execution is then attributed to a trusted Microsoft binary, not to anything the attacker dropped on disk, so signature checks and application allowlists let it through. The attacker runs their code by proxy, through the trusted tool.

I ran one test for each, expecting the usual flow of run, check MDE, reconstruct, detect. Defender prevented both, but not in the same way, and that difference is the post. Mshta was blocked before it started, like the UAC bypass last time. Regsvr32 ran long enough to load its script engine and leave telemetry on three separate sources before Defender killed it.

---

## The test

Two tests, from a normal Medium-integrity shell:

- **T1218.005 test 10, "Mshta used to Execute PowerShell".** mshta runs HTML Applications, which can hold VBScript or JScript. An attacker points it at an inline script or a remote HTA to run arbitrary code, often to start PowerShell. That inline-script-into-PowerShell shape is what the ClickFix lures use, which is why MDE named the alert the way it did. This test uses it to launch PowerShell.
- **T1218.010 test 1, "Regsvr32 local COM scriptlet execution".** regsvr32's normal job is registering and unregistering COM DLLs. Run as `regsvr32 /s /u /i:<file> scrobj.dll`, it instead hands the file to scrobj.dll, the Windows Script Component Runtime, which executes the JScript or VBScript inside a `.sct` scriptlet. The `/u` switch runs the scriptlet's unregister path, so nothing is actually registered and little is left on disk, and the file can even be a URL rather than a local path. The community name for this regsvr32 plus scrobj.dll pattern is Squiblydoo. The scriptlet in this test just launches calc.

**Reproduce:**

```powershell
Invoke-AtomicTest T1218.005 -TestNumbers 10
Invoke-AtomicTest T1218.010 -TestNumbers 1
```

**Clean up:**

```powershell
Invoke-AtomicTest T1218.005 -TestNumbers 10 -Cleanup
Invoke-AtomicTest T1218.010 -TestNumbers 1 -Cleanup
```

---

## Did MDE alert?

Yes, and it prevented both. Microsoft Defender for Endpoint (MDE) rolled the activity into one High incident titled "Multi-stage incident involving Execution & Defense evasion". The alerts that belong to this run, between 12:02 and 12:04:

- "'ClickFix' malware in a command line was prevented" (the mshta attempt)
- "Regsvr32.exe launched suspicious commands"
- "Use of living-off-the-land binary to run malicious code"
- "Suspicious behavior by cmd.exe was observed"
- "'Relvelshe' backdoor was prevented" (the regsvr32 `.sct`)

![Incident ID 9, High, Attack story with the 12:02 to 12:04 alerts and the incident graph](/assets/images/atomic-t1218/incident.png)

One thing to read carefully before trusting the incident as a single story. It grouped 14 alerts, and several are from earlier unrelated test runs on the same host and account that day, including a 10:08 AM UAC bypass and two 11 AM PowerShell obfuscation alerts. On a busy host MDE correlates by asset and account inside a time window, so a multi-stage incident is not always one campaign. The T1218 activity is the 12:02 to 12:04 cluster, not all 14.

---

## What shows up in the logs

### Mshta: nothing to find

The mshta test failed at launch:

```
Executing test: T1218.005-10 Mshta used to Execute PowerShell
Exception calling "Start" with "0" argument(s): "Access is denied"
```

![Both tests: mshta Access is denied, regsvr32 exit code 5, with the Threats found notification](/assets/images/atomic-t1218/atomic-run-blocked.png)

Same shape as the UAC post. "Access is denied" at the process start means mshta never ran. There is no mshta process in `DeviceProcessEvents` and no mshta entry in Prefetch, so there is nothing to reconstruct. Defender flagged it as ClickFix.

### Regsvr32: it ran first, then got killed

regsvr32 returned exit code 5 (access denied), but the telemetry shows it did real work before that. The process started, under cmd.exe:

```kql
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where DeviceName startswith "winlab-vm"
| where FileName =~ "regsvr32.exe"
| project TimeGenerated, InitiatingProcessFileName, FileName, ProcessCommandLine, ProcessIntegrityLevel
| sort by TimeGenerated desc
```

![cmd.exe launched regsvr32.exe at Medium integrity with the /s /u /i scriptlet command line](/assets/images/atomic-t1218/kql-process.png)

The parent is cmd.exe because Invoke-AtomicTest runs a `command_prompt` test through cmd, the same wrapper seen with schtasks in the scheduled task post. The window I typed in sits above that as the grandparent. Worth remembering when reading any atomic result: the parent chain partly belongs to the test harness, not the technique, so do not bake cmd.exe in as if it were regsvr32's normal parent.

Then regsvr32 loaded the script engine:

```kql
DeviceImageLoadEvents
| where TimeGenerated > ago(1h)
| where DeviceName startswith "winlab-vm"
| where FileName =~ "scrobj.dll"
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| sort by TimeGenerated desc
```

![regsvr32.exe loaded C:\Windows\System32\scrobj.dll](/assets/images/atomic-t1218/kql-imageload.png)

regsvr32 loading `scrobj.dll` is Squiblydoo running. After that load, Defender's antivirus detected the `.sct` file itself and stopped the process. The file-layer detection shows up as a sample submission prompt naming the exact file:

![Windows Security sample submission naming C:\AtomicRedTeam\atomics\T1218.010\src\RegSvr32.sct](/assets/images/atomic-t1218/sample-submission-sct.png)

So the sequence is: regsvr32 starts, loads scrobj.dll, begins reading the scriptlet, antivirus detects the `.sct`, process killed with exit code 5. Unlike the UAC bypass, which was stopped upstream of any telemetry, this one left records.

---

## Host artifacts

Two sources outside MDE caught the scrobj.dll load and the regsvr32 run, which matters for a client without MDE P2 or after a trial lapses.

**Sysmon Event ID 7 (image load).** I scoped the config to log only loads of scrobj.dll, so this was the single matching event, no noise to sort through:

![Sysmon Event ID 7: Image regsvr32.exe, ImageLoaded scrobj.dll, UtcTime 18:04:12, Signed true Microsoft](/assets/images/atomic-t1218/sysmon-eid7.png)

**Prefetch.** PECmd parsed the live Prefetch folder. REGSVR32.EXE shows a run at 18:04:12 UTC with the run count bumped to 3, and MSHTA.EXE has no entry for this attempt, which confirms from a second source that it never started.

```
ExecutableName RunCount LastRun             PreviousRun0
REGSVR32.EXE   2        2026-08-30 05:20:09 2026-08-30 05:20:08
REGSVR32.EXE   3        2026-10-28 18:04:12 2026-08-30 05:20:09
```

Three sources agree on the same scrobj.dll load at the same second: MDE `DeviceImageLoadEvents`, Sysmon Event ID 7, and Prefetch. One timing note, same as the scheduled task post: Sysmon and PECmd record UTC (18:04:12), the MDE portal shows local time (12:04:12). Line them up before building a timeline.

---

## Detection

Both regsvr32 and scrobj.dll are signed Microsoft files, so a hash or signature rule passes them. The signal is the behavior, not the file. The strongest anchor for Squiblydoo is the image load, because an attacker can rename or obscure the scriptlet path on the command line but still has to load scrobj.dll to run a COM scriptlet.

```kql
DeviceImageLoadEvents
| where TimeGenerated > ago(1d)
| where InitiatingProcessFileName =~ "regsvr32.exe"
| where FileName =~ "scrobj.dll"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, FolderPath
| sort by TimeGenerated desc
```

This one is validated on this run (the scrobj.dll load is in the screenshot above).

For the wider family, a LOLBin starting a script interpreter or shell:

```kql
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where InitiatingProcessFileName in~ ("mshta.exe","regsvr32.exe","rundll32.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","cscript.exe","wscript.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, ProcessIntegrityLevel
| sort by TimeGenerated desc
```

This one is not validated here. mshta never ran, and the regsvr32 scriptlet was killed before it spawned its child, so neither test produced the parent-child pair this query keys on. The logic is cross-checked against the published Sigma rules for mshta and the LOLBin family. I will validate it on a host where the chain completes.

---

## Tuning

- The benign case for the image-load query is close to zero. Regular software does not drive regsvr32 to load scrobj.dll. If anything shows up, allowlist by the initiating command line, not by dropping the rule.
- The process query returns installers and some admin scripts that legitimately use these binaries. Scope it by adding a suspicious child argument (encoded command, a download cradle, a hidden window) or allowlist known parents.
- On a host with prevention like this one, the process never spawns its shell, so the family query stays quiet. Fall back to the image load and to Defender's own block events.

---

## Takeaways

The two tests landed in different places, and that is the useful part. mshta was blocked at process creation, upstream of any telemetry, the same way the UAC reg.exe write was. regsvr32 ran far enough to load its script engine before the file-layer antivirus caught the scriptlet, so it left a clear record on three independent sources.

Across the series the pattern keeps shifting: tool noise in the PowerShell post, a post-hoc alert in the scheduled task post, an upstream block in the UAC post, and now a split where one technique is stopped before it exists and the other is caught mid-execution. For a LOLBin, the file is trusted by design, so the detection has to sit on what the trusted file does, not on what it is.

---

## References

- [Atomic Red Team T1218.010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md)
- [Atomic Red Team T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md)
- [MITRE ATT&CK T1218.010](https://attack.mitre.org/techniques/T1218/010/)
- [MITRE ATT&CK T1218.005](https://attack.mitre.org/techniques/T1218/005/)
- [Microsoft Learn: DeviceImageLoadEvents table](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceimageloadevents-table)
- [Microsoft Learn: DeviceProcessEvents table](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [Sysinternals Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [Eric Zimmerman tools (PECmd)](https://ericzimmerman.github.io/)
