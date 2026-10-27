---
layout: post
title: "Atomic T1053.005: Scheduled Task"
date: 2026-10-27 10:00:00 -0600
tags: [atomic red team, detection, Persistence, Microsoft Defender for Endpoint, KQL]
excerpt: "Atomic test 2 for T1053.005: what MDE alerted on, what Autoruns and KAPE showed about the task, and a detection."
---

**ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task (Execution, Persistence, Privilege Escalation). Parent: [T1053](https://attack.mitre.org/techniques/T1053/) Scheduled Task/Job.

> **Disclaimer**
>
> - The views in this post are my own and do not represent my employer.
> - This is a detection-engineering exercise. Every step runs against my own lab machine with a payload that does nothing harmful. None of it is for offensive use.
> - The KQL is an example. Validate and tune it for your own environment before using it in production.

---

## The test

Atomic test 2, "Scheduled task Local", runs `schtasks.exe` to create a task named `spawn` that starts `cmd.exe` once at 20:10. Invoke-AtomicTest runs the command through `cmd.exe /c`, which matters later in the process tree.

**Reproduce:**

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 2 -CheckPrereqs
Invoke-AtomicTest T1053.005 -TestNumbers 2
```

---

## Did MDE alert?

Yes. Microsoft Defender for Endpoint (MDE) opened one Low incident, "Masqueraded task or service", with one EDR alert in the Defense evasion category, mapped to [T1036.004](https://attack.mitre.org/techniques/T1036/004/) Masquerade Task or Service.

![Incident 8 "Masqueraded task or service", Low, mapped to T1036.004. The incident graph links admin, winlab-vm, cmd.exe and the SCHTASKS /Create command](/assets/images/atomic-t1053-005/incident-masqueraded-task.png)

The incident graph links `admin`, `winlab-vm`, `cmd.exe` and the `SCHTASKS /Create ... spawn` command, so the alert fired on the task creation itself. The alert text says a suspicious process "registered an unknown file with a common name launching as a scheduled task or service."

T1036.004 covers giving a task or service a name that looks legitimate. `spawn` doesn't look like any Windows or vendor task. What happened is a task created for persistence, which is T1053.005. I can't see the rule behind the alert, so I don't know why MDE picked T1036.004. I mapped it from the behavior instead.

Not seeing the rule is the bigger issue. The alert shows a title, a description and the evidence, but not what it matched on. I can't tell which part of the command it keyed on, or what change would keep it quiet. That's why I wrote my own detection below.

---

## What shows up in the logs

### Where it started

The alert's process tree starts with `explorer.exe` launching `powershell.exe` (PID 3344) at 7:33 AM, followed by a run of "powershell.exe executed a script" events. The task was created four minutes later, at 7:37.

### Finding the command

`DeviceEvents` has a `ScheduledTaskCreated` action type, so I looked there first. On this VM it only had built-in Windows and OneDrive tasks. `spawn` wasn't one of them.

The `schtasks.exe` process was in `DeviceProcessEvents`. I searched wide, over 30 days:

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where DeviceName == "winlab-vm"
| where FileName contains "schtasks" or ProcessCommandLine contains "/Create"
| project Timestamp, ActionType, FileName, FolderPath, ProcessCommandLine
```

![Two rows: schtasks.exe with the /Create command line, and the cmd.exe /c wrapper that launched it](/assets/images/atomic-t1053-005/schtasks-search.png)

Two rows, both from the test: `schtasks.exe`, and the `cmd.exe /c` wrapper that Invoke-AtomicTest used to start it. Nothing else on this VM ran `schtasks` in 30 days.

The `schtasks.exe` event had the rest: account `admin`, integrity level High, parent `cmd.exe`, grandparent `powershell.exe`.

### Reading the command

```
SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10
```

What the command line says about the risk:

- `/SC ONCE /ST 20:10` fires one time. There is no logon or startup trigger, so it never runs again after tonight.
- There is no `/RU`, so the task runs as `admin`, and only while `admin` is logged on.
- There is no `/RL HIGHEST`, so the task runs with admin's limited token, even though `schtasks.exe` itself ran at High.
- The action is `cmd.exe` with no arguments.

One host, one account, a one-time task with no payload, created from an interactive PowerShell session. Verdict: true positive, authorized test, no impact.

---

## The task on disk

MDE showed how the task was created. To see the task itself on the host, I used Autoruns and KAPE.

### Autoruns

On the Scheduled Tasks tab, `spawn` points at `cmd.exe` and is marked "(Verified) Microsoft Windows".

![Autoruns Scheduled Tasks tab: spawn runs C:\windows\system32\cmd.exe, Verified Microsoft Windows, timestamp Mon Sep 15 2025](/assets/images/atomic-t1053-005/autoruns-spawn.png)

That verification is for `cmd.exe`, the file the task runs. It says nothing about who created the task. A task that runs `powershell.exe` or `rundll32.exe` with malicious arguments gets the same label.

The timestamp is also off. Autoruns shows Sep 15 2025 for `spawn`, the same time it shows for the other tasks that run System32 binaries. That date comes from the binary. The task was created on Oct 27.

So Autoruns shows that the task exists and what it runs. It doesn't show who created it or when.

### KAPE

KAPE's `ScheduledTasks` target copies the task files out of `C:\Windows\System32\Tasks`. I ran it from gkape, the GUI, with `C:` as the source and a local output folder.

![gkape with target source C: and the output folder C:\SOC\Tools\KAPE\output\T1053-spawn](/assets/images/atomic-t1053-005/kape-gkape.png)

Each task is a plain XML file. The relevant parts of `spawn`:

```xml
<RegistrationInfo>
  <Date>2026-10-27T06:37:34</Date>
  <Author>WINLAB-VM\admin</Author>
  <URI>\spawn</URI>
</RegistrationInfo>
...
<Actions Context="Author">
  <Exec>
    <Command>C:\windows\system32\cmd.exe</Command>
  </Exec>
</Actions>
<Principals>
  <Principal id="Author">
    <UserId>WINLAB-VM\admin</UserId>
    <LogonType>InteractiveToken</LogonType>
    <RunLevel>LeastPrivilege</RunLevel>
  </Principal>
</Principals>
```

`<Author>` and `<Date>` give who and when. `InteractiveToken` and `LeastPrivilege` confirm what I read from the command line: the task only runs while `admin` is logged on, and without elevation.

Two things to watch with this file. First, `<Author>` and `<Date>` are just fields in the XML. A task registered from an XML file, with `schtasks /Create /XML` or `Register-ScheduledTask -Xml`, keeps whatever values were written in it. Here they are accurate because `schtasks.exe` filled them in.

Second, the time. The XML says 06:37:34 and MDE shows 7:37:34 for the same event. `<Date>` has no time zone. It is written in the VM's local time, while the Defender portal shows times in the zone set in its settings. Line the two up before you build a timeline.

### Autoruns or KAPE

They do different jobs. Autoruns is for a live host when you need a quick answer: what starts automatically on this machine right now. It covers tasks, Run keys, services, WMI subscriptions and more in one view, and it's the fastest way to confirm a cleanup worked. It only shows current state, and only for the host you're on. To use it across many hosts, run `autorunsc` from the command line, export to CSV, and diff against a known-good baseline.

KAPE is for keeping evidence. It copies the raw files with their metadata, so the analysis can happen later, on another machine, after the host has been reimaged. It doesn't tell you what's suspicious. You still have to read or parse what it collected. For one quick question on one host it's more than you need. When the case may go to legal, or the host is about to be wiped, it's the one to run.

With MDE in place, neither one is how you find the creation. Process telemetry already shows who, when and how. They matter when that telemetry is missing: a client onboarded with no EDR, data past the retention window, or a task created before the agent was installed. In those cases the task file on disk is all you have.

---

## Detection

I wrote two queries. The first returns every task created with `schtasks.exe`, for hunting:

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, ProcessIntegrityLevel
| sort by Timestamp desc
```

On a real network this also returns installers, updaters and management agents, which is too much to alert on. The second keeps only tasks created from a command shell or script host:

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, ProcessIntegrityLevel
| sort by Timestamp desc
```

![The second query returns one row: admin, SCHTASKS /Create, parent cmd.exe, grandparent powershell.exe, High](/assets/images/atomic-t1053-005/detection-layer2.png)

It returned the `spawn` row. On this VM both queries return the same single row, because the test was the only `schtasks` run in 30 days. The difference between them shows up on a network with real software on it.

---

## Tuning

- Installers, updaters and management tools (SCCM, Intune scripts) also create tasks from cmd or PowerShell. Allowlist them by task name or command line.
- The parent list matched here partly because Invoke-AtomicTest runs the command through `cmd.exe`. If malware starts `schtasks.exe` itself, the parent is the malware process, which isn't on the list. If the fleet is stable enough, reverse it: list the known parents and alert on the rest.
- Raise the severity when the command line has `/RU SYSTEM`, `/RL HIGHEST`, an `ONLOGON` or `ONSTART` trigger, or a `/TR` path in a user-writable folder (`AppData`, `Temp`, `ProgramData`, `Users\Public`).
- Also match `ProcessVersionInfoOriginalFileName =~ "schtasks.exe"`, so a renamed copy still hits.
- Sigma's "Scheduled Task Creation Via Schtasks.EXE" filters out tasks created by SYSTEM to cut noise. That also hides an attacker who already has SYSTEM, so I left them in.

These queries only see tasks created with `schtasks.exe`. PowerShell's `Register-ScheduledTask`, the Task Scheduler COM API and direct writes to the TaskCache registry key don't use it. MDE's `ScheduledTaskCreated` event isn't tied to `schtasks.exe` (it recorded the OneDrive tasks), but it didn't record `spawn`, so I wouldn't rely on it alone. Windows event 4698 (a scheduled task was created) is the other option. It needs "Audit Other Object Access Events" turned on, and it doesn't fire for a task written straight into the registry.

---

## Takeaways

MDE caught the creation but filed it under masquerading, and I couldn't see the rule behind it. The alert got me to the activity. The technique and the scope came from reading the process events.

Each source answered only part of the question. Autoruns trusted the task because `cmd.exe` is signed, and gave a 2025 date. The XML had the right author and time, but only because `schtasks.exe` wrote them. Only the process event showed how the task got there, so that's where the detection sits.

---

## References

- [Atomic Red Team T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md)
- [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK T1036.004](https://attack.mitre.org/techniques/T1036/004/)
- [Microsoft Learn: schtasks create](https://learn.microsoft.com/windows-server/administration/windows-commands/schtasks-create)
- [Microsoft Learn: DeviceProcessEvents table](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [Sysinternals Autoruns](https://learn.microsoft.com/sysinternals/downloads/autoruns)
- [KAPE (Kroll)](https://www.kroll.com/en-us/services/cyber/incident-response-recovery/kroll-artifact-parser-and-extractor-kape)
