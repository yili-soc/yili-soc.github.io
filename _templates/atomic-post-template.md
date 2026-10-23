---
# ===================================================================
# Atomic Red Team post template
# Copy this file into _posts/ as YYYY-MM-DD-atomic-<id>-<slug>.md,
# fill in every field, then delete these comment lines.
# The `atomic:` block is structured so a coverage table can be built
# from it later (one row per post).
# ===================================================================
layout: post
title: "Atomic <TID>: <Technique name>"
date: YYYY-MM-DD 12:00:00 -0600
tags: [atomic red team, detection, "<tactic>", Microsoft Defender for Endpoint, KQL]
excerpt: "<One sentence: what the test does and whether the detection caught it.>"

atomic:
  technique_id: "<TID>"             # e.g. T1547.001
  technique_name: "<name>"          # e.g. Registry Run Keys / Startup Folder
  parent_technique: "<T-id>"        # e.g. T1547  (omit if the technique has no parent)
  tactics: ["<tactic>"]             # e.g. [Persistence, Privilege Escalation]
  platform: "<os>"                  # e.g. Windows
  data_source: "<table>"            # the main MDE/Sentinel table, e.g. DeviceRegistryEvents
  mde_default_alert: false          # did MDE raise an alert on its own? true / false
  custom_detection: true            # did my custom KQL catch it? true / false
---

## What this technique is

<2-4 sentences. What the technique does and why an attacker uses it.
State the ATT&CK mapping in plain text and link it.>

**ATT&CK:** [<TID>](https://attack.mitre.org/techniques/<T_slug>/) <Technique name>
(<tactic>). Parent: [<Txxxx>](https://attack.mitre.org/techniques/<Txxxx>/).

> **Disclaimer**
>
> - The views in this post are my own and do not represent my employer.
> - This is a detection-engineering exercise. Every step is run against my
>   own lab machine with a harmless payload. Nothing here is for offensive use.
> - The KQL is an example. Validate and tune it for your own environment.

---

## The test

<What the Atomic test does, at a level a defender needs to know what telemetry
to expect. Keep the payload harmless and say so. Show the exact command you ran
so the telemetry is reproducible, and always include the cleanup step.>

**Reproduce:** <one or two lines, benign payload>

**Clean up:** <the exact undo step, important for persistence tests>

---

## What shows up in the logs

<Which table, which ActionType/fields, and a one-line note on the fields that
matter for detection. A short screenshot of the raw event is useful here.>

| Field | Value in my test |
|---|---|
| `<field>` | `<value>` |

---

## Did MDE alert?

<The honest answer: yes / no / partial, and why. This is the most useful part
for a SOC reader, since it tells them whether they can rely on the built-in alert or
need to write their own. If MDE did alert, name the alert title and severity.>

---

## Detection

<The idea in one or two sentences, then the KQL. Explain what each filter does
and why it is there, not just the query.>

```kql
<KQL>
```

---

## Tuning

<What legitimate activity fires this, how to allowlist it, and what raises or
lowers confidence. Keep it practical.>

---

## References

- [Atomic Red Team <TID>](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/<TID>/<TID>.md)
- [MITRE ATT&CK <TID>](https://attack.mitre.org/techniques/<T_slug>/)
- <MDE table doc / any detection reference used>
