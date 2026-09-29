---
layout: post
title: "When the Vendor Is the Way In: Detecting Abused SaaS Integrations in Microsoft Sentinel"
date: 2026-09-26 20:00:00 -0600
tags: [BSidesEdmonton2026, detection, supply chain, OAuth, SaaS, Microsoft Sentinel, KQL, incident response]
excerpt: "Attackers breached Klue, stole the OAuth tokens its customers had granted, and pulled their Salesforce data. How to spot a trusted integration that has changed hands."
---

## 0. Introduction

This case comes from the BSides Edmonton 2026 talk *Advanced SaaS Threats: Case Studies from the Field* by [Damien Miller-McAndrews](https://www.linkedin.com/in/damien-miller-mcandrews/), a threat researcher at Obsidian Security. He walked through three real cases to make one point: many SaaS breaches today use no exploits and no malware. Attackers simply abuse legitimate features and identity trust.

This post covers the third case: the competitive intelligence platform Klue was breached, and attackers stole the OAuth tokens it held on behalf of its customers, then used those tokens to export customers' Salesforce data in bulk. This post adds the customer's side: how to detect and respond to an abused third-party integration in Microsoft Sentinel.

> **Disclaimer**
>
> - The views in this post are my own and do not represent my employer.
> - Incident details come from public sources and the original talk, which are cited in the text. I am not affiliated with Obsidian Security.
> - The KQL queries illustrate detection logic. Adjust and validate them for your own environment before use.

---

## 1. Background

Klue is a competitive intelligence SaaS platform. It connects to customers' Salesforce, HubSpot, SharePoint, Gong, Slack and other systems through OAuth to read sales data. In June 2026, Icarus, an extortion group that only appeared in April, breached Klue. The attackers used a dormant but still valid credential that had been created for a prototype integration, got into Klue's backend, planted malicious code, and stole the OAuth tokens customers had granted to Klue. Over roughly the next 24 hours, they used Python scripts to pull CRM data from several customers through the Salesforce REST API, then sent extortion emails to the victims. Klue then disabled all customer integrations, and Salesforce disabled Klue's app ([BleepingComputer](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/)).

More than a dozen organizations were affected. Those named publicly include LastPass, 8x8, and Snyk ([FINRA](https://www.finra.org/rules-guidance/guidance/cybersecurity-alert-klue-oauth-breach-and-salesforce-data-exfiltration)). Huntress also confirmed it was one of the victims and published the details of its investigation ([Huntress](https://www.huntress.com/blog/klue-breach-investigation)).

This is a textbook SaaS supply chain attack: instead of attacking the target directly, the attacker breaks into a vendor the target trusts and uses the vendor's access to get in. In MITRE ATT&CK terms, it falls under T1199 Trusted Relationship.

This post is based on Obsidian's [technical analysis](https://www.obsidiansecurity.com/blog/icarus-klue-salesforce-integration-supply-chain-attack), Huntress's victim-side investigation, and the original talk.

---

## 2. How the attack works

### The big picture

The customers did nothing wrong. At some point they authorized Klue to access Salesforce, and Klue used the token to sync data on a schedule. Everything was normal. The attacker never touched any customer account. They broke into Klue and took those tokens. To Salesforce, the attacker's requests were simply "Klue calling the API": no sign-in, no MFA, and nothing that would trigger an identity alert. The attacker first worked out what data each customer's Salesforce held, then used scripts to page through it and pull everything out.

### ① The vendor is breached (invisible to customers)

**ATT&CK:** [T1528](https://attack.mitre.org/techniques/T1528/) Steal Application Access Token (on the vendor side)

The attacker used a dormant credential at Klue that had never been cleaned up, got into the backend, planted code, and collected customers' OAuth tokens. According to the talk, that credential was a GitHub personal access token (PAT) that had been alive for about four years. This step happens inside the vendor. Customers can't see it and can't detect it.

### ② Stolen tokens used against customers' Salesforce

**ATT&CK:** [T1550.001](https://attack.mitre.org/techniques/T1550/001/) Application Access Token

This is the first step customers can see, and it left a clear change in the integration's "fingerprint" (Obsidian, Huntress):

- **The User-Agent changed:** Klue's normal integration used `python-httpx`. The attack traffic switched to `python-urllib/3.12` and `python-urllib/3.14`, plus User-Agents of "5238" or blank.
- **The API version changed:** normal calls went to `/services/data/v64.0/`; attack calls used `v59.0`.
- **The source IPs changed:** attack traffic came from a few IPs the integration had never used, located in the Netherlands, France, and Ukraine.

### ③ Discovery

**ATT&CK:** [T1526](https://attack.mitre.org/techniques/T1526/) Cloud Service Discovery (closest fit, my mapping)

The attacker first called Salesforce's Global Describe to list every object in the org. A normal business integration only reads the few objects it needs and almost never enumerates everything.

### ④ Bulk export

**ATT&CK:** [T1213.004](https://attack.mitre.org/techniques/T1213/004/) Customer Relationship Management Software · [T1020](https://attack.mitre.org/techniques/T1020/) Automated Exfiltration

The attacker ran bulk SOQL queries against objects such as Account, Contact, Opportunity, and Task, then paged through the results with QueryMore to pull everything out. In the worst-hit organization, about 13.9 million records were exported.

---

## 3. Detection approach and KQL

What makes this case hard: the attacker uses a **legitimate token**. Detections based on sign-ins, MFA, or identity risk all fail. The only trace is in the API call logs.

But the case also has a useful property: **integrations are far more predictable than people.** An integration usually calls from the same few IPs, with the same User-Agent and the same API version, reads the same few objects, and moves a fairly steady amount of data each day. Build a "fingerprint" like that for each integration and alert when it changes. What Obsidian saw in this incident was every part of the fingerprint changing.

The KQL below applies this idea to Microsoft 365, for two reasons. First, Klue's connections included SharePoint, so the same attack could just as easily land in M365. Second, the Graph API log in M365, `MicrosoftGraphActivityLogs`, records every field the fingerprint needs (`AppId`, `IPAddress`, `UserAgent`, `ApiVersion`, `RequestUri`, `ResponseSizeBytes`). This table has to be turned on separately in Entra's diagnostic settings, and many environments don't have it on by default.

### Detection point 1: the integration's fingerprint changes (step ②)

**Idea:** ask one question: has this app's "User-Agent + API version" combination from today been seen in the last 30 days? Klue normally used `python-httpx` + `v64.0`. During the attack, `python-urllib` + `v59.0` appeared, and that new combination gets listed right away. IP isn't used as a condition, because vendors change cloud servers all the time and IP on its own is too noisy. The results still list the source IPs for the analyst to review.

```kql
let Known = MicrosoftGraphActivityLogs
| where TimeGenerated between (ago(30d) .. ago(1d))
| distinct AppId, UserAgent, ApiVersion;
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1d)
| where AppId in ((Known | distinct AppId))
| join kind=leftanti Known on AppId, UserAgent, ApiVersion
| summarize Requests = count(), IPs = make_set(IPAddress, 10) by AppId, UserAgent, ApiVersion
```

**How it works:** `Known` lists every combination each app used in the last 30 days. The `leftanti` join keeps only combinations that appear today but never appear in `Known`. Apps connected less than 30 days ago have no baseline, so they're left out.

**False positives:** the vendor upgrades its libraries or API version. Changes like that are usually announced in advance, or show up for every customer on the same day. Check with the vendor.

**On the Salesforce side:** Salesforce API logs are only kept for 24 hours, so they need to be pulled into the SIEM on a schedule. If you have Defender for Cloud Apps, you can use its built-in detections.

### Detection point 2: discovery and bulk pulls (steps ③ and ④)

**Idea:** an integration usually touches a fairly steady set of resource types and a fairly steady volume of data each day. If one day it suddenly touches many resource types it has never used, or pulls ten times its usual volume, that points to discovery followed by bulk export.

```kql
let Daily = MicrosoftGraphActivityLogs
| where TimeGenerated > ago(14d)
| extend Resource = tostring(split(tostring(parse_url(RequestUri).Path), "/")[2])
| summarize
    Resources = dcount(Resource),
    MB = sum(ResponseSizeBytes) / 1048576.0
    by AppId, Day = startofday(TimeGenerated);
Daily
| summarize
    TodayMB = sumif(MB, Day == startofday(now())),
    AvgMB = avgif(MB, Day < startofday(now())),
    TodayResources = maxif(Resources, Day == startofday(now())),
    MaxResourcesBefore = maxif(Resources, Day < startofday(now()))
    by AppId
| where (TodayMB > 50 and TodayMB > 10 * AvgMB)
    or TodayResources > MaxResourcesBefore + 3
```

**When both detections fire for the same app**, it's almost certainly token abuse.

---

## 4. Response and automation

### Key points

**1. Isolate the integration yourself; don't wait for the vendor.** When both detections fire, or the vendor publicly discloses a breach, block the connected app in Salesforce and revoke all of its tokens, and disable the matching enterprise app in Entra. Isolate the whole app, not just one token.

**2. Scope the impact and warn about follow-on abuse.** Find every other system connected to this vendor, isolate each one, and review its logs. The stolen contact data is exactly the target list a vishing campaign needs, so warn employees to watch for calls, emails, and extortion messages that impersonate the vendor.

### Is automation needed?

This case is **a good fit for automation**: isolating a third-party integration has limited business impact and can be undone at any time, so clients are far more willing to pre-authorize it than, say, disabling an employee's account.

| Tier | Actions | Impact and reversibility |
|---|---|---|
| Fully automatic | Alert; list the app's permissions, recent IPs, and calls; match against public IOCs; notify the client | No business impact |
| Automatic with pre-authorization | When detection points 1 and 2 both fire, or the vendor publicly discloses a breach: disable the integration and revoke its tokens | Low impact, reversible: the integration stops syncing and can be re-authorized once it's safe |
| Manual approval | Assess data impact, notify the client's legal team, coordinate with the vendor | Needs business and legal judgment |

---

## 5. Summary

- The attacker uses a legitimate token, so identity-based detections all fail. **Detection has to rely on API call logs.**
- Integrations are far more predictable than people. **Build a fingerprint for each integration** (IP, User-Agent, API version, objects accessed, data volume) and alert when it changes.
- Isolating an integration has low business impact, which makes it one of the best candidates for pre-authorized automation.

### Further discussion: what to ask in third-party risk reviews

The way in was the vendor, so everything the customer can detect happens after the fact. What customers can do beforehand is ask the right questions during procurement and annual reviews, instead of only asking for a SOC 2 report:

1. How do you manage development and integration credentials? Do they expire, and are they cleaned up?
2. Where do you store the OAuth tokens you hold for us, and how are they protected?
3. Which fixed IPs does your integration use to reach our systems? (With that list, the customer can set login IP ranges for the integration user in Salesforce, which is the most direct preventive control. Klue didn't publish its egress IPs, so its customers couldn't do this even if they wanted to.)
4. If you're breached, how quickly will you tell us?

---

## References

- Obsidian Security: [Technical Analysis of the Klue Attack: OAuth Abuse, Stale Integrations, and Salesforce Exfiltration](https://www.obsidiansecurity.com/blog/icarus-klue-salesforce-integration-supply-chain-attack)
- Huntress: [Cybercrime Breaches Klue: Salesforce Data Impacted for Many Victims, including Huntress](https://www.huntress.com/blog/klue-breach-investigation)
- BleepingComputer: [Klue OAuth breach linked to 'Icarus' Salesforce data theft attacks](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/)
- FINRA: [Cybersecurity Alert: Klue OAuth Breach and Salesforce Data Exfiltration](https://www.finra.org/rules-guidance/guidance/cybersecurity-alert-klue-oauth-breach-and-salesforce-data-exfiltration)
- Microsoft Learn: [Access Microsoft Graph activity logs](https://learn.microsoft.com/graph/microsoft-graph-activity-logs-overview)
- MITRE ATT&CK: technique IDs in this post are mapped to [ATT&CK v19](https://attack.mitre.org/resources/versions/). Steps with no close match are left unmapped.
