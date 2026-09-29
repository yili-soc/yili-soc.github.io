---
layout: post
title: "From DNS Takeover to Atlassian Org Admin: Detection and Response in Microsoft Sentinel"
date: 2026-09-26 18:00:00 -0600
tags: [BSidesEdmonton2026, detection, Atlassian, DNS, SaaS, Microsoft Sentinel, KQL, incident response]
excerpt: "How an attacker who controlled a company's DNS used Atlassian's own domain verification to become org admin, and how to detect it when identity logs show nothing."
---

## 0. Introduction

This case comes from the BSides Edmonton 2026 talk *Advanced SaaS Threats: Case Studies from the Field* by [Damien Miller-McAndrews](https://www.linkedin.com/in/damien-miller-mcandrews/), a threat researcher at Obsidian Security. He walked through three real cases to make one point: many SaaS breaches today use no exploits and no malware. Attackers simply abuse legitimate features and identity trust.

This post covers the second case: an attacker first took control of the victim company's DNS, then used Atlassian's domain verification feature to become an admin of the victim's Atlassian organization. This post adds how to detect and respond to this kind of attack in Microsoft Sentinel.

> **Disclaimer**
>
> - The views in this post are my own and do not represent my employer.
> - Incident details come from public sources and the original talk, which are cited in the text. I am not affiliated with Obsidian Security.
> - The KQL queries illustrate detection logic and rely on custom log tables. Adjust and validate them for your own environment before use.

---

## 1. Background

### The features being abused

To help companies manage shadow IT, Atlassian offers three features that work together:

- **Domain verification**: a company proves it owns a domain with a DNS TXT record, a verification file on its website, or an IdP integration.
- **Account claiming**: once the domain is verified, the company can turn every Atlassian account registered with that email domain into a managed account, including those accounts' identities in other Atlassian organizations.
- **Join as admin**: admins can see the Atlassian apps that managed accounts use outside the organization, and join the organization that owns those apps as an org admin with one click.

The problem: **the same domain can be verified by more than one organization**, and verification only takes one DNS record. The platform assumes "whoever can verify this domain is this company's IT", but it doesn't check whether the "discovered" organization might actually be the company's real one. Whoever controls DNS can walk through all three steps. In Obsidian's words, DNS effectively becomes a single point of failure for domain-based trust.

---

## 2. How the attack works

### The big picture

The incident below is based on the original BSides Edmonton 2026 talk.

The attacker first took control of the victim company's domain. Instead of attacking Atlassian directly, they created their own Atlassian organization and added a verification record to the victim's DNS. Atlassian then treated the attacker's organization as the "owner" of the victim's domain, and the victim's employee accounts became managed accounts of the attacker's organization. From the attacker's side, the victim's real Atlassian organization now looked like a shadow IT app. The attacker clicked Join as admin, became an admin of the victim's organization, and removed the legitimate admins, locking the security team out. After the security team cleaned up, the attacker came back the same way several times, and the two sides ended up in a long tug of war, because the DNS was still in the attacker's hands.

### ① Taking control of DNS

**ATT&CK:** [T1584.001](https://attack.mitre.org/techniques/T1584/001/) Compromise Infrastructure: Domains

The public blog post doesn't say how the attacker gained control of DNS. According to the talk, in this case the attacker social-engineered the domain registrar to get control of the domain, then changed the NS and MX records. Changing MX meant that all of the victim's inbound email also went to the attacker.

In general, there are a few ways in, and what defenders can see differs for each:

- **Registrar account or registrar support**: change NS and move resolution for the whole domain elsewhere. This happens outside the company, so nothing shows up in the company's own logs.
- **DNS hosting account** (Cloudflare, Route 53, Azure DNS, etc.): add or delete records directly. The hosting platform keeps audit logs.
- **Subdomain takeover**: Atlassian accepts a verification file on the website. If a CNAME for `www` or another subdomain points to a cloud resource that has been deleted, the attacker can register a resource with the same name and host the verification file there, without controlling the whole DNS.

**Evidence:** changes to the domain's NS, MX, or TXT records.

### ② Verifying the victim's domain in the attacker's own organization

The attacker adds the victim's domain to their own Atlassian organization and writes Atlassian's verification TXT record. Because the same domain can be verified by more than one organization, this doesn't affect the victim's own verification status, and the victim gets no notification.

**Evidence:** a new TXT record of the `atlassian-domain-verification` type under the domain.

### ③ Joining the victim's organization as admin

**ATT&CK:** [T1098.003](https://attack.mitre.org/techniques/T1098/003/) Additional Cloud Roles

According to the talk, the attacker used an external email account that was not on the victim's domain, so the victim's SSO and domain policies had no control over it.

**Evidence:** a `joined-as-org-admin` event in the victim organization's audit log. Obsidian notes that this event is only triggered by the shadow IT workflow and is very rare in normal use.

### ④ Taking over and persisting

**ATT&CK:** [T1531](https://attack.mitre.org/techniques/T1531/) Account Access Removal · [T1098.001](https://attack.mitre.org/techniques/T1098/001/) Additional Cloud Credentials (API key)

The attacker removes the legitimate admins and locks the defenders out. According to the talk, the attacker also created an org-level API key and deleted a security policy that prevented data export. The API key doesn't depend on a user account, so deleting the attacker's account doesn't revoke it.

### ⑤ Tug of war

The security team removes the attacker, the attacker comes back through Join as admin, and removes the legitimate admins again. As long as the attacker still controls DNS and that verification record, the loop doesn't stop.

---

## 3. Detection approach and KQL

What sets this case apart: **the attack doesn't start in the identity system; it starts in DNS.** Every step the attacker takes in Atlassian is a normal use of a legitimate feature, so sign-in and identity-based detections are of almost no use. Detection has to cover two layers: whether DNS itself has been changed, and whether Atlassian shows admin actions that only this kind of attack would trigger.

**About the log sources:** the Atlassian connectors in the Sentinel Content hub mainly collect Confluence and Jira product audit logs. The org-level admin log that detection point 2 needs has to be brought in yourself through the events endpoint of the Atlassian Organizations API (for example with a Logic App or the Codeless Connector Platform), and it requires an Atlassian Guard subscription. Detection point 1 also needs a collection job you build yourself. The custom table and field names below are examples only; use whatever your ingestion produces.

### Detection point 1: changes to key DNS records (steps ① and ②)

**Idea:** if the attacker takes over the domain at the registrar, they point NS to their own servers, and the company's own DNS platform logs show nothing at all. So you can't rely only on the DNS platform's activity logs. You need to **resolve your own domains from the outside on a schedule** and compare the NS, MX, and TXT results against a baseline. This can be simple: a scheduled script (for example PowerShell's `Resolve-DnsName`) resolves the domains every hour and writes the results to a custom table, `DnsSnapshot_CL`, through the Logs Ingestion API.

```kql
let Monitored = dynamic(["NS", "MX", "TXT"]);
let Current = DnsSnapshot_CL
| where TimeGenerated > ago(1h)
| where RecordType in (Monitored)
| summarize CurrentValues = make_set(Value) by Domain, RecordType;
let Baseline = DnsSnapshot_CL
| where TimeGenerated between (ago(7d) .. ago(1h))
| where RecordType in (Monitored)
| summarize BaselineValues = make_set(Value) by Domain, RecordType;
Current
| join kind=inner Baseline on Domain, RecordType
| extend
    Added = set_difference(CurrentValues, BaselineValues),
    Removed = set_difference(BaselineValues, CurrentValues)
| where array_length(Added) > 0 or array_length(Removed) > 0
| project Domain, RecordType, Added, Removed
```

**What to focus on:** any change to NS or MX, and any new `atlassian-domain-verification` TXT record. Normally, changes like these can be matched to a change ticket.

**What it doesn't cover:** this query only sees the domains you monitor. Subdomain takeover needs a separate, regular review of your CNAMEs to check that the cloud resources they point to still exist.

### Detection point 2: `joined-as-org-admin` and what follows (steps ③ and ④)

**Idea:** this is the highest-fidelity signal in the whole chain. In normal business almost nobody uses Join as admin to join their own company's organization, so a single occurrence is worth investigating right away. The query doesn't just return this event; it also lists everything that account did in the hour after joining, so an analyst can see at a glance whether admins were removed, API keys created, or policies deleted.

```kql
let Joiners = AtlassianOrgAudit_CL
| where TimeGenerated > ago(1d)
| where Action == "joined-as-org-admin"
| project JoinTime = TimeGenerated, ActorId, ActorName, JoinIp = SourceIp;
AtlassianOrgAudit_CL
| where TimeGenerated > ago(1d)
| join kind=inner Joiners on ActorId
| where TimeGenerated between (JoinTime .. JoinTime + 1h)
| summarize
    Actions = make_list(Action, 50),
    FirstAction = min(TimeGenerated)
    by ActorId, ActorName, JoinTime, JoinIp
```

**Extra check:** review the org admin list regularly. Any admin account outside the company's domain needs a clear reason to be there.

---

## 4. Response and automation

### Key points

If detection point 2 fires, or detection point 1 shows an NS or MX change that can't be matched to a change ticket, treat it as a domain takeover. Three things matter most in this case:

**1. Take back DNS first, then clean up Atlassian.** This is the biggest difference from an ordinary account takeover. The way in is DNS. As long as the attacker still controls DNS and the verification record, any cleanup in Atlassian will be undone again, which is exactly where the tug of war comes from. So the first step is to work with the registrar or DNS host to regain control, restore NS and MX, and delete the attacker's verification TXT record. At the same time, contact Atlassian's security team and tell them another organization has maliciously verified your domain.

**2. Communicate out of band, and clean up everything in one window.** The attacker may control MX, so don't coordinate over company email during the incident. Once DNS is back, remove every persistence point at once: the attacker's account, every API key created during the incident window, and the deleted policies, while restoring the legitimate admins. Cleaning up one piece at a time gives the attacker a way back in.

**3. The impact goes beyond Atlassian.** While MX was changed, every email sent to the company may have been read by the attacker, including password reset emails from other systems. Check every SaaS app for password resets, email changes, and new device sign-ins during that window, and check whether the attacker used the same domain verification trick to take over other SaaS apps.

### Is automation needed?

This case shows one thing clearly: **automation doesn't fix the root cause.** As long as the way in stays open, automatically kicking the attacker out of Atlassian just hands the tug of war to a machine, and the attacker still comes back. Here, the value of automation is mainly faster detection and faster context. The actual response depends on a plan prepared in advance.

| Tier | Actions | Impact and reversibility |
|---|---|---|
| Fully automatic | Alert; collect the current NS/MX/TXT records, the org admin list, and recently created API keys; notify the client | No business impact |
| Automatic with pre-authorization | Suspend new admin accounts that joined through Join as admin (if the platform API supports it) | Low impact, reversible; but until DNS is back, it only buys time |
| Manual approval | Take back the registrar and DNS, remove persistence, contact vendors | Needs coordination across teams; can't be automated |

More important than automation is preparing these in advance: security contacts at the registrar and each SaaS vendor, an out-of-band communication channel for incidents, and an emergency admin account that doesn't depend on the company domain.

---

## 5. Summary

- In this case the attacker didn't break into any account; they only took control of DNS. **Whoever controls DNS "owns" the domain, and with it every SaaS permission built on domain-based trust.**
- Detection has to extend from the identity layer to the DNS layer: monitor NS, MX, and TXT changes from the outside, and watch for events like `joined-as-org-admin` that only show up when the feature is abused.
- The order of response decides the outcome: **take back DNS first, then clean up everything in one window**, or the tug of war never ends.

### Further discussion: this isn't just an Atlassian problem

Many SaaS platforms let you verify a domain through DNS and claim the accounts under it, including common collaboration, meeting, and code hosting platforms. When evaluating any SaaS admin feature, ask three questions:

1. What can this feature do?
2. What makes it trust that the person using it is legitimate?
3. How cheap is it to compromise that trust?

If the trust rests on nothing more than a DNS record, that could be where the next case like this happens.

---

## References

- Obsidian Security: [From DNS Takeover to Org Admin: Secondary Attacks on Atlassian Cloud](https://www.obsidiansecurity.com/blog/from-dns-takeover-to-org-admin-secondary-attacks-on-atlassian-cloud)
- Atlassian Support: [Verify a domain to manage accounts](https://support.atlassian.com/user-management/docs/verify-a-domain-to-manage-accounts/)
- Atlassian Support: [What are my options for shadow IT apps?](https://support.atlassian.com/organization-administration/docs/how-to-work-with-admins-of-discovered-products/)
- Atlassian Support: [What activities does the audit log include?](https://support.atlassian.com/security-and-access-policies/docs/accessing-audit-log-activities/)
- MITRE ATT&CK: technique IDs in this post are mapped to [ATT&CK v19](https://attack.mitre.org/resources/versions/). Steps with no close match are left unmapped.
