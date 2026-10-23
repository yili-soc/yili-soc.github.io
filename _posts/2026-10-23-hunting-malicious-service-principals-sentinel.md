---
layout: post
title: "Hunting Malicious Service Principals in Microsoft Sentinel: Notes from Storm-0940"
date: 2026-10-23 12:00:00 -0600
tags: [detection, Microsoft Sentinel, Entra ID, service principal, KQL, Storm-0940]
excerpt: "I reproduced the core of the Storm-0940 / ConnectWise app abuse in my own tenant to see what it looks like in the logs, and whether it can be caught on behavior alone, without any IOCs."
---

## Where this came from

In late October 2026, Microsoft and Huntress both published on the same attack: the ConnectWise Cloud Backup compromise, which Microsoft attributes to a threat actor it tracks as Storm-0940. The tactics attackers used are quite simple: No phishing email to a user. No malware on an endpoint. No payload at all. The attacker signed in as a trusted application, gave that application a privileged role, and added their own secret to it so they could come back later. That's it.

Two things stuck with me. First, almost every detection we run day to day is built around *users*, and the sign-in events that mattered here don't even show up where most analysts look. Second, Microsoft said the actor automated the whole thing with an agentic AI framework called ARTEX. The technique isn't new, but the automation made it much faster.

Most write-ups of this incident end with a list of IPs, app IDs and user agents. That's useful for a week or two, then it goes stale. And as it turns out, it wouldn't have caught the most important step anyway. So I rebuilt the core of the attack in my own test tenant to see what it looks like in the logs, and whether I could detect it on behavior alone.

> **Disclaimer**
>
> - The views in this post are my own and do not represent my employer.
> - Everything was tested in my own developer tenant. The KQL queries are examples. Adjust and validate them for your own environment before using them in production.

---

## What happened

ConnectWise Cloud Backup is a service MSPs use to back up their clients' Microsoft 365 data, so its app holds broad access in every tenant it's installed in. The app's credential was stolen. Because it's a multi-tenant app, that one credential opened every customer tenant that had it installed.

The core technique is OAuth app abuse. Sign in as the app with its stolen credential ([T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1199](https://attack.mitre.org/techniques/T1199/)). Map the tenant over Microsoft Graph ([T1087.004](https://attack.mitre.org/techniques/T1087/004/)). Make the app a Global Administrator ([T1098.003](https://attack.mitre.org/techniques/T1098/003/)). Then add new secrets to other apps in the tenant as a backdoor ([T1098.001](https://attack.mitre.org/techniques/T1098/001/)). No user, no MFA prompt, no malware. Microsoft says the actor ran all of this with ARTEX, an open-source framework where AI agents chain these steps together on their own. That's how it attempted sign-ins against more than 2,250 tenants, and in some of them got to admin in under three hours.

One detail matters for detection. The published IOCs are an IP range and a few user agents, but the admin grant and the planted secrets didn't come from that IP. They came from Microsoft's internal IPv6 space, the same range the legitimate app uses. A rule built on the IOCs would have missed the persistence.

For the full timeline and indicators, see [Huntress's write-up](https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access) and [Microsoft's post](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/).

---

## Why the usual tools miss it

First, one term. When you register an application in Entra ID, it gets a **service principal** in your tenant: the app's own identity, separate from any person. The app registration is the blueprint; the service principal is what actually signs in and does things. An app can sign in on its own with a secret or certificate, with no user involved. That's called **app-only** (or **client-credentials**) authentication, and it's normal. Backups, automation and integrations all depend on it. It's also why a stolen app credential is so hard to spot.

### 1. The sign-in isn't on the sign-in page

Service principal sign-ins are logged separately from user sign-ins. In Sentinel they land in the `AADServicePrincipalSignInLogs` table, and only if someone turned on that diagnostic setting. The default view in the Entra sign-in logs shows users. If you've never opened the service principal tab, you have a blind spot.

### 2. Conditional Access and MFA don't apply

Conditional Access and multi-factor authentication are built around a person signing in. An app using a secret gets no MFA prompt and no device check. It also skips your location policies, unless you've licensed and set up Conditional Access for workload identities, which most tenants haven't.

### 3. Password resets don't help

There's no user, so there's no password to reset. A secret on an app works until someone removes it. And disabling the compromised app doesn't remove secrets it already planted on other apps, which is exactly how this attacker kept a way back in.

---

## What I did in the lab

Every step below is an ordinary Microsoft Graph call against an app I registered myself. An attacker makes the same calls an admin does. The only difference is who made them and in what order.

I registered a test app called `VictimApp-SPLab`, gave it two application permissions (`Directory.Read.All` and `RoleManagement.ReadWrite.Directory`), and ran three steps:

1. **Signed in app-only and did recon.** Using the app's own secret, with no user involved, I pulled a token and enumerated users, groups, roles, service principals, and applications. This stands in for an attacker mapping the tenant.
2. **Self-assigned a directory role.** The app granted its own service principal the `Directory Readers` role. In the real attack the actor assigned Global Administrator; a low-privilege role produces the same audit event, so there's no reason to hand a test app anything dangerous.
3. **Added a credential.** I planted a second secret on the application, the way an attacker leaves a key behind for later.

---

## Three detections, and what the lab actually showed

The first two queries are for investigation: once you know which app to look at, they show what it did. The third is the actual detection, and it doesn't need to know anything in advance.

### 1. The service principal sign-in, and why it's invisible by default

Start here, because it's the part most people have never seen. My app-only sign-in landed in `AADServicePrincipalSignInLogs`:

```kql
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(1d)
| where AppId == "<your app id>"
| where ResultType == 0        // 0 = success
| project TimeGenerated, AppId, ServicePrincipalName, ServicePrincipalId, IPAddress, ResourceDisplayName
```

![AADServicePrincipalSignInLogs returning the app-only sign-in for VictimApp-SPLab, result 0, resource Microsoft Graph](/assets/images/sp-hunting/sp-signin.png)

This returned the sign-in: `VictimApp-SPLab`, result 0, resource `Microsoft Graph`. Now open the Entra portal and go to **Sign-in logs**. On the default **User sign-ins** tab, this event doesn't exist. Switch to the **Service principal sign-ins** tab and there it is. Same event, two tabs, and most people only ever look at the first one.

### 2. What the app did over Graph

Authentication alone doesn't prove much. The next question is what the identity actually *did*, and that's in `MicrosoftGraphActivityLogs`:

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1d)
| where AppId == "<your app id>"
| project TimeGenerated, AppId, RequestMethod, RequestUri, ResponseStatusCode, IPAddress, UserAgent
| order by TimeGenerated asc
```

The results showed the whole sequence:

- `GET .../roleManagement/directory/roleDefinitions?...Directory Readers` → **200**
- `POST .../roleManagement/directory/roleAssignments` → **201** (role created)
- `POST .../applications/<id>/addPassword` → **403** (my app-only attempt to add a credential, denied)

![MicrosoftGraphActivityLogs showing the role lookup (200), the role assignment (201) and the denied addPassword call (403)](/assets/images/sp-hunting/graph-activity.png)

Two things stand out. First, the status codes tell the story by themselves: look up a role, create the assignment, try to plant a credential. You can read the intent without any threat intel. Second, the 403 is *recorded*. Graph activity logs keep failed attempts too, while the audit log below only shows what succeeded. Together they show what the attacker tried and what they got.

The `UserAgent` here was `python-requests`. On its own that's weak, since plenty of legitimate automation uses it. But the app, the operation and the user agent together are a real signal. Huntress made the same point about the real incident: no single field identifies the attacker, but the combination does.

### 3. The detection that doesn't need an IOC

This is the one I'd actually deploy. It needs no known-bad IP and no app ID. It looks for the behavior itself: **a service principal that grants itself a role or adds a credential to an application.** Legitimate automation does this now and then. A compromised app does it right after getting in.

```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName startswith "Add member to role"
    or OperationName startswith "Update application"
    or OperationName == "Add service principal credentials"
| extend ActorApp  = tostring(InitiatedBy.app.displayName)
| extend ActorSpn  = tostring(InitiatedBy.app.servicePrincipalId)
| extend ActorUser = tostring(InitiatedBy.user.userPrincipalName)
| extend Target    = tostring(TargetResources[0].displayName)
| where isnotempty(ActorApp)     // the change was made BY an app, not a person
| project TimeGenerated, OperationName, ActorApp, ActorSpn, Target, Result
```

![AuditLogs results: the two role assignment events show VictimApp-SPLab in ActorApp, while the credential changes show a user in ActorUser](/assets/images/sp-hunting/auditlogs-actor.png)

*The screenshot is the same query without the `isnotempty(ActorApp)` line, so you can see app-initiated and user-initiated rows side by side.*

Three things I learned writing this against real data:

- **`InitiatedBy.app` vs `InitiatedBy.user` is the field that matters.** When a service principal makes the change, `ActorApp` is populated and there's no user. That's the fingerprint of "an app gave itself a role." My step-2 events showed `VictimApp-SPLab` as `ActorApp` with the user field empty, which is exactly what you want to catch. My step-3 credential add showed a *user*, because I ran it as myself, so the `isnotempty(ActorApp)` filter correctly leaves it out. That filter is the detection: it isolates app-initiated changes and ignores the admin ones.
- **One action produces several audit events, and the operation names vary.** Assigning the role generated both `Add member to role` *and* `Add member to role outside of PIM (permanent)`. Adding a secret generated both `Update application` *and* `Update application – Certificates and secrets management`. If you match operation names exactly with an `in (...)` list, you'll miss the variants. Use `startswith` or `has`. I only found this by looking at what actually landed in the table.
- **Two logs, not one.** The audit log doesn't record the source IP of app-only actions, and it doesn't record what the app *read*. So detection 3 (what changed) and detection 2 (what the app did over Graph, including reads and failures) only tell the full story together.

---

## False positives

Detection 3 can also fire on legitimate things, like CI/CD pipelines, infrastructure-as-code and secret rotation tools. That's not a reason to drop it. It just means you need to know your environment. In practice that means keeping an allowlist of the service principals that are *supposed* to assign roles or manage credentials, and looking at everything else. You build that list once by running the rule over a quiet window and asking "should this app be doing that?" for each hit.

---

## Response

Response here is different from a normal account compromise, for the reasons above: password resets and Conditional Access don't help, because there's no user and the app skips those controls. So the response is:

- **Disable the service principal, but don't delete it.** Deleting loses the consent records and the evidence. Disabling stops the access.
- **Audit the app's credentials and remove any secret or certificate you didn't add.** Disabling the app does not remove credentials already planted on it, and a planted secret on *another* app is a separate way back in.
- **Then rotate anything the app could reach.**

This is a good fit for a Sentinel playbook. On a confirmed hit from detection 3, it would pull the recent sign-in and Graph activity for that service principal into the incident, list the app's credentials so a responder can spot anything unexpected, and then, after an approval step, disable the service principal. The approval step matters, so nothing gets disabled automatically. I haven't built mine yet. That's the next piece of this lab.

---

## Wrapping up

The main thing I took from this: for app abuse like this, the indicators were the weakest part of the picture. The IP changed, the user agents are common, and the app IDs belong to legitimate apps. What held up in my lab was the behavior. An app that gives itself a role, or adds a credential to an application, is rare enough in most tenants to be worth a look every time, and that rule needs no threat intel to fire.

The other thing was visibility. Two of the three logs I used, `AADServicePrincipalSignInLogs` and `MicrosoftGraphActivityLogs`, only exist if someone turns on the diagnostic settings for them, and they need an Entra ID P1 or P2 license. Without them, you'd see the role change in the audit log and very little of what led up to it.

---

## References

- [Microsoft Security Blog: AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/)
- [Huntress: ConnectWise (SkyKick) Vendor Credentials Abused in M365 Attacks](https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access)
- [Microsoft Learn: AADServicePrincipalSignInLogs table](https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs)
- [Microsoft Learn: MicrosoftGraphActivityLogs table](https://learn.microsoft.com/azure/azure-monitor/reference/tables/microsoftgraphactivitylogs)
