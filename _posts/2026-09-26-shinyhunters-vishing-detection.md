---
layout: post
title: "Detecting the ShinyHunters Vishing Attack Chain in Microsoft Sentinel"
date: 2026-09-26
tags: [BSidesEdmonton2026, ShinyHunters, vishing, identity, SaaS, Microsoft Sentinel, KQL, incident response]
excerpt: "How the 2026 ShinyHunters vishing campaign went from one phone call to SaaS data theft, and four Microsoft Sentinel detections, with KQL, to catch it."
---

## 0. Introduction

This post is based on the BSides Edmonton 2026 talk *Advanced SaaS Threats: Case Studies from the Field* by [Damien Miller-McAndrews](https://www.linkedin.com/in/damien-miller-mcandrews/), a threat researcher at Obsidian Security. He walked through three real cases to make one point: many SaaS breaches today use no exploits and no malware. Attackers simply abuse legitimate features and identity trust.

The talk focused on how the attacks worked and what a vendor saw. This post adds the other half: **how to detect and respond to this kind of attack in Microsoft Sentinel.** The talk covered three cases. This post covers the first one: the voice phishing (vishing) campaign run by ShinyHunters in 2026.

> **Disclaimer**
>
> - The views in this post are my own and do not represent my employer.
> - All incident details come from public sources, which are linked in the text. I am not affiliated with Obsidian Security.
> - The KQL queries were tested in a personal lab. Adjust and validate them for your own environment before using them in production.

---

## 1. Background

### Who is ShinyHunters

ShinyHunters is a cybercrime group focused on data theft and extortion. It has been active since around 2019. Its usual model is "pay or we leak": steal data, demand a ransom, and publish the data on a leak site if the victim does not pay. The group has been linked to several large breaches, including the 2024 campaign that used stolen credentials to pull data from Snowflake customers. In the last two years it has shifted toward SaaS: instead of attacking servers, it tricks employees into handing over their identity, then exports data straight out of SaaS apps ([Huntress](https://www.huntress.com/threat-library/threat-actors/shinyhunters)).

In this campaign it used a **real-time phishing panel**, a phishing tool that lets the attacker control the victim's page live from a back end ([Push Security](https://pushsecurity.com/blog/inside-criminal-phishing-panel)). These panels are shared or sold in criminal circles and are not unique to ShinyHunters. Section 2 explains how they work.

### The 2026 vishing campaign

Starting in early 2026, several security firms reported a wave of vishing attacks against SSO accounts. ShinyHunters claimed responsibility and began naming victims on its leak site ([CyberScoop](https://cyberscoop.com/shinyhunters-voice-phishing-sso-okta-mfa-bypass-data-theft/)). One public case is **ADT**: in April 2026, attackers obtained an employee's Okta SSO credentials, got into Salesforce, and exported customer data. ShinyHunters claimed to have stolen more than 10 million records ([Rescana](https://www.rescana.com/post/adt-salesforce-data-breach-2026-shinyhunters-compromise-okta-sso-via-vishing-attack)).

This post is based on three incidents that Obsidian disclosed anonymously in a [public blog post](https://www.obsidiansecurity.com/blog/behind-the-breach-shinyhunters-2026-voice-phishing-campaign) (all part of the same campaign), plus the original BSides Edmonton talk.

---

## 2. How the attack works

### The big picture

An employee gets a call from someone claiming to be from the company's IT department. The caller says there is a problem with the account and it needs to be re-verified right away, then reads out a URL that looks a lot like the company login page. The employee opens it, enters their password, and types in the verification code when the caller asks for it. It feels like a routine check. In reality, the attacker on the other end of the line is using everything the employee enters to log in to the real Okta, live. Once logged in, the attacker immediately registers their own MFA device on the account. From that point on, the attacker can keep logging in even after the employee hangs up or changes their password. Next, the attacker opens the SSO portal, clicks through every app the account can reach, finds valuable data, and starts downloading it in bulk. Along the way, they leave the company's Slack security channel to avoid catching the security team's attention.

### ① Initial access: vishing + real-time phishing tools

Two kinds of phishing tools are common in this type of attack, and they affect detection differently:

- **AitM (Adversary-in-the-Middle) reverse proxy**: the phishing site automatically forwards the employee's input to the real login page, then steals the session cookie issued after a successful login and uses it somewhere else. The same session shows up from two locations, which can be detected.
- **Real-time operator panel**: there is no automatic proxy. The attacker works the panel by hand and logs in from their own machine; the employee only supplies the password and MFA. In Push Security's words, it is functionally the same as AitM, except that each step is done manually by the attacker. The logs show a single login that "looks normal", which makes it harder to detect.

In this campaign, ShinyHunters used a real-time operator panel ([Push Security](https://pushsecurity.com/blog/inside-criminal-phishing-panel)). According to the talk, both kinds of tools showed up in the incidents Obsidian handled.

**Log evidence:** Obsidian saw an authentication sequence that lasted about 10 minutes, with repeated failures before a final success. Public sources do not explain why the failures happen, but the way the panel works suggests an answer: the login is relayed by a human, so typos, expired codes, and push timeouts all cause failures. The panel also has an "incorrect password" button that lets the attacker make the employee type the password again.

### ② Persistence: registering the attacker's own MFA device

Right after logging in, the attacker registers a new MFA device on the account. This turns "needs the employee's help" into "can act alone". **This is the key step in the whole chain.**

**Log evidence:** in Obsidian's incidents, the new device was named "Passkey", and the User-Agent contained `Genymobile` (an Android emulator), which shows the device was not a real phone.

### ③ Discovery: mapping access through the SSO portal

The attacker opens the SSO portal and clicks through the apps the account can reach, to see which systems are available.

**Log evidence:** an unusually high number of SSO apps accessed in a short time.

### ④ Exfiltration: bulk downloads

In one of Obsidian's incidents, the attacker downloaded a large number of files from Google Drive over about 90 minutes. In another, the attacker downloaded several files from Slack within seconds of each other, which points to a script rather than a person.

### ⑤ Defense evasion: leaving the security channel

In one incident, the compromised account left the company's Slack security channel and rejoined a few minutes later, probably to lower the chance of being noticed.

---

## 3. Detection approach and KQL

The hardest part of this attack is that **each step, on its own, looks like normal activity.** Employees mistype passwords, switch phones and register new MFA, and sometimes open many apps or download many files in a day. Obsidian's post makes the same point: each of these activities is a low-confidence signal on its own, and the account takeover only becomes clear when you correlate them at the identity layer.

So the core idea is: **catch the actions that follow each other in the attack chain and link them by user and time.** Of the four detection points below, detection points 1 and 2 cover initial access and persistence (steps ① and ②), one for each tool type: the real-time panel and AitM. Detection points 3 and 4 cover discovery and exfiltration after login (steps ③ and ④) and apply to both tool types.

The queries use **Microsoft Entra ID** logs (`SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`) and Microsoft 365 logs (`OfficeActivity`). The victims in the original incidents used Okta. If your IdP is Okta, the logic is the same, but you need to switch to the tables and fields from the Okta connector. All thresholds are starting points; tune them to your own baseline.

### Detection point 1: MFA registration right after an abnormal login (real-time panel)

**Idea:** employees normally register a new MFA method when they join the company or change phones, and that usually isn't preceded by a string of password failures. The pattern "several failures → success → new MFA registered within 30 minutes" is rare in normal business. This pattern is left by the manual relay of the real-time panel and does not apply to AitM.

**KQL:** `ResultType` only counts wrong passwords (50126) and failed MFA (500121). A normal Entra sign-in also produces some non-zero interim codes, so counting every non-zero code as a failure would create a lot of false positives.

```kql
let lookback = 1d;
let SuspiciousLogins = SigninLogs
| where TimeGenerated > ago(lookback)
| summarize
    Failures = countif(ResultType in ("50126", "500121")),
    Successes = countif(ResultType == "0"),
    LastSuccess = maxif(TimeGenerated, ResultType == "0")
    by UserPrincipalName = tolower(UserPrincipalName), IPAddress, bin(TimeGenerated, 15m)
| where Failures >= 2 and Successes >= 1;
AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName in ("User registered security info", "User registered all required security info")
| extend UserPrincipalName = tolower(coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(TargetResources[0].userPrincipalName)))
| extend MfaTime = TimeGenerated
| join kind=inner SuspiciousLogins on UserPrincipalName
| where MfaTime between (LastSuccess .. LastSuccess + 30m)
| project MfaTime, UserPrincipalName, OperationName, LoginIP = IPAddress, Failures, Successes, LastSuccess
```

**Extra indicators:** an MFA device registered from an Android emulator (User-Agent containing `Genymobile` or `VirtualBox`) and a device named "Passkey" are both high-fidelity signs. If you use Okta, you can search for them directly in the Okta logs. But attackers can change tools and names at any time, and Obsidian's third incident showed no clear emulator traces, so treat them as supporting evidence only.

### Detection point 2: the same session from multiple IPs / countries (AitM)

**Idea:** AitM steals the session cookie issued after login, and the attacker uses it on their own machine. As a result, the same `SessionId` shows up in two places: the IP of the phishing proxy and the attacker's own IP. A real-time panel does not leave this trace, because the attacker uses their own session from start to finish, which is also why the panel is harder to detect. After a cookie is replayed, most follow-up requests are logged as non-interactive sign-ins, so you need to query `AADNonInteractiveUserSignInLogs` too. Querying only `SigninLogs` will miss them.

```kql
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0" and isnotempty(SessionId)
| extend Country = tostring(parse_json(tostring(LocationDetails)).countryOrRegion)
| summarize
    IPs = dcount(IPAddress),
    Countries = dcount(Country),
    IPList = make_set(IPAddress, 10),
    CountryList = make_set(Country, 10),
    Apps = make_set(AppDisplayName, 10),
    First = min(TimeGenerated),
    Last = max(TimeGenerated)
    by SessionId, UserPrincipalName
| where IPs > 1 and Countries > 1
```

**Built-in detections:** Entra ID Protection and Defender XDR already include detections for AitM and token replay. If you have the licenses, use the built-in ones first. This query is mainly here to show how the detection works.

### Detection point 3: many SSO apps accessed in a short time

**Idea:** this detection point rests on an assumption: **once attackers have an identity, they will quickly find out which systems it can reach.** Normal employees use a fairly fixed set of apps each day. An account that opens eight or nine apps one after another within half an hour looks more like someone mapping out access.

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| summarize
    Apps = dcount(AppDisplayName),
    AppList = make_set(AppDisplayName, 50),
    Start = min(TimeGenerated),
    End = max(TimeGenerated)
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 30m)
| where Apps >= 8
```

**False positives:** new hires on their first day, and IT admins testing. You can add these accounts to an exclusion list. On its own this detection is low confidence; it is most useful when it fires together with detection point 1 or 2.

### Detection point 4: bulk downloads soon after MFA registration

**Idea:** this detection point also rests on an assumption: **attackers will grab the data as fast as they can before they are caught.** Download volume alone is noisy, and by the time it fires the data is often already gone. But if the bulk download happens on an account that "just registered a new MFA method", the signal is much stronger.

```kql
let MfaReg = AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in ("User registered security info", "User registered all required security info")
| extend UserPrincipalName = tolower(coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(TargetResources[0].userPrincipalName)))
| project MfaTime = TimeGenerated, UserPrincipalName;
OfficeActivity
| where TimeGenerated > ago(1d)
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| extend UserPrincipalName = tolower(UserId)
| join kind=inner MfaReg on UserPrincipalName
| where TimeGenerated between (MfaTime .. MfaTime + 4h)
| summarize
    Files = count(),
    Sites = make_set(Site_Url, 10),
    FirstDownload = min(TimeGenerated)
    by UserPrincipalName, MfaTime, ClientIP
| where Files >= 100
```

**Coverage:** this query only covers OneDrive / SharePoint. To cover downloads from Google Drive, Slack, or Salesforce, you need to bring each app's logs into Sentinel.

---

## 4. Response and automation

### Response process

Four steps: triage → containment → scoping → hardening.

**Step 1: Triage.** Use the detection points that fired to judge confidence and decide the next step:

| Confidence | What fired | Next step |
|---|---|---|
| Low | Only detection point 3 or 4 | First check for a normal business reason (new hire, IT staff, etc.). Contact the user only if you can't rule it out |
| Medium | Detection point 1 or 2 | Contact the user right away to confirm |
| High | Detection point 1 or 2, plus 3 or 4 | Go straight to containment and confirm with the user afterwards |

When confirming, reach the user **out of band** (for example by phone, not through their company account), because the attacker may be using that account. Ask only two questions: Did you recently get a call from "IT"? Is the newly registered MFA device yours? If either answer is wrong, treat the account as compromised.

**Step 2: Containment.**

1. **Revoke all sign-in sessions** ("Revoke sessions" on the user's page in Entra ID) so the attacker's active sessions stop working right away.
2. **Delete the MFA methods and devices the attacker registered.** Changing the password alone is not enough. The attacker's MFA device is still there, and with self-service password reset they can get back in.
3. Reset the password. If you can't quickly tell which MFA methods belong to the user, disable the account first.

**Step 3: Scoping.** Through SSO the attacker can reach every connected app, so don't stop at Microsoft 365:

- Which SSO apps were accessed during the attack (the output of detection point 3 is your list)
- In each app: any downloads, exports, or new sharing links
- In the mailbox: any new forwarding or delete rules
- In Slack and other collaboration tools: any channel departures or bulk downloads

**Step 4: Hardening.** Treat "register MFA" as a sensitive action (for example, use Conditional Access to allow it only from the corporate network or managed devices), move toward phishing-resistant MFA (FIDO2 security keys, passkeys), and review how the service desk verifies identity before resetting passwords or MFA.

### Is automation needed?

In one of Obsidian's incidents, the attacker downloaded a large number of files from Google Drive in about 90 minutes. A typical manual response chain looks like this: L1 analyst reviews the alert → escalates to L2 → contacts the client → client approves → action is taken. That chain often takes hours. **No matter how fast the detection is, if the response can't keep up, the data still leaves.** This was a recurring point in the talk: detection is not enough; what matters is cutting containment time. So it makes sense to set up some automated playbooks. But not every action should run automatically. The deciding factor is **how much the action affects the business and whether it can be undone if it's wrong**. The table below is a design idea, not a full implementation:

| Tier | Actions | Impact and reversibility |
|---|---|---|
| Fully automatic | Gather context: the user's recent MFA registrations, sign-in IPs and devices, apps accessed, download volume; notify the client and open a ticket | No business impact |
| Automatic with pre-authorization | Revoke sessions; mark the user as compromised in Entra ID Protection ("Confirm user compromised") | Low impact, reversible: a mistake only costs the user one extra sign-in |
| Manual approval | Delete MFA methods; disable the account | High impact: deleting the wrong device or disabling the account stops the employee from working, and a person has to decide which device belongs to the attacker |

Automatically revoking sessions has one easy-to-miss limit: **it only works at the IdP layer.** Access tokens already issued stay valid until they expire (except in apps that support CAE). And the apps the attacker reached through SSO, such as Salesforce, Slack, and Google Drive, each keep their own sessions. Revoking the IdP session does not kick the attacker out of them. So after the playbook revokes sessions, you still need to go through the app list from detection point 3 and end the user's session in each app.

The real challenge here is process, not technology: **pre-authorization has to be agreed with the client before an incident happens.**

---

## 5. Summary

- This attack does not rely on vulnerabilities. It relies on **tricking someone out of their identity**. SSO lets one identity reach every app, which also concentrates the attack surface on that one identity.
- Each step in the chain looks normal on its own. The key to detection is **linking the actions by user and time**, especially the "abnormal login → new MFA registration" sequence.
- The step most often missed during response is **deleting the MFA device the attacker registered**. Changing the password is not enough.
- Detection is about finding the attack; containment speed decides how much damage is done. Low-risk information gathering can be fully automated; high-impact response actions need pre-authorization agreed with the business in advance to move faster.

### Further discussion: what if the attacker changes tactics

All of the detection points above assume the attacker moves fast. What if they deliberately slow down?

- **No new MFA device:** detection points 1 and 4 stop working (both depend on MFA registration). If the attacker uses AitM, detection point 2 still works. But the attacker then depends entirely on the existing session. Once it expires or is revoked, they lose access and have to make another call, which raises their risk.
- **No rush to open other apps:** detection point 3 stops working.
- **No bulk downloads; small amounts over several days instead:** detection point 4 stops working.

Slowing down costs the attacker too: the longer it takes, the more likely the employee remembers the suspicious call and reports it, and the more likely the session expires. But it also shows that detections based on speed can always be bypassed to some degree. The more fundamental fix is on the prevention side: phishing-resistant MFA is bound to the website's domain, so even if a phishing site captures it, it can't be used.

### Accounts to prioritize

This is my own view: the end goal of this attack is data, so two groups of accounts deserve extra attention. One is employees with access to CRM and cloud storage (sales, customer support, and so on; ADT's data leaked from Salesforce). The other is admins and executives. You can put these accounts on a Sentinel watchlist and raise the alert severity when any of the detection points above fire for them.

---

## References

- Obsidian Security: [Behind the breach: ShinyHunters' 2026 voice phishing campaign](https://www.obsidiansecurity.com/blog/behind-the-breach-shinyhunters-2026-voice-phishing-campaign)
- Push Security: [Inside a phishing panel used by ShinyHunters and BlackFile](https://pushsecurity.com/blog/inside-criminal-phishing-panel)
- CyberScoop: [A new wave of 'vishing' attacks is breaking into SSO accounts in real time](https://cyberscoop.com/shinyhunters-voice-phishing-sso-okta-mfa-bypass-data-theft/)
- Rescana: [ADT Salesforce Data Breach 2026: ShinyHunters Compromise Okta SSO via Vishing Attack](https://www.rescana.com/post/adt-salesforce-data-breach-2026-shinyhunters-compromise-okta-sso-via-vishing-attack)
- The Hacker News: [Mandiant Finds ShinyHunters-Style Vishing Attacks Stealing MFA to Breach SaaS Platforms](https://thehackernews.com/2026/01/mandiant-finds-shinyhunters-using.html)
- Huntress: [ShinyHunters Threat Actor Profile](https://www.huntress.com/threat-library/threat-actors/shinyhunters)
