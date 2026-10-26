# NightEagle (APT-Q-95) — Threat Actor Profile

Oct 26, 2026 · @Jessie Parker

*Classification: TLP:CLEAR — compiled from open-source intelligence for portfolio and training use.*

## Executive Summary

NightEagle (APT-Q-95) is a stealthy, espionage-focused threat actor first disclosed publicly by QiAnXin's RedDrip team in July 2025. It is notable for the opposite reason to most commodity actors: it operates quietly against high-value targets using a zero-day in Microsoft Exchange, memory-resident implants, and carefully rotated infrastructure, with the explicit goal of long-term intelligence collection rather than financial gain.

The group has targeted Chinese government, defense, and advanced-technology organizations — semiconductors, quantum computing, artificial intelligence and military research — and, as of 2026 reporting from Kaspersky, has expanded operations against organizations in Russia. Its tradecraft centers on compromising Exchange servers to steal mailbox data, loading a .NET trojan into the IIS worker process, and tunneling into internal networks with a source-modified build of the open-source Chisel tool.

For a red or purple team, NightEagle is a valuable counterpoint to commodity actors like Blind Eagle. Its chain is harder to reproduce — the initial access is a server-side deserialization zero-day — but the post-exploitation behavior (in-memory .NET execution, IIS/Exchange abuse, Chisel tunneling over 443, and Active Directory privilege escalation toward domain controllers) maps cleanly onto ATT&CK and is well suited to emulation in a GOAD-style Active Directory lab. This profile covers attribution, targeting, the full attack lifecycle, tooling, a timeline, an emulation playbook, and detection opportunities.

**Attribution note:** QiAnXin assessed, primarily from the actor's 9 p.m.–6 a.m. Beijing working hours, that NightEagle is "likely" a North American operator. This is a working-hours-based assessment, not a confirmed attribution, and should be treated with appropriate caution throughout.

## Group Overview & Attribution

NightEagle was named by QiAnXin's RedDrip team, which says the group "has the speed of an eagle and has been operating at night in China." It is tracked as APT-Q-95 under QiAnXin's designation scheme. The group is assessed to have been active since at least 2023, and the investigation reportedly began when RedDrip found a bespoke Chisel binary on a customer endpoint.

| Attribute | Assessment |
| --- | --- |
| Aliases | NightEagle, APT-Q-95 |
| First public disclosure | July 2025 (QiAnXin RedDrip, CYDES 2025) |
| Active since | At least 2023 |
| Suspected origin | North America (low-to-moderate confidence) |
| Primary motivation | Espionage / intelligence collection |
| Sophistication | High — zero-day use, memory-resident implants, fast infrastructure rotation |

The attribution rests mainly on operational timing. QiAnXin observed that NightEagle's activity consistently fell between 9 p.m. and 6 a.m. Beijing time, a window that corresponds to daytime hours in North America, and on that basis assessed the actor as "likely" North American. Working-hours analysis is a weak single indicator — it can be deliberately manipulated, and it does not survive on its own — so this profile treats the geographic attribution as a hypothesis rather than an established fact. QiAnXin characterized the group as "fast, accurate, and ruthless," and noted it rotates network infrastructure at an extremely fast rate, which complicates infrastructure-based tracking.

In September 2026, Kaspersky reported NightEagle activity against Russian organizations, extending the group's known victimology beyond China and lending a second independent vendor to the body of public reporting. Microsoft, responding to the original QiAnXin disclosure, said it had "not identified any new actionable vulnerabilities to date" and that its investigation was ongoing.

## Targeting & Victimology

NightEagle's target set is narrow and high-value, consistent with a state-aligned espionage mission rather than opportunistic crime. QiAnXin's reporting placed the group's early operations squarely against Chinese organizations in government, defense, and advanced technology.

The technology targeting is specific and strategically coherent: high-tech manufacturing, chip and semiconductor firms, quantum technology, artificial intelligence, and the military. These are precisely the sectors where intelligence collection yields durable national-security and economic advantage, which fits a group whose stated objective is long-term mailbox access and data theft.

The 2026 Kaspersky reporting marks the most significant shift in known victimology: NightEagle activity against organizations in Russia. Kaspersky did not publicly name the affected companies or quantify the campaign, but the expansion is notable because it broadens the group's geographic focus beyond China and Asia for the first time in public reporting.

The operational takeaway: NightEagle selects few, high-value targets and invests in quiet, persistent access to their email and internal networks. For defenders, that means the relevant detection surface is the Exchange/IIS tier and internal lateral movement — not the mass-phishing funnel that dominates commodity-actor detection.

## Attack Lifecycle

NightEagle's chain is server-centric: it begins at an internet-facing Exchange server rather than a user's inbox, and most of the tradecraft lives in memory on that server and in the internal network behind it. The stages below are mapped to MITRE ATT&CK.

&#91;embedded content: NightEagle attack chain · 6 server-centric stages\]

1. **Initial Access — Exchange exploitation (T1190).** QiAnXin reported NightEagle exploiting a zero-day in Microsoft Exchange Server. The flaw allowed the attacker to obtain the server's `machineKey`, the cryptographic key ASP.NET uses to sign and encrypt state. In the 2026 Russian activity, Kaspersky additionally reported initial access via stolen credentials over corporate VPNs (T1078 / T1133).
2. **Exploitation of trust — ViewState deserialization (T1059 / T1505.003).** With the `machineKey` in hand, the attacker can forge a validly signed, malicious `__VIEWSTATE` payload that the server deserializes and executes. This turns a stolen key into reliable remote code execution on any server of the matching Exchange version, and it is what lets the group "remotely read the mailbox data of any person" on the server.
3. **Implantation — .NET loader in IIS (T1505.004 / T1620).** The group implants a .NET trojan into the IIS service that fronts Exchange, establishing a web-server-resident foothold that survives alongside legitimate Exchange traffic. Kaspersky's 2026 reporting describes the GhostContainer backdoor being loaded into server memory, consistent with in-memory, fileless operation that minimizes disk artifacts.
4. **Command & Control — modified Chisel tunnel (T1572 / T1090).** NightEagle deploys a source-modified build of the open-source Go tool Chisel. Execution parameters and the username/password are hard-coded into the binary; it opens a SOCKS connection to port 443 on the C2 and maps it back to a chosen port, giving the operator a tunnel into the internal network. A scheduled task relaunches it every four hours (T1053.005).
5. **Privilege Escalation & Lateral Movement (T1068 / T1021 / T1003).** In the Russian intrusions, Kaspersky reported NightEagle abusing Active Directory weaknesses to escalate privileges, move laterally, and attempt to compromise domain controllers — the classic path from a single server foothold to domain-wide control.
6. **Collection & Exfiltration (T1114 / T1041).** The group's core objective is mailbox data. With server-level access and tunneled connectivity, collected email and internal data are exfiltrated over the established C2 channel.

Throughout, NightEagle rotates C2 infrastructure quickly and favors memory-resident components, which is what makes network and host detection difficult and pushes defenders toward behavioral and server-tier telemetry.

## Malware & Tooling

NightEagle's toolset reflects its priorities: stay off disk, blend into the Exchange/IIS environment, and keep a reliable tunnel into the internal network. Unlike commodity actors, it does not lean on off-the-shelf RATs; its components are either custom or source-modified open-source tools tailored to the intrusion.

| Tool / component | Type | Role in the chain |
| --- | --- | --- |
| Exchange zero-day | Initial-access exploit | Yields the server `machineKey` for ViewState RCE |
| .NET IIS loader | Custom web-server implant | Runs in the IIS worker process; reads mailbox data |
| GhostContainer | In-memory Exchange backdoor | Remote control, security/log evasion, traffic redirection (Kaspersky, 2026) |
| Modified Chisel | Source-modified Go tunneler | Hard-coded creds; SOCKS to C2:443; relaunched every 4h |
| GitHub-hosted archives | Staging / disguise | Tools stored under names mimicking AdobeSync, TrueConf (Kaspersky, 2026) |

Two tradecraft points are worth drawing out. First, the reliance on the Exchange `machineKey` is the linchpin: once the key is stolen, the attacker can forge signed ViewState payloads indefinitely, which is why key rotation is a core mitigation (below). Second, the Chisel modifications — hard-coding execution parameters and credentials directly into the binary and scheduling it to relaunch every four hours — trade operational flexibility for resilience and a smaller runtime footprint, and the four-hour cadence is itself a hunting opportunity.

The GhostContainer backdoor reported by Kaspersky in 2026 extends the in-memory theme: loaded into server memory rather than dropped to disk, it provides remote control while actively evading Windows security tooling and logging and redirecting network traffic — a design clearly built to frustrate both host EDR and network inspection.

## Notable Campaigns

Public reporting on NightEagle is younger and thinner than on long-tracked commodity actors, but the two vendor disclosures bracket a clear evolution from China-focused espionage to broader geographic activity.

| Period | Report / activity | Notable point |
| --- | --- | --- |
| Since 2023 | Earliest assessed activity | Operations against Chinese targets predate public disclosure |
| Jul 2025 | QiAnXin RedDrip, CYDES 2025 | First public exposure; Exchange zero-day, IIS .NET loader, modified Chisel |
| Jul 2025 | Microsoft response | "No new actionable vulnerabilities identified to date"; investigation ongoing |
| Sep 2026 | Kaspersky | Expansion into Russia; GhostContainer backdoor; VPN-credential access; AD abuse |

The throughline is a consistent operating model — compromise an internet-facing Exchange/IIS tier, operate in memory, tunnel inward, and escalate through Active Directory — applied first to Chinese technology and defense targets and later to Russian organizations. The shift from a single-vendor Chinese disclosure to corroborating Kaspersky reporting a year later is what gives the group a credible, current evidentiary base rather than a one-source story.

## Adversary Emulation Playbook (Red Team)

This section outlines how to reproduce NightEagle's post-exploitation behavior in a contained lab for an assumed-breach / purple-team exercise — not operational guidance. Because the group's initial access is a server-side Exchange zero-day, do not attempt to reproduce the exploit itself; instead, start from an assumed-compromise position on a lab Exchange/IIS host and exercise the downstream chain. Run everything against isolated VMs you own (a GOAD-style Active Directory range with a member Exchange/IIS host works well), use benign stand-in payloads, and keep C2 internal.

1. **Assume-breach on Exchange/IIS (T1190 — simulated).** Begin with a foothold already placed on a lab IIS host. The objective is to validate detection of the downstream behavior, so no real Exchange exploit is needed.
2. **ViewState abuse in the lab (T1505.003).** Using a `machineKey` you control on your own test server, generate a signed ViewState payload (for example with the public `ysoserial.net` tooling) to exercise your detections for anomalous deserialization and `w3wp.exe` child processes. Never run this against systems you do not own.
3. **In-memory .NET execution (T1620).** Load a benign .NET assembly reflectively inside the IIS worker process to produce the telemetry a memory-resident loader would, and confirm your EDR surfaces it.
4. **Chisel tunneling (T1572 / T1090).** Stand up an internal Chisel client/server pair beaconing SOCKS over 443 to a lab-internal C2, and schedule the client to relaunch every four hours. This validates detection of long-lived tunnels and the periodic scheduled-task cadence.
5. **Scheduled-task persistence (T1053.005).** Register the four-hour relaunch task and confirm it appears in your task-creation telemetry.
6. **AD privilege escalation & lateral movement (T1068 / T1021 / T1003).** From the server foothold, run a standard assumed-breach path toward the domain controller — credential harvesting, Kerberos abuse, lateral movement — using tooling you already exercise in your GOAD lab, and tune detections for the server-to-DC pivot.

Mapping note: steps 4–6 overlap heavily with Active Directory attack chains you can already run in a GOAD/Sysmon/Wazuh range, so the same lab can host both the emulation and the detection-engineering work in the next section. The distinctive additions here are the Exchange/IIS entry tier and the Chisel tunnel.

## Detection & Hunting Opportunities (Purple / Blue)

NightEagle's reliance on memory-resident implants and legitimate services means static indicators are of limited value; the strongest detections target server-tier behavior and the tunnel. The table maps each stage to a practical detection for an Exchange/IIS plus Sysmon/Wazuh (or any SIEM/EDR) stack.

| Technique | Signal to hunt | Primary data source |
| --- | --- | --- |
| ViewState deserialization (T1505.003) | `w3wp.exe` spawning cmd/powershell; ViewState validation errors in event logs | Sysmon 1, IIS logs, Windows App log |
| In-memory .NET loader (T1620) | CLR loaded into `w3wp.exe` unexpectedly; reflective assembly loads | Sysmon 7 (image load), EDR AMSI/CLR telemetry |
| machineKey theft / reuse (T1552) | Access to `web.config` / machineKey; ViewState signed by an unexpected key | File-access auditing, IIS config monitoring |
| Chisel tunnel (T1572 / T1090) | Long-lived SOCKS over 443 from a server; JA3/SNI anomalies; constant beacon | Network / proxy logs, Zeek, firewall |
| 4-hour scheduled task (T1053.005) | Task creation relaunching a binary on a fixed 4h interval | Sysmon 1, Event ID 4698 |
| AD escalation to DC (T1003 / T1021) | Server host authenticating to the domain controller; LSASS access; DCSync | Sysmon 10, Windows Security 4624/4662 |

Two high-value hunts come straight from the kill chain. The first is a web server tier process anomaly: `w3wp.exe` (the IIS worker) almost never spawns a command shell or PowerShell in normal operation, so that parent/child pairing on an Exchange host is a reliable, low-noise anchor. The second is the tunnel cadence — a server making a persistent outbound SOCKS connection on 443, re-established on a fixed four-hour schedule, is highly abnormal for a mail server.

An illustrative Sysmon/Sigma-style rule for the IIS anchor:

```yaml
title: IIS Worker Spawning a Command Shell
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\w3wp.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
  condition: selection
level: high
```

Layer in config-integrity monitoring on the Exchange `machineKey` and alerting on ViewState validation failures, and ingest the whole set into Wazuh so the server-tier and AD detections correlate; the GOAD/Exchange lab in the previous section produces the exact telemetry to tune the thresholds before the rules reach production.

## ATT&CK Technique Matrix

Consolidated mapping of the techniques referenced above, grouped by tactic. Mappings are compiled from QiAnXin and Kaspersky reporting and are representative rather than exhaustive.

| Tactic | Technique (ID) | How NightEagle uses it |
| --- | --- | --- |
| Initial Access | Exploit Public-Facing Application (T1190) | Zero-day against Microsoft Exchange |
| Initial Access | External Remote Services (T1133) | VPN access in the 2026 Russian activity |
| Initial Access | Valid Accounts (T1078) | Stolen credentials over corporate VPN |
| Execution | Command & Scripting Interpreter (T1059) | Code execution via forged ViewState |
| Persistence | Server Software Component: Web Shell (T1505.003) | ViewState deserialization on IIS/Exchange |
| Persistence | IIS Components (T1505.004) | .NET loader implanted into the IIS service |
| Persistence | Scheduled Task (T1053.005) | Relaunches the Chisel tunnel every 4 hours |
| Defense Evasion | Reflective Code Loading (T1620) | In-memory .NET / GhostContainer execution |
| Defense Evasion | Impair Defenses / Indicator Removal | GhostContainer evades Windows security and logging |
| Credential Access | Unsecured Credentials (T1552) | Theft and reuse of the Exchange machineKey |
| Credential Access | OS Credential Dumping (T1003) | Credential theft during AD escalation |
| Privilege Escalation | Exploitation for Priv-Esc (T1068) | Abuse of Active Directory weaknesses |
| Lateral Movement | Remote Services (T1021) | Movement toward domain controllers |
| Command & Control | Protocol Tunneling (T1572) | Modified Chisel SOCKS tunnel |
| Command & Control | Proxy (T1090) | Internal proxying via Chisel |
| Collection | Email Collection (T1114) | Reads mailbox data from Exchange |
| Exfiltration | Exfil Over C2 Channel (T1041) | Data returned over the tunnel |

## Assessment, Mitigations & References

**Outlook.** NightEagle is a capable, patient espionage actor that is likely to continue operating against high-value technology, defense and government targets, and the 2026 expansion into Russia suggests a widening rather than narrowing aperture. Its reliance on Exchange/IIS compromise, in-memory implants and fast infrastructure rotation makes it a persistent detection challenge, and its geographic attribution remains an open, contested question.

**Prioritized mitigations.**

1. Patch Exchange promptly and keep internet-facing Exchange/OWA exposure to a minimum; consider fronting it with additional authentication.
2. Rotate the Exchange `machineKey` and monitor `web.config` integrity; a stolen key enables indefinite ViewState RCE until rotated.
3. Alert on IIS worker (`w3wp.exe`) processes spawning shells or PowerShell, and on unexpected CLR/assembly loads in the worker.
4. Enforce phishing-resistant MFA on all VPN and remote-access paths; NightEagle used stolen VPN credentials in 2026.
5. Hunt for long-lived outbound SOCKS tunnels on 443 from server assets and for scheduled tasks relaunching binaries on fixed intervals.
6. Tighten Active Directory hygiene — tiered admin, LSASS protection, and DC authentication monitoring — to break the server-to-domain-controller path.

**References.**

1. The Hacker News — [NightEagle APT Exploits Microsoft Exchange Flaw](https://thehackernews.com/2025/07/nighteagle-apt-exploits-microsoft.html) (July 2025)
2. The Record — [Hacking group NightEagle expands from China to Russia](https://therecord.media/hacking-group-nighteagle-expands-russia-china) (September 2026)
3. Kaspersky — [Kaspersky identifies NightEagle campaign targeting organizations in Russia](https://www.kaspersky.com/about/press-releases/kaspersky-identifies-nighteagle-campaign-targeting-organizations-in-russia) (September 2026)
4. Dark Reading — [North American APT Uses Exchange Zero-Day Against China](https://www.darkreading.com/cyberattacks-data-breaches/north-american-apt-exchange-zero-day-attacks-china) (July 2025)
5. Cyber Security News — [NightEagle APT Exploiting 0-Days](https://cybersecuritynews.com/nighteagle-apt-exploiting-0-days/) (2025)

*Prepared as an open-source intelligence portfolio piece. All indicators and techniques are drawn from the public vendor reporting cited above. The North American attribution is a working-hours-based assessment from QiAnXin, not a confirmed finding.*
