# Blind Eagle (APT-C-36) — Threat Actor Profile

**A red & purple team–oriented adversary profile**  ·  Oct 26, 2026  ·  Author: @Jessie Parker

*Classification: TLP:CLEAR — compiled from open-source intelligence for portfolio and training use.*

## Executive Summary

Blind Eagle (APT-C-36) is a Spanish-speaking threat group that has run continuous phishing-driven operations against Latin America since 2018, with a pronounced focus on Colombia. It is unusual among tracked "APT" actors in that its motivation is dual and often financial: the same group steals online-banking credentials in one campaign and conducts state-adjacent espionage in the next.

The group's tradecraft is deliberately simple and overwhelmingly effective. It leans on government- and bank-themed spearphishing, dynamic-DNS and URL-shortener infrastructure with geolocation filtering, custom intermediate loaders, and a rotating cast of commodity remote-access trojans (RATs) — AsyncRAT, Remcos, njRAT, Quasar, LimeRAT, BitRAT and others — delivered from legitimate platforms such as Google Drive, Bitbucket, GitHub and the Discord CDN.

For a red or purple team this makes Blind Eagle an ideal emulation target. Its chain is modular, built almost entirely from public tooling, and maps cleanly onto MITRE ATT&CK, so each stage can be reproduced in a lab and used to validate detections. This profile covers the group's attribution, targeting, full attack lifecycle, tooling, a timeline of notable campaigns, an emulation playbook, and concrete detection opportunities for a Sysmon/Wazuh-style stack.

## Group Overview & Attribution

Blind Eagle is tracked under several names across vendors: APT-C-36 (the designation that first appeared in Trend Micro and 360 reporting), AguilaCiega, TAG-144 (Recorded Future), and APT-Q-98 (QiAnXin). The group has been active since at least 2018 and is assessed to operate out of South America.

| Attribute | Assessment |
| --- | --- |
| Aliases | APT-C-36, AguilaCiega, TAG-144, APT-Q-98 |
| Active since | 2018 (continuous) |
| Suspected origin | South America / Spanish-speaking |
| Primary motivation | Financial (banking credential theft) and espionage |
| Sophistication | Low-to-moderate tradecraft, high operational tempo |

The strongest public attribution signal is temporal. In its 2025 reporting, Check Point found that commits to the group's payload-hosting GitHub repositories were consistently authored in the UTC-5 timezone, which aligns with several South American countries and matches the group's near-exclusive targeting of Colombian victims ([Check Point Research](https://research.checkpoint.com/2025/blind-eagle-and-justice-for-all/)).

Attribution is complicated by signs of collaboration or outsourcing. Kaspersky's GReAT observed a mid-2024 campaign whose artifacts used variable names and strings in Portuguese rather than the group's usual Spanish, and relied on Brazilian image-hosting sites — a possible indicator of third-party involvement ([Kaspersky GReAT](https://securelist.com/blindeagle-apt/113414/)). Recorded Future further resolved the activity into five distinct clusters under the TAG-144 label, each with overlapping but varied tradecraft, which is consistent with either a team-based operation or shared tooling across affiliated operators ([Recorded Future](https://assets.recordedfuture.com/insikt-report-pdfs/2025/cta-2025-0826.pdf)).

## Targeting & Victimology

Blind Eagle's defining operational trait is a narrow geographic focus. Where many financially motivated operations cast globally, Blind Eagle typically restricts a campaign to a single country and actively discards victims outside the target region using geolocation-aware URL shorteners ([Kaspersky GReAT](https://securelist.com/blindeagle-apt/113414/)). Colombia is the consistent center of gravity; Kaspersky attributed roughly 87% of victims in its observed May–June 2024 espionage campaigns to Colombian targets. Ecuador, Chile and Panama are recurring secondary targets.

Sector targeting spans government (including the judiciary, tax authority DIAN, and the Attorney General's office), banking and finance, energy and oil & gas, education, health, and telecommunications.

The group operates at genuinely high volume for a targeted actor. Check Point documented a single December 2024 campaign ("PARAISO") that infected more than 1,600 victims with Remcos RAT, with roughly 9,000 total infections across a week of related campaigns. A separate operational failure exposed a phishing dataset of over 8,000 stolen credential records — username, password, email and ATM PIN fields — harvested from a campaign impersonating Colombian banks ([Check Point Research](https://research.checkpoint.com/2025/blind-eagle-and-justice-for-all/)).

The takeaway for defenders and emulation planners: Blind Eagle pairs APT-style target selection with near-commodity scale, so its lures and infrastructure recur across campaigns and are highly reusable for detection testing.

## Attack Lifecycle

Blind Eagle's chain is consistent across campaigns: a themed phishing lure, a geofenced redirect, a scripted downloader, one or more custom intermediate loaders, in-memory injection into a trusted process, and a commodity RAT for collection and C2. The stages below are mapped to MITRE ATT&CK.

&#91;embedded content: Blind Eagle infection chain · 6 stages, geofenced gate\]

1. **Initial Access — Spearphishing (T1566.001 / T1566.002).** Emails impersonate Colombian government bodies (DIAN, the Attorney General, the Ministry of Foreign Affairs) or banks, carrying an urgent pretext such as an unpaid tax obligation or a court summons. They include a link and often an attached PDF or DOCX that repeats the same link.
2. **Delivery & Evasion — Geofencing and legitimate hosting (T1102 / T1608).** Links pass through URL shorteners that perform geolocation detection; a connection from outside the target country is redirected to the real impersonated site, so the malicious path is never exposed to analysts or sandboxes. Payloads are staged on Google Drive, Dropbox, Bitbucket, GitHub, Pastebin and the Discord CDN behind dynamic-DNS names.
3. **User Execution — Archive and .url lures (T1204.001 / T1204.002).** The dropper is usually a compressed archive, sometimes in obscure formats such as LHA or UUE to evade users and tooling. In the November 2024–2025 campaigns the group also weaponized malicious `.url` files that mimic the behavior of CVE-2024-43451, triggering a WebDAV/HTTP callback that both signals the victim's interaction and fetches the next stage ([Check Point Research](https://research.checkpoint.com/2025/blind-eagle-and-justice-for-all/)).
4. **Execution — Scripted downloaders (T1059.001 / T1059.005 / T1047).** Extracted contents are typically VBScript or PowerShell stagers using WScript/XMLHTTP to pull a second stage from a hardcoded server. Second-stage artifacts are frequently text, images (with payloads hidden via steganography, T1027.003) or .NET executables.
5. **Defense Evasion — Packing and process injection (T1027 / T1055.012 / T1140).** The group protects payloads with the HeartCrypt packer-as-a-service and NET-Reactor obfuscation, then uses process hollowing to run the final RAT inside a legitimate process — Check Point observed injection into `MSBuild.exe`, `InstallUtil.exe` and `csc.exe`.
6. **Execution via Sideloading — HijackLoader (T1574.002 / T1218).** A June 2024 variant delivered legitimately signed ASUS or IObit executables that sideload a malicious DLL, executing HijackLoader, which in turn injected AsyncRAT ([Kaspersky GReAT](https://securelist.com/blindeagle-apt/113414/)).
7. **Persistence (T1053.005 / T1547.001).** The intermediate .NET RAT can maintain persistence through scheduled tasks and can run PowerShell on command.
8. **Collection & Credential Access (T1056.001 / T1555.003 / T1113).** Final RATs provide keylogging, screenshot capture and browser monitoring. In banking campaigns a modified Quasar RAT watched for window titles matching about ten Colombian financial institutions and began keylogging only when a match appeared.
9. **Command & Control and Exfiltration (T1071.001 / T1105 / T1041 / T1567.002).** RAT C2 runs over dynamic-DNS domains; data is exfiltrated over the C2 channel or to cloud storage.

## Malware & Tooling Arsenal

Blind Eagle's design philosophy is "buy the ends, build the middle." Final payloads are almost always public or leaked RATs, which keeps development cost low and lets the group rotate tooling between campaigns; the intermediate loaders and droppers that glue the chain together are custom. This is also what makes the group reproducible in a lab — most components are open-source or widely documented.

| Tool | Type | Role in the chain |
| --- | --- | --- |
| AsyncRAT | Commodity RAT | Common final payload; keylogging, screenshots, remote control |
| Remcos | Commodity RAT | Frequent final payload (e.g. the 2024–25 `.url` campaigns) |
| njRAT | Commodity RAT | Espionage payload; plugin support, RDP sessions |
| Quasar RAT | Open-source RAT (modified) | Repurposed as a banking trojan vs. Colombian financial institutions |
| LimeRAT / BitRAT | Commodity RATs | Rotated final payloads across earlier campaigns |
| DCRAT | Commodity RAT | Final payload in the Sept 2025 Caminho campaign |
| HijackLoader | Modular loader | Injects the RAT after DLL sideloading (June 2024 onward) |
| HeartCrypt | Packer-as-a-Service | Packs payloads; injects a .NET stage into `csc.exe` |
| PureCrypter (variant) | .NET loader / downloader | Profiles the host, fetches and injects the final RAT |
| Caminho | Loader | Delivery/loading stage in the 2025 Zscaler-reported campaign |
| .url file (CVE-2024-43451 mimic) | Initial-access artifact | Triggers WebDAV/HTTP callback; signals interaction and pulls next stage |

Two tradecraft notes stand out. First, the group protects its .NET downloader with HeartCrypt plus NET-Reactor string and control-flow obfuscation, then network-encrypts C2 traffic with an AES key derived via `Rfc2898DeriveBytes` from a mutex-name password and a fixed salt ([Check Point Research](https://research.checkpoint.com/2025/blind-eagle-and-justice-for-all/)). Second, intermediate stages are hidden in plain sight — base64/ASCII-encoded text blobs, steganographic images, and payloads tucked into the resource sections of otherwise legitimate executables ([Kaspersky GReAT](https://securelist.com/blindeagle-apt/113414/)).

## Notable Campaigns

The group's evolution is best read as steady refinement of a stable playbook rather than wholesale reinvention. The table lists the campaigns and reports that mark meaningful shifts, oldest first.

| Period | Campaign / Report | Notable change |
| --- | --- | --- |
| 2018 | First tracked activity | Spam + commodity RATs against Colombia begins |
| Sep 2021 | Trend Micro: APT-C-36 spam | BitRAT delivery; URL-shortener geofencing documented |
| May 2024 | Kaspersky: espionage wave | Portuguese-language artifacts; Brazilian image hosts (possible outsourcing) |
| Jun 2024 | Kaspersky: HijackLoader | DLL sideloading via signed ASUS/IObit binaries; AsyncRAT |
| Nov 2024–Feb 2025 | Check Point: "...And Justice for All" | Malicious `.url` files mimicking CVE-2024-43451; HeartCrypt → PureCrypter → Remcos |
| Dec 2024 | "PARAISO" / "marte" / "saturno" | 1,600+ infections in one campaign; Bitbucket/GitHub payload hosting |
| Feb 2025 | "OPFail" exposure | Group leaked 8,000+ stolen banking credential records |
| Sep 2025 | Zscaler: Caminho + DCRAT | New loader (Caminho) and DCRAT vs. a Colombian government agency |
| 2025 | Recorded Future: TAG-144 | Activity resolved into five distinct operational clusters |
| May–Aug 2026 | LevelBlue / OTX tracking | AsyncRAT via AutoIt RunPE; DuckDNS C2; njRAT and LimeRAT in rotation |

The through-line matters more than any single campaign: government and bank lures, geofenced delivery, commodity RATs, and legitimate-platform hosting have held for seven years. The notable 2024–25 additions — the `.url`/WebDAV technique and HijackLoader DLL sideloading — show the group will adopt a fresh technique within days of its public disclosure (Check Point noted the `.url` variant appeared six days after Microsoft patched CVE-2024-43451).

## Adversary Emulation Playbook (Red Team)

This section outlines how to reproduce Blind Eagle's behavior inside a contained lab to validate detection and response — an assumed-breach / purple-team exercise, not operational guidance. Run everything against isolated VMs you own (a GOAD-style Active Directory range works well), use benign stand-in payloads, and keep C2 on an internal network segment. The goal is telemetry, not compromise.

1. **Phishing lure (T1566).** Build a Spanish-language, government- or bank-themed email with an embedded link and a matching PDF/DOCX attachment. The objective is to exercise mail-gateway and user-reporting telemetry, not to land a payload — so the link can point at a lab web server you control.
2. **Geofenced delivery (T1102).** Stand up a simple redirector that serves the next stage only to a lab-internal source IP and sends everything else to a decoy page. This validates whether egress proxies and URL detonation see the real path.
3. **`.url` callback (T1204).** Drop a benign `.url` file that points at an internal WebDAV/HTTP listener. Confirm the host generates the `Microsoft-WebDAV-MiniRedir` request and that your sensors capture the outbound connection and the user-interaction trigger.
4. **Scripted stager (T1059.001 / T1059.005).** Use a VBScript or PowerShell downloader that retrieves an inert marker file from the lab server via XMLHTTP/`Invoke-WebRequest`. This exercises script-block logging and script-interpreter detections.
5. **Loader behavior + hosting abuse (T1218 / T1574.002 / T1105).** Emulate sideloading by placing a benign test DLL beside a signed host binary in a user-writable directory, and host your inert payload on a developer platform (a private GitHub/Bitbucket repo or a Discord webhook) to test platform-allowlisting and download detections.
6. **Process injection (T1055.012).** Use a safe, well-known injector (for example an Atomic Red Team process-hollowing test) targeting `MSBuild.exe` or `InstallUtil.exe`, so you can tune detections for a legitimate .NET utility hosting foreign code.
7. **C2 stand-in (T1071.001 / T1571).** Substitute an open-source C2 framework or an AsyncRAT lab build for the live malware, beaconing to an internal dynamic-DNS-style name. This lets you profile the beacon cadence and credential-collection behavior without touching real infrastructure.

Mapping note: this chain lines up almost one-to-one with techniques already exercised in a GOAD/Sysmon/Wazuh home lab, so the same range can host the emulation and the detection-engineering work in the next section.

## Detection & Hunting Opportunities (Purple / Blue)

Because Blind Eagle relies on commodity tooling and legitimate services, the strongest detections target behavior and sequence rather than static indicators. The table maps each stage to a practical detection for a Sysmon + Wazuh (or any SIEM/EDR) stack.

| Technique | Signal to hunt | Primary data source |
| --- | --- | --- |
| `.url` / WebDAV callback (T1204) | Outbound 80/445 with User-Agent `Microsoft-WebDAV-MiniRedir`; `.url` opened from a mail/download path | Sysmon 3 (network), 22 (DNS), proxy logs |
| Script stagers (T1059) | `winword.exe`/`outlook.exe`/explorer spawning `wscript`, `cscript`, `mshta` or `powershell` | Sysmon 1 (process create) |
| Obscure archives (T1027) | Handling of `.lha` / `.uue` attachments; extraction to `%AppData%` then execution | EDR file + process events |
| Process hollowing (T1055.012) | `MSBuild.exe` / `InstallUtil.exe` / `csc.exe` created suspended, then `WriteProcessMemory` / remote-thread | Sysmon 1, 8 (CreateRemoteThread), 10 (ProcessAccess) |
| DLL sideloading (T1574.002) | Signed binary loading an unsigned DLL from a user-writable path | Sysmon 7 (image load) |
| Legit-platform C2 (T1102 / T1071) | Beacons to DDNS (`duckdns`, `ip-ddns`, `ydns`) and payload pulls from `raw.githubusercontent`, `bitbucket`, Discord CDN, Pastebin | Sysmon 22, proxy/DNS logs |
| Credential access (T1056.001) | Keylogging hooks; browser-window-title monitoring tied to bank names | EDR behavioral telemetry |

Two high-value, low-noise hunts come straight from the kill chain. The first is the WebDAV callback, which is rare in most environments and distinctive to the `.url` technique. The second is a .NET build utility hosting injected code — legitimate `MSBuild.exe` almost never spawns under Office or scripts, so the parent/child pairing is a reliable anchor.

An illustrative Sysmon/Sigma-style rule for the injection anchor:

```yaml
title: .NET Utility Spawned by Office or Script Interpreter
logsource:
  product: windows
  category: process_creation
detection:
  selection_child:
    Image|endswith:
      - '\MSBuild.exe'
      - '\InstallUtil.exe'
      - '\csc.exe'
  selection_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\outlook.exe'
      - '\wscript.exe'
      - '\powershell.exe'
  condition: selection_child and selection_parent
level: high
```

In a Wazuh deployment, ingest Sysmon via the Windows agent and promote matches on these sequences to high-severity alerts; the same GOAD range used for emulation produces the exact telemetry needed to tune the thresholds before the rules reach production.

## ATT&CK Technique Matrix

Consolidated mapping of the techniques referenced above, grouped by tactic.

| Tactic | Technique (ID) | How Blind Eagle uses it |
| --- | --- | --- |
| Initial Access | Spearphishing Link (T1566.002) | Gov/bank-themed emails with embedded links |
| Initial Access | Spearphishing Attachment (T1566.001) | PDF/DOCX attachments repeating the malicious link |
| Execution | User Execution (T1204.001/.002) | Victim opens archive or `.url` / clicks link |
| Execution | PowerShell / VBScript (T1059.001/.005) | Scripted downloaders pull the next stage |
| Execution | WMI (T1047) | Host and environment reconnaissance |
| Persistence | Scheduled Task (T1053.005) | .NET RAT persistence option |
| Persistence | Registry Run / Startup (T1547.001) | Autostart on some variants |
| Defense Evasion | Process Hollowing (T1055.012) | RAT injected into MSBuild/InstallUtil/csc |
| Defense Evasion | DLL Side-Loading (T1574.002) | Signed ASUS/IObit binaries load malicious DLL |
| Defense Evasion | Signed Binary Proxy (T1218) | Legitimate utilities host/execute the payload |
| Defense Evasion | Steganography (T1027.003) | Payloads hidden in images |
| Defense Evasion | Packing / Obfuscation (T1027) | HeartCrypt PaaS + NET-Reactor |
| Defense Evasion | Deobfuscate/Decode (T1140) | Base64/ASCII-encoded intermediate stages |
| Credential Access | Keylogging (T1056.001) | Captures banking and app credentials |
| Credential Access | Credentials from Browsers (T1555.003) | Modified Quasar harvests browser credentials |
| Collection | Screen Capture (T1113) | RAT screenshot capability |
| Command & Control | Web Protocols (T1071.001) | HTTP(S) RAT C2 |
| Command & Control | Ingress Tool Transfer (T1105) | Staged payload downloads |
| Command & Control | Web Service (T1102) | Google Drive, GitHub, Bitbucket, Discord, Pastebin |
| Command & Control | Non-Standard Port (T1571) | RAT C2 on ports such as 30201/30204 |
| Exfiltration | Exfil Over C2 (T1041) | Data returned over the RAT channel |
| Exfiltration | Exfil to Cloud Storage (T1567.002) | Cloud-hosted drop points |

*Technique mappings are compiled from Check Point, Kaspersky GReAT and Darktrace reporting; treat them as representative rather than exhaustive, since the group's toolset rotates between campaigns.*

## Assessment, Mitigations & References

**Outlook.** Blind Eagle is highly likely to persist as a dominant threat to Colombia and the wider region. Its reliance on commodity RATs and legitimate hosting is a feature, not a limitation — it keeps costs low, complicates attribution, and lets the group rotate tooling faster than signature-based defenses adapt. Its rapid adoption of the CVE-2024-43451 technique shows it will continue to fold newly disclosed methods into an otherwise stable playbook.

**Prioritized mitigations.**

1. Deploy phishing-resistant MFA and tighten mail-gateway controls on government- and bank-themed lures; treat urgency pretexts (tax debt, court summons) as a user-training focus.
2. Block or closely monitor dynamic-DNS resolution and payload retrieval from developer/CDN platforms (raw.githubusercontent, Bitbucket, Discord CDN, Pastebin) where business need does not exist.
3. Disable or monitor `.url` files from mail/download paths and alert on `Microsoft-WebDAV-MiniRedir` outbound requests.
4. Apply application control to .NET build utilities (`MSBuild.exe`, `InstallUtil.exe`, `csc.exe`) and to signed-binary DLL sideloading from user-writable directories.
5. Enforce egress filtering and, where feasible, geo-based egress controls; alert on beacons to non-standard C2 ports.
6. Train users on obscure archive formats (LHA, UUE) used specifically to bypass recognition.

**References.**

1. Check Point Research — [Blind Eagle: ...And Justice for All](https://research.checkpoint.com/2025/blind-eagle-and-justice-for-all/) (March 2025)
2. Kaspersky GReAT — [BlindEagle flying high in Latin America](https://securelist.com/blindeagle-apt/113414/) (August 2024)
3. Recorded Future (Insikt Group) — [TAG-144 / Blind Eagle activity clusters](https://assets.recordedfuture.com/insikt-report-pdfs/2025/cta-2025-0826.pdf) (August 2025)
4. Darktrace — [Patch and Persist: Detection of Blind Eagle (APT-C-36)](https://darktrace.com/blog/patch-and-persist-darktraces-detection-of-blind-eagle-apt-c-36) (June 2025)
5. Zscaler ThreatLabz — [BlindEagle targets Colombian government with Caminho and DCRAT](https://www.zscaler.com/blogs/security-research/blindeagle-targets-colombian-government-agency-caminho-and-dcrat) (September 2025)
6. Trend Micro — [APT-C-36 updates its spam campaign against South American entities](https://www.trendmicro.com/en_hk/research/21/i/apt-c-36-updates-its-long-term-spam-campaign-against-south-ameri.html) (2021)
7. SOCRadar — [Dark Web Profile: BlindEagle](https://socradar.io/blog/dark-web-profile-blindeagle/) (June 2026)

*Prepared as an open-source intelligence portfolio piece. All indicators and techniques are drawn from the public vendor reporting cited above.*
