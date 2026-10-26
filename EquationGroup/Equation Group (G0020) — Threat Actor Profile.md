# Equation Group (G0020) — Threat Actor Profile

Oct 26, 2026 · @Jessie Parker

*Classification: TLP:CLEAR — compiled from open-source intelligence for portfolio and training use.*

## Executive Summary

Equation Group (MITRE G0020) is widely regarded as the most technically sophisticated threat actor ever documented. Publicly disclosed by Kaspersky in February 2015 and assessed to have operated since at least 2001, it is linked in extensive open-source reporting to the U.S. National Security Agency's Tailored Access Operations (TAO) unit — an attribution Kaspersky itself did not make, and one this profile treats as a strong but not independently confirmed assessment.

The group's hallmark is engineering depth that still sets the benchmark for state-level capability: reprogramming hard-drive firmware to survive reformatting and OS reinstallation, hidden encrypted virtual filesystems, supply-chain interdiction of physical media, and modular espionage platforms (EquationDrug, GrayFish) built with operational discipline rarely seen elsewhere. It also shares exploits and code with Stuxnet, placing it at the center of the most consequential offensive-cyber lineage on record.

For a red or purple team, Equation Group matters less as an emulation target — its firmware implants and interdiction are not reproducible in a lab, and its live exploits are long patched — and more as the origin of techniques that reshaped the entire threat landscape. The 2016–2017 Shadow Brokers leak spilled the group's toolkit into the open, and the EternalBlue exploit it contained powered WannaCry and NotPetya, two of the most damaging cyber events in history. This profile covers attribution, targeting, signature capabilities, the tooling arsenal, the Shadow Brokers fallout, and the detection lessons that remain directly actionable today.

## Group Overview & Attribution

Kaspersky Lab publicly revealed Equation Group on February 16, 2015, naming it for the group's heavy use of strong encryption and complex obfuscation. Kaspersky assessed the group had been active since at least 2001 — with some artifacts suggesting roots as far back as 1996 — and described an operation involving dozens of operators and a decade-plus of continuous development.

| Attribute | Assessment |
| --- | --- |
| Aliases | Equation Group, G0020; linked to NSA / TAO |
| First public disclosure | February 2015 (Kaspersky) |
| Active since | At least 2001 |
| Suspected sponsor | United States / NSA TAO (not independently confirmed) |
| Primary motivation | Strategic espionage |
| Sophistication | Exceptional — the public benchmark for state capability |

The attribution to the NSA is widely reported but rests on circumstantial indicators rather than a formal confirmation. Kaspersky deliberately did not name a sponsor. The public case rests on several threads: NSA codewords such as "STRAITACID" and "STRAITSHOOTER" found inside the malware; compilation timestamps clustering in a U.S. Eastern-time workday; and F-Secure's linkage of the firmware implant IRATEMONK to TAO via an NSA capabilities catalog published by Der Spiegel in 2013. Later tooling overlaps surfaced by the Shadow Brokers leak strengthened the connection in the eyes of many analysts.

It is worth separating these strands by source. The Western open-source case (Kaspersky, F-Secure, the Der Spiegel catalog, the Snowden disclosures) is substantial but stops short of attribution by name. A separate 2022 attribution of an intrusion at Northwestern Polytechnical University to TAO came from Chinese government bodies (CVERC and Qihoo 360), citing activity timing aligned to U.S. working hours and holidays, operator errors, and American-English keyboard input. As with any state-linked case, the geopolitical position of the attributing party is part of the context, and this profile presents the NSA linkage as a strong consensus assessment rather than an established fact.

## Targeting & Victimology

Equation Group's targeting is consistent with strategic national-intelligence collection rather than financial or disruptive motives. Kaspersky documented roughly 500 infections across at least 42 countries by 2015, but stressed that the true figure was likely far higher — the malware includes a self-termination mechanism that removes it from systems, deliberately shrinking the observable footprint.

The heaviest concentrations of victims were in Iran, Russia, Pakistan, Afghanistan, India, Syria, and Mali. Reported target categories span government and diplomatic institutions, military, telecommunications, aerospace, energy, nuclear research, nanotechnology, financial institutions, media, and academic and cryptographic research — the classic collection priorities of a state intelligence service.

Two targeting characteristics stand out for their discipline. First, the group used IP-based geofencing and username-based selection on discussion forums to avoid infecting non-targets, which both protected operations and reduced exposure. Second, it was willing to use physical supply-chain interdiction — Kaspersky documented conference CD-ROMs intercepted in the mail and replaced with malware-bearing copies — a level of operational reach that distinguishes a state program from ordinary intrusion sets.

The later Chinese reporting on the Northwestern Polytechnical University intrusion described tens of thousands of compromised devices and more than 140 GB of exfiltrated data, with institutions in multiple countries allegedly used as relay infrastructure — a scale and tradecraft consistent with the group's documented capability, if attributed by a party with its own geopolitical stake.

## Signature Capabilities & Lifecycle

Equation Group is defined less by a single intrusion chain than by a set of capabilities that were, at the time of disclosure, years ahead of the field. The stages below describe the group's general operating pattern, mapped to MITRE ATT&CK where applicable.

1. **Initial Access — multiple vectors (T1190 / T1189 / T1195).** The group used exploitation of public-facing services, web-based exploitation of selected visitors, and — most distinctively — physical supply-chain interdiction, intercepting shipped media and replacing it with trojanized versions.
2. **Execution & Exploitation (T1203 / T1068).** Operations drew on a deep reserve of exploits, including zero-days later seen in Stuxnet. Exploitation was highly targeted, with victim validation before the full toolkit was deployed.
3. **Defense Evasion & Validation (T1480 / T1497 / T1027).** Payloads used environmental keying and target validation so that malware would only fully execute on intended systems, alongside heavy encryption and obfuscation to resist analysis.
4. **Persistence — firmware-level (T1542.002).** The group's signature capability was reprogramming the firmware of hard drives from numerous major manufacturers, planting code that survives disk reformatting and OS reinstallation and is effectively invisible to the operating system. Kaspersky assessed this would require access to manufacturer source code.
5. **Concealment — hidden storage (T1564).** Implants created hidden, encrypted virtual filesystems and hidden disk sectors to stage tools and exfiltrated data outside the view of normal forensic tooling.
6. **Lateral Movement via removable media (T1091 / T1092).** The FANNY worm propagated over networks and USB drives, including into air-gapped environments, using a hidden storage area on the USB device to ferry commands and results across the gap.
7. **Collection & Exfiltration (T1005 / T1041).** With long-dwell, stealthy access, the group collected high-value intelligence and exfiltrated it over encrypted channels, with the self-termination feature limiting the evidence left behind.

The through-line is engineering investment: custom implants, firmware persistence, and air-gap bridging reflect a program with resources and source-level access far beyond a typical intrusion set, and most of these techniques only became broadly understood after the group was exposed.

## Malware & Tooling Arsenal

Equation Group operated a family of modular platforms rather than a single implant, layering a validator, a loader, and a full espionage platform so that each stage only exposed the next to validated targets. The named components below are drawn from Kaspersky's reporting.

| Component | Type | Role |
| --- | --- | --- |
| DOUBLEFANTASY | Validator / recon | Confirms the victim is a real target before escalation |
| EQUATIONLASER | Early implant | Earlier-generation backdoor bridging to later platforms |
| EQUATIONDRUG | Espionage platform | Modular, plugin-based platform for long-dwell collection |
| GRAYFISH | Loader / platform | Most sophisticated platform; boot-level, runs from the Windows registry |
| FANNY | Worm | Spreads over USB and networks; bridges air gaps; shares code with Stuxnet |
| IRATEMONK | Firmware implant | Reprograms hard-drive firmware for persistence below the OS |
| TRIPLEFANTASY | Full-featured backdoor | Later validator/backdoor used alongside GrayFish |

Two points deserve emphasis. First, the firmware capability — the ability to reflash hard-drive firmware across many vendors — is the single most striking item in the arsenal, because it defeats the standard incident-response assumption that reformatting or replacing a disk removes an infection. Second, the FANNY worm is a direct thread to Stuxnet: it carried the same "privLib" code and the same LNK exploit later used by Stuxnet, and Kaspersky assessed FANNY likely predated it — evidence that the two development efforts were "either the same or working closely together."

The overall design philosophy — staged validation, modular plugins, encrypted hidden storage, and persistence below the operating system — is what made the group so difficult to detect, and why its full scope was understood only after years of operation.

## The Shadow Brokers Leak & Fallout

The most consequential chapter in Equation Group's story is not an intrusion it conducted but the exposure of its own toolkit. Beginning in August 2016, an entity calling itself The Shadow Brokers published a series of leaks containing Equation Group exploitation tools. Kaspersky assessed the material as authentic based on matching implementation quirks — notably a specific RC6 encryption variant — shared with known Equation Group code. The newest files dated to mid-2013, and it was speculated that post-Snowden security lockdowns ended the breach.

The April 2017 release ("Lost in Translation") was the pivotal one. It exposed a Windows exploitation framework (FuzzBunch) and a set of SMB exploits — above all EternalBlue, which targets a vulnerability in Microsoft's SMBv1 protocol — along with the DoublePulsar kernel implant used to run payloads after exploitation. Microsoft had patched the underlying vulnerability (MS17-010) in March 2017, weeks before the public dump, but global patching lagged badly.

Within two months, state-tolerated and criminal actors folded EternalBlue into self-propagating attacks. WannaCry (May 2017) paired EternalBlue with DoublePulsar to spread ransomware to hundreds of thousands of systems across 150+ countries; NotPetya (June 2017) used EternalBlue within a destructive wiper that caused an estimated ten billion dollars in damage. The lineage below traces how a state toolkit became a global catastrophe once it escaped containment.

&#91;embedded content: Shadow Brokers lineage · from leaked tooling to WannaCry and NotPetya\]

## Lessons for Red & Purple Teams

Equation Group is a poor fit for literal emulation and a rich source of lessons. Its defining capabilities — hard-drive firmware implants, source-level vendor access, and physical interdiction — are not reproducible in a home lab, and its live exploits are long since patched. The useful exercise is not to rebuild the group's tooling but to validate that a modern defensive stack would catch the techniques it pioneered, which are now commodity.

The right framing is **detection validation in an isolated lab**, using existing public, benign test resources rather than weaponized code:

1. **SMBv1 exploitation detection (T1210).** The EternalBlue-class technique is exhaustively covered by public detection content. Validate that your IDS/EDR fires on SMBv1 exploitation patterns using well-known community rule sets, against a deliberately unpatched, isolated VM you own — no exploit construction required.
2. **DoublePulsar-style implant detection (T1055).** Public tooling and signatures exist to identify the DoublePulsar kernel implant's behavior; confirm your stack detects it in the lab.
3. **Removable-media and air-gap bridging (T1091 / T1092).** Emulate the FANNY concept with a benign marker on a USB device using a framework such as Atomic Red Team, and verify your telemetry captures autorun/removable-media execution and anomalous USB staging.
4. **Firmware and boot integrity (T1542).** You cannot reproduce IRATEMONK, but you can validate that firmware and boot-integrity controls are in place and monitored — UEFI Secure Boot, measured boot/TPM attestation, and vendor firmware-integrity checks — and confirm your asset inventory would surface a disk whose firmware no longer matches a known-good baseline.
5. **Legacy-protocol inventory.** The highest-value "emulation" is an audit: enumerate where SMBv1 and other deprecated protocols still run, since that is the exact exposure that turned a patched vulnerability into WannaCry.

The meta-lesson is about containment, not offense: Equation Group's greatest real-world impact came from losing control of its arsenal. For a red team, the takeaway is tool hygiene and the blast radius of capability if it leaks; for a blue team, it is that nation-state techniques become everyone's problem within months of disclosure, so patching cadence and legacy-protocol elimination are strategic, not routine.

## Detection & Hunting Opportunities

Most of Equation Group's original tradecraft was invisible by design, but the techniques its leak unleashed are now well within reach of standard detection. The table maps the actionable surface to practical detections for a modern SIEM/EDR stack.

| Technique | Signal to hunt | Primary data source |
| --- | --- | --- |
| SMBv1 exploitation (T1210) | SMBv1 in use at all; exploitation patterns against port 445 | Network IDS, EDR, firewall logs |
| DoublePulsar implant (T1055) | Known kernel-implant ping/response behavior on SMB | Network IDS, memory/EDR telemetry |
| Removable-media execution (T1091) | Autorun or staged execution from USB; hidden-area staging | Sysmon 1/11, EDR device events |
| Firmware persistence (T1542) | Disk firmware version drift from a known-good baseline | Firmware-integrity tooling, asset inventory |
| Hidden storage (T1564) | Unexplained disk regions; large unaccounted sectors | Disk forensics, integrity monitoring |
| Legacy-protocol exposure | Deprecated SMBv1/other legacy services still enabled | Network inventory, config scans |

The two highest-value, lowest-effort actions are not clever detections at all — they are inventory. First, find and eliminate SMBv1: it is the single exposure that turned a patched vulnerability into a global ransomware event, and its mere presence is the finding. Second, maintain a firmware and boot-integrity baseline so that a disk whose firmware no longer matches known-good is surfaced by routine asset management rather than discovered during an incident.

For the exploitation techniques specifically, mature community and vendor detection content exists and is well-maintained; the defensive task is coverage validation, not novel rule development. An illustrative hunt focus for SMBv1 abuse:

```yaml
title: SMBv1 Negotiation or Exploitation Indicators
logsource:
  category: network_connection
detection:
  smbv1_in_use:
    DestinationPort: 445
    Protocol: 'SMBv1'
  condition: smbv1_in_use
level: high
note: >
  SMBv1 should not be present in a modern environment.
  Treat any SMBv1 negotiation as an exposure to investigate.
```

## ATT&CK Technique Matrix

Representative mapping of the techniques associated with Equation Group, grouped by tactic. Compiled from Kaspersky reporting and public ATT&CK material; representative rather than exhaustive.

| Tactic | Technique (ID) | How Equation Group uses it |
| --- | --- | --- |
| Initial Access | Supply Chain Compromise (T1195) | Interdiction of shipped physical media |
| Initial Access | Exploit Public-Facing App (T1190) | Exploitation of internet-facing services |
| Initial Access | Drive-by Compromise (T1189) | Web exploitation of selected visitors |
| Execution | Exploitation for Client Execution (T1203) | Deep reserve of exploits, incl. shared-with-Stuxnet zero-days |
| Persistence | Pre-OS Boot: Component Firmware (T1542.002) | Hard-drive firmware reprogramming (IRATEMONK) |
| Persistence | Boot or Logon Autostart (T1547) | Registry- and boot-level loading (GrayFish) |
| Defense Evasion | Execution Guardrails (T1480) | Environmental keying / target validation |
| Defense Evasion | Obfuscated Files or Information (T1027) | Heavy encryption across all stages |
| Defense Evasion | Hide Artifacts (T1564) | Hidden encrypted virtual filesystems |
| Defense Evasion | Rootkit (T1014) | Below-OS and kernel-level concealment |
| Lateral Movement | Replication via Removable Media (T1091) | FANNY worm over USB |
| C2 | Communication Through Removable Media (T1092) | Air-gap bridging via USB hidden storage |
| Lateral Movement | Exploitation of Remote Services (T1210) | SMB exploitation (EternalBlue lineage) |
| Collection | Data from Local System (T1005) | Espionage collection on target hosts |
| Exfiltration | Exfil Over C2 Channel (T1041) | Encrypted exfiltration with self-termination |

## Assessment, Mitigations & References

**Outlook.** Equation Group is a historical case study more than an active-threat concern, but its legacy is permanent. It set the benchmark for state-level tradecraft — firmware persistence, air-gap bridging, staged validation — and its leaked toolkit proved that the most dangerous outcome of elite offensive capability can be its loss of containment. The techniques it pioneered are now baseline expectations in capability assessments of any advanced actor.

**Prioritized mitigations.**

1. Eliminate SMBv1 and other deprecated protocols entirely; their presence is the exposure, not merely the exploit.
2. Patch promptly and treat patch cadence as strategic — WannaCry struck systems two months after a fix shipped.
3. Deploy firmware and boot-integrity controls: UEFI Secure Boot, measured boot with TPM attestation, and vendor firmware-integrity verification.
4. Maintain a known-good firmware baseline and asset inventory so firmware drift surfaces in routine management, not incidents.
5. Control and monitor removable media; restrict autorun and alert on anomalous USB staging.
6. Validate detection coverage for SMB exploitation and kernel-implant behavior using public, benign test content in an isolated lab.

**References.**

1. Kaspersky — [Equation Group: The Crown Creator of Cyber-Espionage](https://www.kaspersky.com/about/press-releases/2015_equation-group-the-crown-creator-of-cyber-espionage) (February 2015)
2. Wikipedia — [Equation Group](https://en.wikipedia.org/wiki/Equation_Group) (overview and attribution summary)
3. MITRE ATT&CK — [Equation (G0020)](https://attack.mitre.org/groups/G0020/)
4. Check Point Research — [Brokers in the Shadows: Analyzing Vulnerabilities and Attacks Spawned by the Leaked NSA Hacking Tools](https://research.checkpoint.com/2017/brokers-shadows-analyzing-vulnerabilities-attacks-spawned-leaked-nsa-hacking-tools) (May 2017)
5. Security Affairs — [The Equation Group shows the most complex and sophisticated hacking techniques ever seen](https://securityaffairs.com/33637/cyber-crime/the-equation-group-atp.html) (2015)

*Prepared as an open-source intelligence portfolio piece. All details are drawn from the public reporting cited above. The attribution of Equation Group to the NSA is a widely held open-source assessment, not an independently confirmed fact, and this profile treats it as such.*
