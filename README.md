# Threat-Intelligence-Reports
A collection of open-source threat intelligence reports profiling active threat actors. Each report covers attribution, targeting, and a full ATT&CK-mapped attack lifecycle, then pairs an adversary-emulation playbook with concrete detection logic for a Sysmon/Wazuh stack — bridging the offensive and defensive sides of each threat

## Reports

Newest first. Open a folder to read the full profile; where available, a red/purple team briefing deck (.pptx) sits alongside it.

| Report | Active since | Motivation | Why it's worth studying |
| --- | --- | --- | --- |
| [Scattered Spider (G1015)](Scattered-Spider/) | 2022 | Financial: extortion and ransomware | Help desk vishing to ESXi ransomware, with almost no malware |
| [NightEagle (APT-Q-95)](NightEagle/) | At least 2023 | Espionage | Exchange zero-day, in-memory IIS implant, modified Chisel tunnel |
| [Blind Eagle (APT-C-36)](Blind-Eagle/) | 2018 | Financial and espionage | Geofenced phishing into commodity RATs; a clean emulation target |
| [Equation Group (G0020)](EquationGroup/) | At least 2001 | Strategic espionage | Firmware implants and the Shadow Brokers to WannaCry/NotPetya lineage |

All reports are TLP:CLEAR and compiled from open-source vendor, government and court reporting, cited in each profile.
