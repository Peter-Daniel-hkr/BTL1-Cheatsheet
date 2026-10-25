# BTL1 Cheatsheet

A command-line-first reference for the **Blue Team Level 1 (BTL1)** exam, covering security operations, threat investigation, digital forensics, and incident response.

## Table of Contents

- [SOC Fundamentals](#soc-fundamentals)
- [Active Directory](#active-directory)
- [Phishing Analysis](#phishing-analysis)
- [Threat Intelligence](#threat-intelligence)
- [Digital Forensics](#digital-forensics)
- [Splunk SIEM](#splunk-siem)
- [Incident Response](#incident-response)
- [Quick Reference](#quick-reference)
- [Investigation Rules](#investigation-rules)
- [References](#references)

## Quick Reference

| Task                                     | Tools / Commands                                         |
| ---------------------------------------- | -------------------------------------------------------- |
| Identify file types and calculate hashes | `file`, `md5sum`, `sha1sum`, `sha256sum`, `Get-FileHash` |
| Investigate emails and URLs              | PhishTool, VirusTotal, URLScan, CyberChef                |
| Examine disk images                      | FTK Imager, Autopsy                                      |
| Parse Windows forensic artifacts         | PECmd, RBCmd, KAPE                                       |
| Analyze memory dumps                     | Volatility                                               |
| Analyze Windows event logs               | Event Viewer, PowerShell, DeepBlueCLI                    |
| Search security telemetry                | Splunk                                                   |
| Analyze network captures                 | Wireshark, TShark                                        |
| Investigate Active Directory             | `Get-ADUser`, `Get-ADComputer`, LDAP                     |
| Correlate attacker behavior              | MITRE ATT&CK, Cyber Kill Chain                           |

## Investigation Rules

- Preserve evidence and record cryptographic hashes.
- Record timestamps and document timezone assumptions.
- Confirm field names before writing Splunk searches.
- Correlate evidence across independent sources.
- Distinguish observed facts from hypotheses.
- Document the rationale for containment and the actions taken.
- Use authorized systems, datasets, and lab environments.

## References

- [BTL1 — Security Blue Team](https://www.securityblue.team/why-btl1)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Volatility 3](https://github.com/volatilityfoundation/volatility3)
- [Eric Zimmerman's Tools](https://ericzimmerman.github.io/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [CyberChef](https://github.com/gchq/CyberChef)
