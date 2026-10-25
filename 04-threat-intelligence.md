# Threat Intelligence

A practical reference for collecting, enriching, correlating, and tracking Indicators of Compromise (IOCs) during security investigations.

## Table of Contents

- [IOC Types](#ioc-types)
- [Threat Intelligence Tools](#threat-intelligence-tools)
- [Domain and IP Collection](#domain-and-ip-collection)
- [Hash Collection](#hash-collection)
- [Intelligence Workflow](#intelligence-workflow)
- [IOC Tracking Template](#ioc-tracking-template)

## IOC Types

Indicators of Compromise (IOCs) are observable artifacts that may help identify malicious activity or investigate a potential security incident.

| IOC Type                | Example / Description                                                               |
| ----------------------- | ----------------------------------------------------------------------------------- |
| IPv4 / IPv6 address     | An IP address associated with suspicious infrastructure or activity                 |
| Domain                  | A suspicious or malicious domain name                                               |
| URL                     | A web address associated with phishing, malware, or other suspicious activity       |
| Email address           | A sender or account associated with suspicious messages                             |
| MD5 / SHA-1 / SHA-256   | Cryptographic hashes used to identify file contents                                 |
| Filename                | A filename associated with suspicious activity                                      |
| Certificate fingerprint | A hash identifying a digital certificate                                            |
| Registry path           | A Windows Registry location associated with suspicious configuration or persistence |
| Process name            | The name of a process associated with suspicious behavior                           |
| Command line            | A process command line that may reveal suspicious execution or activity             |

**Important:** An IOC is a lead for investigation, not conclusive proof of compromise. Its significance depends on context, reliability, and corroborating evidence.

## Threat Intelligence Tools

| Tool                                           | Purpose                                                         |
| ---------------------------------------------- | --------------------------------------------------------------- |
| [VirusTotal](https://www.virustotal.com/)      | File, URL, IP address, and domain reputation                    |
| [AbuseIPDB](https://www.abuseipdb.com/)        | IP address abuse reports                                        |
| [URLScan.io](https://urlscan.io/)              | Web-page behavior, requests, and redirect analysis              |
| [URLhaus](https://urlhaus.abuse.ch/)           | Intelligence on URLs associated with malware distribution       |
| [MISP](https://www.misp-project.org/)          | Sharing, correlating, and managing threat indicators            |
| [OpenCTI](https://www.opencti.io/)             | Managing threat intelligence entities and relationships         |
| [MITRE ATT&CK](https://attack.mitre.org/)      | Knowledge base of adversary tactics, techniques, and procedures |
| [DomainTools](https://www.domaintools.com/)    | Domain registration and infrastructure intelligence             |
| [CyberChef](https://github.com/gchq/CyberChef) | Data decoding, transformation, and indicator extraction         |

### Intelligence Handling Notes

- Check multiple sources where appropriate rather than relying on a single reputation result.
- Record the source and retrieval time for intelligence findings.
- Distinguish observed facts from third-party assessments.
- Consider false positives, stale records, shared hosting, and legitimate infrastructure.
- Follow organizational policies before submitting potentially sensitive indicators or files to public services.

## Domain and IP Collection

Use the following Linux commands to collect domain-registration and DNS information.

```bash
whois <DOMAIN>
dig <DOMAIN>
dig A <DOMAIN>
dig AAAA <DOMAIN>
dig MX <DOMAIN>
dig NS <DOMAIN>
dig TXT <DOMAIN>
dig -x <IP>
```

Replace `<DOMAIN>` with the target domain and `<IP>` with the target IP address.

| Command             | Purpose                                                               |
| ------------------- | --------------------------------------------------------------------- |
| `whois <DOMAIN>`    | Retrieve available domain-registration information                    |
| `dig <DOMAIN>`      | Query DNS records using the default query type                        |
| `dig A <DOMAIN>`    | Query IPv4 address records                                            |
| `dig AAAA <DOMAIN>` | Query IPv6 address records                                            |
| `dig MX <DOMAIN>`   | Query mail exchanger records                                          |
| `dig NS <DOMAIN>`   | Query name-server records                                             |
| `dig TXT <DOMAIN>`  | Query TXT records, which may include SPF and verification information |
| `dig -x <IP>`       | Perform a reverse DNS lookup                                          |

**Investigation tip:** DNS and registration information can change over time. Record when the information was collected, and correlate it with historical DNS, passive DNS, proxy logs, and other available telemetry.

## Hash Collection

File hashes help identify files and compare artifacts with known indicators.

### Linux

```bash
md5sum <FILE>
sha1sum <FILE>
sha256sum <FILE>
```

### Windows PowerShell

```powershell
Get-FileHash -Algorithm MD5 <FILE>
Get-FileHash -Algorithm SHA1 <FILE>
Get-FileHash -Algorithm SHA256 <FILE>
```

Replace `<FILE>` with the target file path. Quote paths containing spaces.

| Algorithm | Typical Use                                    | Security Consideration                             |
| --------- | ---------------------------------------------- | -------------------------------------------------- |
| MD5       | Matching legacy indicators                     | Known collision weaknesses                         |
| SHA-1     | Matching existing intelligence records         | Known collision weaknesses                         |
| SHA-256   | File identification and integrity verification | Preferred of these three for modern investigations |

Use SHA-256 as the default for file identification and evidence integrity. MD5 and SHA-1 can still be useful when matching historical threat intelligence.

## Intelligence Workflow

Follow a repeatable process to collect, validate, and apply threat intelligence.

1. **Extract indicators** from alerts, emails, files, network traffic, and logs.
2. **Normalize indicators** and timestamps into consistent formats.
3. **Enrich indicators** using multiple relevant reputation and intelligence sources.
4. **Record provenance**, confidence, and first- and last-observed times.
5. **Search internal telemetry** for each IOC across relevant data sources.
6. **Correlate related indicators** and infrastructure to identify potential relationships.
7. **Map observed behavior** to MITRE ATT&CK when supported by evidence.
8. **Recommend detection or blocking changes** based on confidence, context, and potential impact.
9. **Document findings** and revisit indicators when new evidence becomes available.

### Intelligence Validation Checklist

- [ ] Is the indicator correctly extracted and normalized?
- [ ] Is the source credible and the information sufficiently recent?
- [ ] Do independent sources support the assessment?
- [ ] Is there evidence of the indicator in internal telemetry?
- [ ] Could the indicator belong to legitimate shared infrastructure?
- [ ] Are first-seen and last-seen timestamps based on observed data or external reports?
- [ ] Is the proposed response proportionate to the confidence and potential impact?

## IOC Tracking Template

Use this template to document an indicator and its investigative context.

```text
Indicator:
Type:
Source:
Source URL / Reference:
Collected at:
First observed:
Last observed:
Reputation:
Confidence:
Related indicators:
Internal sightings:
Associated host/user:
ATT&CK technique:
Recommended action:
Investigation notes:
```

### Field Guidance

| Field                    | What to Record                                                       |
| ------------------------ | -------------------------------------------------------------------- |
| `Indicator`              | The IP, domain, URL, hash, or other observable                       |
| `Type`                   | The indicator category                                               |
| `Source`                 | The intelligence provider, alert, log, or evidence source            |
| `Source URL / Reference` | A report URL or internal case/evidence reference, where appropriate  |
| `Collected at`           | When the information was retrieved                                   |
| `First observed`         | The earliest known observation, including timezone                   |
| `Last observed`          | The most recent known observation, including timezone                |
| `Reputation`             | The reported reputation or assessment and its source                 |
| `Confidence`             | Confidence in the assessment, with a documented rationale            |
| `Related indicators`     | Associated domains, IPs, hashes, or other artifacts                  |
| `Internal sightings`     | Relevant matches in organizational telemetry                         |
| `Associated host/user`   | The affected or potentially affected asset or account                |
| `ATT&CK technique`       | A relevant technique identifier when supported by observed behavior  |
| `Recommended action`     | A proportionate investigation, detection, or response recommendation |
| `Investigation notes`    | Context, supporting evidence, limitations, and conclusions           |

---

**Investigation principle:** An IOC match is a lead, not automatically proof of compromise. Validate it against local telemetry and the context in which it appeared. Record the source, timestamp, confidence, and supporting evidence before recommending containment or blocking.
