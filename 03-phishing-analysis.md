# Phishing Analysis

A practical reference for investigating suspicious emails, analyzing URLs and attachments, validating indicators of compromise (IOCs), and documenting phishing incidents.

## Table of Contents

- [Email Artifacts](#email-artifacts)
- [File Identification and Hashing](#file-identification-and-hashing)
- [URL and Domain Investigation](#url-and-domain-investigation)
- [URL Reputation and Analysis](#url-reputation-and-analysis)
- [Attachment Analysis](#attachment-analysis)
- [CyberChef](#cyberchef)
- [Phishing Investigation Workflow](#phishing-investigation-workflow)
- [IOC Record Template](#ioc-record-template)

## Email Artifacts

Collect and review the following artifacts when investigating a suspicious email.

| Artifact                        | What to Investigate                                                              |
| ------------------------------- | -------------------------------------------------------------------------------- |
| Sender address                  | Check the sender's address and domain for impersonation or unexpected variations |
| Reply-To address                | Determine whether replies are redirected to a different address or domain        |
| Return-Path                     | Examine the envelope sender recorded in the message                              |
| Recipient addresses             | Identify targeted users and potential distribution scope                         |
| Subject                         | Look for impersonation, urgency, unusual requests, or inconsistencies            |
| Message-ID                      | Record the message identifier for correlation and searching                      |
| Received headers                | Reconstruct the message's apparent mail-server path and timestamps               |
| Sending IP and reverse DNS      | Identify the connecting mail infrastructure and investigate the associated IP    |
| Date and time                   | Establish the timeline and account for timezone differences                      |
| SPF, DKIM, and DMARC results    | Review sender-authentication results and policy alignment                        |
| URLs and domains                | Extract links and identify suspicious domains, paths, and parameters             |
| Attachment filenames and hashes | Record filenames, file types, and cryptographic hashes                           |

### Email Investigation Notes

- Treat the visible `From` address as an assertion, not proof of the sender's identity.
- Review `Reply-To` and `Return-Path` for inconsistencies with the expected sender.
- Examine the full `Received` header chain carefully. Some headers may be supplied by untrusted systems; prioritize headers added by trusted mail infrastructure.
- SPF, DKIM, and DMARC results provide useful authentication evidence, but a passing result does not guarantee that a message is benign.
- Preserve the original email, preferably in its original format, along with the complete headers when permitted by your evidence-handling procedures.

## File Identification and Hashing

Identify attachment file types and calculate hashes before submitting files to reputation services or conducting further analysis.

### Linux

```bash
file <FILE>
strings <FILE>
md5sum <FILE>
sha1sum <FILE>
sha256sum <FILE>
```

Replace `<FILE>` with the path to the attachment.

| Command     | Purpose                                         |
| ----------- | ----------------------------------------------- |
| `file`      | Identify the likely file type from its contents |
| `strings`   | Extract printable character sequences           |
| `md5sum`    | Calculate an MD5 digest                         |
| `sha1sum`   | Calculate a SHA-1 digest                        |
| `sha256sum` | Calculate a SHA-256 digest                      |

### Windows PowerShell

```powershell
Get-FileHash <FILE>
Get-FileHash -Algorithm MD5 <FILE>
Get-FileHash -Algorithm SHA1 <FILE>
Get-FileHash -Algorithm SHA256 <FILE>
```

For paths containing spaces, use quotation marks:

```powershell
Get-FileHash -Algorithm SHA256 "C:\Evidence\suspicious attachment.exe"
```

`Get-FileHash` uses SHA-256 by default.

**Important:** Prefer SHA-256 for evidence integrity and file identification. MD5 and SHA-1 may still help match existing threat-intelligence records, but both have known collision weaknesses. A hash alone does not establish whether a file is malicious.

## URL and Domain Investigation

Use DNS and domain-registration information to investigate suspicious domains and their associated infrastructure.

### Linux Commands

```bash
whois <DOMAIN>
dig <DOMAIN>
dig A <DOMAIN>
dig MX <DOMAIN>
dig NS <DOMAIN>
dig TXT <DOMAIN>
dig -x <IP>
nslookup <DOMAIN>
```

Replace `<DOMAIN>` with the target domain and `<IP>` with the target IP address.

| Command             | Purpose                                                        |
| ------------------- | -------------------------------------------------------------- |
| `whois <DOMAIN>`    | Retrieve available domain-registration information             |
| `dig <DOMAIN>`      | Query DNS records using the resolver's default record type     |
| `dig A <DOMAIN>`    | Query IPv4 address records                                     |
| `dig MX <DOMAIN>`   | Query mail exchanger records                                   |
| `dig NS <DOMAIN>`   | Query authoritative name-server records                        |
| `dig TXT <DOMAIN>`  | Query TXT records, which may include SPF and verification data |
| `dig -x <IP>`       | Perform a reverse DNS lookup                                   |
| `nslookup <DOMAIN>` | Query DNS using the `nslookup` utility                         |

### Investigation Checklist

- [ ] Review domain registration details and available creation dates.
- [ ] Examine A, AAAA, MX, NS, and TXT records as relevant.
- [ ] Check for suspicious subdomains and lookalike domains.
- [ ] Identify the URL path, query parameters, and any encoded values.
- [ ] Trace redirects in an approved analysis environment.
- [ ] Review TLS certificate details and certificate history when available.
- [ ] Investigate associated IP addresses and hosting infrastructure.
- [ ] Correlate findings with email, endpoint, proxy, DNS, and SIEM logs.

**Caution:** Domain age, hosting location, and certificate information are contextual indicators, not proof of malicious activity. DNS and registration records can also change over time.

## URL Reputation and Analysis

### Useful Tools

| Tool                                        | Primary Use                                                                            |
| ------------------------------------------- | -------------------------------------------------------------------------------------- |
| [VirusTotal](https://www.virustotal.com/)   | Review URL, domain, IP, and file reputation data                                       |
| [URLScan.io](https://urlscan.io/)           | Examine website behavior, redirects, page resources, and screenshots                   |
| [URLhaus](https://urlhaus.abuse.ch/)        | Investigate URLs associated with malware distribution                                  |
| [AbuseIPDB](https://www.abuseipdb.com/)     | Review reported abusive IP addresses                                                   |
| [DomainTools](https://www.domaintools.com/) | Investigate domain registration and related infrastructure                             |
| [PhishTool](https://www.phishtool.com/)     | Support phishing email analysis and investigation                                      |
| WannaBrowser                                | Browser-based website analysis; verify current availability and suitability before use |
| URL2PNG                                     | Website screenshot service; verify current availability and suitability before use     |

### What to Check

| Check                           | Investigation Goal                                                           |
| ------------------------------- | ---------------------------------------------------------------------------- |
| Domain registration and age     | Identify recently registered or suspiciously similar domains                 |
| DNS records                     | Determine the domain's associated infrastructure                             |
| Redirect chain                  | Identify intermediate URLs and the final destination                         |
| URL path and parameters         | Find unusual paths, encoded data, or suspicious parameters                   |
| Reputation and detections       | Review reports from multiple reputation sources                              |
| Certificate details             | Examine certificate validity, subject names, and available history           |
| Hosting infrastructure          | Identify relevant IP addresses, hosting providers, and related domains       |
| Page behavior and impersonation | Look for credential harvesting, brand impersonation, or unexpected downloads |

**Operational caution:** Submitting URLs to third-party analysis services may disclose the URL to other users or researchers. URLs can contain sensitive tokens, personal information, or unique tracking identifiers. Follow organizational policy before submitting them.

Avoid opening suspicious links directly on a production workstation or using real credentials in an analysis environment.

## Attachment Analysis

### Useful Tools

| Tool                                                        | Primary Use                                                    |
| ----------------------------------------------------------- | -------------------------------------------------------------- |
| [VirusTotal](https://www.virustotal.com/)                   | Review file hashes, reputation, and available analysis results |
| [Talos File Reputation](https://www.talosintelligence.com/) | Investigate file and threat reputation information             |
| [Hybrid Analysis](https://www.hybrid-analysis.com/)         | Review sandbox-based file analysis reports                     |
| [ANY.RUN](https://any.run/)                                 | Interactive malware sandbox and behavioral analysis            |
| [Joe Sandbox](https://www.joesandbox.com/)                  | Automated malware analysis and sandbox reports                 |
| [ExifTool](https://exiftool.org/)                           | Inspect file metadata                                          |
| [CyberChef](https://github.com/gchq/CyberChef)              | Decode, transform, and inspect suspicious data                 |

### Safe Handling Procedure

1. Preserve the original attachment and record its source.
2. Record its filename, apparent file type, size, and SHA-256 hash.
3. Review existing reputation reports where appropriate.
4. Inspect metadata and extract relevant strings or embedded indicators.
5. Use an approved isolated analysis environment if deeper examination is required.
6. Record observed behavior and correlate findings with endpoint and network telemetry.

**Safety note:** Do not open suspicious attachments directly on a production system. Use an approved isolated analysis environment, and do not upload potentially confidential files to public services without authorization.

## CyberChef

[CyberChef](https://github.com/gchq/CyberChef) is a browser-based data transformation tool useful for decoding and inspecting suspicious strings, URLs, and encoded content.

### Useful Operations

| Operation               | Purpose                                                       |
| ----------------------- | ------------------------------------------------------------- |
| From Base64             | Decode Base64-encoded data                                    |
| From Hex                | Convert hexadecimal data into bytes or text where appropriate |
| URL Decode              | Decode percent-encoded URL data                               |
| From HTML Entity        | Decode HTML entities                                          |
| Extract URLs            | Identify URLs within input data                               |
| Extract IP addresses    | Identify IP address strings                                   |
| Extract email addresses | Identify email address strings                                |

**Remember:** Base64 is an encoding format, not encryption. Decoded content may still be malicious; inspect the result as data rather than executing it.

## Phishing Investigation Workflow

Use this workflow to investigate a suspected phishing email systematically.

- [ ] Preserve the original email and complete headers.
- [ ] Extract the sender, recipient, Reply-To, Return-Path, and sending IP where available.
- [ ] Record the subject, Message-ID, and relevant timestamps.
- [ ] Extract URLs, domains, and attachment filenames.
- [ ] Calculate attachment hashes, prioritizing SHA-256.
- [ ] Review reputation results from relevant intelligence sources.
- [ ] Examine redirects, DNS records, and domain characteristics.
- [ ] Search internal email, DNS, proxy, endpoint, and SIEM telemetry for the indicators.
- [ ] Determine whether recipients clicked links, submitted credentials, or executed attachments.
- [ ] Establish the scope and impact of the incident.
- [ ] Document evidence, conclusions, confidence, and recommended response actions.

## IOC Record Template

Use the following template to document the indicators and findings associated with a phishing investigation.

```text
Sender:
Reply-To:
Return-Path:
Subject:
Message-ID:
Sending IP:
Domain:
URL:
Attachment:
MD5:
SHA1:
SHA256:
Recipient:
Timestamp:
Timezone:
Reputation:
Internal sightings:
Observed behavior:
Conclusion:
Recommended actions:
```

Keep observed facts separate from hypotheses. Include timestamps and timezone assumptions, reference the sources used to validate each indicator, and document any limitations in the available evidence.

---

**Investigation principle:** Reputation tools provide supporting evidence, not definitive proof that an indicator is malicious. Correlate independent sources, validate findings against internal telemetry, and document the reasoning behind your conclusions.
