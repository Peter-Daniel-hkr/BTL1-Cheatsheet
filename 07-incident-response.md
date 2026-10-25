# Incident Response

## PICERL Incident Response Lifecycle

```text
Preparation
Identification
Containment
Eradication
Recovery
Lessons Learned
```

## Initial Triage

Record the following details when investigating an alert or suspected incident:

```text
Alert:
Severity:
Detection time:
Affected host:
Affected user:
Source IP:
Destination IP:
File / process:
IOC:
Data source:
```

Establish the initial scope, validate the alert, and preserve relevant evidence before taking actions that could destroy useful data.

## Windows Host Triage

### Command Prompt

```cmd
ipconfig /all
arp -a
netstat -ano
tasklist
tasklist /svc
whoami /all
net users
net localgroup administrators
sc query
```

### PowerShell

```powershell
Get-NetIPConfiguration
Get-NetTCPConnection
Get-Process
Get-Service
Get-ScheduledTask
Get-LocalUser
Get-WinEvent -LogName Security -MaxEvents 100
```

Use these commands to review network configuration, active connections, running processes, services, scheduled tasks, local accounts, and recent Security log events.

> **Note:** Some commands require elevated privileges. If feasible, preserve volatile evidence such as active connections and running processes before isolating or shutting down the host.

## Linux Host Triage

```bash
ip addr
ip route
ss -tulpn
ps aux
who
w
last
journalctl
```

Use these commands to inspect network interfaces, routing, listening sockets, processes, logged-in users, login history, and system logs.

> **Note:** Access to some network and process details may require root privileges. The availability and contents of logs depend on the Linux distribution and logging configuration.

## Network Analysis — Wireshark

Open the capture in Wireshark and establish the relevant time range. Use display filters to narrow the traffic for investigation.

### Common Display Filters

| Purpose                             | Display filter                             |
| ----------------------------------- | ------------------------------------------ |
| Traffic involving an IP             | `ip.addr == <IP>`                          |
| Source IP                           | `ip.src == <IP>`                           |
| Destination IP                      | `ip.dst == <IP>`                           |
| TCP port 443                        | `tcp.port == 443`                          |
| DNS traffic                         | `dns`                                      |
| HTTP traffic                        | `http`                                     |
| HTTP GET requests                   | `http.request.method == "GET"`             |
| HTTP POST requests                  | `http.request.method == "POST"`            |
| DNS queries containing a domain     | `dns.qry.name contains "<domain>"`         |
| Initial TCP SYN packets without ACK | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| Frames containing a string          | `frame contains "<string>"`                |

Replace placeholders such as `<IP>` and `<domain>` with actual values. Wireshark display filters are used to view matching packets; they do not remove other packets from the capture.

### TShark

List available capture interfaces:

```bash
tshark -D
```

Read a capture file:

```bash
tshark -r <capture.pcap>
```

Display DNS packets:

```bash
tshark -r <capture.pcap> -Y 'dns'
```

Display HTTP request packets:

```bash
tshark -r <capture.pcap> -Y 'http.request'
```

> **Note:** HTTP filters may not reveal application-layer details in encrypted HTTPS traffic. Use available TLS metadata and other relevant telemetry when the payload is encrypted.

## Evidence Collection

- Record the evidence source and acquisition time.
- Hash relevant files where appropriate.
- Preserve the original evidence.
- Record the tool name and version.
- Maintain a chain-of-custody record.
- Do not alter the original evidence during analysis.
- Document evidence transfers, access, and any transformations performed.

## Containment

Depending on the incident and approved procedures:

- Isolate the affected host.
- Block confirmed malicious indicators.
- Disable or restrict compromised accounts.
- Revoke exposed sessions or tokens.
- Preserve volatile evidence where feasible.
- Document each containment action and its impact.

Containment actions should be proportionate to the incident and coordinated with the appropriate incident-response stakeholders. Consider business impact and the risk of alerting an attacker before acting.

## Eradication and Recovery

- Remove confirmed malicious files and persistence mechanisms.
- Correct the exploited vulnerability.
- Rotate exposed credentials.
- Restore trusted systems or data.
- Validate endpoint health.
- Monitor for recurring indicators.
- Document any remaining risk.

Verify that the initial access method and associated persistence have been addressed before returning affected systems to normal operation.

## Incident Report

Use this template to document the investigation and response:

```text
Incident ID:
Summary:
Detection source:
Initial detection:
Affected systems:
Affected users:
Timeline:
Root cause:
Initial access:
Execution:
Persistence:
Command and control:
Impact:
Confirmed IOCs:
Containment:
Eradication:
Recovery:
Recommendations:
Outstanding questions:
```

Clearly distinguish confirmed facts from hypotheses. Record supporting evidence for conclusions and identify any gaps that remain unresolved.

## Post-Incident Review

Review the following questions after the incident:

- [ ] Was detection timely?
- [ ] Were logs sufficient?
- [ ] Which indicators were missed?
- [ ] Were containment decisions effective?
- [ ] Did the attacker move to other systems?
- [ ] Which detection rules need improvement?
- [ ] What preventive controls should change?

Document lessons learned, assign owners to follow-up actions, and track remediation to completion.
