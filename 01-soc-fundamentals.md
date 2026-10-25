# SOC Fundamentals

A practical reference for basic Security Operations Center (SOC) investigations, host triage, common network services, event log analysis, and command-line tools.

## Table of Contents

- [Common Ports](#common-ports)
- [Windows Command Prompt](#windows-command-prompt)
- [PowerShell Host Investigation](#powershell-host-investigation)
- [File Hashes and Identification](#file-hashes-and-identification)
- [Windows Event IDs](#windows-event-ids)
- [Linux Investigation](#linux-investigation)
- [Data Representation](#data-representation)
- [Initial Triage Checklist](#initial-triage-checklist)

## Common Ports

| Port      | Service         | Description                                                                                |
| --------- | --------------- | ------------------------------------------------------------------------------------------ |
| 20/21     | FTP             | File transfer; port 20 is traditionally used for active-mode data, and port 21 for control |
| 22        | SSH             | Secure remote access                                                                       |
| 23        | Telnet          | Unencrypted remote access                                                                  |
| 25        | SMTP            | Email transfer                                                                             |
| 53        | DNS             | Name resolution                                                                            |
| 67/68     | DHCP            | Dynamic IP configuration; UDP 67 for servers and UDP 68 for clients                        |
| 80        | HTTP            | Web traffic                                                                                |
| 110       | POP3            | Email retrieval                                                                            |
| 123       | NTP             | Time synchronization                                                                       |
| 143       | IMAP            | Email access                                                                               |
| 389       | LDAP            | Directory access                                                                           |
| 443       | HTTPS           | Encrypted web traffic                                                                      |
| 445       | SMB             | Windows file sharing                                                                       |
| 514       | Syslog          | Log forwarding; traditionally uses UDP                                                     |
| 587       | SMTP Submission | Email submission                                                                           |
| 636       | LDAPS           | LDAP over TLS                                                                              |
| 993       | IMAPS           | IMAP over TLS                                                                              |
| 995       | POP3S           | POP3 over TLS                                                                              |
| 1433      | MSSQL           | Microsoft SQL Server                                                                       |
| 3306      | MySQL           | MySQL database                                                                             |
| 3389      | RDP             | Remote Desktop Protocol                                                                    |
| 5985/5986 | WinRM           | Windows remote management; HTTP on 5985 and HTTPS on 5986 by default                       |

**Investigation tip:** Ports indicate likely services, not proof of application identity. Confirm suspicious connections using process information, service configuration, logs, and network telemetry.

## Windows Command Prompt

### Basic Host and Network Reconnaissance

Run the following commands in Command Prompt (`cmd.exe`):

```cmd
ipconfig /all
arp -a
route print
netstat -ano
netstat -ab
tasklist
tasklist /svc
systeminfo
whoami /all
net users
net localgroup
net localgroup administrators
net localgroup "Remote Desktop Users"
net share
sc query
```

| Command                                 | Purpose                                                                                 |
| --------------------------------------- | --------------------------------------------------------------------------------------- |
| `ipconfig /all`                         | Display network interfaces and IP configuration                                         |
| `arp -a`                                | Display the ARP cache                                                                   |
| `route print`                           | Display the routing table                                                               |
| `netstat -ano`                          | Show network connections, listening ports, and associated PIDs                          |
| `netstat -ab`                           | Show executables associated with connections and listening ports; may require elevation |
| `tasklist`                              | List running processes                                                                  |
| `tasklist /svc`                         | Show services hosted by each process                                                    |
| `systeminfo`                            | Display operating system and host information                                           |
| `whoami /all`                           | Display the current user's identity, groups, and privileges                             |
| `net users`                             | List local user accounts                                                                |
| `net localgroup`                        | List local groups                                                                       |
| `net localgroup administrators`         | List members of the local Administrators group                                          |
| `net localgroup "Remote Desktop Users"` | List members of the local Remote Desktop Users group                                    |
| `net share`                             | List shared resources                                                                   |
| `sc query`                              | Display service information and status                                                  |

### Export the Process List

Save the current process list to a text file:

```cmd
tasklist > tasklist.txt
```

### Map Network Connections to Process IDs

First, list network connections and their associated process IDs:

```cmd
netstat -ano
```

Then inspect a specific PID:

```cmd
tasklist /FI "PID eq <PID>"
```

Replace `<PID>` with the numeric process ID from the `netstat` output.

## PowerShell Host Investigation

### Basic Host Reconnaissance

Run the following commands in PowerShell:

```powershell
Get-NetIPConfiguration
Get-NetIPAddress
Get-NetTCPConnection
Get-Process
Get-Service
Get-LocalUser
Get-LocalGroup
Get-ScheduledTask
Get-ChildItem Env:
Get-HotFix
Get-CimInstance Win32_OperatingSystem
Get-CimInstance Win32_Process
```

| Command                                 | Purpose                                                                |
| --------------------------------------- | ---------------------------------------------------------------------- |
| `Get-NetIPConfiguration`                | Display network configuration                                          |
| `Get-NetIPAddress`                      | List IP addresses                                                      |
| `Get-NetTCPConnection`                  | Display TCP connections and listening endpoints                        |
| `Get-Process`                           | List running processes                                                 |
| `Get-Service`                           | List services                                                          |
| `Get-LocalUser`                         | List local user accounts                                               |
| `Get-LocalGroup`                        | List local groups                                                      |
| `Get-ScheduledTask`                     | List scheduled tasks                                                   |
| `Get-ChildItem Env:`                    | Display environment variables                                          |
| `Get-HotFix`                            | List installed Windows hotfixes                                        |
| `Get-CimInstance Win32_OperatingSystem` | Retrieve operating system information                                  |
| `Get-CimInstance Win32_Process`         | Retrieve process information, including available command-line details |

### Find Running Services

```powershell
Get-Service | Where-Object { $_.Status -eq 'Running' }
```

### Inspect a Process

Retrieve details for a specific process:

```powershell
Get-Process -Id <PID> | Select-Object *
```

Replace `<PID>` with the target process ID.

For additional process details, including executable paths and command lines where available:

```powershell
Get-CimInstance Win32_Process -Filter "ProcessId = <PID>" |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
```

### Inspect Scheduled Tasks

List scheduled tasks:

```powershell
Get-ScheduledTask
```

Inspect a specific task:

```powershell
Get-ScheduledTask -TaskName "<TASK_NAME>" | Select-Object *
```

Replace `<TASK_NAME>` with the target task's name.

**Investigation tip:** Review unexpected task actions, execution paths, triggers, and task principals. A task's presence alone does not establish malicious activity.

## File Hashes and Identification

### Windows

Calculate file hashes using PowerShell:

```powershell
Get-FileHash <FILE>
Get-FileHash -Algorithm MD5 <FILE>
Get-FileHash -Algorithm SHA1 <FILE>
Get-FileHash -Algorithm SHA256 <FILE>
```

Replace `<FILE>` with the path to the target file. Quote paths containing spaces, for example:

```powershell
Get-FileHash -Algorithm SHA256 "C:\Evidence\suspicious file.exe"
```

`Get-FileHash` uses SHA-256 by default.

### Linux

Identify files, calculate hashes, and inspect printable strings:

```bash
file <FILE>
md5sum <FILE>
sha1sum <FILE>
sha256sum <FILE>
strings <FILE>
```

Replace `<FILE>` with the target file path.

| Command     | Purpose                                                |
| ----------- | ------------------------------------------------------ |
| `file`      | Identify a file's type using its contents and metadata |
| `md5sum`    | Calculate an MD5 digest                                |
| `sha1sum`   | Calculate a SHA-1 digest                               |
| `sha256sum` | Calculate a SHA-256 digest                             |
| `strings`   | Extract printable character sequences                  |

**Important:** Prefer SHA-256 for evidence integrity and file identification. MD5 and SHA-1 can still be useful when matching legacy indicators, but they have known collision weaknesses. Hashes identify content; they do not independently prove that a file is malicious or trustworthy.

## Windows Event IDs

The following event IDs are useful during Windows security investigations. Availability and event details depend on auditing configuration, log source, and Windows version.

| Event ID | Meaning                                    | Log / Notes                                 |
| -------- | ------------------------------------------ | ------------------------------------------- |
| 4624     | Successful logon                           | Security                                    |
| 4625     | Failed logon                               | Security                                    |
| 4634     | Logoff                                     | Security                                    |
| 4648     | Logon attempted using explicit credentials | Security                                    |
| 4672     | Special privileges assigned to a new logon | Security                                    |
| 4688     | Process creation                           | Security; requires appropriate auditing     |
| 4697     | Service installed                          | Security; depends on auditing configuration |
| 4720     | User account created                       | Security                                    |
| 4728     | Member added to a global security group    | Security                                    |
| 4732     | Member added to a local security group     | Security                                    |
| 7045     | Service installed                          | System                                      |

### Read Recent Security Events

Retrieve the latest 100 events from the Security log:

```powershell
Get-WinEvent -LogName Security -MaxEvents 100
```

Reading the Security log may require administrative privileges.

### Search Selected Event IDs

Search for successful logons, failed logons
