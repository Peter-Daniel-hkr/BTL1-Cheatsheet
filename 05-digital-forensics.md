# Digital Forensics

## Evidence Handling

- Preserve original evidence.
- Record the acquisition method, date, time, and timezone.
- Calculate hashes before and after transfers where appropriate.
- Work from forensic copies whenever possible.
- Record tool names and versions.
- Maintain chain-of-custody documentation.
- Create forensic images only when authorized.

## Hashes

### Linux

```bash
md5sum <file>
sha1sum <file>
sha256sum <file>
```

### Windows

```powershell
Get-FileHash <file>
Get-FileHash -Algorithm MD5 <file>
Get-FileHash -Algorithm SHA1 <file>
Get-FileHash -Algorithm SHA256 <file>
```

## File Identification and Metadata

```bash
file <file>
strings <file>
exiftool <file>
exiftool -a -u -g1 <file>
```

## FTK Imager

1. Add the evidence source.
2. Select the appropriate disk image or device.
3. Review partitions and file systems.
4. Export relevant artifacts.
5. Verify hashes and document findings.
6. Create forensic images only when authorized.

## Autopsy

1. Create a case.
2. Add the disk image as a data source.
3. Run the relevant ingest modules.
4. Examine deleted files, browser artifacts, and file metadata.
5. Review keyword-search results.
6. Examine timelines and correlate timestamps.
7. Export relevant files and document findings.

## Windows Event Logs

### Common Location

```text
C:\Windows\System32\winevt\Logs\
```

### Read Events with PowerShell

```powershell
Get-WinEvent -LogName Security -MaxEvents 100
Get-WinEvent -LogName System -MaxEvents 100

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4624, 4625, 4648
}

Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id      = 7045
}
```

**Useful event IDs:**

| Event ID | Meaning                                    |
| -------- | ------------------------------------------ |
| `4624`   | Successful logon                           |
| `4625`   | Failed logon                               |
| `4648`   | Logon attempted using explicit credentials |
| `7045`   | A service was installed                    |

## DeepBlueCLI

### Analyze an Exported EVTX File

```powershell
.\DeepBlue.ps1 <file.evtx>
```

### Analyze the Local Security Log

```powershell
.\DeepBlue.ps1 -log security
```

### Analyze the Local System Log

```powershell
.\DeepBlue.ps1 -log system
```

### Process EVTX Files in a Directory and Redirect Output

```powershell
.\DeepBlue.ps1 .\evtx\* > output.txt
```

If execution is blocked in an authorized lab, follow the lab's execution-policy instructions. A per-user policy change may be used where permitted:

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser
```

> **Note:** Execution-policy changes reduce a PowerShell execution barrier; they do not make scripts trustworthy. Use only authorized scripts and restore the previous policy when appropriate.

## Windows Prefetch — PECmd

### Common Location

```text
C:\Windows\Prefetch\
```

### Display Help

```cmd
PECmd.exe -h
```

### Parse a Prefetch File

```cmd
PECmd.exe -f <file.pf>
```

### Parse a Directory

```cmd
PECmd.exe -d <prefetch_directory>
```

## Windows Recycle Bin — RBCmd

### Common Location

```text
C:\$Recycle.Bin\<USER_SID>\
```

### Display Help

```cmd
RBCmd.exe -h
```

### Parse a Specific Recycle Bin Metadata File

```cmd
RBCmd.exe -f <file>
```

### Parse a Directory

```cmd
RBCmd.exe -d <Recycle_Bin_directory>
```

### Parse a Directory Recursively

If supported by the installed version:

```cmd
RBCmd.exe -d <Recycle_Bin_directory> -r
```

### Export CSV Output

If supported by the installed version:

```cmd
RBCmd.exe -d <Recycle_Bin_directory> --csv <output_directory>
```

### Recycle Bin Artifacts

- **`$I` files:** Contain metadata such as the original path, file size, and deletion time.
- **`$R` files:** Contain the corresponding recycled content when it is retained.
- Correlate deletion times with endpoint logs and other artifacts.

> **Version note:** Check `RBCmd.exe -h` before using version-specific switches.

## Windows Shortcuts and Jump Lists

### LNK Files

```text
C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Recent\
```

### Automatic Jump Lists

```text
C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\
```

### Custom Jump Lists

```text
C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\
```

Use artifact parsers and Autopsy to extract timestamps, paths, and application activity.

## KAPE

### Display Help

```cmd
kape.exe --help
```

Use the appropriate configured targets and modules for the collection scope. Verify the available targets and modules in the installed version before acquisition.

## Volatility 3

### Display Available Options

```bash
python3 vol.py -h
```

### Identify the Image and Operating System Information

```bash
python3 vol.py -f <memory_image> windows.info
```

### List Processes

```bash
python3 vol.py -f <memory_image> windows.pslist
```

### View the Process Tree

```bash
python3 vol.py -f <memory_image> windows.pstree
```

### Inspect Command Lines

```bash
python3 vol.py -f <memory_image> windows.cmdline
```

### Inspect Network Connections

```bash
python3 vol.py -f <memory_image> windows.netscan
```

### List Files

```bash
python3 vol.py -f <memory_image> windows.filescan
```

### List Loaded DLLs

```bash
python3 vol.py -f <memory_image> windows.dlllist
```

> **Note:** Volatility 3 plugin availability and output depend on the image, operating system, and installed version. Use `python3 vol.py -h` to verify available plugins.

## Scalpel — File Carving

### Display Help

```bash
scalpel -h
```

### Carve Files from a Disk Image

```bash
scalpel -c <config> -o <output_directory> <disk_image>
```

File carving may recover content without the original directory structure. Validate recovered files and document their provenance.

## Linux Artifacts

### Common Files and Locations

| Path                         | Purpose                                                              |
| ---------------------------- | -------------------------------------------------------------------- |
| `/etc/passwd`                | Local account information                                            |
| `/etc/shadow`                | Password hashes and password-aging information; access is restricted |
| `/var/log/auth.log`          | Authentication-related events on systems using this log              |
| `/var/log/secure`            | Authentication and security events on systems using this log         |
| `/var/log/syslog`            | General system messages on systems using this log                    |
| `/var/log/audit/audit.log`   | Linux audit subsystem records, when configured                       |
| `/var/lib/dpkg/status`       | Installed package information on Debian-based systems                |
| `/home/<USER>/.bash_history` | Bash command history, if saved                                       |

> Log paths vary by distribution and logging configuration. Some systems use `systemd-journald` instead of, or alongside, traditional log files.

### Useful Commands

```bash
last
lastlog
who
w
ps aux
ss -tulpn
journalctl
```

## Browser Artifacts

Review the following artifacts using appropriate forensic tools:

- Browser history
- Download records
- Cached files
- Cookies
- Session data

Interpret timestamps in their correct timezone and account for browser-specific storage formats.

## Forensic Timeline

Record the following details for each relevant event:

```text
Timestamp:
Timezone:
Host:
User:
Artifact:
Original path:
Event:
Source:
Hash:
Interpretation:
Confidence:
```

Correlate file timestamps with event logs, process creation, DNS requests, network captures, and Splunk events.

**Important:** File timestamps alone do not establish when an attacker first accessed a system. Consider timestamp semantics, possible clock differences, timezones, and whether an artifact could have been modified or manipulated.
