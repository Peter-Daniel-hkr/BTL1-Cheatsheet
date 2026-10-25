# Splunk SIEM

## Basic Search

Replace `<index>` and the placeholder values with the appropriate index and search terms. Use the exact field names available in your dataset.

```spl
index=<index>
index=<index> "<search_term>"
index=<index> src="<IP>"
index=<index> dest="<IP>"
index=<index> user="<username>"
```

## Counts and Statistics

```spl
index=<index> | stats count
index=<index> | stats count by host
index=<index> | stats count by user
index=<index> | stats count by src_ip
index=<index> | stats count by EventCode
index=<index> | sort - count
```

## Top and Rare Values

```spl
index=<index> | top limit=10 Image
index=<index> | rare limit=10 Image
```

## Tables and Fields

```spl
index=<index> | table _time host user EventCode Image CommandLine
index=<index> | fields host user EventCode
index=<index> | fields - _raw
```

- `table` displays selected fields in a tabular format.
- `fields` includes or excludes fields from subsequent processing.
- `fields - _raw` removes the raw event field from the results.

## Windows Authentication

### Successful Logons

```spl
index=<index> EventCode=4624
```

### Failed Logons

```spl
index=<index> EventCode=4625
```

### Search Successful and Failed Logons

```spl
index=<index> (EventCode=4624 OR EventCode=4625)
```

### Group Failed Logons by Account

```spl
index=<index> EventCode=4625
| stats count by TargetUserName
| sort - count
```

## Process Execution

### Process Creation Events

```spl
index=<index> EventCode=4688
```

### Search for PowerShell

```spl
index=<index> powershell
```

### Search for Suspicious Process Names

```spl
index=<index> (Image="*\\powershell.exe" OR Image="*\\cmd.exe")
```

### Inspect Process Events

```spl
index=<index> EventCode=4688
| table _time host SubjectUserName NewProcessName CreatorProcessName ProcessCommandLine
```

> **Note:** Field names depend on the event provider, data normalization, and extraction configuration. Windows process creation events may use fields such as `NewProcessName` and `ProcessCommandLine`, while Sysmon commonly uses `Image` and `CommandLine`.

## Sysmon

### Process Creation

```spl
index=<index> EventCode=1
```

### Network Connection Events

```spl
index=<index> EventCode=3
```

### File Creation

```spl
index=<index> EventCode=11
```

### Registry Events

```spl
index=<index> (EventCode=12 OR EventCode=13 OR EventCode=14)
```

These Event IDs correspond to common Sysmon events. Confirm that Sysmon data is being ingested and that the event ID field is extracted correctly.

## Suricata

### Search Alerts

```spl
index=<index> sourcetype=suricata event_type=alert
```

### Count Alerts by Signature

```spl
index=<index> sourcetype=suricata event_type=alert
| stats count by alert.signature
| sort - count
```

### Count Alerts by Source IP

```spl
index=<index> sourcetype=suricata event_type=alert
| stats count by src_ip
| sort - count
```

> **Note:** Suricata field names and sourcetype values vary by ingestion pipeline. Inspect raw events to verify fields such as `alert.signature` and `src_ip`.

## FortiGate

### Search UTM Alerts

```spl
index=<index> sourcetype=fortigate_utm level=alert
```

### Count Alerts by Attack

```spl
index=<index> sourcetype=fortigate_utm level=alert
| stats count by attack
| sort - count
```

### Count Alerts by Severity

```spl
index=<index> sourcetype=fortigate_utm level=alert
| stats count by severity
```

> **Note:** Adjust the sourcetype, severity field, and alert filters to match the FortiGate data source and parsing configuration.

## IOC Search

### Search an IP Address

```spl
index=<index> "<IP>"
```

### Search a Domain

```spl
index=<index> "<DOMAIN>"
```

### Search a File Hash

```spl
index=<index> "<HASH>"
```

### Search a Filename

```spl
index=<index> "<FILENAME>"
```

Searching for an IOC as a quoted string can find occurrences in raw event text, but it may also return partial matches or unrelated events. Where possible, use an exact, extracted field such as `src_ip`, `dest_ip`, or a normalized hash field.

## Timeline

Search for an IOC and sort matching events chronologically:

```spl
index=<index> "<IOC>"
| sort 0 _time
| table _time sourcetype host user src_ip dest_ip EventCode Image CommandLine
```

- `sort 0 _time` sorts all returned events by time in ascending order.
- Confirm the time range and timezone before interpreting the timeline.
- Missing fields may be omitted or appear empty in the table.

## First and Last Seen

```spl
index=<index> "<IOC>"
| stats min(_time) AS first_seen max(_time) AS last_seen by host
```

This reports the earliest and latest matching event timestamps for each host within the selected time range. The result depends on the available data and the search window; it does not necessarily represent the IOC's true first or last occurrence across the environment.

## Investigation Checklist

- [ ] Identify the index and sourcetype.
- [ ] Confirm available field names and inspect raw events.
- [ ] Establish the relevant time range and timezone.
- [ ] Search for the initial IOC or alert.
- [ ] Group activity by host, user, source IP, and destination IP.
- [ ] Pivot to endpoint and network telemetry.
- [ ] Build a timeline and correlate related events.
- [ ] Preserve the raw events supporting the conclusion.
- [ ] Document the query, time range, findings, and limitations.

---

**Note:** These queries use generic field names and example placeholders. Inspect raw events and the dataset's extracted fields before adapting a query. Replace `<index>` and other placeholders with actual values; the angle-bracket placeholders are not intended to be entered literally.
