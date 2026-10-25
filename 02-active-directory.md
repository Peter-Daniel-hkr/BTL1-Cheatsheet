# Active Directory

A practical reference for investigating Active Directory (AD) domains, users, groups, computers, service principal names (SPNs), LDAP queries, and Windows authentication events using PowerShell.

## Table of Contents

- [Domain Information](#domain-information)
- [Searching AD Objects](#searching-ad-objects)
- [User Properties](#user-properties)
- [Groups](#groups)
- [Computers](#computers)
- [Service Principal Names](#service-principal-names)
- [LDAP Filters](#ldap-filters)
- [Windows Authentication Events](#windows-authentication-events)
- [AD Investigation Checklist](#ad-investigation-checklist)

## Domain Information

Use the Active Directory PowerShell module to retrieve domain, forest, domain controller, and organizational unit information.

```powershell
Get-ADDomain
Get-ADForest
Get-ADDomainController -Filter *
Get-ADOrganizationalUnit -Filter *
```

| Command                              | Purpose                                                    |
| ------------------------------------ | ---------------------------------------------------------- |
| `Get-ADDomain`                       | Retrieve information about the current or specified domain |
| `Get-ADForest`                       | Retrieve forest information                                |
| `Get-ADDomainController -Filter *`   | List domain controllers                                    |
| `Get-ADOrganizationalUnit -Filter *` | List organizational units (OUs)                            |

## Searching AD Objects

### Find a User

```powershell
Get-ADUser -Identity "<username>" -Properties *
```

Replace `<username>` with the user's distinguished name, GUID, SID, or supported account identifier, such as a SAM account name.

### Retrieve Selected User Properties

```powershell
Get-ADUser -Identity "<username>" -Properties LastLogonDate, LockedOut, Modified, PasswordExpired, PasswordLastSet
```

### Find All Users

```powershell
Get-ADUser -Filter *
```

Retrieve users with their last-logon dates:

```powershell
Get-ADUser -Filter * -Properties LastLogonDate |
    Select-Object SamAccountName, LastLogonDate
```

### Find Disabled Accounts

```powershell
Get-ADUser -Filter 'Enabled -eq $false'
```

### Find Locked Accounts

```powershell
Search-ADAccount -LockedOut -UsersOnly
```

### Find Accounts with Expired Passwords

```powershell
Search-ADAccount -PasswordExpired -UsersOnly
```

### Find Accounts That Have Not Logged On Recently

Search for accounts inactive for at least 90 days:

```powershell
Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 90.00:00:00
```

**Investigation tip:** Inactivity and last-logon attributes require careful interpretation. Replication, logon type, attribute updates, and the selected domain controller can affect the results. Validate findings against additional evidence before classifying an account as abandoned.

## User Properties

Retrieve individual properties to investigate account configuration and potential anomalies.

```powershell
Get-ADUser -Identity "<username>" -Properties Description
Get-ADUser -Identity "<username>" -Properties MemberOf
Get-ADUser -Identity "<username>" -Properties ServicePrincipalName
Get-ADUser -Identity "<username>" -Properties PasswordLastSet, PasswordExpired, PasswordNeverExpires, PasswordNotRequired, LockedOut, Enabled
```

### Show Selected Properties

List users with their display names, email addresses, and last-logon dates:

```powershell
Get-ADUser -Filter * -Properties DisplayName, EmailAddress, LastLogonDate |
    Select-Object SamAccountName, DisplayName, EmailAddress, LastLogonDate
```

### Search User Descriptions

Descriptions may contain useful contextual information and should be reviewed for unexpected or sensitive content.

```powershell
Get-ADUser -Filter * -Properties Description |
    Select-Object SamAccountName, Description
```

| Attribute              | Purpose                                                                            |
| ---------------------- | ---------------------------------------------------------------------------------- |
| `SamAccountName`       | User's legacy logon name                                                           |
| `DisplayName`          | Display name                                                                       |
| `Description`          | Account description                                                                |
| `MemberOf`             | Direct group memberships represented by distinguished names                        |
| `ServicePrincipalName` | SPNs registered on the account                                                     |
| `LastLogonDate`        | Convenient, approximate last-logon value derived from replicated logon information |
| `PasswordLastSet`      | Time the password was last set                                                     |
| `PasswordExpired`      | Indicates whether the password is expired                                          |
| `PasswordNeverExpires` | Indicates whether the account's password is configured not to expire               |
| `PasswordNotRequired`  | Indicates whether the account is configured without a password requirement         |
| `LockedOut`            | Indicates whether the account is locked out                                        |
| `Enabled`              | Indicates whether the account is enabled                                           |

## Groups

### List and Inspect Groups

```powershell
Get-ADGroup -Filter *
Get-ADGroup -Identity "<group>" -Properties *
Get-ADGroupMember -Identity "<group>"
Get-ADPrincipalGroupMembership -Identity "<username>"
```

| Command                                                 | Purpose                                                            |
| ------------------------------------------------------- | ------------------------------------------------------------------ |
| `Get-ADGroup -Filter *`                                 | List AD groups                                                     |
| `Get-ADGroup -Identity "<group>" -Properties *`         | Retrieve group details and additional properties                   |
| `Get-ADGroupMember -Identity "<group>"`                 | List direct members of a group                                     |
| `Get-ADPrincipalGroupMembership -Identity "<username>"` | Retrieve group memberships for a user or other supported principal |

### Find Privileged Group Membership

Inspect membership in commonly privileged groups:

```powershell
Get-ADGroupMember -Identity "Domain Admins"
Get-ADGroupMember -Identity "Enterprise Admins"
Get-ADGroupMember -Identity "Administrators"
```

**Important:** The `Administrators` group can refer to a domain or local group depending on the context. Specify the appropriate identity or domain when needed.

For nested memberships, direct membership queries alone may not reveal the full effective privilege path. Investigate nested groups and relevant domain or local group configurations.

## Computers

### List and Inspect Computer Accounts

```powershell
Get-ADComputer -Filter *
Get-ADComputer -Identity "<computer>" -Properties *
Get-ADComputer -Filter * -Properties OperatingSystem |
    Select-Object Name, OperatingSystem
```

| Command                                                | Purpose                                                      |
| ------------------------------------------------------ | ------------------------------------------------------------ |
| `Get-ADComputer -Filter *`                             | List computer accounts                                       |
| `Get-ADComputer -Identity "<computer>" -Properties *`  | Retrieve a computer account and its additional properties    |
| `Get-ADComputer -Filter * -Properties OperatingSystem` | Retrieve computer accounts with operating system information |

Useful properties to review include:

- `Name`
- `DNSHostName`
- `OperatingSystem`
- `OperatingSystemVersion`
- `Enabled`
- `LastLogonDate`
- `ServicePrincipalName`
- `whenCreated`
- `whenChanged`

Computer account information in AD does not necessarily reflect the host's current operational state. Validate suspicious or stale accounts against endpoint and network telemetry.

## Service Principal Names

A **Service Principal Name (SPN)** associates a service instance with an account. SPNs are useful when investigating service accounts, unexpected service registrations, and potential Kerberos-related risks.

### Find User Accounts with SPNs

```powershell
Get-ADUser -Filter * -Properties ServicePrincipalName |
    Where-Object { $_.ServicePrincipalName } |
    Select-Object SamAccountName, ServicePrincipalName
```

### Find Computer Accounts with SPNs

```powershell
Get-ADComputer -Filter * -Properties ServicePrincipalName |
    Where-Object { $_.ServicePrincipalName } |
    Select-Object Name, ServicePrincipalName
```

**Investigation tip:** Review unexpected SPNs, unusual account ownership, privileged service accounts, and recent changes. An SPN is normal for many legitimate services and is not, by itself, evidence of compromise.

## LDAP Filters

LDAP filters provide a way to search directory objects by their attributes.

### Find User Objects

```text
(&(objectCategory=person)(objectClass=user))
```

### Find a Particular Account

```text
(&(objectCategory=person)(objectClass=user)(sAMAccountName=<username>))
```

Replace `<username>` with the target account's SAM account name.

### Find User Objects with an SPN

```text
(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))
```

### Useful LDAP Attributes

| Attribute              | Purpose                                                             |
| ---------------------- | ------------------------------------------------------------------- |
| `sAMAccountName`       | Account logon name                                                  |
| `displayName`          | Display name                                                        |
| `description`          | Object description                                                  |
| `memberOf`             | Direct group memberships                                            |
| `lastLogonTimestamp`   | Replicated, approximate last-logon timestamp                        |
| `whenCreated`          | Object creation timestamp                                           |
| `whenChanged`          | Timestamp of the last directory object change                       |
| `userAccountControl`   | Bit flags describing account settings                               |
| `servicePrincipalName` | Registered service principal names                                  |
| `pwdLastSet`           | Password last-set timestamp represented as a Windows FILETIME value |

**Note:** LDAP filters use their own syntax and are not interchangeable with PowerShell's `-Filter` expressions. Escape special characters appropriately when constructing filters from user-supplied values.

## Windows Authentication Events

Windows Security logs can provide evidence of authentication activity and account or group changes.

### Query Authentication Events

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = @(4624, 4625, 4648)
}
```

### Query Account and Group Changes

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = @(4720, 4728, 4732)
}
```

### Event ID Reference

| Event ID | Meaning                                    |
| -------- | ------------------------------------------ |
| 4624     | Successful logon                           |
| 4625     | Failed logon                               |
| 4648     | Logon attempted using explicit credentials |
| 4720     | User account created                       |
| 4728     | Member added to a global security group    |
| 4732     | Member added to a local security group     |

These events generally require appropriate auditing to be enabled. Log availability, retention, and permissions can affect query results.

For investigations involving privileged group membership, also consider relevant group-management events such as 4735, 4756, and other events appropriate to the group scope and environment.

## AD Investigation Checklist

Use this checklist when investigating a potentially compromised or suspicious Active Directory account.

- [ ] Is the account enabled or disabled?
- [ ] Is the account locked out?
- [ ] When was the account created or last modified?
- [ ] Which groups is the account a member of?
- [ ] Does the account have unusual or excessive privileges?
- [ ] What are the account's password settings?
- [ ] Does the account have registered SPNs?
- [ ] Is there unusual authentication activity?
- [ ] Was the account recently added to a privileged group?
- [ ] Are the timestamps consistent with the incident timeline?
- [ ] Do AD findings correlate with endpoint, network, and SIEM evidence?

---

**Operational note:** The Active Directory PowerShell module and appropriate permissions are required for `Get-AD*` commands. Use read-only queries during investigation unless changes are explicitly authorized. Preserve relevant evidence and document the source, timestamps, and limitations of your findings.
