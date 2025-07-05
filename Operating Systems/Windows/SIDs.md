### Content

- [SID architecture](#sid-architecture)
- [Well Known SIDs](#well-known-sids)

---

Security Principal is Anything that can be authenticated by the Windows operating system, including user and computer accounts, processes that run in the security context or another user/computer account, or the security groups that these accounts belong to.

- Every single security principal is identified by a unique [Security Identifier (SID)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) for its lifetime.
- Operating system refers to accounts and processes that run in the security context of the account by using their SIDs.
- For domain accounts, the SID  is created by concatenating the domain (SID) with an account (RID).
- SIDs are unique within their scope (domain or local), and they're never reused.

# SID architecture

- A SID is a data structure in binary format that contains a variable number of values.
- The first values in the structure contain information about the SID structure.
- The remaining values are arranged in a hierarchy (similar to a telephone number), and they identify the SID-issuing authority (for example, NT Authority), the SID-issuing domain, and a particular security principal or group.

The following image illustrates the structure of a SID.

<img src="/assets/security-identifier-architecture.png" width="65%" height="70%" style="display: block; margin:auto;">

| Component            | Description                                                                                                                                                                                                                                                                                                                                                                                   |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Revision             | The version of the SID structure that's used in a particular SID.                                                                                                                                                                                                                                                                                                                             |
| Identifier authority | Identifies the highest level of authority that can issue SIDs for a particular type of security principal.<br>For example, the identifier authority value in the SID for the Everyone group is 1 (World Authority).<br>The identifier authority value in the SID for a specific Windows Server account or group is 5 (NT Authority).                                                          |
| Subauthorities       | The most important information in a SID, which is contained in a series of one or more subauthority values. All values up to, but not including, the last value in the series collectively identify a domain in an enterprise. This part of the series is called the domain identifier. The last value in the series, the RID, identifies a particular account or group relative to a domain. |

The components of a SID are easier to visualize when SIDs are converted from a binary to a string format by using standard notation: `S-R-X-Y1-Y2-Yn-1-Yn`
In this notation, the components of a SID are described in the following table:

|Component|Description|
|---|---|
|S|Indicates that the string is a SID|
|R|Indicates the revision level|
|X|Indicates the identifier authority value|
|Y|Represents a series of subauthority values, where _n_ is the number of values|

The SID's most important information is contained in the series of subauthority `Y` values. The first part of the series (`-Y1-Y2-Y_n_-1`) is the domain identifier.
This element of the SID becomes significant in an enterprise with several domains. Specifically, the domain identifier differentiates SIDs that one domain issues from SIDs that all other domains in the enterprise issue. No two domains in an enterprise share the same domain identifier.

The last item in the series of subauthority values (`-Y_n_`) is the RID. It distinguishes one account or group from all other accounts and groups in the domain. No two accounts or groups in any domain share the same RID.

##### Example

Built-in Administrators group SID is represented in standardized SID notation as the following string: `S-1-5-32-544`
This SID has four components:

- A revision level (1)
- An identifier authority value (5, NT Authority)
- A domain identifier (32, Built-in)
- An RID (544, Administrators)


SIDs for built-in accounts and groups always have the same domain identifier value, 32. As they're local to a single computer or, with domain controllers for a network domain, they're local to several computers that are acting as one.
Built-in accounts and groups need to be distinguished from one another within the scope of the Builtin domain. Therefore, the SID for each account and group has a unique RID. An RID value of 544 is unique to the built-in Administrators group.

Every domain in an enterprise has a Domain Admins group, and the SID for each group is different. The following example represents the SID for the Domain Admins group in the Contoso, Ltd. domain (Contoso\Domain Admins):

`S-1-5-21-1004336348-1177238915-682003330-512`

- A revision level (1)
- An identifier authority (5, NT Authority)
- A domain identifier (21-1004336348-1177238915-682003330, Contoso)
- An RID (512, Domain Admins)

When a new domain user or group account is created, Active Directory stores the account's SID in the `ObjectSID` property of a User or Group object.
It also assigns the new object a globally unique identifier (GUID) in its `ObjectGUID` property, which is a 128-bit value that's unique not only in the enterprise, but also across the world.

## Well Known SIDs:

| SID                     | Display name                                     |
| ----------------------- | ------------------------------------------------ |
| S-1-5-1                 | Dialup                                           |
| S-1-5-113               | Local account                                    |
| S-1-5-114               | Local account and member of Administrators group |
| S-1-5-2                 | Network                                          |
| S-1-5-3                 | Batch                                            |
| S-1-5-4                 | Interactive                                      |
| S-1-5-5- _X_-_Y_        | Logon Session                                    |
| S-1-5-6                 | Service                                          |
| S-1-5-7                 | Anonymous Logon                                  |
| S-1-5-8                 | Proxy                                            |
| S-1-5-9                 | Enterprise Domain Controllers                    |
| S-1-5-10                | Self                                             |
| S-1-5-11                | Authenticated Users                              |
| S-1-5-12                | Restricted Code                                  |
| S-1-5-13                | Terminal Server User                             |
| S-1-5-14                | Remote Interactive Logon                         |
| S-1-5-15                | This Organization                                |
| S-1-5-17                | IUSR                                             |
| S-1-5-18                | System (or LocalSystem)                          |
| S-1-5-19                | NT Authority (LocalService)                      |
| S-1-5-20                | NetworkService                                   |
| S-1-5-_domain_-500      | Administrator                                    |
| S-1-5-_domain_-501      | Guest                                            |
| S-1-5-_domain_-502      | KRBTGT                                           |
| S-1-5-_domain_-512      | Domain Admins                                    |
| S-1-5-_domain_-513      | Domain Users                                     |
| S-1-5-_domain_-514      | Domain Guests                                    |
| S-1-5-_domain_-515      | Domain Computers                                 |
| S-1-5-_domain_-516      | Domain Controllers                               |
| S-1-5-_domain_-517      | Cert Publishers                                  |
| S-1-5-_root domain_-518 | Schema Admins                                    |
| S-1-5-_root domain_-519 | Enterprise Admins                                |
| S-1-5-_domain_-520      | Group Policy Creator Owners                      |
| S-1-5-_domain_-521      | Read-only Domain Controllers                     |
| S-1-5-_domain_-522      | Clonable Controllers                             |
| S-1-5-_domain_-525      | Protected Users                                  |
| S-1-5-_root domain_-526 | Key Admins                                       |
| S-1-5-_domain_-527      | Enterprise Key Admins                            |
| S-1-5-32-544            | Administrators                                   |
| S-1-5-32-545            | Users                                            |
| S-1-5-32-546            | Guests                                           |
| S-1-5-32-547            | Power Users                                      |
| S-1-5-32-548            | Account Operators                                |
| S-1-5-32-549            | Server Operators                                 |
| S-1-5-32-550            | Print Operators                                  |
| S-1-5-32-551            | Backup Operators                                 |
| S-1-5-32-552            | Replicators                                      |
| S-1-5-_domain_-553      | RAS and IAS Servers                              |
| S-1-5-32-554            | Builtin\Pre-Windows 2000 Compatible Access       |
| S-1-5-32-555            | Builtin\Remote Desktop Users                     |
| S-1-5-32-556            | Builtin\Network Configuration Operators          |
| S-1-5-32-557            | Builtin\Incoming Forest Trust Builders           |
| S-1-5-32-558            | Builtin\Performance Monitor Users                |
| S-1-5-32-559            | Builtin\Performance Log Users                    |
| S-1-5-32-560            | Builtin\Windows Authorization Access Group       |
| S-1-5-32-561            | Builtin\Terminal Server License Servers          |
| S-1-5-32-562            | Builtin\Distributed COM Users                    |
| S-1-5-32-568            | Builtin\IIS_IUSRS                                |
| S-1-5-32-569            | Builtin\Cryptographic Operators                  |
| S-1-5-_domain_-571      | Allowed RODC Password Replication Group          |
| S-1-5-_domain_-572      | Denied RODC Password Replication Group           |
| S-1-5-32-573            | Builtin\Event Log Readers                        |
| S-1-5-32-574            | Builtin\Certificate Service DCOM Access          |
| S-1-5-32-575            | Builtin\RDS Remote Access Servers                |
| S-1-5-32-576            | Builtin\RDS Endpoint Servers                     |
| S-1-5-32-577            | Builtin\RDS Management Servers                   |
| S-1-5-32-578            | Builtin\Hyper-V Administrators                   |
| S-1-5-32-579            | Builtin\Access Control Assistance Operators      |
| S-1-5-32-580            | Builtin\Remote Management Users                  |
| S-1-5-64-10             | NTLM Authentication                              |
| S-1-5-64-14             | SChannel Authentication                          |
| S-1-5-64-21             | Digest Authentication                            |
| S-1-5-80                | NT Service                                       |
| S-1-5-80-0              | All Services                                     |
| S-1-5-83-0              | NT VIRTUAL MACHINE\Virtual Machines              |


