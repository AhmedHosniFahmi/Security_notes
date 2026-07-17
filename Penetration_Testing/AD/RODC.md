### Content

- [Overview](#overview)
	- [The RODC Filtered Attribute Set (FAS)](#the-rodc-filtered-attribute-set-(fas))
	- [RODC Management](#rodc-management)
	- [RODC Authentication](#rodc-authentication)
- [Enumeration](#enumeration)


> Resource:
> - [At the Edge of Tier Zero: The Curious Case of the RODC](https://specterops.io/blog/2023/01/25/at-the-edge-of-tier-zero-the-curious-case-of-the-rodc/) from SpecterOps.
> - [RDOC](https://www.thehacker.recipes/ad/movement/builtins/rodc#rodc-management) from The Hacker Recipes
> - [Read-Only DCs and the Active Directory Schema](https://learn.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema) and [RODC Filtered Attribute Set, Credential Caching, and the Authentication Process with an RODC](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753459(v=ws.10)#credential-caching) which are great from Microsoft Learn
> - [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory](https://adsecurity.org/?p=3592) 


---
### Overview

The read-only Domain Controller (RODC) is a solution that Microsoft introduced for physical locations that don’t have adequate security to host a Domain Controller but still require directory services for resources in those locations. A branch office is the classic use case.

#### The RODC Filtered Attribute Set (FAS)

(FAS) is a configurable set of AD schema attributes that are blocked from replicating to Read-Only Domain Controllers, designed to protect sensitive credential-like data (passwords, keys, etc.) in case an RODC is physically compromised.

Any attribute added to the FAS is stripped from RODC replication entirely. One hard limitation is that system-critical attributes (those required by `AD DS`, `LSA`, `SAM`, or `Kerberos` — identifiable by `schemaFlagsEx` & 0x1 = TRUE) cannot be added to the FAS, as blocking their replication would break core domain functionality.

#### RODC Management

Any user or group specified in the `managedBy` attribute of an RODC has local admin access to the RODC server.

If you compromise:

- An account listed in the `managedBy` attribute of an RODC, you have local admin on the RODC.
- An account with delegated rights to modify the `managedBy` attribute of an RODC, you can make yourself an admin.

#### RODC Authentication

For a principal to authenticate locally, the RODC must be allowed to retrieve his credentials. Only users, groups and computers that are in the [msDS-RevealOnDemandGroup](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-revealondemandgroup) and not in [msDS-NeverRevealGroup](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-neverrevealgroup) may have their credentials [cached](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753459\(v=ws.10\)#credential-caching) on the RODC to be used for future local authentication (in this case, their principal name IDs are added to its [msDS-Revealed-List](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-revealedlist) attribute).

The attributes `msDS-RevealOnDemandGroup` and `msDS-NeverRevealGroup` define the [Password Replication Policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc730883\(v=ws.10\)) of the RODC.

> The default PRP (Password Replication Policy) specifies that no account passwords can be cached on any RODC, and certain accounts are explicitly denied from being cached on any RODC.

If credentials are cached, the RODC authenticates locally and issues a TGT signed/encrypted with its own derived krbtgt key: `krbtgt_XXXXX` where `XXXXX` = random version number. This version number is stored in `msDS-SecondaryKrbTgtNumber` attribute of the krbtgt account.

> The RODC computer account holds reset rights on `krbtgt_XXXXX`'s password.

The generated TGT includes the `kvno` field, indicating which key version was used to sign it. With this TGT, the principal can request a Service Ticket (ST) against the RODC or any writable DC, as long as the principal is in `msDS-RevealOnDemandGroup` and not in `msDS-NeverRevealGroup.`

The TGT requesting process from The Hacker Recipes


<img src="/assets/RODC_tgt_request.png">


The TGS requesting process from The Hacker Recipes


<img src="/assets/RODC_tgs_request.png">


---
### Enumeration

From Linux:

```bash
$ bloodyad --host dc01.garfield.htb -d garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' get object 'RODC01$' --resolve-sd         


msDFSR-ComputerReferenceBL: CN=RODC01,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=garfield,DC=htb
msDS-AuthenticatedAtDC: CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb
msDS-AuthenticatedToAccountlist: CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb; CN=DC01,OU=Domain Controllers,DC=garfield,DC=htb; CN=Administrator,CN=Users,DC=garfield,DC=htb
msDS-KrbTgtLink: CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb
msDS-NeverRevealGroup: CN=Denied RODC Password Replication Group,CN=Users,DC=garfield,DC=htb; CN=Account Operators,CN=Builtin,DC=garfield,DC=htb; CN=Server Operators,CN=Builtin,DC=garfield,DC=htb; CN=Backup Operators,CN=Builtin,DC=garfield,DC=htb; CN=Administrators,CN=Builtin,DC=garfield,DC=htb
msDS-RevealOnDemandGroup: CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb
msDS-RevealedDSAs: CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb; CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb; CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb; CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb; CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb
msDS-RevealedUsers: 
<SNIP>
B:96:A00009000700000052D8D41E03000000CC2053E8BC5706489E8A6EA5D630B51B9DB10000000000009DB1000000000000:CN=Administrator,CN=Users,DC=garfield,DC=htb; B:96:7D0009000700000052D8D41E03000000CC2053E8BC5706489E8A6EA5D630B51B9EB10000000000009EB1000000000000:CN=Administrator,CN=Users,DC=garfield,DC=htb; B:96:5E0009000700000052D8D41E03000000CC2053E8BC5706489E8A6EA5D630B51B9DB10000000000009DB1000000000000:CN=Administrator,CN=Users,DC=garfield,DC=htb; B:96:5A0009000700000052D8D41E03000000CC2053E8BC5706489E8A6EA5D630B51B9DB10000000000009DB1000000000000:CN=Administrator,CN=Users,DC=garfield,DC=htb; B:96:370009000700000052D8D41E03000000CC2053E8BC5706489E8A6EA5D630B51B9DB10000000000009DB1000000000000:CN=Administrator,CN=Users,DC=garfield,DC=htb
msDS-SupportedEncryptionTypes: 28
nTSecurityDescriptor.Owner: Domain Admins
[SNIP]
```

From Windows

```PowerShell
# using ActiveDirectory module
PS C:\> Get-ADComputer "RODC01" -Property * | Select Name,ManagedBy,'msDS-AuthenticatedToAccountlist','msDS-NeverRevealGroup','msDS-RevealedDSAs','msDS-RevealedUsers','msDS-RevealOnDemandGroup'


Name                            : RODC01
ManagedBy                       :
msDS-AuthenticatedToAccountlist : {CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb, CN=DC01,OU=Domain Controllers,DC=garfield,DC=htb, CN=Administrator,CN=Users,DC=garfield,DC=htb}
msDS-NeverRevealGroup           : {CN=Denied RODC Password Replication Group,CN=Users,DC=garfield,DC=htb, CN=Account Operators,CN=Builtin,DC=garfield,DC=htb, CN=Server Operators,CN=Builtin,DC=garfield,DC=htb, CN=Backup
                                  Operators,CN=Builtin,DC=garfield,DC=htb...}
msDS-RevealedDSAs               : {CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb, CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb, CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb, CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb...}
msDS-RevealedUsers              : {B:96:A000090002000000DB512A200300000089319147AA5D0949B0489270A3B2AAD9C673020000000000C673020000000000:CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb,
                                  B:96:7D00090002000000DB512A200300000089319147AA5D0949B0489270A3B2AAD9C773020000000000C773020000000000:CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb,
                                  B:96:5E00090002000000DB512A200300000089319147AA5D0949B0489270A3B2AAD9C673020000000000C673020000000000:CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb,
                                  B:96:5A00090002000000DB512A200300000089319147AA5D0949B0489270A3B2AAD9C673020000000000C673020000000000:CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb...}
msDS-RevealOnDemandGroup        : {CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb}
```