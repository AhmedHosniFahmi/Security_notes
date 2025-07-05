### Content
- [Enumerating ACLs with PowerView](#enumerating-acls-with-powerview)
- [Enumerating ACLs with ActiveDirectory Module](#enumerating-acls-with-activedirectory-module)
- [Enumerating ACLs with BloodHound](#enumerating-acls-with-bloodhound)
---

## Enumerating ACLs with PowerView

Extract and view every ACL in the domain

``` PowerShell
PS C:\> Find-InterestingDomainAcl
```

Find and return only the ACLs where a specific user's SID that we have control of appears.

``` PowerShell
# At first, obtain the SID of the controlled target user.
PS C:\> $sid = Convert-NameToSid wley
# Find all domain objects that our user has rights over
PS C:\> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid} 

ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=DOMAIN,DC=LOCAL
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-1176
ActiveDirectoryRights  : ExtendedRight
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 256
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1181
AceType                : AccessAllowedObject
AceFlags               : ContainerInherit
IsInherited            : False
InheritanceFlags       : ContainerInherit
PropagationFlags       : None
AuditFlags             : None

# You can resolve the ObjectAceType GUID by adding (-ResolveGUIDs) flag before identity filter.
```

The `ObjectAceType : 00299570-246d-11d0-a768-00aa006e0529` GUID value cat be found [here](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb) as User-Force-Change-Password extended right.

This means that the user `wley` with SID `S-1-5-21-3842939050-3880317879-2865463114-1181` have User-Force-Change-Password extended right on the user with SID `S-1-5-21-3842939050-3880317879-2865463114-1176` `damundsen`

We deduce that we can control user `Dana Amundsen`, now we need to know what we have control off as user `Dana Amundsen`
``` PowerShell
# Use (Get-ADUser -Filter "Name -eq 'Dana Amundsen'") to get the SamAccountName of the user Dana Amundsen
PS C:\> $sid2 = Convert-NameToSid damundsen
PS C:\> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose

AceType               : AccessAllowed
ObjectDN              : CN=Help Desk Level 1,OU=Security Groups,OU=Corp,DC=DOMAIN,DC=LOCAL
ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
OpaqueLength          : 0
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-4022
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1176
AccessMask            : 131132
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed
```

User `damundsen` has `GenericWrite` privileges over the `Help Desk Level 1` group with `GenericWrite` rights, So we can add any user (or ourselves) to this group and inherit any rights that this group has applied to it.

Now let's Investigate if the `Help Desk Level 1` group is a member of another parent group.

``` PowerShell
PS C:\> Get-DomainGroup -Identity "Help Desk Level 1" | select memberof

memberof                                                                      
--------                                                                      
CN=Information Technology,OU=Security Groups,OU=Corp,DC=DOMAIN,DC=LOCAL
```

The group `Help Desk Level 1` appeared to be nested from the group `Information Technology`.
Now, Let's see what the group `Information Technology` can control.

``` PowerShell
PS C:\> $itgroupsid = Convert-NameToSid "Information Technology"
PS C:\> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose

......[SNIP]......
AceType               : AccessAllowed
ObjectDN              : CN=Angela Dunn,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=DOMAIN,DC=LOCAL
ActiveDirectoryRights : GenericAll
OpaqueLength          : 0
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-1164
......[SNIP]......
```

Members of the `Information Technology` group have `GenericAll` rights over the user `adunn`, which means we could:
- Modify group membership
- Force change a password
- Perform a targeted Kerberoasting attack and attempt to crack the user's password if it is weak

let's see if the `adunn` user has any type of interesting access:

``` PowerShell
PS C:\> $adunnsid = Convert-NameToSid adunn 
PS C:\> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose
......[SNIP]......
AceQualifier           : AccessAllowed
ObjectDN               : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set
......[SNIP]......
......[SNIP]......
AceQualifier           : AccessAllowed
ObjectDN               : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
......[SNIP]......
```


> [!Tip]
> `adunn` user has `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-In-Filtered-Set` rights over the domain object. This means that this user can be leveraged to perform a `DCSync` attack.

---
## Enumerating ACLs with ActiveDirectory Module

Create a list of domain users or domain groups.

``` PowerShell
PS C:\> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
PS C:\> Get-ADGroup -Filter * | Select-Object -ExpandProperty SamAccountName > ad_groups.txt
```

Loop through the domain users ACLs and select the `Access property`, which will give us information about access rights.

``` Powershell
PS C:\> foreach($line in [System.IO.File]::ReadLines("ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'DOMAIN\\ControledUserName'}}

Path                  : Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=DOMAIN,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
InheritanceType       : All
ObjectType            : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : DOMAIN\ControledUserName
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
```

Perform a Reverse Search & Mapping to a GUID Value

``` Powershell
PS C:\> $guid= "00299570-246d-11d0-a768-00aa006e0529"
PS C:\> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl

Name              : User-Force-Change-Password
DisplayName       : Reset Password
DistinguishedName : CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration,DC=DOMAIN,DC=LOCAL
rightsGuid        : 00299570-246d-11d0-a768-00aa006e0529
```

---

## Enumerating ACLs with BloodHound

search for a user and select the `Node Info` tab and scroll down to `Outbound Control Rights`. 
This option will show us objects we have control over directly, via group membership, and the number of objects that our user could lead to us controlling via ACL attack paths under `Transitive Object Control`.

If we right-click on the line between the two objects, a menu will pop up. If we select `Help`, we will be presented with help around abusing this ACE, including:
- More info on the specific right, tools, and commands that can be used to pull off this attack
- Operational Security (Opsec) considerations
- External references.