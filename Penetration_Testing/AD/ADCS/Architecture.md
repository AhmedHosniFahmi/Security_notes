### Content

- [Key Terminologies in ADCS](#key-terminologies-in-adcs)
- [Certificates](#certificates)
- [Certificate Authorities](#certificate-authorities)
- [Public Key Services Container](#public-key-services-container)
- [Certificate Templates](#certificate-templates)
- [Enrollment Process](#enrollment-process)
- [Issuance Requirements](#issuance-requirements)
- [Certificate Mapping](#certificate-mapping)
	- [CVE-2022-26923 (Certifried)](#cve-2022-26923-(certifried))
	- [New Controls](#new-controls)
		- [Mapping Methods](#mapping-methods)
			- [Kerberos Certificate Mapping](#kerberos-certificate-mapping)
			- [Schannel Certificate Mapping](#schannel-certificate-mapping)
- [Issuance Policy](#issuance-policy)
- [Enumeration](#enumeration)
	- [From Windows](#from-windows)
	- [From Linux](#from-linux)

---
### Key Terminologies in ADCS

- `Public Key Infrastructure (PKI)`: Full system managing certificate lifecycle via CAs and public key cryptography.
- `Certificate Authority (CA)`: Entity that issues and manages certificate validity.
- `Certificate Templates`: Predefined or custom blueprints defining certificate properties (purpose, key size, validity, policies) that a principal can enroll into.
- `Certificate Enrollment`: Process where an entity requests and receives a certificate after identity verification.
- `Certificate Manager`: Role handling certificate issuance, management, and revocation authorization.
- `Digital Certificate`: Electronic document binding an identity to a public key for authentication.
- `Certificate Revocation`: Invalidation of compromised/expired certificates via Certificate Revocation Lists (CRLs) or Online Certificate Status Protocol (OCSP).
- `Key Management`: Mechanisms ensuring secure handling and usage of private keys.
- `Backup Operator`: Role with rights to backup/restore CA data, manage AD CS service, and read CA records.
- `Standalone CAs`: AD-independent CAs handling certificate requests manually or via web.
- `Enterprise CAs`: AD-integrated CAs automating certificate issuance via Group Policy or Enrollment Web Services.
- `Certificate Signing Requests (CSRs)`: Signed requests containing a public key and identity info, submitted to a CA for certificate issuance.
- `Certificate Revocation List (CRL)`: CA-signed list of all revoked certificates for status verification.
- `Extended/Enhanced Key Usages (EKUs)`: Certificate extensions restricting usage to specific scenarios (e.g., code signing, smart card logon).

---
### Certificates

A certificate is an `X.509-formatted digitally signed document` used for encryption, message signing, and authentication. It consists of multiple key fields:

- `Subject`: The certificate owner's identity.
- `Public Key`: Links the Subject to a separate private key.
- `NotBefore` and `NotAfter` dates: Define the certificate's validity duration.
- `Serial Number`: A unique identifier assigned by the issuing CA.
- `Issuer`: Identifies the certificate issuer, often a CA.
- `SubjectAlternativeName (SAN)`: Alternative names associated with the Subject.
- `Basic Constraints`: Specify if the certificate is a CA or end entity, along with any usage constraints.
- `Extended Key Usages (EKUs)`: Object identifiers describing specific usage scenarios for the certificate. Common EKUs cover functionalities like code signing, encrypting file systems, secure email, client and server authentication, and smart card logon.
- `Signature Algorithm` and `Signature`: Indicate the algorithm used for signing the certificate and the resulting signature made with the issuer's private key.

The certificate's content links an identity (`the Subject`) to a `key pair`, enabling applications to utilize this key pair in operations as evidence of the user's identity.

---
### Certificate Authorities

CA is responsible for the issuance of certificates, validating digital identities, enabling secure communications, and establishing trust within networks. The root CA certificate is created by the CA itself through the signing of a new certificate using its private key (the root CA certificate is self-signed).

ADCS is responsible for setting the certificate's :

- Subject and Issuer fields to the CA's name.
- Basic Constraints to Subject Type=CA.
- NotBefore/NotAfter fields are set to five years by default.

After creating the self-signed certificates, the domain's hosts can add the root CA certificate to their trust store to establish a trust relationship with the CA.

---
### Public Key Services Container

All ADCS related containers are stored in configuration naming context under Public Key Services container: `CN=Public Key Services,CN=Services,CN=Configuration,DC={forest root domain},DC={root domain}`. 

Under Public Key Services container you find the following subcontainers:

- AIA
- CDP
- Certificate Templates
- Certification Authorities
- Enrollment Services
- KRA
- OID

and the following entry (not a container):

- NTAuthCertificates

ADCS stores trusted root CA certificates in four locations under the container `CN=Public Key Services,CN=Services,CN=Configuration,DC=,DC=`. These include:

- `Certification Authorities` container:
	- Used to store trusted root certificates.
	- Contains objects of `certificateAuthority` type.
	- CA certificates are written to `cACertificate` attribute.
	- Domain joined machines add these CA certificates into their trusted root certification authorities store.
- `Enrollment Services` container:
	- Used to store Enterprise CA objects.
		- These objects encapsulate key attributes such as `pKIEnrollmentService` `objectClass`, `cACertificate` data, `dNSHostName` defining the CA's DNS, and `certificateTemplates` outlining the certificate configurations.
	- Clients use this container to locate Enterprise CAs in the forest.
	- The certificates issued by Enterprise CAs are deployed to the Intermediate Certification Authorities store on Windows machines.
- `NTAuthCertificates` AD object:
	- Used to store certificates for CAs that are eligible to issue smart card logon certificates and perform client private key archival in CA database.
	- Windows devices in AD networks integrate these CAs into their Intermediate Certification Authorities store.
	- Authentication to AD using certificates require that client certificates being signed by one of the CAs listed within NTAuthCertificates.
- `AIA (Authority Information Access)` container:
	- Used to store intermediate CA certificates and cross-certificates.
	- Contains entries of `certificateAuthority` type.
		- CA certificates are written to `cACertificate` attribute
		- Cross-Certificates are written to `crossCertificatePair` attribute.
	- All certificates from this container are propagated to each client as a part of group policy processing to client’s Intermediate Certification Authorities container.


One can view the status of the certificates in these containers (and other AD-CS-related containers) by opening the pkiview.msc MMC snap-in, right clicking on the Enterprise PKI object, and clicking Manage AD Containers.

<img src="/assets/ADCS_root_CA_certificate_place0.png">

Additionally, any LDAP browsing tool such as such as the adsiedit.msc or ldp.exe can view the raw information about these containers.

<img src="/assets/ADCS_root_CA_certificate_place.png">

---
### Certificate Templates

- Used to establish certificate settings that include enrollment policies, validity duration, intended usage, subject specifications, and requester eligibility.
- Managed through the Certificate Templates feature and stored as `pKICertificateTemplate` AD objects.
- Their settings are defined through attributes.
- Their enrollment permissions and template edits controller through their security descriptor.
- Have `pKIExtendedKeyUsage` attribute within their AD certificate template object, which contains a cluster of enabled `OIDs (Object Identifier)` that impact the permissible uses of the certificate. `OIDs` refer to functionalities such as:
	- Client Authentication: `1.3.6.1.5.5.7.3.2`
	- PKINIT Client Authentication: `1.3.6.1.5.2.3.4`
	- Smart Card Logon: `1.3.6.1.4.1.311.20.2.2`
	- Any Purpose: `2.5.29.37.0`
	- SubCA: `(no EKUs)`

---
### Enrollment Process

1. `Find an Enterprise CA`: Based on the objects in the Enrollment Services container.
2. `Generate a public-private key pair and create a CSR`
	1. Client generate a public-private key pair
	2. Client create a certificate signing request (CSR) message which contains the public key, the certificate template name, the subject of the certificate and various other details.
3. `Client sign the CSR with private key and send to Enterprise CA server`
4. `CA check if the client is authorized to request certificates`: If the client is authorized, the CA looks up the certificate template AD object specified in the CSR to determine whether or not to issue a certificate. The CA checks if the certificate template AD object's permissions allow the authenticating account to obtain a certificate.
5. `CA generate the certificate, sign it and if allowed, sends it to the client`: If the permissions allow, the CA generates a certificate using the settings defined by the certificate template, such as EKUs, cryptography settings, and issuance requirements. If allowed by the certificate's template settings, the CA uses other information supplied in the CSR and signs the certificate using its private key and returns it to the client.
6. `The Client receives the certificate`: Once received, it is stored in the Windows Certificate Store. The certificate can then be used for specific purposes as defined by the Extended Key Usage (EKU) Object Identifier (OID) included within it.

---
### Issuance Requirements

Beside inherent restrictions within the certificate template and the Enterprise CA access controls, there are two additional settings used to control certificate enrollment:

1. CA certificate manager approval:
   triggers `CT_FLAG_PEND_ALL_REQUESTS (0x2)` bit within the AD object's `msPKI-EnrollmentFlag` attribute. As a result, all certificate requests based on the template are placed into a pending state, visible within the **Pending Requests** section in `certsrv.msc`. This requires a certificate manager's approval or denial before the certificate can be issued.
2. This number of authorized signatures and application policy:
	1. The first specify how many co-sign the CSR should get before the CA accepts to sign it.
	2. The second forces the CA to verify that the certificate used to sign a CSR carries a specific EKU OID before accepting the request. This ensures only holders of a designated certificate type (e.g., Certificate Request Agent) can sign CSRs, preventing arbitrary users from submitting requests on behalf of others.

To access those settings in the ADCS server:

Certification Authority console running (`certsrv.msc`) -> right click on Certificate Templates -> click Manage, which will open Certificate Template Console -> right click on any template -> click on properties -> select the tab `Issuance Requirements`:

<img src="/assets/ADCS_issuance_requirements.png">

---
### Certificate Mapping

Certificate mapping is the process of associating an issued certificate with the AD account it belongs to, ensuring a certificate presented for authentication actually belongs to the claiming user and not someone else.

Why was certificate mapping introduced? because of **CVE-2022-26923 (Certifried)**

#### CVE-2022-26923 (Certifried)

user accounts and computer accounts. Both can enroll in certificate templates, but they use different attributes for certificate mapping:

- User use the attribute `UserPrincipalName (UPN)` in `SubjectAltName (SAN)`
- Computer use the attribute `dNSHostName` or `UPN` in `SubjectAltName (SAN)`

When a certificate is issued for authentication, the CA maps it back to an AD account using the SAN field of the certificate. For computer accounts, this mapping is done via the `dNSHostName` attribute. 

**The Flaw**: Domain user can create a computer account (by default `ms-DS-MachineAccountQuota = 10`) and modify its `dNSHostName` attribute , even setting it to the DNS name of a Domain Controller.

Attack Flow:

1. Create a computer account (allowed by default via `MachineAccountQuota`)
2. Modify the computer account's `dNSHostName` to match the DC's DNS name (`dc01.lab.local`)
3. Request a certificate for that computer account via a template that allows computer enrollment (e.g., Machine template)
4. CA issues the certificate with dc01.lab.local in the SAN
5. Attacker uses the certificate to authenticate via Kerberos PKINIT
6. CA implicitly maps the certificate to the DC account (via `dNSHostName` match)
7. Attacker receives a TGT as the Domain Controller account
8. DCSync

#### New Controls

Microsoft has implemented a new security extension for issued certificates, along with two registry keys to properly handle certificate mapping.

- `szOID_NTDS_CA_SECURITY_EXT` is a new certificate extension which is automatically embedded into every issued certificate and contains the `objectSid` of the requester.

And two new registry keys:

- `StrongCertificateBindingEnforcement` -> Kerberos implicit mapping
- `CertificateMappingMethods` -> Schannel implicit mapping.

Both keys share the same three modes:

1. `Disabled (0)`: No strong mapping enforced, deprecated since April 2023, no longer valid.
2. `Compatibility (1)`: Uses strong mapping if available, falls back to weak mapping with a warning event.
3. `Full Enforcement`: Auth fails if certificate doesn't contain `szOID_NTDS_CA_SECURITY_EXT`

##### Mapping Methods

1. Explicit Mapping: The administrator manually links a certificate to an account by writing the certificate's identifier directly into the account's `altSecurityIdentities` attribute. Authentication requires:
	1. Certificate signed by a trusted CA
	2. Certificate identifier matches the `altSecurityIdentities` value exactly
2. Implicit Mapping: The CA automatically maps the certificate to an account using information already inside the certificate with the DNS or the UPN (`userPrincipalName`) field.

###### Kerberos Certificate Mapping

During Kerberos authentication, the KDC refers to this registry key `StrongCertificateBindingEnforcement` to decide how strictly a certificate must be tied to an AD account before authentication is allowed:

- Disabled mode (0): No strong mapping enforced. The `szOID_NTDS_CA_SECURITY_EXT` extension is completely ignored and the KDC falls back to weak implicit mapping.
- Compatibility mode (1):
	- The KDC first checks for explicit certificate mapping is present in account's `altSecurityIdentities` . If absent:
		- It checks for `szOID_NTDS_CA_SECURITY_EXT`. If that's also absent:
			- Authentication is still allowed if the user account predates the certificate.
- Full Enforcement mode (2):
	- The KDC first checks if explicit certificate mapping is present in account's `altSecurityIdentities`. If yes, the authentication is allowed; if no:
		- It checks for `szOID_NTDS_CA_SECURITY_EXT`, If it is not present or invalid, the authentication is refused.

How does mapping work?

If the registry key value is 0:

- If the registry key value is 0 and the certificate contains a UPN value (used for a user account):
	- The KDC will first attempt to map the certificate to a user with a matching `userPrincipalName` value. If no validation can be performed:
		- The KDC will search for an account with a matching `sAMAccountName` property. If none can be found:
			- It will retry with a $ at the end of the username. Therefore, a certificate with a UPN can be mapped to a machine account.

- If the registry key value is 0 and the certificate contains a DNS value (used for a machine account):
	- The KDC splits the username (ex: `machine.corp.local`) into two parts:
		- The domain: `corp.local` which will be validated against the AD domain
		- The user: `machine` which will be validated by adding a $ at the end and searching for an account with a corresponding `sAMAccountName`.

If the registry key value is 1 or 2, the `szOID_NTDS_CA_SECURITY_EXT` security extension will be used to map the account using its `objectSid`. If the registry key is set to 1 and no security extension is present, the mapping behavior is similar to a registry key value of 0.

###### Schannel Certificate Mapping

During Schannel (TLS) authentication, this registry key `CertificateMappingMethods` controls which methods are used to map a client certificate to an AD account. Multiple values can be combined to enable multiple mapping methods simultaneously.

- `0x0001`: Subject/issuer explicit mapping
- `0x0002`: Issuer explicit mapping
- `0x0004`: SAN implicit mapping
- `0x0008`: S4USelf implicit Kerberos mapping
- `0x0010`: S4USelf explicit Kerberos mapping

The current default value is `0x18` (`0x8` and `0x10`). Schannel doesn't directly support the `szOID_NTDS_CA_SECURITY_EXT` security extension, but it can utilize it by "converting" the Schannel certificate mapping to a Kerberos certificate mapping using S4USelf. The mapping process will then be performed as explained in [Kerberos Certificate Mapping](#kerberos-certificate-mapping)

If any certificate authentication issues arise in an Active Directory environment, Microsoft has officially recommended setting the `CertificateMappingMethods` value to `0x1f` (the old value).


> Schannel (Secure Channel): A built-in Windows TLS/SSL engine, responsible for encrypting and authenticating network communications on Windows. Just as Kerberos is the protocol Windows uses to authenticate users within the domain (issuing tickets to prove identity), Schannel handles authentication at the TLS layer — when a client connects to a service over HTTPS, LDAPS, or RDP for example, Schannel is what negotiates the encryption and, when client certificates are involved, maps the presented certificate back to an AD account to determine who is authenticating.

Windows has multiple SSPs which are managed by LSASS, each responsible for a different authentication protocol:

| SSP           | What it Handles                        |
| ------------- | -------------------------------------- |
| Schannel      | TLS/SSL, certificate-based auth        |
| Kerberos      | Kerberos tickets, PKINIT               |
| NTLM (msv1_0) | NTLMv1, NTLMv2 challenge-response      |
| Negotiate     | Auto-selects between Kerberos and NTLM |
| Digest        | HTTP Digest authentication             |
| CredSSP       | RDP Network Level Authentication (NLA) |

---
### Issuance Policy

You can imagine that an issuance policy is like a label represented as an `OID`, which will be embedded into a certificate when a CA issues it. And administrator can configure these issuance policy OIDs at the certificate template level at the template's  `msPKI-Certificate-Policy` attribute.

<img src="/assets/ADCS_issuance_policy.png">

Displaying the `msPKI-Certificate-Policy` attribute of a specific template will only display the issuance policies OIDs:

```Powershell
PS C:> Get-ADObject "CN=MyTemplate,$TemplateContainer" -Properties msPKI-Certificate-Policy

DistinguishedName        : CN=MyTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=dumpster,DC=fire
msPKI-Certificate-Policy : {0.4.0.1862.1.4, 1.3.6.1.4.1.311.21.8.4571196.1884641.3293620.10686285.12068043.134.14350251.6856375, 1.3.6.1.4.1.311.21.31}
Name                     : MyTemplate
ObjectClass              : pKICertificateTemplate
ObjectGUID               : d8afc3b5-d46e-4b07-bde3-525e51cccd6b
```

###### msPKI-Enterprise-Oid

As a fact, an issuance policy isn't just a label or an OID, it's an Active Directory objects of the class `msPKI-Enterprise-Oid` which lives in the PKI OID container: `CN=OID,CN=Public Key Services,CN=Services,CN=Configuration`. Issuance policies objects can be listed as following:

```Powershell
PS C:> Get-ADObject -Filter * -SearchBase $OIDContainer -Properties DisplayName,msPKI-Cert-Template-OID

...

DisplayName             : Low Assurance
DistinguishedName       : CN=400.1C3418CDEC5F144B867AB87CECD684B2,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=dumpster,DC=fire
msPKI-Cert-Template-OID : 1.3.6.1.4.1.311.21.8.4571196.1884641.3293620.10686285.12068043.134.1.400
Name                    : 400.1C3418CDEC5F144B867AB87CECD684B2
ObjectClass             : msPKI-Enterprise-Oid
ObjectGUID              : b378917c-9687-4bad-9da2-bde53159e337

DisplayName             : Medium Assurance
DistinguishedName       : CN=401.EDD449C54F4DC0B1EDD89320E4B5D353,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=dumpster,DC=fire
msPKI-Cert-Template-OID : 1.3.6.1.4.1.311.21.8.4571196.1884641.3293620.10686285.12068043.134.1.401
Name                    : 401.EDD449C54F4DC0B1EDD89320E4B5D353
ObjectClass             : msPKI-Enterprise-Oid
ObjectGUID              : 6e146426-a64d-402d-9f25-83d3a6fd2492

DisplayName             : High Assurance
DistinguishedName       : CN=402.1BC1CD66F67C8135F9617DAB96A5C2E8,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=dumpster,DC=fire
msPKI-Cert-Template-OID : 1.3.6.1.4.1.311.21.8.4571196.1884641.3293620.10686285.12068043.134.1.402
Name                    : 402.1BC1CD66F67C8135F9617DAB96A5C2E8
ObjectClass             : msPKI-Enterprise-Oid
ObjectGUID              : 3fe83888-07d6-48f1-a308-9efd254cde20
...
```

Organizations might use issuance policies to apply access controls wherever certificates are used. A classic example is setting an enrollment requirement on a template so that **the enrollee has to sign with a certificate that already carries a specific issuance policy**, which is required to prove they've already been issued a certificate of a certain privilege level before they can get a more privileged one.

<img src="/assets/ADCS_issuance_policy_required.png">

You can use `certutil.exe` to dump the content of a certificate (including the issuance policies embedded into it), `certutil` will try to resolve the OID of the issuance policy to display its human readable name  

```powershell
PS C:> certutil -Dump .mycert.pem
X509 Certificate:
Version: 3
...
Certificate Extensions: 10
...
    2.5.29.32: Flags = 0, Length = 43
    Certificate Policies
        [1]Certificate Policy:
             Policy Identifier=Secure Signature Creation Device Qualified Certificate
        [2]Certificate Policy:
             Policy Identifier=MyIssuancePolicy
        [3]Certificate Policy:
             Policy Identifier=Endorsement Key Certificate Verified
...
```

###### msDS-OIDToGroupLink

The AD class of issuance policies (`msPKI-Enterprise-Oid`) has an attribute called [msDS-OIDToGroupLink](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-oidtogrouplink).

It's an attribute that lets you link an issuance policy to an AD group. You set it by putting the distinguished name of the target group as the value. So the issuance policy object now has a pointer to a group.

When a user performs client authentication with a certificate that carries that issuance policy OID, the KDC will:

1. See the OID in the cert.
2. Resolve it to the linked group via `msDS-OIDToGroupLink` attribute.
3. Inject that group's SID into the user's Kerberos PAC.

Meaning the user gets an access token that says they're a member of that group, even if they're not actually a member of it in AD.





---
## Enumeration

> The ADCS server might be installed on the Domain Controller, but in most cases, organizations prefer installing this service on an independent server.

### From Windows

`Cert Publishers` group authorizes `Certificate Authorities` to publish certificates to the directory, indicating the presence of an ADCS server. That means that the ADCS server will be a member of this group.

```powershell
PS C:\> net localgroup "Cert Publishers"
```

Using `ActiveDirectory`.

```PowerShell
# Getting the domain root name
$configNC = (Get-ADRootDSE).configurationNamingContext

# List all PKI-related containers
Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,$configNC"

# Enumerate Certificate Authorities (CAs)
Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC" -Filter {ObjectClass -eq "pKIEnrollmentService"} -Properties * | select Name, DisplayName, DNSHostName, CACertificateDN, CertificateTemplates, DistinguishedName
```

Using `Certify.exe` from the [Certify Github](https://github.com/GhostPack/Certify) or the binary compiled in the [SharpCollection repository](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_x64/Certify.exe).

```PowerShell
.\Certify.exe find
```

Using [PSPKI's PowerShell module](https://github.com/PKISolutions/PSPKI).

```PowerShell
# Enumerate the Cirtificate Authorities in the environment
PS C:\> Get-CertificationAuthority | fl


Name                : lab-LAB-DC-CA
DisplayName         : lab-LAB-DC-CA
ComputerName        : LAB-DC.lab.local
ConfigString        : LAB-DC.lab.local\lab-LAB-DC-CA
DistinguishedName   : CN=lab-LAB-DC-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local
Type                : Enterprise Root CA
IsEnterprise        : True
IsRoot              : True
OperatingSystem     : Microsoft Windows Server 2019 Standard
IsAccessible        : True
RegistryOnline      : True
ServiceStatus       : Running
SetupStatus         : ServerInstall, ClientInstall, SecurityUpgraded, ServerIsUptoDate
Certificate         : [Subject]
                        CN=lab-LAB-DC-CA, DC=lab, DC=local

                      [Issuer]
                        CN=lab-LAB-DC-CA, DC=lab, DC=local

                      [Serial Number]
                        ...

                      [Not Before]
                        ...

                      [Not After]
                        ...

                      [Thumbprint]
                        ...

EnrollmentEndpoints : {https://lab-dc.lab.local/lab-LAB-DC-CA_CES_Kerberos/service.svc/CES}

# Enumerate the rights over a certificate authority server
PS C:\tools> Get-CertificationAuthority -ComputerName LAB-DC.lab.local | Get-CertificationAuthorityAcl | select -ExpandProperty access


Rights            : Enroll
AccessControlType : Allow
IdentityReference : NT AUTHORITY\Authenticated Users
IsInherited       : False
InheritanceFlags  : None
PropagationFlags  : None

Rights            : ManageCA, ManageCertificates
AccessControlType : Allow
IdentityReference : BUILTIN\Administrators
IsInherited       : False
InheritanceFlags  : None
PropagationFlags  : None

Rights            : ManageCA, ManageCertificates
AccessControlType : Allow
IdentityReference : LAB\Domain Admins
IsInherited       : False
InheritanceFlags  : None
PropagationFlags  : None

Rights            : ManageCA, ManageCertificates
AccessControlType : Allow
IdentityReference : LAB\Enterprise Admins
IsInherited       : False
InheritanceFlags  : None
PropagationFlags  : None
```

Using `certutil.exe`.

```PowerShell
# Enumerate the value of the CA's flags:
PS C:\> certutil.exe -config "LAB-DC.lab.local\lab-LAB-DC-CA" -getreg "policy\EditFlags"
```

### From Linux

```bash
# Using nxc to identify if there are ADCS servers in the Domain
$ netexec ldap <IP> -u user -p pass -M adcs

# Using Certipy to enumerate ADCS Service
$ certipy find -u 'user@corp.local' -p 'pass' -dc-ip <IP> -target <DC_FQDN> -stdout
# Add -vulnerable flag to show the vulnerable templates
```

---