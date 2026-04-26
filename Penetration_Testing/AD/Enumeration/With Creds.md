### Content

- [From Linux](#from-linux)
	- [NXC](#nxc)
	- [SMBMap](#smbmap)
	- [rpcclient](#rpcclient)
	- [Impacket](#impacket)
	- [Windapsearch](#windapsearch)
	- [BloodHound](#bloodhound)
- [From Windows](#from-windows)
	- [ActiveDirectory Module](#activedirectory-module)
	- [Nltest](#nltest)
	- [PowerView](#powerview)
	- [Snaffler](#snaffler)
	- [Living Off the Land](#living-off-the-land)
		- [Basic Enumeration](#basic-enumeration)
		- [Network Enumeration](#network-enumeration)
		- [WMI](#wmi)
		- [NET](#net)
		- [Dsquery](#dsquery)
			- [userAccountControl Values](#useraccountcontrol-values)

> [!Note]
> Enumerate the domain DCs:
> 
> - Using PowerShell `ActiveDirectory` module
> 
> `Get-ADDomainController -filter * | select IPv4Address` 
> 
> - Using native PowerShell
> 
> `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | select IPAddress`
> 
> - Using `Nslookup` (will work if the DC runs DNS)
> 
> `nslookup`
> `Set type=all`
> `_ldap._tcp.dc._msdcs.DOMAIN.COM`
> 
> - Using CMD - `nltest`
>   
>   `nltest /dclist:domain_name` -> finds all domain controllers in a specific domain.

---
## From Linux

#### NXC

``` bash
# Domain User Enumeration (retrieve a list of all domain users).
$ nxc smb 172.16.5.5 -u username -p password --users
# List of domain groups.
$ nxc smb 172.16.5.5 -u username -p password --groups
# List logged on users
$ nxc smb 172.16.5.130 -u username -p password --loggedon-users
# Shares enumeartion
$ nxc smb 172.16.5.5 -u username -p password --shares
# The module spider_plus will dig through each readable share on the host and list all readable files.
$ nxc smb 172.16.5.5 -u username -p password -M spider_plus --share 'Department Shares'
# When completed, CME writes the results to a JSON file located at /tmp/cme_spider_plus/<ip of host>.
```

#### SMBMap

``` bash
# Shares enumeartion
$ smbmap -u username -p password -d DOMAIN.LOCAL -H 172.16.5.5
# Recursive List Of All Directories
$ smbmap -u username -p password -d DOMAIN.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```

#### rpcclient

``` bash
# Abuse SMB NULL session
$ rpcclient -U "" -N 172.16.5.5
# Enumerate all usernames after logging in with credentials or abusing the SMB NULL session
rpcclient $> enumdomusers
user:[administrator] rid:[0x1f4]
user:[guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
# Enumerate specific user
rpcclient $> queryuser 0x1f4
```

#### Impacket

``` bash
# To connect to a host with psexec.py, we need credentials for a user with local administrator privileges.
# psexec.py utilizes an interactive shell
$ psexec.py domain.local/username:'password'@IP

# Wmiexec.py utilizes a semi-interactive shell
# This is a more stealthy approach
$ wmiexec.py domain.local/username:'password'@IP 
```

#### Windapsearch

``` bash
# Enumerate domain admins group members
$ python3 windapsearch.py --dc-ip 172.16.5.5 -u user@domain.local -p password --da
# Find privileged users
$ python3 windapsearch.py --dc-ip 172.16.5.5 -u user@domain.local -p password -PU
```

#### BloodHound

[BloodHound Cypher Cheatsheet](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)

```bash
$ bloodhound-ce-python -c All -d 'DOMAIN.LOCAL' -u 'USER' -p 'PASS' -ns <DC-IP> --dns-tcp
$ zip -r file.zip *.json
# Upload data the zip file into BlooHound
```

---
## From Windows
#### ActiveDirectory Module

[ActiveDirectory PowerShell module ](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps)

``` Powershell
# Check whether the module is imported and import it if not
PS C:\Users> get-module
# If it's not there, install its sub feature (Server machine)
PS C:\Users> Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature
# windows 10/11
Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"

# Import it if it's not imported
PS C:\Users> import-module ActiveDirectory

# Get Domain Info
PS C:\Users> Get-ADDomain
# Search for a user by a specific Properity
PS C:\Users> Get-ADUser -Filter {samAccountName -like "todd.wolfe"} | select *
# Extract all domain admin privileged users accounts
PS C:\Users> Get-ADUser -Filter * -Properties adminCount | Where-Object { $_.adminCount -eq 1 }
# filtering for accounts with the ServicePrincipalName property populated.
# This will get us a listing of accounts that may be susceptible to a Kerberoasting attack
PS C:\Users> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
# Checking for any trust relationships the domain has
PS C:\Users> Get-ADTrust -Filter *
# Group Enumeration
PS C:\Users> Get-ADGroup -Filter * | select name
# Get more detailed information about a particular group
PS C:\Users> Get-ADGroup -Identity "Group Name from above"
# Get a member listing from the group above
PS C:\Users> Get-ADGroupMember -Identity "Group Name from above"
# to show only distinguishname and samaccountname ( | select -Property distinguishedName,samaccountname )

# Checking for Reversible Encryption Option using Get-ADUser
PS C:\Users> Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
```

#### Nltest

```bash
# finds all domain controllers in a specific domain.
nltest /dclist:domain_name

# finds the current DC for a user or computer.
nltest /dsgetdc:domain_name

# lists all domains trusted by the current domain.
nltest /trusted_domains

# queries DNS for DC records.
nltest /dnsgetdc:domain_name
```

#### PowerView

[PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)

``` Powershell
# Information of a specific user in a specific domain
PS C:\Users> Get-DomainUser -Identity mmorgan -Domain inlanefreight.local
# Information of all users in a domain
PS C:\Users> Get-DomainUser -Domain inlanefreight.local
# Enumerate a domain group members and also list it's nested groups members of there was any
PS C:\Users> Get-DomainGroupMember -Identity "Domain Admins" -Recurse
# Trust Enumeration
PS C:\Users> Get-DomainTrustMapping
# Testing for Local Admin Access on a specific machine (current or remote machine).
PS C:\Users> Test-AdminAccess -ComputerName ACADEMY-EA-MS01
# Check for users with the SPN attribute set (may be subjected to a Kerberoasting attack).
PS C:\Users> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
# Checking for Reversible Encryption Option using Get-DomainUser
PS C:\Users> Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol

# SharpView .NET port of PowerView. Many of the same functions supported by PowerView can be used with SharpView.
# type a method name with `-Help` to get an argument list.
PS C:\Users> .\SharpView.exe Get-DomainUser -Help
# Enumerate information about a specific user
PS C:\Users> .\SharpView.exe Get-DomainUser -Identity forend
# SharpView can be more beneficial in an environment hardened against powershell usage. 
```

#### Snaffler

[Snaffler](https://github.com/SnaffCon/Snaffler) is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment.
works by obtaining a list of hosts within the domain and then enumerating those hosts for shares and readable directories.
Once that is done, it iterates through any directories readable by our user and hunts for files that could serve to better our position within the assessment.

``` Powershell
PS C:\Users> Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

---
### Living Off the Land

The techniques here for testing AD environment from a managed `Windows` host with no internet access, and all efforts to load tools onto it have failed.

#### Basic Enumeration

```powershell
# Prints the PC's Name
PS C:\> hostname
# Print information about the current PowerShell session.
PS C:\> get-host
# (Query WINdows STAtion) shows current sessions on the host.
PS C:\> qwinsta
# Change to a version that has no logging feature if available.
PS C:\> powershell.exe -version 2
# OS version and revision level
PS C:\>[System.Environment]::OSVersion.Version
# Patches and hotfixes applied
PS C:\> wmic qfe get Caption,Description,HotFixID,InstalledOn
# Display environment vars
PS C:\> Get-ChildItem Env: | ft Key,Value
# Display environment vars
PS C:\> cmd /c set
# Display the user domain
PS C:\> cmd /c echo %USERDOMAIN%
# The DC the host checks in with
PS C:\> cmd /c echo %logonserver%
# Print the system information summary
PS C:\> systeminfo
# List available modules
PS C:\> get-module
# Will print the execution policy settings for each scope on a host.
PS C:\> Get-ExecutionPolicy -List
# Change the current process policy.
PS C:\> Set-ExecutionPolicy Bypass -Scope Process
# Get the specified user's PowerShell history.
PS C:\> Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
# State of the Windows firewall and Windows defender.
PS C:\> netsh advfirewall show allprofiles
# Windows Defender Check
PS C:\> cmd /c sc query windefend
# Check Windows defender status and configuration settings
PS C:\> Get-MpComputerStatus
```

#### Network Enumeration

```PowerSHell
# Display all network adapters
PS C:\> ipconfig /all
# Dipslay the arp table
PS C:\> arp -a
# Display the routing table (IPv4 & IPv6)
PS C:\> route print
# 
PS C:\>
```

#### WMI

[Windows Management Instrumentation (WMI)](https://docs.microsoft.com/en-us/windows/win32/wmisdk/about-wmi) - [cheatsheet](https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4)for querying host and domain info using wmic.

```Powershell
# Patch level and description of the Hotfixes applied
PS C:\> wmic qfe get Caption,Description,HotFixID,InstalledOn
# Basic host information to include any attributes within the list
PS C:\> wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List
# Listing all processes on host
PS C:\> wmic process list /format:list
# Displays domain and DC info
PS C:\> wmic ntdomain list /format:list
# Info about local accounts and domain accounts that have logged into the device
PS C:\> wmic useraccount list /format:list
# Info about local groups
PS C:\> wmic group list /format:list
# Info about any system accounts that are being used as service accounts
PS C:\> wmic sysaccount list /format:list
# Info about the domain, its child and the external forest that our current domain has a trust with.
PS C:\> wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress
```

#### NET

[Net](https://docs.microsoft.com/en-us/windows/win32/winsock/net-exe-2)

| **Command**                                     | **Description**                                                                                                              |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `net accounts`                                  | Information about password requirements                                                                                      |
| `net accounts /domain`                          | Password and lockout policy                                                                                                  |
| `net group /domain`                             | Information about domain groups                                                                                              |
| `net group "Domain Admins" /domain`             | List users with domain admin privileges                                                                                      |
| `net group "domain computers" /domain`          | List of PCs connected to the domain                                                                                          |
| `net group "Domain Controllers" /domain`        | List PC accounts of domains controllers                                                                                      |
| `net group <domain_group_name> /domain`         | User that belongs to the group                                                                                               |
| `net groups /domain`                            | List of domain groups                                                                                                        |
| `net localgroup`                                | All available groups                                                                                                         |
| `net localgroup administrators /domain`         | List users that belong to the administrators group inside the domain (the group `Domain Admins` is included here by default) |
| `net localgroup Administrators`                 | Information about a group (admins)                                                                                           |
| `net localgroup administrators [username] /add` | Add user to administrators                                                                                                   |
| `net share`                                     | Check current shares                                                                                                         |
| `net user <ACCOUNT_NAME> /domain`               | Get information about a user within the domain                                                                               |
| `net user /domain`                              | List all users of the domain                                                                                                 |
| `net user /domain username`                     | Information about a domain user                                                                                              |
| `net user %username%`                           | Information about the current user                                                                                           |
| `net use x: \computer\share`                    | Mount the share locally                                                                                                      |
| `net view`                                      | Get a list of computers                                                                                                      |
| `net view /all /domain[:domainname]`            | Shares on the domains                                                                                                        |
| `net view \\computer /ALL`                      | List shares of a computer                                                                                                    |
| `net view /domain`                              | List of PCs of the domain                                                                                                    |

> [!Important]
> If you believe the network defenders are actively logging/looking for any commands out of the normal, you can try this workaround to using net commands. Typing `net1` instead of `net` will execute the same functions without the potential trigger from the net string.
> 
> `net view` --> `net1 view`

#### Dsquery

[Dsquery](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11)) will exist on any host with the `Active Directory Domain Services Role` installed, and the `dsquery` DLL exists on all modern Windows systems by default now and can be found at `C:\Windows\System32\dsquery.dll`.

All we need is `elevated privileges` on a host or the ability to run an instance of Command Prompt or PowerShell from a `SYSTEM` context.

[dsquery wildcard search](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754232(v=ws.11))

``` PowerShell
# User Search
PS C:\> dsquery user
# Computer Search
PS C:\> dsquery computer
# dsquery wildcard search to view all objects in an OU.
PS C:\> dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
```

Combine `dsquery` with LDAP filters.

``` PowerShell
# Users With Specific Attributes Set (PASSWD_NOTREQD) -> password not required
PS C:\> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

# Look for all Domain Controllers in the current domain, limiting to five results.
PS C:\> dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName

# Look for all domain admin privileged users recursively through the "Domain Admins" group and its sub groups 
PS C:\> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(memberof:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL))" -attr sAMAccountName
# Or use
PS C:\> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(adminCount=1))"
```

- `-filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)"`
	- `userAccountControl:1.2.840.113556.1.4.803:` Specifies that we are looking at the [User Account Control (UAC) attributes](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties) for an object.
		- This portion can change to include three different values when searching for information in AD (also known as [Object Identifiers (OIDs)](https://ldap.com/ldap-oid-reference-guide/).
			- `1.2.840.113556.1.4.803` --> When using this rule, we are saying the bit value must match completely to meet the search requirements.
			- `1.2.840.113556.1.4.804` --> When using this rule, we are saying that we want our results to show any attribute match if any bit in the chain matches.
			- `1.2.840.113556.1.4.1941` --> This rule is used to match filters that apply to the Distinguished Name of an object and will search through all ownership and membership entries.
	- `=8192` represents the decimal bitmask we want to match in this search.


##### userAccountControl Values

| Property flag                  | Value in hexadecimal | Value in decimal |
| ------------------------------ | -------------------- | ---------------- |
| SCRIPT                         | 0x0001               | 1                |
| ACCOUNTDISABLE                 | 0x0002               | 2                |
| HOMEDIR_REQUIRED               | 0x0008               | 8                |
| LOCKOUT                        | 0x0010               | 16               |
| PASSWD_NOTREQD                 | 0x0020               | 32               |
| PASSWD_CANT_CHANGE             | 0x0040               | 64               |
| ENCRYPTED_TEXT_PWD_ALLOWED     | 0x0080               | 128              |
| TEMP_DUPLICATE_ACCOUNT         | 0x0100               | 256              |
| NORMAL_ACCOUNT                 | 0x0200               | 512              |
| INTERDOMAIN_TRUST_ACCOUNT      | 0x0800               | 2048             |
| WORKSTATION_TRUST_ACCOUNT      | 0x1000               | 4096             |
| SERVER_TRUST_ACCOUNT           | 0x2000               | 8192             |
| DONT_EXPIRE_PASSWORD           | 0x10000              | 65536            |
| MNS_LOGON_ACCOUNT              | 0x20000              | 131072           |
| SMARTCARD_REQUIRED             | 0x40000              | 262144           |
| TRUSTED_FOR_DELEGATION         | 0x80000              | 524288           |
| NOT_DELEGATED                  | 0x100000             | 1048576          |
| USE_DES_KEY_ONLY               | 0x200000             | 2097152          |
| DONT_REQ_PREAUTH               | 0x400000             | 4194304          |
| PASSWORD_EXPIRED               | 0x800000             | 8388608          |
| TRUSTED_TO_AUTH_FOR_DELEGATION | 0x1000000            | 16777216         |
