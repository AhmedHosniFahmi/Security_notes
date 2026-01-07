### Content

- [Protections](#protections)
- [Users and Groups](#users-and-groups)
- [Environment](#environment)
- [Services and Processes](#services-and-processes)
- [Network](#network)
	- [Network Tips](#network-tips)
- [Applications](#applications)

---

> [!Note]
> 
> What we target:
> 
> - `NT AUTHORITY\SYSTEM` account
> - The built-in local `administrator` account.
> - A member of the local `Administrators` group.
> - A standard (non-privileged) domain user who is part of the local `Administrators` group.
> - A domain admin that is part of the local Administrators group.

---
### Protections

``` powershell
# Check Windows Defender Status
C:\> Get-MpComputerStatus

# List AppLocker Rules
C:\> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Test AppLocker Policy
C:\> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone

# Get Password Policy & Other Account Information
C:\> net accounts

# Examine last installed updates
PS C:\> systeminfo
PS C:\>cmd /c wmic qfe list brief
PS C:\> Get-Hotfix
```

---
### Users and Groups

```PowerShell
# Current User
C:\> cmd.exe /c echo %USERNAME%
# Current User Privileges
C:\> whoami /priv
# Logged-In Users
C:\> query user
# Get All Users
C:\> net user


# Current User Group Information
C:\> whoami /groups
# Get All Groups
C:\> net localgroup
# Details About a Group
C:\> net localgroup <groupName>
# Extraxt group's members
C:\> Get-ADGroupMember -Identity <groupName>
```

---
### Environment

```PowerShell
# Display All Environment Variables
C:\> set
PS C:\> Get-ChildItem Env:

# System Info
C:\> systeminfo

# Reviewing Path Variable
C:\> echo %PATH%
PS C:\> echo $Env:PATH

# Display System Hotfixes
C:\> wmic qfe
PS C:\> Get-HotFix | ft -AutoSize

# Installed Programs
PS C:\> wmic product get name
PS C:\> Get-WmiObject -Class Win32_Product |  select Name, Version

# Checking Windows Version
PS C:\> [environment]::OSVersion.Version
```

---
### Services and Processes

```PowerShell
# List running processes
C:\> tasklist /svc
C:\> get-process 
# To search for a specific process
C:\> get-process -ProcessName "*sl*" -Id 13132

# List avaiable services
C:\> Get-Service | Where-Object {$_.Status -eq "Running"}
C:\> Get-Service | ? {$_.DisplayName -like 'Druva*'}
C:\> sc query
# More formated html table output with wmic (open it in browser)
C:\> wmic service get * /format:htable > services.html
# Get specific properties
C:\> wmic service get name,startname
# started services only
C:\> wmic service where started=true get  name, startname
# Specific pattern name
C:\> wmic service where 'name like "%sql%"' get  name, startname

######## Named Pipes #########
# Using pipelist from Sysinternals
C:\> pipelist.exe /accepteula
# Using powershell
C:\> gci \\.\pipe\

# Using accesschk from Sysinternals
# Search for all named pipes that allow write access
C:\> accesschk.exe -w \pipe\* -v
# Review specific named pipe permisions
C:\> accesschk.exe /accepteula \\.\Pipe\lsass -v
C:\> accesschk.exe /accepteula \pipe\SQLLocal\SQLEXPRESS01 -v
```

---
### Network

``` powershell
# Interface(s), IP Address(es), DNS Information
C:\> ipconfig /all

# ARP table
C:\> arp -a

# Routing Table
C:\> route print

# Active TCP and UDP connections
C:\> netstat -ano
# You can see the PID in the output
# List running processes to map the PID to an executable (get-process -Id 3324)
# Instead, you can use -b to resolve the executable name if you are admin
```

#### Network Tips

- The main thing to look for with Active Network Connections are entries listening on loopback addresses (`127.0.0.1:<PortNumber>` and `[::1]:<PortNumber>`)
	- Port `14147`, used for FileZilla's administrative interface. By connecting to this port, it may be possible to extract FTP passwords in addition to creating an FTP Share at `c:\` as the FileZilla Server user (potentially Administrator).
	- `Splunk Universal Forwarder`, installed on endpoints to send logs into Splunk. For more information, check out [Splunk Universal Forwarder Hijacking](https://airman604.medium.com/splunk-universal-forwarder-hijacking-5899c3e0e6b2) and [SplunkWhisperer2](https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/).
	- `Erlang Port` (25672). Erlang is a programming language designed around distributed computing and will have a network port that allows other Erlang nodes to join the cluster. The secret to join this cluster is called a cookie.
		- Many applications that utilize Erlang will either use a weak cookie (RabbitMQ uses `rabbit` by default) or place the cookie in a configuration file that is not well protected. Some example Erlang applications are SolarWinds, RabbitMQ, and CouchDB. For more information check out the [Erlang-arce blogpost from Mubix](https://malicious.link/post/2018/erlang-arce/)

---
### Applications

```PowerShell
# Read the Windows registry to collect more granular information about installed programs.
PS C:\> $INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\> $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\> $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize

# Using CMD we can list the 'Program Files' and 'Program Files (x86)' to find the installed apps
C:\> dir "C:\Program Files"
C:\> dir "C:\Program Files (x86)"
```