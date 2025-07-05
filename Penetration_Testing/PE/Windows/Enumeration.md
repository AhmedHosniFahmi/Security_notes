### Content

- [Protections Enumeration](#protections-enumeration)
- [Users and Groups Enumeration](#users-and-groups-enumeration)
- [Environment Enumeration](#environment-enumeration)
- [Services and Processes](#services-and-processes)
- [Network](#network)

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

### Protections  Enumeration

``` powershell
# Check Windows Defender Status
C:\> Get-MpComputerStatus

# List AppLocker Rules
C:\> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Test AppLocker Policy
C:\> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone

# Get Password Policy & Other Account Information
C:\> net accounts
```

### Users and Groups Enumeration

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

### Environment Enumeration

```PowerShell
# Display All Environment Variables
C:\> cmd.exe /c set

# System Info
C:\> systeminfo

# Display System Hotfixes
C:\> wmic qfe
C:\> Get-HotFix | ft -AutoSize

# Installed Programs
C:\> wmic product get name
C:\> Get-WmiObject -Class Win32_Product |  select Name, Version
```

### Services and Processes

```PowerShell
# List running processes
C:\> tasklist /svc

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
# List running processes to map the PID to an executable
# Instead, you can use -b to resolve the executable name if you are admin
```

#### Network Tips

- The main thing to look for with Active Network Connections are entries listening on loopback addresses (`127.0.0.1:<PortNumber>` and `[::1]:<PortNumber>`)
	- Port `14147`, used for FileZilla's administrative interface. By connecting to this port, it may be possible to extract FTP passwords in addition to creating an FTP Share at `c:\` as the FileZilla Server user (potentially Administrator).
	- `Splunk Universal Forwarder`, installed on endpoints to send logs into Splunk. For more information, check out [Splunk Universal Forwarder Hijacking](https://airman604.medium.com/splunk-universal-forwarder-hijacking-5899c3e0e6b2) and [SplunkWhisperer2](https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/).
	- `Erlang Port` (25672). Erlang is a programming language designed around distributed computing and will have a network port that allows other Erlang nodes to join the cluster. The secret to join this cluster is called a cookie.
		- Many applications that utilize Erlang will either use a weak cookie (RabbitMQ uses `rabbit` by default) or place the cookie in a configuration file that is not well protected. Some example Erlang applications are SolarWinds, RabbitMQ, and CouchDB. For more information check out the [Erlang-arce blogpost from Mubix](https://malicious.link/post/2018/erlang-arce/)